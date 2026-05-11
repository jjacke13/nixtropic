/*
 * CTAPHID framing — assemble HID OUT reports into a request buffer,
 * dispatch by command, fragment the response back into HID IN reports.
 *
 * State: IDLE / ASSEMBLING. While assembling, packets from a different
 * CID are rejected with CHANNEL_BUSY (FIDO U2F HID §3.4.3).
 *
 * Channel allocation: monotonic counter starting at 1; we never recycle
 * CIDs in Phase 4. After FIDO_HID_MAX_CHANNELS allocations, fresh INITs
 * still succeed but cycle from 1 again (acceptable for stub).
 *
 * Phase 4 M2 commands wired here:
 *   - INIT      0x86  channel allocation + caps echo
 *   - PING      0x81  echo payload
 *   - MSG       0x83  U2F APDU passthrough → return SW=0x6E00 (CLA n/s)
 *   - CANCEL    0x91  abort current transaction
 *   - CBOR      0x90  routed to fido_hid_cbor_dispatch (stub in M2)
 *
 * Same cooperative-USB caveat as lt-rpc: the tud_hid_set_report_cb fires
 * from tud_task() so callbacks and main-loop drain do not preempt each
 * other. If TinyUSB is ever ported to IRQ-driven endpoint handling, this
 * code needs a critical-section guard around the response buffer.
 */

#include "ctaphid.h"
#include "proto.h"
#include "user_presence.h"

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "tusb.h"

/* ===== State ===== */

typedef enum {
    FH_STATE_IDLE = 0,
    FH_STATE_ASSEMBLING,
} fh_state_t;

static fh_state_t s_state;

/* Request assembly (single in-flight) */
static uint32_t s_cur_cid;          /* CID currently being assembled */
static uint8_t  s_req_cmd;          /* command without INIT flag */
static uint16_t s_req_total;
static uint16_t s_req_received;
static uint8_t  s_next_seq;
static uint8_t  s_req_buf[FIDO_HID_MAX_PAYLOAD];

/* Response emission */
static uint32_t s_resp_cid;
static uint8_t  s_resp_cmd;         /* cmd with INIT flag set */
static uint16_t s_resp_total;
static uint16_t s_resp_sent;
static uint8_t  s_resp_seq;
static bool     s_resp_pending;
static uint8_t  s_resp_buf[FIDO_HID_MAX_PAYLOAD];

/* CID allocator */
static uint32_t s_next_cid;

/* ===== Helpers ===== */

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t) p[0] << 24) |
           ((uint32_t) p[1] << 16) |
           ((uint32_t) p[2] << 8) |
            (uint32_t) p[3];
}

static void write_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t) v;
}

static void write_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t) v;
}

static void reset_assembly(void)
{
    s_state        = FH_STATE_IDLE;
    s_cur_cid      = 0;
    s_req_cmd      = 0;
    s_req_total    = 0;
    s_req_received = 0;
    s_next_seq     = 0;
    /* Zero the request buffer so stale bytes from an abandoned transaction
     * cannot leak into a future handler that doesn't strictly gate on
     * req_len. Cheap (2 KB memset on a 160 MHz Cortex-M33); matches the
     * lt-rpc invariant that survived the cpp-reviewer audit. */
    memset(s_req_buf, 0, sizeof s_req_buf);
}

/* ===== Response queueing ===== */

static void queue_response(uint32_t cid, uint8_t cmd_with_flag,
                           const uint8_t *payload, size_t len)
{
    if (len > FIDO_HID_MAX_PAYLOAD) len = FIDO_HID_MAX_PAYLOAD;
    if (len > 0u) memcpy(s_resp_buf, payload, len);
    s_resp_cid     = cid;
    s_resp_cmd     = cmd_with_flag;
    s_resp_total   = (uint16_t) len;
    s_resp_sent    = 0;
    s_resp_seq     = 0;
    s_resp_pending = true;
}

static void queue_error(uint32_t cid, uint8_t err)
{
    uint8_t payload = err;
    queue_response(cid, FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_ERROR, &payload, 1);
}

static bool emit_response_packet(void)
{
    if (!s_resp_pending) return false;
    /* TinyUSB instance 1 = FIDO HID. */
    if (!tud_hid_n_ready(1)) return false;

    uint8_t pkt[FIDO_HID_REPORT_LEN];
    memset(pkt, 0, sizeof pkt);
    write_be32(pkt, s_resp_cid);

    bool is_first = (s_resp_sent == 0u);
    size_t cap;
    size_t hdr_size;
    if (is_first) {
        pkt[4] = s_resp_cmd;                 /* already has INIT flag */
        write_be16(&pkt[5], s_resp_total);
        cap      = FIDO_HID_INIT_DATA_LEN;
        hdr_size = 7u;
    } else {
        pkt[4] = (uint8_t)(s_resp_seq & 0x7Fu);
        cap      = FIDO_HID_CONT_DATA_LEN;
        hdr_size = 5u;
        s_resp_seq++;
    }

    size_t remaining = (size_t)(s_resp_total - s_resp_sent);
    size_t chunk     = remaining > cap ? cap : remaining;
    if (chunk > 0u) {
        memcpy(&pkt[hdr_size], &s_resp_buf[s_resp_sent], chunk);
    }
    s_resp_sent = (uint16_t)(s_resp_sent + chunk);

    if (!tud_hid_n_report(1, 0, pkt, FIDO_HID_REPORT_LEN)) {
        /* Push failed; roll back, retry next tick. */
        s_resp_sent = (uint16_t)(s_resp_sent - chunk);
        if (!is_first) s_resp_seq--;
        return false;
    }

    /* INIT response with empty payload (BCNT=0) is still a valid packet —
     * we've emitted it; mark done. Otherwise check the byte counter. */
    if (s_resp_sent >= s_resp_total) {
        s_resp_pending = false;
    }
    return true;
}

/* ===== Channel allocation ===== */

static uint32_t alloc_channel(void)
{
    uint32_t cid = s_next_cid;
    s_next_cid++;
    /* Skip 0 and broadcast on wraparound. CIDs are 32-bit so wrap is a
     * theoretical concern, not a practical one for stub use. */
    if (s_next_cid == 0u) s_next_cid = 1u;
    if (s_next_cid == FIDO_HID_CID_BROADCAST) s_next_cid = 1u;
    return cid;
}

/* ===== Command handlers ===== */

static void handle_init(uint32_t req_cid, const uint8_t *payload, size_t len)
{
    /* CTAPHID_INIT request payload is the 8-byte nonce. INIT on a
     * non-broadcast CID is the "channel sync" form: resync the channel
     * but keep the same CID. INIT on broadcast allocates a fresh CID. */
    if (len != 8u) {
        queue_error(req_cid, FIDO_HID_ERR_INVALID_LEN);
        return;
    }

    uint32_t out_cid;
    if (req_cid == FIDO_HID_CID_BROADCAST) {
        out_cid = alloc_channel();
    } else {
        /* Channel sync — keep same CID, just reset any in-flight state
         * belonging to it. */
        out_cid = req_cid;
        if (s_state == FH_STATE_ASSEMBLING && s_cur_cid == req_cid) {
            reset_assembly();
        }
    }

    uint8_t resp[FIDO_HID_INIT_RESP_LEN];
    memcpy(&resp[0], payload, 8);            /* echo nonce */
    write_be32(&resp[8], out_cid);
    resp[12] = (uint8_t) FIDO_HID_PROTOCOL_VER;
    resp[13] = (uint8_t) FIDO_HID_DEVICE_VER_MAJOR;
    resp[14] = (uint8_t) FIDO_HID_DEVICE_VER_MINOR;
    resp[15] = (uint8_t) FIDO_HID_DEVICE_VER_BUILD;
    resp[16] = (uint8_t) FIDO_HID_CAPABILITIES;

    queue_response(req_cid, FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_INIT,
                   resp, sizeof resp);
}

static void handle_ping(uint32_t cid, const uint8_t *payload, size_t len)
{
    queue_response(cid, FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_PING,
                   payload, len);
}

static void handle_msg(uint32_t cid, const uint8_t *payload, size_t len)
{
    /* U2F APDUs aren't supported — return SW=0x6E00 (CLA not supported).
     * libfido2 falls back to CTAP2 when MSG fails this way. */
    (void) payload;
    (void) len;
    const uint8_t sw[2] = { 0x6Eu, 0x00u };
    queue_response(cid, FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_MSG, sw, 2);
}

static void handle_cancel(uint32_t cid, const uint8_t *payload, size_t len)
{
    /* CANCEL has empty payload by spec. We treat extra bytes as
     * non-fatal — just abort. Response is required (FIDO spec §11.2.9.1.4):
     * empty payload, echoing CANCEL with the INIT flag. */
    (void) payload;
    (void) len;
    if (s_state == FH_STATE_ASSEMBLING && s_cur_cid == cid) {
        reset_assembly();
    }
    queue_response(cid, FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_CANCEL, NULL, 0);
}

static void handle_cbor(uint32_t cid, const uint8_t *payload, size_t len)
{
    /* Borrow s_resp_buf as scratch — same pattern as lt-rpc. The
     * fido_hid_cbor_dispatch() prototype lives here in M2 as a weak stub
     * returning INVALID_COMMAND for everything; M3 wires real GetInfo. */
    int n = fido_hid_cbor_dispatch(payload, len, s_resp_buf, FIDO_HID_MAX_PAYLOAD);
    if (n < 0) {
        queue_error(cid, FIDO_HID_ERR_OTHER);
        return;
    }
    /* Set response directly — handler already wrote into s_resp_buf. */
    s_resp_cid     = cid;
    s_resp_cmd     = (uint8_t)(FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_CBOR);
    s_resp_total   = (uint16_t) n;
    s_resp_sent    = 0;
    s_resp_seq     = 0;
    s_resp_pending = true;
}

/* M2 stub — every CTAP2 command answers CTAP2_ERR_INVALID_COMMAND (0x01).
 * Override via fido_hid/ctap2.c in M3. Weak symbol so M3 can replace
 * without changing this file. */
__attribute__((weak))
int fido_hid_cbor_dispatch(const uint8_t *req, size_t req_len,
                           uint8_t *resp, size_t resp_max)
{
    (void) req;
    (void) req_len;
    if (resp_max < 1u) return -1;
    resp[0] = 0x01u;            /* CTAP2_ERR_INVALID_COMMAND */
    return 1;
}

/* ===== Request dispatch ===== */

static void dispatch_request(uint32_t cid)
{
    uint8_t  cmd = s_req_cmd;
    uint16_t len = s_req_received;

    if (cmd == FIDO_HID_CMD_INIT) {
        handle_init(cid, s_req_buf, len);
    } else if (cmd == FIDO_HID_CMD_PING) {
        handle_ping(cid, s_req_buf, len);
    } else if (cmd == FIDO_HID_CMD_MSG) {
        handle_msg(cid, s_req_buf, len);
    } else if (cmd == FIDO_HID_CMD_CANCEL) {
        handle_cancel(cid, s_req_buf, len);
    } else if (cmd == FIDO_HID_CMD_CBOR) {
        handle_cbor(cid, s_req_buf, len);
    } else {
        queue_error(cid, FIDO_HID_ERR_INVALID_CMD);
    }
}

/* ===== Packet ingest ===== */

static void handle_init_packet(uint32_t cid, const uint8_t *pkt)
{
    uint8_t  cmd_byte = pkt[4];
    uint16_t bcnt     = (uint16_t)(((uint16_t) pkt[5] << 8) | (uint16_t) pkt[6]);
    uint8_t  cmd      = (uint8_t)(cmd_byte & 0x7Fu);

    /* Broadcast CID is reserved for CTAPHID_INIT (channel allocation). */
    if (cid == FIDO_HID_CID_BROADCAST && cmd != FIDO_HID_CMD_INIT) {
        queue_error(cid, FIDO_HID_ERR_INVALID_CHANNEL);
        return;
    }

    /* CTAPHID_INIT is special: its request is always atomic (a single
     * 8-byte nonce fits inside one INIT packet), it may arrive from any
     * CID including the broadcast one, and per FIDO U2F HID §3.4.3 it
     * must NEVER displace an in-flight transaction owned by a different
     * CID. Dispatch it here without touching the assembly state machine.
     *
     * cpp-reviewer audit 2026-05-11 finding M2: prior code routed INIT
     * through the same s_cur_cid-overwriting path as every other
     * command, so a host that sent an INIT on a fresh CID mid-assembly
     * silently clobbered the original transaction's state. */
    if (cmd == FIDO_HID_CMD_INIT) {
        if (bcnt > FIDO_HID_INIT_DATA_LEN) {
            queue_error(cid, FIDO_HID_ERR_INVALID_LEN);
            return;
        }
        /* INIT on the channel currently assembling = sync; reset it. */
        if (s_state == FH_STATE_ASSEMBLING && cid == s_cur_cid) {
            reset_assembly();
        }
        handle_init(cid, &pkt[7], (size_t) bcnt);
        return;
    }

    /* Phase 6 M1 — M3 reentrancy defense (docs/PHASE-6-PLAN.md §3 row
     * M3): while user_presence_check is awaiting touch, the CBOR
     * dispatcher cannot accept any new transaction.  pin.c file-statics
     * (s_pin_token, s_eph_priv) are not reentrant; ECC keypair gen on
     * TROPIC01 must run to completion before any new sign request.
     * Refuse with CHANNEL_BUSY regardless of CID — INIT was already
     * fast-pathed above so stuck channels can still be reset. */
    if (user_presence_is_awaiting()) {
        queue_error(cid, FIDO_HID_ERR_CHANNEL_BUSY);
        return;
    }

    /* Non-INIT commands: if another CID has a transaction in flight,
     * refuse with CHANNEL_BUSY (FIDO U2F HID §3.4.3). */
    if (s_state == FH_STATE_ASSEMBLING && cid != s_cur_cid) {
        queue_error(cid, FIDO_HID_ERR_CHANNEL_BUSY);
        return;
    }

    if (bcnt > FIDO_HID_MAX_PAYLOAD) {
        reset_assembly();
        queue_error(cid, FIDO_HID_ERR_INVALID_LEN);
        return;
    }

    /* Zero the request buffer at every INIT — same invariant lt-rpc holds
     * after the Phase 3 audit (no stale-data info-disclosure if a future
     * handler reads beyond req_len). */
    memset(s_req_buf, 0, sizeof s_req_buf);

    s_cur_cid      = cid;
    s_req_cmd      = cmd;
    s_req_total    = bcnt;
    s_req_received = 0;
    s_next_seq     = 0;

    size_t avail = bcnt > FIDO_HID_INIT_DATA_LEN ? FIDO_HID_INIT_DATA_LEN : (size_t) bcnt;
    if (avail > 0u) {
        memcpy(s_req_buf, &pkt[7], avail);
        s_req_received = (uint16_t) avail;
    }

    if (s_req_received >= s_req_total) {
        dispatch_request(cid);
        reset_assembly();
    } else {
        s_state = FH_STATE_ASSEMBLING;
    }
}

static void handle_cont_packet(uint32_t cid, const uint8_t *pkt)
{
    if (s_state != FH_STATE_ASSEMBLING || cid != s_cur_cid) {
        /* Spurious CONT — drop per CTAPHID §3.4.3. Don't emit an error
         * because it could correspond to a host that already moved on. */
        return;
    }

    uint8_t seq = (uint8_t)(pkt[4] & 0x7Fu);
    if (seq != s_next_seq) {
        reset_assembly();
        queue_error(cid, FIDO_HID_ERR_INVALID_SEQ);
        return;
    }
    s_next_seq++;

    uint16_t remaining = (uint16_t)(s_req_total - s_req_received);
    size_t   chunk     = remaining > FIDO_HID_CONT_DATA_LEN
                            ? FIDO_HID_CONT_DATA_LEN
                            : (size_t) remaining;
    if (chunk > 0u) {
        memcpy(&s_req_buf[s_req_received], &pkt[5], chunk);
        s_req_received = (uint16_t)(s_req_received + chunk);
    }

    if (s_req_received >= s_req_total) {
        dispatch_request(cid);
        reset_assembly();
    }
}

/* ===== Public API ===== */

void fido_hid_init(void)
{
    reset_assembly();
    s_resp_pending = false;
    s_resp_total   = 0;
    s_resp_sent    = 0;
    s_resp_cid     = 0;
    s_resp_cmd     = 0;
    s_resp_seq     = 0;
    /* CIDs 0x00000001..0xFFFFFFFE are valid; we start at 1. */
    s_next_cid     = 1u;
}

void fido_hid_task(void)
{
    while (emit_response_packet()) {
        /* drain until backpressure or done */
    }
}

void fido_hid_handle_packet(const uint8_t *pkt, size_t len)
{
    if (len < FIDO_HID_REPORT_LEN) return;

    uint32_t cid = read_be32(pkt);
    if (cid == 0u) {
        /* CID 0 is reserved; reject. */
        queue_error(cid, FIDO_HID_ERR_INVALID_CHANNEL);
        return;
    }

    uint8_t byte4 = pkt[4];
    if (byte4 & FIDO_HID_CMD_INIT_FLAG) {
        handle_init_packet(cid, pkt);
    } else {
        handle_cont_packet(cid, pkt);
    }
}
