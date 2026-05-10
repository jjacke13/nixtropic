/*
 * lt-rpc framing layer — assembles HID OUT reports into a request buffer,
 * dispatches to the registered handler, fragments the response into HID
 * IN reports.
 *
 * State machine has two states: IDLE (waiting for INIT) and ASSEMBLING
 * (collected an INIT, expecting CONT packets until bcnt bytes received).
 * Mid-transaction OUT packets with mismatched CID/SEQ are dropped silently.
 *
 * Response is emitted by hid_rpc_task() draining one packet at a time
 * whenever tud_hid_n_ready() returns true. Keeps callbacks short.
 */

#include "rpc.h"
#include "lt_rpc_proto.h"

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "tusb.h"

/* ===== State ===== */

typedef enum {
    RPC_STATE_IDLE = 0,
    RPC_STATE_ASSEMBLING,
} rpc_state_t;

static rpc_state_t s_state;

/* Request assembly */
static uint8_t  s_req_buf[LT_RPC_MAX_PAYLOAD];
static uint16_t s_req_total;        /* BCNT from INIT */
static uint16_t s_req_received;     /* bytes accumulated so far */
static uint8_t  s_req_cmd;          /* command byte without INIT flag */
static uint8_t  s_next_seq;         /* expected SEQ for next CONT (starts 0) */

/* Response emission */
static uint8_t  s_resp_buf[HID_RPC_RESP_MAX];
static uint16_t s_resp_total;       /* bytes in response */
static uint16_t s_resp_sent;        /* bytes already pushed to TinyUSB */
static uint8_t  s_resp_cmd;         /* command byte to echo (with INIT flag) */
static uint8_t  s_resp_seq;         /* next SEQ for outgoing CONT */
static bool     s_resp_pending;     /* response queued, not fully emitted */

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
    s_state        = RPC_STATE_IDLE;
    s_req_total    = 0;
    s_req_received = 0;
    s_req_cmd      = 0;
    s_next_seq     = 0;
    /* Zero the request buffer so an aborted-mid-transfer leak path can't
     * carry payload bytes from the previous transaction into the next one
     * (e.g., previous transaction's ECC sign challenge). Cheap (1 KB memset
     * on a 160 MHz Cortex-M33) and removes a class of latent issues. */
    memset(s_req_buf, 0, sizeof s_req_buf);
}

/* ===== Response queueing ===== */

static void queue_response(uint8_t cmd_with_flag, const uint8_t *payload, size_t len)
{
    if (len > HID_RPC_RESP_MAX) {
        len = HID_RPC_RESP_MAX;
    }
    if (len > 0u) {
        memcpy(s_resp_buf, payload, len);
    }
    s_resp_total   = (uint16_t) len;
    s_resp_sent    = 0;
    s_resp_cmd     = cmd_with_flag;
    s_resp_seq     = 0;
    s_resp_pending = true;
}

static void queue_error(uint8_t err_code)
{
    uint8_t payload = err_code;
    queue_response(LT_RPC_CMD_INIT_FLAG | LT_RPC_CMD_ERROR, &payload, 1);
}

/* Pump a single response packet to the host if the IN EP is ready.
 * Returns true iff a packet was queued. */
static bool emit_response_packet(void)
{
    if (!s_resp_pending) return false;
    if (!tud_hid_n_ready(0)) return false;

    uint8_t pkt[LT_RPC_HID_REPORT_LEN];
    memset(pkt, 0, sizeof pkt);
    write_be32(pkt, LT_RPC_CID_DEFAULT);

    bool is_first = (s_resp_sent == 0u);
    size_t cap;
    size_t hdr_size;
    if (is_first) {
        pkt[4] = s_resp_cmd;                /* already has INIT flag set */
        write_be16(&pkt[5], s_resp_total);
        cap      = LT_RPC_INIT_DATA_LEN;
        hdr_size = 7u;
    } else {
        pkt[4] = (uint8_t)(s_resp_seq & 0x7Fu);
        cap      = LT_RPC_CONT_DATA_LEN;
        hdr_size = 5u;
        s_resp_seq++;
    }

    size_t remaining = (size_t)(s_resp_total - s_resp_sent);
    size_t chunk     = remaining > cap ? cap : remaining;
    if (chunk > 0u) {
        memcpy(&pkt[hdr_size], &s_resp_buf[s_resp_sent], chunk);
    }
    s_resp_sent = (uint16_t)(s_resp_sent + chunk);

    if (!tud_hid_n_report(0, 0, pkt, LT_RPC_HID_REPORT_LEN)) {
        /* Push failed; will retry next task tick. Roll back send pointer. */
        s_resp_sent = (uint16_t)(s_resp_sent - chunk);
        if (!is_first) s_resp_seq--;
        return false;
    }

    if (s_resp_sent >= s_resp_total) {
        s_resp_pending = false;
    }
    return true;
}

/* ===== Request dispatch ===== */

static void dispatch_request(void)
{
    rpc_handler_fn fn = hid_rpc_lookup(s_req_cmd);
    if (fn == NULL) {
        queue_error(LT_RPC_ERR_INVALID_CMD);
        return;
    }

    /* Borrow s_resp_buf as scratch for the handler's output. The framing
     * layer hasn't queued anything yet at this point.
     *
     * IMPORTANT — assumes cooperative USB scheduling: tud_hid_set_report_cb
     * is only ever called from tud_task() in the main loop (same thread as
     * hid_rpc_task). If the firmware is ever ported to an IRQ-mode USB
     * driver, an OUT report arriving mid-drain could clobber s_resp_buf
     * while emit_response_packet is still copying from it. TinyUSB's
     * stm32_fsdev driver pumps from tud_task, so we are safe today. */
    int n = fn(s_req_buf, s_req_received, s_resp_buf, HID_RPC_RESP_MAX);
    if (n < 0) {
        queue_error(LT_RPC_ERR_OTHER);
        return;
    }
    /* Set the response fields directly — handler already wrote into
     * s_resp_buf so there's nothing to copy. */
    s_resp_total   = (uint16_t) n;
    s_resp_sent    = 0;
    s_resp_cmd     = (uint8_t)(LT_RPC_CMD_INIT_FLAG | s_req_cmd);
    s_resp_seq     = 0;
    s_resp_pending = true;
}

/* ===== Packet ingest ===== */

static void handle_init_packet(const uint8_t *pkt)
{
    uint8_t  cmd_byte = pkt[4];
    uint16_t bcnt     = (uint16_t)(((uint16_t)pkt[5] << 8) | (uint16_t)pkt[6]);

    if (bcnt > LT_RPC_MAX_PAYLOAD) {
        /* Bigger than we can buffer. Reset + emit error. */
        reset_assembly();
        queue_error(LT_RPC_ERR_INVALID_LEN);
        return;
    }

    /* Zero the request buffer at the start of every INIT so any stale bytes
     * from a previous (or abandoned-mid-assembly) transaction cannot leak
     * into a handler that doesn't strictly gate on req_len. cppcheck-clean
     * code today + audit 2026-05-10 confirmed the current handlers DO gate
     * properly, but a future handler addition shouldn't have to remember
     * this invariant. */
    memset(s_req_buf, 0, sizeof s_req_buf);

    s_req_cmd      = (uint8_t)(cmd_byte & 0x7Fu);
    s_req_total    = bcnt;
    s_req_received = 0;
    s_next_seq     = 0;

    size_t avail = bcnt > LT_RPC_INIT_DATA_LEN ? LT_RPC_INIT_DATA_LEN : (size_t) bcnt;
    if (avail > 0u) {
        memcpy(s_req_buf, &pkt[7], avail);
        s_req_received = (uint16_t) avail;
    }

    if (s_req_received >= s_req_total) {
        dispatch_request();
        s_state = RPC_STATE_IDLE;
    } else {
        s_state = RPC_STATE_ASSEMBLING;
    }
}

static void handle_cont_packet(const uint8_t *pkt)
{
    if (s_state != RPC_STATE_ASSEMBLING) {
        /* Spurious CONT; ignore. CTAPHID spec calls for ERR_INVALID_SEQ
         * but for M2 we just drop silently to keep state machine simple. */
        return;
    }

    uint8_t seq = (uint8_t)(pkt[4] & 0x7Fu);
    if (seq != s_next_seq) {
        /* Sequence mismatch — abort transaction, host should retry. */
        reset_assembly();
        queue_error(LT_RPC_ERR_INVALID_LEN);
        return;
    }
    s_next_seq++;

    uint16_t remaining = (uint16_t)(s_req_total - s_req_received);
    size_t   chunk     = remaining > LT_RPC_CONT_DATA_LEN ? LT_RPC_CONT_DATA_LEN : (size_t) remaining;
    if (chunk > 0u) {
        memcpy(&s_req_buf[s_req_received], &pkt[5], chunk);
        s_req_received = (uint16_t)(s_req_received + chunk);
    }

    if (s_req_received >= s_req_total) {
        dispatch_request();
        reset_assembly();
    }
}

static void handle_packet(const uint8_t *pkt, size_t len)
{
    if (len < LT_RPC_HID_REPORT_LEN) {
        /* Short report — shouldn't happen with 64-byte HID, ignore. */
        return;
    }

    uint32_t cid = read_be32(pkt);
    if (cid != LT_RPC_CID_DEFAULT) {
        reset_assembly();
        queue_error(LT_RPC_ERR_CID_MISMATCH);
        return;
    }

    uint8_t byte4 = pkt[4];
    if (byte4 & LT_RPC_CMD_INIT_FLAG) {
        handle_init_packet(pkt);
    } else {
        handle_cont_packet(pkt);
    }
}

/* ===== Public API ===== */

void hid_rpc_init(void)
{
    reset_assembly();
    s_resp_pending = false;
    s_resp_total   = 0;
    s_resp_sent    = 0;
    s_resp_seq     = 0;
    s_resp_cmd     = 0;
}

void hid_rpc_task(void)
{
    /* Drain queued response one packet at a time; emit_response_packet
     * is no-op if nothing pending or IN EP busy. */
    while (emit_response_packet()) {
        /* loop until we can't push another, or done */
    }
}

/* ===== TinyUSB HID class callbacks ===== */

void tud_hid_set_report_cb(uint8_t instance,
                           uint8_t report_id,
                           hid_report_type_t report_type,
                           uint8_t const *buffer,
                           uint16_t bufsize)
{
    (void) instance;
    (void) report_id;
    (void) report_type;
    handle_packet(buffer, bufsize);
}

uint16_t tud_hid_get_report_cb(uint8_t instance,
                               uint8_t report_id,
                               hid_report_type_t report_type,
                               uint8_t *buffer,
                               uint16_t reqlen)
{
    (void) instance;
    (void) report_id;
    (void) report_type;
    (void) buffer;
    (void) reqlen;
    return 0;
}
