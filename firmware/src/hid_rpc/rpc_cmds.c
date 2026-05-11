/*
 * lt-rpc command handlers.
 *
 * M2 commands:
 *   PING        echoes the request payload verbatim
 *   GET_RANDOM  draws N bytes (N in [1, 256]) from the STM32 HW TRNG
 *
 * M3 adds CHIP_ID; M4 adds ECC_GENERATE / ECC_SIGN / ECC_PUBKEY.
 *
 * Handler contract (matches rpc_handler_fn in rpc.h):
 *   - Read request from req[0..req_len)
 *   - Write response to resp[0..resp_max)
 *   - Return the number of bytes written, or a negative value on error
 *
 * The framing layer wraps a successful return into an INIT response with
 * cmd echoed (top bit set). A negative return is converted into an
 * LT_RPC_CMD_ERROR response.
 */

#include "rpc.h"
#include "lt_rpc_proto.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "platform/rng.h"
#include "tropic/tropic.h"
#include "fido_hid/slots.h"
#include "fido_hid/pin.h"

#include "stm32u5xx_hal.h"

/* ===== Handlers ===== */

static int handle_ping(const uint8_t *req, size_t req_len,
                       uint8_t *resp, size_t resp_max)
{
    size_t n = req_len > resp_max ? resp_max : req_len;
    if (n > 0u) {
        memcpy(resp, req, n);
    }
    return (int) n;
}

static int handle_get_random(const uint8_t *req, size_t req_len,
                             uint8_t *resp, size_t resp_max)
{
    if (req_len < 1u) {
        return -1;
    }
    size_t n = req[0];
    /* N=0 is invalid (host explicitly asked for nothing). Reject rather
     * than silently coercing to 1, so a buggy caller gets a clear error. */
    if (n == 0u) {
        return -1;
    }
    /* req[0] is uint8_t so n is in [1, 255]. No 256u cap needed — kept
     * here as a safety floor in case the request layout ever widens. */
    if (n > 255u) n = 255u;
    if (n > resp_max) n = resp_max;

    /* Use the STM32 HW TRNG directly — no libtropic / TROPIC01 needed for
     * M2. The chip's TRNG is exercised in M3+ via lt_random_value_get. */
    RNG_HandleTypeDef *h = rng_handle();
    if (h == NULL) {
        return -1;
    }

    size_t produced = 0;
    while (produced < n) {
        uint32_t word;
        if (HAL_RNG_GenerateRandomNumber(h, &word) != HAL_OK) {
            return -1;
        }
        size_t take = n - produced;
        if (take > 4u) take = 4u;
        for (size_t i = 0; i < take; ++i) {
            resp[produced + i] = (uint8_t)((word >> (8 * i)) & 0xFFu);
        }
        produced += take;
    }
    return (int) n;
}

static int handle_chip_id(const uint8_t *req, size_t req_len,
                          uint8_t *resp, size_t resp_max)
{
    (void) req;
    (void) req_len;
    /* lt_chip_id_t is 128 bytes. The HID RPC fragmenter will split this
     * across 3 packets (INIT 57 + CONT 59 + CONT 12). */
    if (resp_max < 128u) {
        return -1;
    }
    return tropic_chip_id_read(resp, resp_max);
}

static int handle_ecc_generate(const uint8_t *req, size_t req_len,
                               uint8_t *resp, size_t resp_max)
{
    (void) resp;
    (void) resp_max;
    if (req_len < 2u) {
        return -1;
    }
    if (tropic_ecc_generate(req[0], req[1]) != 0) {
        return -1;
    }
    /* 0 B response → just OK acknowledgement. */
    return 0;
}

static int handle_ecc_pubkey(const uint8_t *req, size_t req_len,
                             uint8_t *resp, size_t resp_max)
{
    if (req_len < 1u) {
        return -1;
    }
    return tropic_ecc_pubkey_read(req[0], resp, resp_max);
}

static int handle_ecc_sign(const uint8_t *req, size_t req_len,
                           uint8_t *resp, size_t resp_max)
{
    if (req_len < 1u + 1u) {
        return -1;
    }
    /* req layout: [0] slot | [1..] message bytes (up to 4 KB) */
    return tropic_ecc_eddsa_sign(req[0], &req[1], req_len - 1u, resp, resp_max);
}

static int handle_ecc_erase(const uint8_t *req, size_t req_len,
                            uint8_t *resp, size_t resp_max)
{
    (void) resp;
    (void) resp_max;
    if (req_len < 1u) return -1;
    return (tropic_ecc_erase(req[0]) == 0) ? 0 : -1;
}

/* ===== Phase 5 M1 debug handlers — slot-manager visibility ===== */

static int handle_slots_bitmap(const uint8_t *req, size_t req_len,
                               uint8_t *resp, size_t resp_max)
{
    (void) req; (void) req_len;
    if (resp_max < 5u) return -1;
    uint32_t bm = slots_bitmap();
    resp[0] = (uint8_t)(bm >> 24);
    resp[1] = (uint8_t)(bm >> 16);
    resp[2] = (uint8_t)(bm >>  8);
    resp[3] = (uint8_t) bm;
    resp[4] = (uint8_t) slots_count_used();
    return 5;
}

static int handle_slots_alloc(const uint8_t *req, size_t req_len,
                              uint8_t *resp, size_t resp_max)
{
    if (req_len < 32u) return -1;
    if (resp_max < 1u + 18u) return -1;
    uint8_t cred_id[18];
    int idx = -1;
    if (slots_alloc(req, 8u /* SLOTS_ALG_ED25519 */,
                    NULL, 0u,    /* debug alloc — no user_handle */
                    cred_id, &idx) != 0) {
        return -1;
    }
    resp[0] = (uint8_t) idx;
    memcpy(&resp[1], cred_id, sizeof cred_id);
    return 1 + (int) sizeof cred_id;
}

static int handle_slots_erase(const uint8_t *req, size_t req_len,
                              uint8_t *resp, size_t resp_max)
{
    (void) resp; (void) resp_max;
    if (req_len < 1u) return -1;
    if (slots_erase((int) req[0]) != 0) return -1;
    return 0;
}

static int handle_slots_meta(const uint8_t *req, size_t req_len,
                             uint8_t *resp, size_t resp_max)
{
    if (req_len < 1u) return -1;
    if (resp_max < 50u) return -1;
    slot_meta_t m;
    if (slots_read_meta((int) req[0], &m) != 0) return -1;
    resp[0] = m.alg;
    resp[1] = m.flags;
    memcpy(&resp[2],  m.rp_id_hash,    32);
    memcpy(&resp[34], m.cred_id_nonce, 16);
    return 50;
}

static int handle_slots_reset(const uint8_t *req, size_t req_len,
                              uint8_t *resp, size_t resp_max)
{
    (void) req; (void) req_len; (void) resp; (void) resp_max;
    if (slots_factory_reset() != 0) return -1;
    return 0;
}

/* Phase 6 M2 — Force-UV flag accessors.
 *
 * GET is unauthenticated: the same information is already public
 * via `options.alwaysUv` in CTAP2 GetInfo, so a vendor-channel read
 * leaks nothing new.
 *
 * SET is PIN-gated in BOTH directions: requires an active
 * pinUvAuthToken (user has run CTAP2 getPinToken this boot).  An
 * attacker with only USB access — but no PIN — cannot toggle
 * Force-UV in either direction.  Symmetric gating prevents the
 * "silently disable my defense" attack AND the "lock me out by
 * enabling Force-UV before I set a PIN" attack.
 *
 * Bootstrap path (no PIN yet): the auto-enable in pin.c's setPIN
 * handler fires when `was_pin_set == 0` AND setPIN succeeds, so the
 * first-time user gets Force-UV implicitly without needing to call
 * this RPC. */
static int handle_force_uv_get(const uint8_t *req, size_t req_len,
                               uint8_t *resp, size_t resp_max)
{
    (void) req; (void) req_len;
    if (resp_max < 1u) return -1;
    resp[0] = (uint8_t)(slots_force_uv_get() ? 1u : 0u);
    return 1;
}

static int handle_force_uv_set(const uint8_t *req, size_t req_len,
                               uint8_t *resp, size_t resp_max)
{
    (void) resp; (void) resp_max;
    if (req_len < 1u) return -1;

    /* PIN-gate: refuse if there is no active pinUvAuthToken session. */
    if (!pin_token_is_valid()) {
        return -1;
    }

    int value = (req[0] != 0u) ? 1 : 0;
    if (slots_force_uv_set(value) != 0) {
        return -1;
    }
    return 0;
}

/* ===== Table + lookup ===== */

typedef struct {
    uint8_t        cmd;
    rpc_handler_fn fn;
} rpc_entry_t;

static const rpc_entry_t HANDLERS[] = {
    { LT_RPC_CMD_PING,         handle_ping },
    { LT_RPC_CMD_GET_RANDOM,   handle_get_random },
    { LT_RPC_CMD_CHIP_ID,      handle_chip_id },
    { LT_RPC_CMD_ECC_GENERATE, handle_ecc_generate },
    { LT_RPC_CMD_ECC_SIGN,     handle_ecc_sign },
    { LT_RPC_CMD_ECC_PUBKEY,   handle_ecc_pubkey },
    { LT_RPC_CMD_ECC_ERASE,    handle_ecc_erase },
    { LT_RPC_CMD_SLOTS_BITMAP, handle_slots_bitmap },
    { LT_RPC_CMD_SLOTS_ALLOC,  handle_slots_alloc },
    { LT_RPC_CMD_SLOTS_ERASE,  handle_slots_erase },
    { LT_RPC_CMD_SLOTS_META,   handle_slots_meta },
    { LT_RPC_CMD_SLOTS_RESET,  handle_slots_reset },
    { LT_RPC_CMD_FORCE_UV_GET, handle_force_uv_get },
    { LT_RPC_CMD_FORCE_UV_SET, handle_force_uv_set },
    { 0, NULL },  /* sentinel */
};

rpc_handler_fn hid_rpc_lookup(uint8_t cmd)
{
    for (size_t i = 0; HANDLERS[i].fn != NULL; ++i) {
        if (HANDLERS[i].cmd == cmd) return HANDLERS[i].fn;
    }
    return NULL;
}
