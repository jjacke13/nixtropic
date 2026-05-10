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
    if (n == 0u) n = 1u;
    if (n > 256u) n = 256u;
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
    { 0, NULL },  /* sentinel */
};

rpc_handler_fn hid_rpc_lookup(uint8_t cmd)
{
    for (size_t i = 0; HANDLERS[i].fn != NULL; ++i) {
        if (HANDLERS[i].cmd == cmd) return HANDLERS[i].fn;
    }
    return NULL;
}
