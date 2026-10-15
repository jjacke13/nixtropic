/*
 * authenticatorConfig (0x0D), CTAP 2.1 §6.11 — Phase 9 M3.
 *
 * Only toggleAlwaysUv (0x02) is implemented; GetInfo announces it with
 * `authnrCfg`.  With a PIN set, the request needs a pinUvAuthToken with
 * the acfg permission over 32×0xFF || 0x0D || subCommand ||
 * subCommandParams.  Without a PIN no authentication exists to ask for,
 * so the toggle is open (§6.11 steps 3-4: initial configuration).
 * `fido2-token -S -u <device>` drives it.
 */

#include "ctap2.h"
#include "cbor.h"
#include "pin.h"
#include "pin_token.h"
#include "slots.h"

#include <stdint.h>
#include <string.h>

#include "stm32u5xx_hal.h"   /* HAL_GetTick: token timers */

#define CFG_SUB_TOGGLE_ALWAYS_UV  0x02u
#define CFG_PARAMS_MAX            64u

typedef struct {
    int            got_sub;
    uint64_t       sub;
    const uint8_t *params;          /* raw CBOR of subCommandParams */
    size_t         params_len;
    int            protocol;        /* -1 = absent */
    const uint8_t *auth;
    size_t         auth_len;
} cfg_req_t;

static int parse_cfg(const uint8_t *req, size_t req_len, cfg_req_t *c)
{
    memset(c, 0, sizeof *c);
    c->protocol = -1;
    cbor_reader_t r;
    cbor_reader_init(&r, req, req_len);
    size_t n;
    if (cbor_reader_read_map_header(&r, &n) < 0) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    for (size_t i = 0; i < n; ++i) {
        uint64_t key, v;
        if (cbor_reader_read_uint(&r, &key) < 0) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        if (key == 1u) {
            if (cbor_reader_read_uint(&r, &c->sub) < 0) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            c->got_sub = 1;
        } else if (key == 2u) {
            size_t start = r.pos;
            if (cbor_reader_skip(&r) < 0) return CTAP2_ERR_INVALID_CBOR;
            c->params = &req[start];
            c->params_len = r.pos - start;
        } else if (key == 3u) {
            if (cbor_reader_read_uint(&r, &v) < 0) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            c->protocol = (v > 0xFFFFu) ? 0xFFFF : (int) v;
        } else if (key == 4u) {
            if (cbor_reader_read_bytes(&r, &c->auth, &c->auth_len) < 0) {
                return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
        } else if (cbor_reader_skip(&r) < 0) {
            return CTAP2_ERR_INVALID_CBOR;
        }
    }
    return 0;
}

/* §6.11 step 4. */
static int check_acfg_token(const cfg_req_t *c)
{
    if (c->auth == NULL) return CTAP2_ERR_PUAT_REQUIRED;
    if (c->protocol < 0) return CTAP2_ERR_MISSING_PARAMETER;
    if (c->protocol != (int) PIN_PROTOCOL_VERSION) return CTAP1_ERR_INVALID_PARAMETER;
    if (c->params_len > CFG_PARAMS_MAX) return CTAP2_ERR_REQUEST_TOO_LARGE;

    uint8_t msg[32 + 2 + CFG_PARAMS_MAX];
    memset(msg, 0xFF, 32);
    msg[32] = CTAP2_CMD_CONFIG;
    msg[33] = (uint8_t) c->sub;
    if (c->params_len > 0u) memcpy(&msg[34], c->params, c->params_len);
    if (puat_verify(c->auth, c->auth_len, msg, 34u + c->params_len, HAL_GetTick()) != 0
        || !puat_has_perm(PUAT_PERM_ACFG)) {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    return 0;
}

int ctap2_config(const uint8_t *req, size_t req_len, uint8_t *resp, size_t resp_max)
{
    (void) resp_max;                /* status-only answers */
    cfg_req_t c;
    int rc = parse_cfg(req, req_len, &c);
    if (rc == 0 && !c.got_sub) rc = CTAP2_ERR_MISSING_PARAMETER;
    if (rc == 0 && c.sub != CFG_SUB_TOGGLE_ALWAYS_UV) rc = CTAP1_ERR_INVALID_PARAMETER;
    if (rc == 0 && pin_is_set()) rc = check_acfg_token(&c);
    if (rc == 0 && slots_force_uv_set(slots_force_uv_get() ? 0 : 1) != 0) {
        rc = CTAP2_ERR_OTHER;
    }
    resp[0] = (uint8_t) rc;
    return 1;
}
