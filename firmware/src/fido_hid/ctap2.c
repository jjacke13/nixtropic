/*
 * CTAP2 dispatcher — strong override of the M2 weak stub.
 *
 * fido_hid_cbor_dispatch:
 *   req[0]               sub-command byte
 *   req[1..req_len)      CBOR parameter map (may be empty for GetInfo)
 *   resp[0]              CTAP2 status code we write
 *   resp[1..)            CBOR response body (may be empty)
 *
 * Returns total response length (≥1 on a normal CTAP2 response), or
 * negative on framing-level error (CTAPHID_ERROR will be emitted by the
 * caller).
 */

#include "ctaphid.h"
#include "ctap2.h"
#include "cbor.h"
#include "proto.h"
#include "pin.h"
#include "credstore.h"
#include "slots.h"
#include "user_presence.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "stm32u5xx_hal.h"  /* HAL_GetTick for Reset 10s post-boot window */

/* CTAP2.1 §6.8: authenticatorReset must be issued within this many ms
 * of power-up. After the window, return CTAP2_ERR_NOT_ALLOWED. */
#define RESET_WINDOW_MS  10000u

/* nixtropic AAGUID per PROJECT.md plan decision #6:
 *   "nixtropic" (9 bytes: 6E 69 78 74 72 6F 70 69 63) + 6 zero bytes +
 *   version byte.
 *
 * Trailing byte history:
 *   0x01 — Phase 4 stub firmware (embedded Ed25519 seed, fixed credId)
 *   0x02 — Phase 5 M2 firmware (TROPIC01-backed per-credential keys,
 *          resident credentials, shared hw monotonic counter)
 *
 * Authenticators MUST keep their AAGUID stable across instances of the
 * same model. The bump from 0x01 to 0x02 marks the behavior change:
 * Phase 5 stores credentials on the chip, Phase 4 did not — relying
 * parties wanting to distinguish "this is real" from "this was stub"
 * can do so by AAGUID.
 *
 * Non-static so ctap2_creds.c can reference the same blob. */
const uint8_t NIXTROPIC_AAGUID[16] = {
    0x6Eu, 0x69u, 0x78u, 0x74u,  /* "nixt" */
    0x72u, 0x6Fu, 0x70u, 0x69u,  /* "ropi" */
    0x63u, 0x00u, 0x00u, 0x00u,  /* "c" + pad */
    0x00u, 0x00u, 0x00u, 0x02u,  /* pad + Phase 5 M2 version */
};

/* ----- authenticatorGetInfo (0x04) -----
 *
 * Returns a CBOR map keyed by unsigned ints (CTAP §6.4 §6.4.0 Table 1):
 *   1: versions (array of strings) — REQUIRED
 *   3: aaguid (16-byte byte string) — REQUIRED
 *   4: options (map<text, bool>)
 *   5: maxMsgSize (uint)
 *   6: pinUvAuthProtocols (array of uint) — supported PIN protocol versions
 *   9: transports (array of strings)
 *   10: algorithms (array of maps with "alg" + "type")
 *
 * Map keys MUST appear in canonical numeric order (1, 3, 4, 5, 6, 9, 10).
 * Options map text keys also in canonical (length, then byte) order:
 *   "rk" (2) < "up" (2) < "plat" (4) < "clientPin" (9)
 *
 * Algorithms (key 10) advertises COSE algorithm identifiers:
 *   -8 = EdDSA (Ed25519) — matches TROPIC01's primary curve
 *   -7 = ES256 (ECDSA over P-256) — TROPIC01 also supports
 * Type is always "public-key".
 *
 * pinUvAuthProtocols (key 6) is REQUIRED by libfido2's
 * fido_dev_set_pin / fido_do_ecdh — without it the client can't tell
 * which PIN protocol to negotiate and aborts with FIDO_ERR_INTERNAL.
 * Phase 5 M3 supports protocol 1 only.
 */
static int build_get_info(uint8_t *resp, size_t resp_max)
{
    cbor_writer_t w;
    cbor_writer_init(&w, resp, resp_max);

    /* Top-level map: 7 entries (Phase 5 M3 added pinUvAuthProtocols) */
    cbor_write_map_header(&w, 7);

    /* key 1 → versions = ["FIDO_2_0"] */
    cbor_write_uint(&w, 1);
    cbor_write_array_header(&w, 1);
    cbor_write_text(&w, "FIDO_2_0");

    /* key 3 → aaguid */
    cbor_write_uint(&w, 3);
    cbor_write_byte_string(&w, NIXTROPIC_AAGUID, sizeof NIXTROPIC_AAGUID);

    /* key 4 → options.  CTAP2.1 canonical text-key order (length-then-lex
     * on encoded bytes): rk (2), up (2), plat (4), alwaysUv (8),
     * clientPin (9). */
    cbor_write_uint(&w, 4);
    cbor_write_map_header(&w, 5);

    cbor_write_text(&w, "rk");
    cbor_write_bool(&w, true);           /* Phase 5 M2: resident keys supported (TROPIC01 R-mem) */
    cbor_write_text(&w, "up");
    cbor_write_bool(&w, true);           /* Phase 6 M1: real user-presence via SW1 / PH3 */
    cbor_write_text(&w, "plat");
    cbor_write_bool(&w, false);          /* not a platform authenticator */
    cbor_write_text(&w, "alwaysUv");
    cbor_write_bool(&w, slots_force_uv_get() != 0);
                                         /* Phase 6 M2: Force-UV — when true, signing ops require
                                          * pinAuth regardless of RP's `userVerification` hint.
                                          * Auto-enabled on first setPIN; togglable via lt-rpc. */
    cbor_write_text(&w, "clientPin");
    cbor_write_bool(&w, pin_is_set());   /* Phase 5 M3: PIN protocol supported; "true" = PIN currently set */

    /* key 5 → maxMsgSize.
     * Cap at 1024 to match FIDO_HID_MAX_PAYLOAD / 2 — half the buffer
     * leaves room for response framing overhead. */
    cbor_write_uint(&w, 5);
    cbor_write_uint(&w, 1024);

    /* key 6 → pinUvAuthProtocols = [1].
     * Phase 5 M3 implements pinProtocol version 1 only (P-256 + AES-256-
     * CBC + HMAC-SHA-256). pinProtocol 2 (HKDF derivation, AES-CTR, longer
     * sharedSecret) is a Phase 6+ option if needed for newer clients. */
    cbor_write_uint(&w, 6);
    cbor_write_array_header(&w, 1);
    cbor_write_uint(&w, 1);

    /* key 9 → transports = ["usb"] */
    cbor_write_uint(&w, 9);
    cbor_write_array_header(&w, 1);
    cbor_write_text(&w, "usb");

    /* key 10 → algorithms.
     * Order in the array doesn't have to match anything; advertised first
     * is preferred. Ed25519 first because TROPIC01 native curve. */
    cbor_write_uint(&w, 10);
    cbor_write_array_header(&w, 2);

    /* { "alg": -8, "type": "public-key" } */
    cbor_write_map_header(&w, 2);
    cbor_write_text(&w, "alg");
    cbor_write_negint(&w, -8);           /* COSE EdDSA */
    cbor_write_text(&w, "type");
    cbor_write_text(&w, "public-key");

    /* { "alg": -7, "type": "public-key" } */
    cbor_write_map_header(&w, 2);
    cbor_write_text(&w, "alg");
    cbor_write_negint(&w, -7);           /* COSE ES256 */
    cbor_write_text(&w, "type");
    cbor_write_text(&w, "public-key");

    if (cbor_writer_error(&w)) return -1;
    return (int) cbor_writer_len(&w);
}

/* ===== Public dispatcher — strong override of M2 weak stub ===== */

int fido_hid_cbor_dispatch(const uint8_t *req, size_t req_len,
                           uint8_t *resp, size_t resp_max)
{
    if (resp_max < 1u) return -1;
    if (req_len < 1u) {
        resp[0] = CTAP1_ERR_INVALID_LENGTH;
        return 1;
    }

    uint8_t sub = req[0];

    switch (sub) {
    case CTAP2_CMD_GET_INFO: {
        int n = build_get_info(&resp[1], resp_max - 1u);
        if (n < 0) {
            resp[0] = CTAP2_ERR_OTHER;
            return 1;
        }
        resp[0] = CTAP2_OK;
        return n + 1;
    }
    case CTAP2_CMD_MAKE_CREDENTIAL:
        return ctap2_make_credential(&req[1], req_len - 1u, resp, resp_max);
    case CTAP2_CMD_GET_ASSERTION:
        return ctap2_get_assertion(&req[1], req_len - 1u, resp, resp_max);
    case CTAP2_CMD_CLIENT_PIN:
        return pin_handle_cbor(&req[1], req_len - 1u, resp, resp_max);
    case CTAP2_CMD_RESET: {
        /* CTAP2.1 §6.8 + Phase 6 M2 tightening (docs/PHASE-6-PLAN.md
         * §4.7, H1 defense).
         *
         * Three gates depending on device state:
         *
         *   1. 10-second post-boot window (always — primary host-software
         *      protection per spec).
         *   2. If any state exists (PIN set OR ≥1 credential registered),
         *      additionally require a fresh SW1 press within 10 s.  This
         *      is the anti-passive-physical gate: an attacker who briefly
         *      gets your unplugged dongle can no longer Reset it just by
         *      replugging within the 10 s window — they'd need to also
         *      hold it long enough to press the button.
         *   3. Virgin device (no PIN, no creds) skips the SW1 requirement
         *      because there's nothing to defend.  This avoids forcing
         *      first-time users to press SW1 just to bootstrap.
         *
         * Reset wipes ALL credentials, PIN state, M&D state, AND the
         * Force-UV flag.  Recovery from RP side: user re-registers
         * all credentials. */
        if (HAL_GetTick() > RESET_WINDOW_MS) {
            resp[0] = CTAP2_ERR_NOT_ALLOWED;
            return 1;
        }
        int state_exists = pin_is_set() || (slots_count_used() > 0);
        if (state_exists) {
            up_result_t up = user_presence_check(10000u);
            if (up != UP_OK) {
                resp[0] = CTAP2_ERR_OPERATION_DENIED;
                return 1;
            }
        }
        if (credstore_factory_reset() != 0) {
            resp[0] = CTAP2_ERR_OTHER;
            return 1;
        }
        resp[0] = CTAP2_OK;
        return 1;
    }
    case CTAP2_CMD_GET_NEXT_ASSERTION:
        /* GetNextAssertion iterates multiple matches per allowList.
         * Our single-credential-per-allowList-entry flow doesn't need
         * it. CTAP2 §6.3: returning NOT_ALLOWED is valid. */
        resp[0] = CTAP2_ERR_NOT_ALLOWED;
        return 1;
    default:
        resp[0] = CTAP1_ERR_INVALID_COMMAND;
        return 1;
    }
}
