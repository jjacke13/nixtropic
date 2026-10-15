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
#include "credmgmt.h"

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
 * same model.  Trailing byte = capability set version:
 *   0x01 — Phase 4 (stub backend, embedded keypair)
 *   0x02 — Phase 5 M2..M5 (TROPIC01 chip-side keys, hardware-PIN)
 *   0x03 — Phase 6 (real SW1 UP + Force-UV + credentialManagement)
 *   0x04 — Phase 9 M3 (EdDSA only, real rk, permission tokens,
 *          authenticatorConfig, makeCredUvNotRqd)
 *
 * AAGUID bump policy + history in docs/WEBAUTHN-NOTES.md §3.
 *
 * Non-static so ctap2_creds.c can reference the same blob. */
const uint8_t NIXTROPIC_AAGUID[16] = {
    0x6Eu, 0x69u, 0x78u, 0x74u,  /* "nixt" */
    0x72u, 0x6Fu, 0x70u, 0x69u,  /* "ropi" */
    0x63u, 0x00u, 0x00u, 0x00u,  /* "c" + pad */
    0x00u, 0x00u, 0x00u, 0x04u,  /* pad + Phase 9 version */
};

/* ----- authenticatorGetInfo (0x04) -----
 *
 * CBOR map keyed by unsigned ints (CTAP §6.4), canonical order:
 *   1: versions            ["FIDO_2_0"]
 *   3: aaguid
 *   4: options             (below)
 *   5: maxMsgSize          1024
 *   6: pinUvAuthProtocols  [1]
 *   9: transports          ["usb"]
 *  10: algorithms          [{alg: -8 (EdDSA)}, {alg: -7 (ES256)}], type "public-key"
 *
 * Phase 9 M3: only what is implemented.  Not "FIDO_2_1": that version
 * requires hmac-secret, credProtect and PIN/UV protocol 2 (CTAP §9).
 * The CTAP 2.1 features we have are announced by their own option IDs,
 * which clients read independently (libfido2 dev.c).  credentialMgmtPreview
 * is gone (it announces command 0x41, which does not exist here).  ES256
 * (P-256 ECDSA on the chip) since M3b; the RP's order picks the algorithm.
 *
 * Options, canonical order (length, then bytes):
 *   rk                discoverable credentials (GetAssertion without allowList)
 *   up                SW1 touch
 *   plat              false: roaming authenticator
 *   alwaysUv          Force-UV (authenticatorConfig toggleAlwaysUv)
 *   credMgmt          authenticatorCredentialManagement 0x0A
 *   authnrCfg         authenticatorConfig 0x0D
 *   clientPin         true = a PIN is set
 *   pinUvAuthToken    ClientPIN 0x09 permission tokens
 *   makeCredUvNotRqd  = !alwaysUv: non-discoverable credentials without
 *                     a token when a PIN is set
 */
static int build_get_info(uint8_t *resp, size_t resp_max)
{
    int always_uv = slots_force_uv_get() != 0;
    cbor_writer_t w;
    cbor_writer_init(&w, resp, resp_max);
    cbor_write_map_header(&w, 7);

    cbor_write_uint(&w, 1);
    cbor_write_array_header(&w, 1);
    cbor_write_text(&w, "FIDO_2_0");

    cbor_write_uint(&w, 3);
    cbor_write_byte_string(&w, NIXTROPIC_AAGUID, sizeof NIXTROPIC_AAGUID);

    cbor_write_uint(&w, 4);
    cbor_write_map_header(&w, 9);
    cbor_write_text(&w, "rk");               cbor_write_bool(&w, true);
    cbor_write_text(&w, "up");               cbor_write_bool(&w, true);
    cbor_write_text(&w, "plat");             cbor_write_bool(&w, false);
    cbor_write_text(&w, "alwaysUv");         cbor_write_bool(&w, always_uv);
    cbor_write_text(&w, "credMgmt");         cbor_write_bool(&w, true);
    cbor_write_text(&w, "authnrCfg");        cbor_write_bool(&w, true);
    cbor_write_text(&w, "clientPin");        cbor_write_bool(&w, pin_is_set());
    cbor_write_text(&w, "pinUvAuthToken");   cbor_write_bool(&w, true);
    cbor_write_text(&w, "makeCredUvNotRqd"); cbor_write_bool(&w, !always_uv);

    /* maxMsgSize: half of FIDO_HID_MAX_PAYLOAD, leaving room for framing. */
    cbor_write_uint(&w, 5);
    cbor_write_uint(&w, 1024);

    /* PIN/UV auth protocol 1 only (P-256, AES-256-CBC, HMAC-SHA-256);
     * libfido2 needs this key to negotiate a PIN at all. */
    cbor_write_uint(&w, 6);
    cbor_write_array_header(&w, 1);
    cbor_write_uint(&w, 1);

    cbor_write_uint(&w, 9);
    cbor_write_array_header(&w, 1);
    cbor_write_text(&w, "usb");

    cbor_write_uint(&w, 10);
    static const int64_t ALGS[] = { -8, -7 };
    cbor_write_array_header(&w, 2);
    for (size_t i = 0; i < 2u; ++i) {
        cbor_write_map_header(&w, 2);
        cbor_write_text(&w, "alg");
        cbor_write_negint(&w, ALGS[i]);
        cbor_write_text(&w, "type");
        cbor_write_text(&w, "public-key");
    }

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

    /* Phase 6 M3: any non-credMgmt CBOR command resets the
     * credentialManagement iterator (CTAP2.1 §6.8 "iterator state
     * expires on any other authenticator operation"). */
    if (sub != CTAP2_CMD_CREDENTIAL_MGMT) {
        credmgmt_reset_iterator();
    }
    /* Same for the GetNextAssertion state (CTAP §6.3).  GetAssertion
     * replaces it itself. */
    if (sub != CTAP2_CMD_GET_ASSERTION && sub != CTAP2_CMD_GET_NEXT_ASSERTION) {
        ctap2_assertion_reset();
    }

    /* Phase 9 M3: one structural check of the whole parameter map before
     * any handler reads a field (nesting depth, lengths, no trailing
     * bytes).  The handlers' own checks stay as a second line. */
    if (req_len > 1u && cbor_validate(&req[1], req_len - 1u) != 0) {
        resp[0] = CTAP2_ERR_INVALID_CBOR;
        return 1;
    }

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
         * Two gates (CTAP 2.1 §6.6):
         *
         *   1. 10-second post-boot window.
         *   2. A fresh SW1 press within 10 s, always.  Phase 9 M3 dropped
         *      the "virgin device needs no touch" shortcut: it decided
         *      "virgin" from state reads that report empty after a read
         *      error, so a chip fault could skip the touch (Jan, M3
         *      review).  The spec asks for user interaction anyway.
         *
         * Reset wipes ALL credentials, PIN state, M&D state, AND the
         * Force-UV flag.  Recovery from RP side: user re-registers
         * all credentials. */
        if (HAL_GetTick() > RESET_WINDOW_MS) {
            resp[0] = CTAP2_ERR_NOT_ALLOWED;
            return 1;
        }
        up_result_t up = user_presence_check(10000u);
        if (up != UP_OK) {
            resp[0] = (up == UP_CANCEL) ? CTAP2_ERR_KEEPALIVE_CANCEL
                                        : CTAP2_ERR_OPERATION_DENIED;
            return 1;
        }
        /* Tokens and PIN failure state die with the PIN (Phase 9 M3),
         * also when the wipe stopped part-way. */
        int reset_rc = credstore_factory_reset();
        pin_reset_ram();
        resp[0] = (reset_rc == 0) ? CTAP2_OK : CTAP2_ERR_OTHER;
        return 1;
    }
    case CTAP2_CMD_CREDENTIAL_MGMT:
        return credmgmt_handle_cbor(&req[1], req_len - 1u, resp, resp_max);
    case CTAP2_CMD_CONFIG:
        return ctap2_config(&req[1], req_len - 1u, resp, resp_max);

    case CTAP2_CMD_GET_NEXT_ASSERTION:
        return ctap2_get_next_assertion(resp, resp_max);
    default:
        resp[0] = CTAP1_ERR_INVALID_COMMAND;
        return 1;
    }
}
