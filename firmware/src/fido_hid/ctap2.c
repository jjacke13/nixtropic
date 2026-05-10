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

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* nixtropic AAGUID per PROJECT.md plan decision #6:
 *   "nixtropic" (9 bytes: 6E 69 78 74 72 6F 70 69 63) + 6 zero bytes +
 *   version byte (0x01 for Phase 4 generation).
 *
 * Authenticators MUST keep their AAGUID stable across instances of the
 * same model. Bump the trailing byte if we ever materially change the
 * authenticator's behavior in a way relying parties would want to
 * distinguish (e.g., Phase 5 enabling real TROPIC01-backed credentials).
 *
 * Non-static so ctap2_creds.c can reference the same blob. */
const uint8_t NIXTROPIC_AAGUID[16] = {
    0x6Eu, 0x69u, 0x78u, 0x74u,  /* "nixt" */
    0x72u, 0x6Fu, 0x70u, 0x69u,  /* "ropi" */
    0x63u, 0x00u, 0x00u, 0x00u,  /* "c" + pad */
    0x00u, 0x00u, 0x00u, 0x01u,  /* pad + Phase 4 version */
};

/* ----- authenticatorGetInfo (0x04) -----
 *
 * Returns a CBOR map keyed by unsigned ints (CTAP §6.4 §6.4.0 Table 1):
 *   1: versions (array of strings) — REQUIRED
 *   3: aaguid (16-byte byte string) — REQUIRED
 *   4: options (map<text, bool>)
 *   5: maxMsgSize (uint)
 *   9: transports (array of strings)
 *   10: algorithms (array of maps with "alg" + "type")
 *
 * Map keys MUST appear in canonical numeric order (1, 3, 4, 5, 9, 10).
 * Options map text keys also in canonical (length, then byte) order:
 *   "rk" (2) < "up" (2) < "plat" (4) < "clientPin" (9)
 *
 * Algorithms (key 10) advertises COSE algorithm identifiers:
 *   -8 = EdDSA (Ed25519) — matches TROPIC01's primary curve
 *   -7 = ES256 (ECDSA over P-256) — TROPIC01 also supports
 * Type is always "public-key".
 */
static int build_get_info(uint8_t *resp, size_t resp_max)
{
    cbor_writer_t w;
    cbor_writer_init(&w, resp, resp_max);

    /* Top-level map: 6 entries */
    cbor_write_map_header(&w, 6);

    /* key 1 → versions = ["FIDO_2_0"] */
    cbor_write_uint(&w, 1);
    cbor_write_array_header(&w, 1);
    cbor_write_text(&w, "FIDO_2_0");

    /* key 3 → aaguid */
    cbor_write_uint(&w, 3);
    cbor_write_byte_string(&w, NIXTROPIC_AAGUID, sizeof NIXTROPIC_AAGUID);

    /* key 4 → options. Canonical text-key order: rk, up, plat, clientPin */
    cbor_write_uint(&w, 4);
    cbor_write_map_header(&w, 4);

    cbor_write_text(&w, "rk");
    cbor_write_bool(&w, false);          /* no resident keys in Phase 4 */
    cbor_write_text(&w, "up");
    cbor_write_bool(&w, true);           /* user-presence stubbed true (P5/P6) */
    cbor_write_text(&w, "plat");
    cbor_write_bool(&w, false);          /* not a platform authenticator */
    cbor_write_text(&w, "clientPin");
    cbor_write_bool(&w, false);          /* ClientPIN comes in Phase 5 */

    /* key 5 → maxMsgSize.
     * Cap at 1024 to match FIDO_HID_MAX_PAYLOAD / 2 — half the buffer
     * leaves room for response framing overhead. */
    cbor_write_uint(&w, 5);
    cbor_write_uint(&w, 1024);

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
    case CTAP2_CMD_GET_NEXT_ASSERTION:
    case CTAP2_CMD_CLIENT_PIN:
    case CTAP2_CMD_RESET:
        /* Phase 5 territory (ClientPIN/Reset; persistent credential
         * iteration). Return NOT_ALLOWED so fido2-token tells "feature
         * absent" apart from "unknown command". */
        resp[0] = CTAP2_ERR_NOT_ALLOWED;
        return 1;
    default:
        resp[0] = CTAP1_ERR_INVALID_COMMAND;
        return 1;
    }
}
