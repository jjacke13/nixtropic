/*
 * CTAP2 command dispatcher — implements the FIDO Alliance Client to
 * Authenticator Protocol 2.1 spec (CTAP 2.1, 2021-06-15 final).
 *
 *   https://fidoalliance.org/specs/fido-v2.1-ps-20210615/
 *     fido-client-to-authenticator-protocol-v2.1-ps-20210615.html
 *
 * Wired into the CTAPHID framing via fido_hid_cbor_dispatch() — the
 * framing layer hands us a fully-assembled CTAPHID_CBOR payload, we
 * peel off byte 0 (sub-command) and produce the response (whose
 * first byte is the CTAP2 status code per §6).
 *
 * Sub-commands implemented:
 *
 *   0x01  authenticatorMakeCredential       §6.1
 *   0x02  authenticatorGetAssertion         §6.2
 *   0x04  authenticatorGetInfo              §6.4
 *   0x06  authenticatorClientPIN            §6.5  (pin.c — protocol v1)
 *   0x07  authenticatorReset                §6.7  (10 s post-boot window)
 *   0x08  authenticatorGetNextAssertion     §6.3  (multi-credential rp)
 *   0x0A  authenticatorCredentialManagement §6.8  (credmgmt.c)
 *
 * CBOR encoding rules: CTAP2 canonical (§7.1) — shortest length-prefix,
 * lexicographic byte ordering of map keys.  Caller responsibility for
 * canonical ordering; cbor.c does NOT sort.
 *
 * Originally derived from SoloKeys solo1 (https://github.com/
 * solokeys/solo) — but substantially rewritten for trezor-crypto
 * primitives + TROPIC01-backed credential storage (Phase 5 M2).
 */

#ifndef NIXTROPIC_FIDO_HID_CTAP2_H
#define NIXTROPIC_FIDO_HID_CTAP2_H

#include <stdint.h>
#include <stddef.h>

/* CTAP2 sub-commands (first byte of a CTAPHID_CBOR payload). */
#define CTAP2_CMD_MAKE_CREDENTIAL   0x01u
#define CTAP2_CMD_GET_ASSERTION     0x02u
#define CTAP2_CMD_GET_INFO          0x04u
#define CTAP2_CMD_CLIENT_PIN        0x06u
#define CTAP2_CMD_RESET             0x07u
#define CTAP2_CMD_GET_NEXT_ASSERTION 0x08u
#define CTAP2_CMD_CREDENTIAL_MGMT   0x0Au   /* CTAP2.1 §6.8 (Phase 6 M3) */

/* CTAP2 status codes (CTAP §6.4). */
#define CTAP2_OK                          0x00u
#define CTAP1_ERR_INVALID_COMMAND         0x01u
#define CTAP1_ERR_INVALID_PARAMETER       0x02u
#define CTAP1_ERR_INVALID_LENGTH          0x03u
#define CTAP2_ERR_CBOR_UNEXPECTED_TYPE    0x11u
#define CTAP2_ERR_INVALID_CBOR            0x12u
#define CTAP2_ERR_MISSING_PARAMETER       0x14u
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM   0x26u
#define CTAP2_ERR_OPERATION_DENIED        0x27u
#define CTAP2_ERR_KEY_STORE_FULL          0x28u
#define CTAP2_ERR_NO_CREDENTIALS          0x2Eu
#define CTAP2_ERR_NOT_ALLOWED             0x30u
/* Phase 5 M3: ClientPIN protocol error codes (CTAP2 §6.4) */
#define CTAP2_ERR_PIN_INVALID             0x31u  /* wrong PIN */
#define CTAP2_ERR_PIN_BLOCKED             0x32u  /* persistent retries exhausted */
#define CTAP2_ERR_PIN_AUTH_INVALID        0x33u  /* pinAuth tag mismatch */
#define CTAP2_ERR_PIN_AUTH_BLOCKED        0x34u  /* 3 consec fails this boot — needs power-cycle */
#define CTAP2_ERR_PIN_NOT_SET             0x35u  /* operation needs PIN but none set */
#define CTAP2_ERR_PIN_REQUIRED            0x36u  /* MakeCred/GetAssertion w/o pinAuth */
#define CTAP2_ERR_PIN_POLICY_VIOLATION    0x37u  /* PIN length / content rejected */
#define CTAP2_ERR_REQUEST_TOO_LARGE       0x39u
#define CTAP2_ERR_OTHER                   0x7Fu

/* Cred handlers — defined in ctap2_creds.c, called from ctap2.c
 * dispatcher. They each take the CBOR parameter body (without the
 * sub-command byte) and write the full response (status byte + CBOR). */
int ctap2_make_credential(const uint8_t *req, size_t req_len,
                          uint8_t *resp, size_t resp_max);
int ctap2_get_assertion(const uint8_t *req, size_t req_len,
                        uint8_t *resp, size_t resp_max);

#endif /* NIXTROPIC_FIDO_HID_CTAP2_H */
