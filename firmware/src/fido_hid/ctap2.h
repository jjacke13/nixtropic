/*
 * CTAP2 command dispatcher.
 *
 * Wired into the CTAPHID framing via fido_hid_cbor_dispatch() — the
 * framing layer hands us a fully-assembled CTAPHID_CBOR payload, we
 * peel off byte 0 (sub-command) and produce the response (whose first
 * byte is the CTAP2 status code).
 *
 * M3 implements authenticatorGetInfo (0x04).
 * M4 adds authenticatorMakeCredential (0x01) + authenticatorGetAssertion (0x02).
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

/* CTAP2 status codes (CTAP §6.4). */
#define CTAP2_OK                          0x00u
#define CTAP1_ERR_INVALID_COMMAND         0x01u
#define CTAP1_ERR_INVALID_PARAMETER       0x02u
#define CTAP1_ERR_INVALID_LENGTH          0x03u
#define CTAP2_ERR_CBOR_UNEXPECTED_TYPE    0x11u
#define CTAP2_ERR_INVALID_CBOR            0x12u
#define CTAP2_ERR_MISSING_PARAMETER       0x14u
#define CTAP2_ERR_OPERATION_DENIED        0x27u
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM   0x26u
#define CTAP2_ERR_NOT_ALLOWED             0x30u
#define CTAP2_ERR_OTHER                   0x7Fu

#endif /* NIXTROPIC_FIDO_HID_CTAP2_H */
