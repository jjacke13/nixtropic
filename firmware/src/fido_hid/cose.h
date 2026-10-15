/*
 * COSE public keys and the ES256 signature format for FIDO credentials
 * (Phase 9 M3b).  Chip-free, host-tested (tests/host/test_cose.c).
 *
 * EdDSA (-8): OKP key, Ed25519, 32-byte x; signatures are the chip's
 * 64 raw bytes.  ES256 (-7): EC2 key, P-256, x and y from the chip's
 * 64-byte x || y; the chip signs raw r || s (API Table 32) and WebAuthn
 * wants an ASN.1 DER ECDSA-Sig-Value (WebAuthn §6.5.6).
 */

#ifndef NIXTROPIC_FIDO_HID_COSE_H
#define NIXTROPIC_FIDO_HID_COSE_H

#include <stddef.h>
#include <stdint.h>

#include "cbor.h"

#define COSE_ALG_EDDSA        (-8)
#define COSE_ALG_ES256        (-7)
#define COSE_ED25519_PUB_LEN  32u
#define COSE_P256_PUB_LEN     64u    /* x || y, no 0x04 prefix */
#define COSE_ES256_DER_MAX    72u    /* SEQUENCE of two 33-byte INTEGERs */

/* Public key length for a COSE algorithm, 0 if unsupported. */
size_t cose_pub_len(int alg);

/* Write the COSE_Key map for `alg` in CTAP2 canonical key order.
 * Returns 0, or -1 on an unsupported alg, a wrong key length or a full
 * writer. */
int cose_write_pubkey(cbor_writer_t *w, int alg, const uint8_t *pub, size_t pub_len);

/* Raw r || s (32 + 32 bytes) → DER.  Returns the DER length or -1. */
int cose_es256_der(const uint8_t rs[64], uint8_t *out, size_t out_max);

#endif /* NIXTROPIC_FIDO_HID_COSE_H */
