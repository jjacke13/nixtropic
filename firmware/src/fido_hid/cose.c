/*
 * COSE public keys and ES256 DER signatures.  See cose.h.
 */

#include "cose.h"

#include <string.h>

size_t cose_pub_len(int alg)
{
    switch (alg) {
    case COSE_ALG_EDDSA: return COSE_ED25519_PUB_LEN;
    case COSE_ALG_ES256: return COSE_P256_PUB_LEN;
    default:             return 0;
    }
}

int cose_write_pubkey(cbor_writer_t *w, int alg, const uint8_t *pub, size_t pub_len)
{
    if (w == NULL || pub == NULL || pub_len == 0 || pub_len != cose_pub_len(alg)) {
        return -1;
    }
    if (alg == COSE_ALG_EDDSA) {
        /* { 1: 1 (OKP), 3: -8, -1: 6 (Ed25519), -2: x } */
        cbor_write_map_header(w, 4);
        cbor_write_uint(w, 1);    cbor_write_uint(w, 1);
        cbor_write_uint(w, 3);    cbor_write_negint(w, COSE_ALG_EDDSA);
        cbor_write_negint(w, -1); cbor_write_uint(w, 6);
        cbor_write_negint(w, -2); cbor_write_byte_string(w, pub, 32);
    } else {
        /* { 1: 2 (EC2), 3: -7, -1: 1 (P-256), -2: x, -3: y } */
        cbor_write_map_header(w, 5);
        cbor_write_uint(w, 1);    cbor_write_uint(w, 2);
        cbor_write_uint(w, 3);    cbor_write_negint(w, COSE_ALG_ES256);
        cbor_write_negint(w, -1); cbor_write_uint(w, 1);
        cbor_write_negint(w, -2); cbor_write_byte_string(w, pub, 32);
        cbor_write_negint(w, -3); cbor_write_byte_string(w, &pub[32], 32);
    }
    return cbor_writer_error(w) ? -1 : 0;
}

/* One unsigned 32-byte big-endian integer as a DER INTEGER: leading zero
 * bytes dropped (one kept for zero), 0x00 prepended when the top bit is set. */
static size_t der_int(const uint8_t v[32], uint8_t *out)
{
    size_t i = 0;
    while (i < 31u && v[i] == 0u) ++i;
    size_t n = 32u - i;
    int pad = (v[i] & 0x80u) != 0;
    out[0] = 0x02;
    out[1] = (uint8_t)(n + (size_t) pad);
    if (pad) out[2] = 0x00;
    memcpy(&out[2 + pad], &v[i], n);
    return 2u + (size_t) pad + n;
}

int cose_es256_der(const uint8_t rs[64], uint8_t *out, size_t out_max)
{
    if (rs == NULL || out == NULL) return -1;
    uint8_t body[COSE_ES256_DER_MAX - 2u];
    size_t len = der_int(rs, body);
    len += der_int(&rs[32], &body[len]);
    if (len + 2u > out_max) return -1;
    out[0] = 0x30;
    out[1] = (uint8_t) len;               /* ≤ 70: short form */
    memcpy(&out[2], body, len);
    return (int)(len + 2u);
}
