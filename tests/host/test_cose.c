/*
 * Host tests for firmware/src/fido_hid/cose.c (Phase 9 M3b): COSE_Key
 * encodings for EdDSA and ES256, and the raw r||s → DER conversion.
 */
#include <string.h>

#include "check.h"
#include "fido_hid/cbor.h"
#include "fido_hid/cose.h"

static int encode(int alg, const uint8_t *pub, size_t len, uint8_t *out, size_t cap)
{
    cbor_writer_t w;
    cbor_writer_init(&w, out, cap);
    if (cose_write_pubkey(&w, alg, pub, len) != 0) return -1;
    return (int) cbor_writer_len(&w);
}

static void test_ed25519_key(void)
{
    uint8_t pub[32];
    for (int i = 0; i < 32; ++i) pub[i] = (uint8_t) i;
    uint8_t out[96];
    int n = encode(COSE_ALG_EDDSA, pub, 32, out, sizeof out);
    /* { 1: 1, 3: -8, -1: 6, -2: h'00..1f' } */
    static const uint8_t head[] = { 0xA4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20 };
    CHECK(n == (int) sizeof head + 32);
    CHECK(memcmp(out, head, sizeof head) == 0);
    CHECK(memcmp(&out[sizeof head], pub, 32) == 0);
}

static void test_es256_key(void)
{
    uint8_t pub[64];
    for (int i = 0; i < 64; ++i) pub[i] = (uint8_t)(0x80 + i);
    uint8_t out[96];
    int n = encode(COSE_ALG_ES256, pub, 64, out, sizeof out);
    /* { 1: 2, 3: -7, -1: 1, -2: x, -3: y }, CTAP2 canonical key order */
    static const uint8_t head[] = { 0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20 };
    CHECK(n == 77);
    CHECK(memcmp(out, head, sizeof head) == 0);
    CHECK(memcmp(&out[10], pub, 32) == 0);
    CHECK(out[42] == 0x22 && out[43] == 0x58 && out[44] == 0x20);
    CHECK(memcmp(&out[45], &pub[32], 32) == 0);
}

static void test_key_mismatch(void)
{
    uint8_t pub[64] = { 0 };
    uint8_t out[96];
    CHECK(encode(COSE_ALG_EDDSA, pub, 64, out, sizeof out) < 0);
    CHECK(encode(COSE_ALG_ES256, pub, 32, out, sizeof out) < 0);
    CHECK(encode(-257, pub, 64, out, sizeof out) < 0);          /* RS256 */
    CHECK(encode(COSE_ALG_ES256, pub, 64, out, 40) < 0);        /* no room */
}

static void test_der_plain(void)
{
    uint8_t rs[64];
    memset(rs, 0x11, 32);
    memset(&rs[32], 0x22, 32);
    uint8_t der[COSE_ES256_DER_MAX];
    int n = cose_es256_der(rs, der, sizeof der);
    CHECK(n == 70);
    CHECK(der[0] == 0x30 && der[1] == 68);
    CHECK(der[2] == 0x02 && der[3] == 32 && der[4] == 0x11);
    CHECK(der[36] == 0x02 && der[37] == 32 && der[38] == 0x22);
}

static void test_der_high_bit_and_zeros(void)
{
    uint8_t rs[64] = { 0 };
    rs[0] = 0x80;                     /* r: top bit set → 0x00 pad, 33 bytes */
    rs[63] = 0x05;                    /* s: 31 leading zeros → one byte */
    uint8_t der[COSE_ES256_DER_MAX];
    int n = cose_es256_der(rs, der, sizeof der);
    static const uint8_t want_head[] = { 0x30, 38, 0x02, 33, 0x00, 0x80 };
    CHECK(n == 40);
    CHECK(memcmp(der, want_head, sizeof want_head) == 0);
    CHECK(der[37] == 0x02 && der[38] == 1 && der[39] == 0x05);

    /* s = 0x00..0080: strip zeros, then pad the high bit */
    memset(rs, 0x7F, 32);
    memset(&rs[32], 0, 32);
    rs[63] = 0x80;
    n = cose_es256_der(rs, der, sizeof der);
    CHECK(n == 2 + 34 + 4);
    CHECK(der[36] == 0x02 && der[37] == 2 && der[38] == 0x00 && der[39] == 0x80);

    /* both 0xFF..: the largest encoding, 72 bytes */
    memset(rs, 0xFF, 64);
    n = cose_es256_der(rs, der, sizeof der);
    CHECK(n == 72 && der[1] == 70);

    /* zero integer: one 0x00 byte */
    memset(rs, 0, 64);
    n = cose_es256_der(rs, der, sizeof der);
    CHECK(n == 8);
    CHECK(der[2] == 0x02 && der[3] == 1 && der[4] == 0x00);
}

static void test_der_no_room(void)
{
    uint8_t rs[64];
    memset(rs, 0xFF, 64);
    uint8_t der[COSE_ES256_DER_MAX];
    CHECK(cose_es256_der(rs, der, 71) < 0);
    CHECK(cose_es256_der(NULL, der, sizeof der) < 0);
}

int main(void)
{
    test_ed25519_key();
    test_es256_key();
    test_key_mismatch();
    test_der_plain();
    test_der_high_bit_and_zeros();
    test_der_no_room();
    return check_done("cose");
}
