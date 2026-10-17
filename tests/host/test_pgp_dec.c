/*
 * Host tests for the wrapped OpenPGP DEC key (Phase 9 M5,
 * docs/PHASE-9-M5-DESIGN.md): pgp_dec.c on openpgp_state.c against the
 * mock chip.
 *
 * Covers: AES-256-GCM known answer (the vendored code as built here), the
 * X25519 shared secret against a reference computed from the peer side, a
 * wrong KEK, a one-bit flip in every stored field (public key, nonce,
 * ciphertext, tag), no key, faults in every step of generation (the old key
 * stays), no plaintext private key anywhere in R-mem (§5.7), and the
 * replay residual (J5, asserted so it stays visible).
 */
#include <stdbool.h>
#include <string.h>

#include "check.h"
#include "mock_tropic.h"
#include "aes/aesgcm.h"
#include "ed25519-donna/ed25519.h"
#include "openpgp/openpgp_state.h"
#include "openpgp/pgp_dec.h"
#include "openpgp/pgp_lifecycle.h"
#include "openpgp/pgp_pin.h"
#include "sha2.h"
#include "tropic/tropic.h"

static const uint8_t K1[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
static const uint8_t K2[32] = { 2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
static const uint8_t PEER_PRIV[32] = { 0x70, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x40 };

/* Golden record, made once outside this code (Python `cryptography`:
 * HMAC-SHA256, X25519, AESGCM) — pins the stored format of O3 schema 2:
 * k = 01..20, KEK = HMAC(k, "nixtropic/openpgp/dec-kek/v1"), priv = clamp(40..5f),
 * nonce = a0..ab, AAD = "NXDW" | 3 | 2 | pub. */
static const uint8_t G_K[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20
};
static const uint8_t G_KEK[32] = {
    0x22, 0x1a, 0xc6, 0xe2, 0x00, 0xd8, 0xe8, 0x8f, 0x68, 0x86, 0xff, 0xe4, 0x8d, 0x39, 0xd9,
    0x10, 0x2e, 0xfa, 0xef, 0x68, 0x22, 0x93, 0xe3, 0x45, 0x3f, 0x7a, 0xc8, 0x0d, 0xb9, 0x0b, 0xb1,
    0x47
};
static const uint8_t G_PUB[32] = {
    0x79, 0xa6, 0x31, 0xee, 0xde, 0x1b, 0xf9, 0xc9, 0x8f, 0x12, 0x03, 0x2c, 0xde, 0xad, 0xd0,
    0xe7, 0xa0, 0x79, 0x39, 0x8f, 0xc7, 0x86, 0xb8, 0x8c, 0xc8, 0x46, 0xec, 0x89, 0xaf, 0x85, 0xa5,
    0x1a
};
static const uint8_t G_NONCE[12] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab
};
static const uint8_t G_CT[32] = {
    0x9c, 0xd0, 0x25, 0xb8, 0x85, 0x39, 0x31, 0x9f, 0x4f, 0xa0, 0x58, 0x0c, 0xdd, 0x49, 0x4d,
    0x9d, 0x16, 0x8f, 0x94, 0x3b, 0xb3, 0xbe, 0xc0, 0x7a, 0xcb, 0xf5, 0x85, 0xf0, 0x65, 0x0f, 0x1e,
    0xf4
};
static const uint8_t G_TAG[16] = {
    0x19, 0x4c, 0x44, 0x73, 0x39, 0x94, 0x5f, 0x1c, 0x65, 0xd0, 0x71, 0x68, 0x22, 0x4d, 0xfa,
    0x46
};

static void boot(void)
{
    mock_reset(7);
    openpgp_state_test_reboot();
    pgp_pin_test_reboot();
    pgp_lifecycle_test_reboot();
    CHECK(pgp_lifecycle_boot() == 0);
}

static bool all_zero(const uint8_t *b, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; ++i) acc |= b[i];
    return acc == 0u;
}

/* shared via the card vs X25519(peer_priv, card_pub). */
static bool ecdh_matches(const uint8_t kek[32], const uint8_t pub[32])
{
    uint8_t peer_pub[32], want[32], got[32];
    curve25519_scalarmult_basepoint(peer_pub, PEER_PRIV);
    curve25519_scalarmult(want, PEER_PRIV, pub);
    return pgp_dec_ecdh(kek, peer_pub, got) == PGP_DEC_OK && memcmp(got, want, 32) == 0
        && !all_zero(got, 32);
}

static int ecdh_rc(const uint8_t kek[32], bool *out_zero)
{
    uint8_t peer_pub[32], got[32];
    memset(got, 0xEE, sizeof got);
    curve25519_scalarmult_basepoint(peer_pub, PEER_PRIV);
    int rc = pgp_dec_ecdh(kek, peer_pub, got);
    *out_zero = all_zero(got, sizeof got);
    return rc;
}

/* GCM spec test case 14: K = 0^256, IV = 0^96, P = 0^128. */
static void test_gcm_kat(void)
{
    static const uint8_t C[16] = { 0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
                                   0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18 };
    static const uint8_t T[16] = { 0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
                                   0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19 };
    uint8_t key[32] = { 0 }, iv[12] = { 0 }, msg[16] = { 0 }, tag[16];
    gcm_ctx ctx;
    CHECK(gcm_init_and_key(key, sizeof key, &ctx) == RETURN_GOOD);
    CHECK(gcm_encrypt_message(iv, sizeof iv, NULL, 0, msg, sizeof msg, tag, sizeof tag, &ctx)
          == RETURN_GOOD);
    CHECK(memcmp(msg, C, 16) == 0 && memcmp(tag, T, 16) == 0);
}

static void test_round_trip(void)
{
    uint8_t kek[32], pub[32], pub2[32], again[32];
    boot();
    pgp_dec_kek(K1, kek);
    CHECK(memcmp(kek, K1, 32) != 0);
    CHECK(pgp_dec_read_pubkey(pub) == PGP_DEC_NO_KEY && all_zero(pub, 32));
    bool z;
    CHECK(ecdh_rc(kek, &z) == PGP_DEC_NO_KEY && z);
    CHECK(pgp_dec_generate(kek, pub) == PGP_DEC_OK && !all_zero(pub, 32));
    CHECK(pgp_dec_read_pubkey(again) == PGP_DEC_OK && memcmp(again, pub, 32) == 0);
    CHECK(ecdh_matches(kek, pub));
    openpgp_state_test_reboot();                             /* survives a reboot */
    CHECK(openpgp_state_load() == 0 && ecdh_matches(kek, pub));
    CHECK(pgp_dec_generate(kek, pub2) == PGP_DEC_OK && memcmp(pub2, pub, 32) != 0);
    CHECK(ecdh_matches(kek, pub2));
    CHECK(pgp_dec_generate(NULL, pub2) == PGP_DEC_BAD_PARAM);
    uint8_t out[32];
    memset(out, 0xEE, sizeof out);
    CHECK(pgp_dec_ecdh(NULL, pub, out) == PGP_DEC_BAD_PARAM && all_zero(out, 32));
    memset(out, 0xEE, sizeof out);
    CHECK(pgp_dec_ecdh(kek, NULL, out) == PGP_DEC_BAD_PARAM && all_zero(out, 32));
}

static void test_wrong_kek_and_tamper(void)
{
    uint8_t kek[32], kek2[32], pub[32];
    openpgp_dec_rec_t good, bad;
    bool z;
    boot();
    pgp_dec_kek(K1, kek);
    pgp_dec_kek(K2, kek2);
    CHECK(pgp_dec_generate(kek, pub) == PGP_DEC_OK);
    CHECK(ecdh_rc(kek2, &z) == PGP_DEC_BAD_WRAP && z);
    CHECK(openpgp_state_dec_get(&good) == 0);
    uint8_t *fields[4] = { bad.pub, bad.nonce, bad.ct, bad.tag };
    const size_t lens[4] = { sizeof bad.pub, sizeof bad.nonce, sizeof bad.ct, sizeof bad.tag };
    for (int f = 0; f < 4; ++f) {
        for (size_t at = 0; at < lens[f]; at += lens[f] - 1u) {   /* first and last byte */
            bad = good;
            fields[f][at] ^= 0x01u;
            CHECK(openpgp_state_dec_set(&bad) == 0);
            unsigned m = mock_mutations();
            CHECK(ecdh_rc(kek, &z) == PGP_DEC_BAD_WRAP && z);
            CHECK(mock_mutations() == m);                     /* nothing rewritten */
        }
    }
    CHECK(openpgp_state_dec_set(&good) == 0 && ecdh_matches(kek, pub));
}

/* One fault in each step of generation: no new key, the old one still works. */
static void test_generate_faults(void)
{
    uint8_t kek[32], pub[32], pub2[32];
    struct { mock_op_t op; unsigned n; } f[] = {
        { MOCK_OP_RANDOM, 1 },                   /* private key */
        { MOCK_OP_RANDOM, 2 },                   /* nonce */
        { MOCK_OP_RMEM_WRITE, 1 },               /* O3 copy A */
    };
    for (size_t i = 0; i < sizeof f / sizeof f[0]; ++i) {
        boot();
        pgp_dec_kek(K1, kek);
        CHECK(pgp_dec_generate(kek, pub) == PGP_DEC_OK);
        mock_fail_nth(f[i].op, f[i].n, -1, false);
        memset(pub2, 0xEE, sizeof pub2);
        CHECK(pgp_dec_generate(kek, pub2) == PGP_DEC_ERR && all_zero(pub2, 32));
        mock_disarm();
        openpgp_state_test_reboot();
        CHECK(openpgp_state_load() == 0 && ecdh_matches(kek, pub));
    }
}

/* §5.7: no 32-byte window anywhere in R-mem is the private key. */
static void test_no_plaintext_at_rest(void)
{
    uint8_t kek[32], pub[32], b[444], cand[32];
    boot();
    pgp_dec_kek(K1, kek);
    CHECK(pgp_dec_generate(kek, pub) == PGP_DEC_OK);
    unsigned scanned = 0;
    for (uint16_t s = 0; s < 512; ++s) {
        size_t n = 0;
        if (tropic_rmem_read(s, b, sizeof b, &n) != 0 || n < 32u) continue;
        for (size_t i = 0; i + 32u <= n; ++i) {
            curve25519_scalarmult_basepoint(cand, &b[i]);
            CHECK(memcmp(cand, pub, 32) != 0);
            ++scanned;
        }
    }
    CHECK(scanned > 400u);                       /* O3 both copies at least */
    /* Nor a PIN or its SHA-256 (§5.7; factory PINs bound by the boot). */
    static const char *pins[] = { "123456", "12345678" };
    for (size_t p = 0; p < 2; ++p) {
        uint8_t h[32];
        sha256_Raw((const uint8_t *) pins[p], strlen(pins[p]), h);
        for (uint16_t s = 0; s < 512; ++s) {
            size_t n = 0;
            if (tropic_rmem_read(s, b, sizeof b, &n) != 0) continue;
            for (size_t i = 0; i + 32u <= n; ++i) CHECK(memcmp(&b[i], h, 32) != 0);
            for (size_t i = 0; i + strlen(pins[p]) <= n; ++i) {
                CHECK(memcmp(&b[i], pins[p], strlen(pins[p])) != 0);
            }
        }
    }
}

/* The stored format is pinned by an outside vector (cpp-reviewer 3): the
 * KEK label, the AAD and the GCM direction cannot drift without a red test. */
static void test_golden_record(void)
{
    uint8_t kek[32], pub[32];
    openpgp_dec_rec_t r;
    pgp_dec_kek(G_K, kek);
    CHECK(memcmp(kek, G_KEK, 32) == 0);
    boot();
    memcpy(r.pub, G_PUB, 32);
    memcpy(r.nonce, G_NONCE, 12);
    memcpy(r.ct, G_CT, 32);
    memcpy(r.tag, G_TAG, 16);
    CHECK(openpgp_state_dec_set(&r) == 0);
    CHECK(pgp_dec_read_pubkey(pub) == PGP_DEC_OK && memcmp(pub, G_PUB, 32) == 0);
    CHECK(ecdh_matches(G_KEK, G_PUB));
}

/* A fresh nonce per seal (E1, cpp-reviewer 1): non-zero, never repeated. */
static void test_nonce_fresh(void)
{
    uint8_t kek[32], pub[32], zero[12] = { 0 };
    openpgp_dec_rec_t a, b;
    boot();
    pgp_dec_kek(K1, kek);
    CHECK(pgp_dec_generate(kek, pub) == PGP_DEC_OK && openpgp_state_dec_get(&a) == 0);
    CHECK(pgp_dec_generate(kek, pub) == PGP_DEC_OK && openpgp_state_dec_get(&b) == 0);
    CHECK(memcmp(a.nonce, zero, 12) != 0 && memcmp(b.nonce, zero, 12) != 0);
    CHECK(memcmp(a.nonce, b.nonce, 12) != 0);
}

/* J5 residual: a complete older record sealed under the same KEK opens. */
static void test_replay_residual(void)
{
    uint8_t kek[32], pub_old[32], pub_new[32];
    openpgp_dec_rec_t old;
    boot();
    pgp_dec_kek(K1, kek);
    CHECK(pgp_dec_generate(kek, pub_old) == PGP_DEC_OK && openpgp_state_dec_get(&old) == 0);
    CHECK(pgp_dec_generate(kek, pub_new) == PGP_DEC_OK);
    CHECK(openpgp_state_dec_set(&old) == 0 && ecdh_matches(kek, pub_old));
}

int main(void)
{
    test_gcm_kat();
    test_round_trip();
    test_wrong_kek_and_tamper();
    test_generate_faults();
    test_no_plaintext_at_rest();
    test_replay_residual();
    test_golden_record();
    test_nonce_fresh();
    return check_done("pgp_dec");
}
