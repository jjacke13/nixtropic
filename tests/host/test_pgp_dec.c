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
#include "tropic/tropic.h"

static const uint8_t K1[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
static const uint8_t K2[32] = { 2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
static const uint8_t PEER_PRIV[32] = { 0x70, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x40 };

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
    return check_done("pgp_dec");
}
