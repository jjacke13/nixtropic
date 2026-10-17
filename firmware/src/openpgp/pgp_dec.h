/*
 * The OpenPGP decryption key (X25519), wrapped under the PW1 KEK
 * (Phase 9 M5, docs/history/PHASE-9-M5-DESIGN.md).
 *
 * TROPIC01 has no X25519 for user keys, so the private key is computed on
 * the STM32 and stored in O3 (openpgp_state.h) — only AES-256-GCM-wrapped:
 *
 *   KEK   = HMAC-SHA256(k, "nixtropic/openpgp/dec-kek/v1")   (E2)
 *           k = HMAC(s, 0x02) from the PW1 binding (pin_md_kernel.h)
 *   nonce = 12 fresh bytes from the chip TRNG per seal          (E1)
 *   AAD   = "NXDW" | obj 3 | schema 2 | public key              (E3)
 *
 * Unwrap checks the tag first (constant time) and decrypts only after a
 * match (E10); a failed tag never yields plaintext.  The private key lives
 * on the stack for one X25519 and is wiped; nothing here caches anything.
 * The KEK cache and the access rules are the applet's (design §4).
 */
#ifndef NIXTROPIC_OPENPGP_PGP_DEC_H
#define NIXTROPIC_OPENPGP_PGP_DEC_H

#include <stdint.h>

#define PGP_DEC_KEY_LEN   32u    /* k, KEK, X25519 keys, shared secret */

/* Return codes (PGP_KEYS_* values where they mean the same). */
#define PGP_DEC_OK         0
#define PGP_DEC_NO_KEY    (-1)   /* = PGP_KEYS_NO_KEY */
#define PGP_DEC_ERR       (-2)   /* TRNG / crypto / state write (= PGP_KEYS_CHIP_ERR) */
#define PGP_DEC_BAD_PARAM (-3)   /* = PGP_KEYS_BAD_PARAM */
#define PGP_DEC_BAD_WRAP  (-5)   /* the stored wrap fails its tag: damage or a wrong KEK */

/* KEK from the PW1 binding's k. */
void pgp_dec_kek(const uint8_t k[PGP_DEC_KEY_LEN], uint8_t kek[PGP_DEC_KEY_LEN]);

/* New key pair: TRNG → clamp → public key → seal under `kek` → one O3
 * commit (replaces the old key).  `pub_out` gets the public key. */
int pgp_dec_generate(const uint8_t kek[PGP_DEC_KEY_LEN], uint8_t pub_out[PGP_DEC_KEY_LEN]);

/* The stored public key (no PIN, no unwrap). */
int pgp_dec_read_pubkey(uint8_t pub_out[PGP_DEC_KEY_LEN]);

/* shared = X25519(unwrap(kek), peer).  On any failure `shared_out` is zero. */
int pgp_dec_ecdh(const uint8_t kek[PGP_DEC_KEY_LEN], const uint8_t peer[PGP_DEC_KEY_LEN],
                 uint8_t shared_out[PGP_DEC_KEY_LEN]);

#endif /* NIXTROPIC_OPENPGP_PGP_DEC_H */
