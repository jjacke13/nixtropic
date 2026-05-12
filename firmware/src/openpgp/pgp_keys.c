/*
 * Phase 7 M4 — OpenPGP key ops, thin wrappers over the TROPIC01 chip.
 * See pgp_keys.h.
 */

#include "pgp_keys.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "tropic/tropic.h"
#include "ed25519-donna/ed25519.h"   /* ed25519_publickey() */
#include "memzero.h"

/* Ed25519 = curve 0 in tropic_ecc_generate.  P-256 = 1; that's not
 * exposed at this layer in M4. */
#define CURVE_ED25519  0u

/* DIAGNOSTIC GLOBAL — last raw tropic_ecc_* rc.  M4 HW debug surfaces
 * this via SW so we can see what libtropic actually complains about.
 * Will get tidied to a proper return-channel after we know the bug. */
int pgp_keys_last_chip_rc = 0;
int pgp_keys_last_chip_stage = 0;  /* 1=generate, 2=pubkey_read */

int pgp_keys_generate_sig(uint8_t pubkey_out[PGP_KEYS_PUBKEY_LEN])
{
    if (pubkey_out == NULL) return PGP_KEYS_BAD_PARAM;

    /* TROPIC01 R-config gates — should be no-op on factory-virgin chip. */
    int rc = tropic_ecc_ensure_slot_authorized(PGP_KEYS_SIG_SLOT);
    if (rc != 0) {
        pgp_keys_last_chip_rc = rc;
        pgp_keys_last_chip_stage = (tropic_last_ensure_step == 2) ? 4 : 3;
        return PGP_KEYS_CHIP_ERR;
    }

    /* HOST-SIDE KEYGEN PATH (M4 2026-05-12)
     *
     * lt_ecc_key_read on our specific dongle's chip-firmware build
     * returns LT_L2_RESP_DISABLED (32) — the L2 opcode is feature-
     * gated off (like FW_LOG_EN; see libtropic_functional_tests.h:368).
     * UAP-bitmap denials would surface as LT_L3_UNAUTHORIZED at L3
     * level instead, which is NOT what we're seeing.
     *
     * Workaround: host-side generate the Ed25519 seed (32 B from
     * chip TRNG), derive pubkey via trezor_crypto ed25519_publickey(),
     * then store the seed on chip via lt_ecc_key_store.  Chip-side
     * EDDSA_SIGN still works (Phase 5 FIDO uses it on slots 0..28
     * successfully — same opcode, no FW gating).
     *
     * SECURITY NOTE: the 32-byte seed transiently exists in STM32
     * RAM (the `seed` array below).  We zero it before return.  This
     * matches Phase 5's FIDO credential-key path (host-derives the
     * credential KDF seed, stores on chip).  An attacker with full
     * STM32 RAM access during the ~milliseconds between seed-gen
     * and memzero could extract — addressed at the same level as
     * Phase 5 (i.e., not at all in M4; M6 audit may suggest specific
     * mitigations).
     */

    /* Erase any existing key first.  Store also requires empty slot. */
    (void) tropic_ecc_erase(PGP_KEYS_SIG_SLOT);

    uint8_t seed[32];
    rc = tropic_random(seed, sizeof seed);
    if (rc != 0) {
        pgp_keys_last_chip_rc = rc;
        pgp_keys_last_chip_stage = 5;  /* TRNG */
        memzero(seed, sizeof seed);
        return PGP_KEYS_CHIP_ERR;
    }

    /* Derive pubkey from seed.  trezor_crypto's ed25519_publickey
     * implements RFC 8032 §5.1.5 — SHA-512(seed) → scalar derive,
     * scalar*B → pubkey. */
    ed25519_publickey(seed, pubkey_out);

    /* Store the seed on chip.  Future signs use lt_ecc_eddsa_sign which
     * re-derives the scalar from the stored seed (same RFC 8032 step). */
    rc = tropic_ecc_store(PGP_KEYS_SIG_SLOT, CURVE_ED25519, seed);
    memzero(seed, sizeof seed);
    if (rc != 0) {
        pgp_keys_last_chip_rc = rc;
        pgp_keys_last_chip_stage = 6;  /* STORE */
        return PGP_KEYS_CHIP_ERR;
    }

    pgp_keys_last_chip_rc = 0;
    pgp_keys_last_chip_stage = 0;
    return PGP_KEYS_OK;
}

int pgp_keys_read_sig_pubkey(uint8_t pubkey_out[PGP_KEYS_PUBKEY_LEN])
{
    if (pubkey_out == NULL) return PGP_KEYS_BAD_PARAM;
    /* M4 HW debug: lt_ecc_key_read is feature-disabled on our chip
     * (returns LT_L2_RESP_DISABLED).  GENERATE-then-RE-READ workflow
     * is replaced with the host-side keygen path in
     * pgp_keys_generate_sig() that returns the pubkey directly.
     * For READ (P1=81 after a prior generate), we need a cached
     * pubkey — that's M5 polish (R-mem-persisted).  For now, READ
     * just returns NO_KEY → 0x6A88.  GnuPG's normal flow is generate
     * → captures pubkey in response → never re-reads. */
    (void) pubkey_out;
    return PGP_KEYS_NO_KEY;
}

int pgp_keys_sign_with_sig(const uint8_t *msg, size_t msg_len,
                            uint8_t sig_out[PGP_KEYS_SIG_LEN])
{
    if (msg == NULL || sig_out == NULL) return PGP_KEYS_BAD_PARAM;
    if (msg_len == 0u) return PGP_KEYS_BAD_PARAM;

    int rc = tropic_ecc_eddsa_sign(PGP_KEYS_SIG_SLOT, msg, msg_len,
                                    sig_out, PGP_KEYS_SIG_LEN);
    if (rc < 0) {
        return PGP_KEYS_CHIP_ERR;
    }
    /* tropic_ecc_eddsa_sign returns sig length on success (64).  Sanity
     * check that against our expected. */
    if (rc != (int) PGP_KEYS_SIG_LEN) {
        return PGP_KEYS_CHIP_ERR;
    }
    return PGP_KEYS_OK;
}

int pgp_keys_erase_sig(void)
{
    int rc = tropic_ecc_erase(PGP_KEYS_SIG_SLOT);
    return (rc == 0) ? PGP_KEYS_OK : PGP_KEYS_CHIP_ERR;
}
