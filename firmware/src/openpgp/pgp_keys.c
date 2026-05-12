/*
 * Phase 7 M4 — OpenPGP key ops, thin wrappers over the TROPIC01 chip.
 * See pgp_keys.h.
 */

#include "pgp_keys.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "tropic/tropic.h"
#include "openpgp_state.h"   /* openpgp_state_dec_priv_get/set */
#include "ed25519-donna/ed25519.h"   /* ed25519_publickey() + curve25519_scalarmult */
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

    /* On TROPIC01 App FW 2.0.0+ (after running `nix run .#fw-update-chip`)
     * chip-side keygen via lt_ecc_key_generate + lt_ecc_key_read works
     * cleanly on slot 29.  The earlier host-side workaround (host-derive
     * seed → ed25519_publickey → lt_ecc_key_store) was a 0.3.1
     * engineering-FW quirk; reverted now that we're on supported FW.
     *
     * This restores plan §4.6: private key material never leaves the
     * secure element — same model Phase 5 FIDO uses. */

    /* Erase any existing key first.  lt_ecc_key_generate doesn't auto-
     * overwrite; libtropic wrapper coerces "already empty" to success
     * so calling unconditionally is safe. */
    (void) tropic_ecc_erase(PGP_KEYS_SIG_SLOT);

    int rc = tropic_ecc_generate(PGP_KEYS_SIG_SLOT, CURVE_ED25519);
    if (rc != 0) {
        pgp_keys_last_chip_rc = rc;
        pgp_keys_last_chip_stage = 1;  /* generate */
        return PGP_KEYS_CHIP_ERR;
    }

    rc = tropic_ecc_pubkey_read(PGP_KEYS_SIG_SLOT, pubkey_out,
                                 PGP_KEYS_PUBKEY_LEN);
    if (rc < 0) {
        pgp_keys_last_chip_rc = rc;
        pgp_keys_last_chip_stage = 2;  /* pubkey_read */
        return PGP_KEYS_CHIP_ERR;
    }

    pgp_keys_last_chip_rc = 0;
    pgp_keys_last_chip_stage = 0;
    return PGP_KEYS_OK;
}

int pgp_keys_read_sig_pubkey(uint8_t pubkey_out[PGP_KEYS_PUBKEY_LEN])
{
    if (pubkey_out == NULL) return PGP_KEYS_BAD_PARAM;
    /* Restored after chip FW update to 2.0.0 — lt_ecc_key_read works
     * cleanly on slot 29 now.  Returns NO_KEY if slot is empty. */
    int rc = tropic_ecc_pubkey_read(PGP_KEYS_SIG_SLOT, pubkey_out,
                                     PGP_KEYS_PUBKEY_LEN);
    if (rc < 0) {
        memset(pubkey_out, 0, PGP_KEYS_PUBKEY_LEN);
        return PGP_KEYS_NO_KEY;
    }
    return PGP_KEYS_OK;
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

/* ===== M5 — DEC slot (X25519, host-side compute, priv in R-mem) ===== */

#include "ed25519-donna/ed25519.h"  /* curve25519_scalarmult{,_basepoint} */

int pgp_keys_generate_dec(uint8_t pubkey_out[PGP_KEYS_PUBKEY_LEN])
{
    if (pubkey_out == NULL) return PGP_KEYS_BAD_PARAM;

    /* 32 random bytes from chip TRNG, then RFC 7748 §5 X25519 clamping. */
    uint8_t priv[32];
    int rc = tropic_random(priv, sizeof priv);
    if (rc != 0) {
        memzero(priv, sizeof priv);
        return PGP_KEYS_CHIP_ERR;
    }
    priv[0]  &= 248u;
    priv[31] &= 127u;
    priv[31] |=  64u;

    /* Derive pubkey = priv * BASEPOINT (curve25519_donna_basepoint). */
    curve25519_scalarmult_basepoint(pubkey_out, priv);

    /* Persist the clamped priv to R-mem.  Trust model: readable by
     * anyone with SH0 + L3.  M6 wraps this with M&D-gated KEK. */
    rc = openpgp_state_dec_priv_set(priv);
    memzero(priv, sizeof priv);
    if (rc != 0) {
        pgp_keys_last_chip_rc = rc;
        pgp_keys_last_chip_stage = 6;
        return PGP_KEYS_CHIP_ERR;
    }
    return PGP_KEYS_OK;
}

/* Derive the X25519 public key from the stored private key.  Used both
 * by READ PUBLIC KEY (P1=81) and indirectly by ECDH paths. */
int pgp_keys_read_dec_pubkey(uint8_t pubkey_out[PGP_KEYS_PUBKEY_LEN])
{
    if (pubkey_out == NULL) return PGP_KEYS_BAD_PARAM;

    uint8_t priv[32];
    int rc = openpgp_state_dec_priv_get(priv);
    if (rc != 0) {
        memzero(priv, sizeof priv);
        return PGP_KEYS_NO_KEY;
    }
    /* All-zero priv = "no key generated yet". */
    uint8_t zero[32] = {0};
    if (memcmp(priv, zero, sizeof zero) == 0) {
        memzero(priv, sizeof priv);
        return PGP_KEYS_NO_KEY;
    }

    curve25519_scalarmult_basepoint(pubkey_out, priv);
    memzero(priv, sizeof priv);
    return PGP_KEYS_OK;
}

/* Perform X25519 ECDH: shared = dec_priv * peer_pubkey.
 * Used by PSO:DEC (Decipher) APDU handler. */
int pgp_keys_ecdh_dec(const uint8_t peer_pubkey[PGP_KEYS_PUBKEY_LEN],
                      uint8_t shared_out[PGP_KEYS_PUBKEY_LEN])
{
    if (peer_pubkey == NULL || shared_out == NULL) return PGP_KEYS_BAD_PARAM;

    uint8_t priv[32];
    int rc = openpgp_state_dec_priv_get(priv);
    if (rc != 0) {
        memzero(priv, sizeof priv);
        return PGP_KEYS_CHIP_ERR;
    }
    uint8_t zero[32] = {0};
    if (memcmp(priv, zero, sizeof zero) == 0) {
        memzero(priv, sizeof priv);
        return PGP_KEYS_NO_KEY;
    }

    curve25519_scalarmult(shared_out, priv, peer_pubkey);
    memzero(priv, sizeof priv);
    return PGP_KEYS_OK;
}

int pgp_keys_erase_dec(void)
{
    uint8_t zero[32] = {0};
    if (openpgp_state_dec_priv_set(zero) != 0) return PGP_KEYS_CHIP_ERR;
    return PGP_KEYS_OK;
}

/* ===== M5 — AUT slot (chip-side Ed25519, full implementation) ===== */

int pgp_keys_generate_aut(uint8_t pubkey_out[PGP_KEYS_PUBKEY_LEN])
{
    if (pubkey_out == NULL) return PGP_KEYS_BAD_PARAM;
    (void) tropic_ecc_erase(PGP_KEYS_AUT_SLOT);
    int rc = tropic_ecc_generate(PGP_KEYS_AUT_SLOT, CURVE_ED25519);
    if (rc != 0) {
        pgp_keys_last_chip_rc = rc;
        pgp_keys_last_chip_stage = 1;
        return PGP_KEYS_CHIP_ERR;
    }
    rc = tropic_ecc_pubkey_read(PGP_KEYS_AUT_SLOT, pubkey_out,
                                 PGP_KEYS_PUBKEY_LEN);
    if (rc < 0) {
        pgp_keys_last_chip_rc = rc;
        pgp_keys_last_chip_stage = 2;
        return PGP_KEYS_CHIP_ERR;
    }
    return PGP_KEYS_OK;
}

int pgp_keys_read_aut_pubkey(uint8_t pubkey_out[PGP_KEYS_PUBKEY_LEN])
{
    if (pubkey_out == NULL) return PGP_KEYS_BAD_PARAM;
    int rc = tropic_ecc_pubkey_read(PGP_KEYS_AUT_SLOT, pubkey_out,
                                     PGP_KEYS_PUBKEY_LEN);
    if (rc < 0) {
        memset(pubkey_out, 0, PGP_KEYS_PUBKEY_LEN);
        return PGP_KEYS_NO_KEY;
    }
    return PGP_KEYS_OK;
}

int pgp_keys_sign_with_aut(const uint8_t *msg, size_t msg_len,
                            uint8_t sig_out[PGP_KEYS_SIG_LEN])
{
    if (msg == NULL || sig_out == NULL) return PGP_KEYS_BAD_PARAM;
    if (msg_len == 0u) return PGP_KEYS_BAD_PARAM;
    int rc = tropic_ecc_eddsa_sign(PGP_KEYS_AUT_SLOT, msg, msg_len,
                                    sig_out, PGP_KEYS_SIG_LEN);
    if (rc < 0) return PGP_KEYS_CHIP_ERR;
    if (rc != (int) PGP_KEYS_SIG_LEN) return PGP_KEYS_CHIP_ERR;
    return PGP_KEYS_OK;
}

int pgp_keys_erase_aut(void)
{
    int rc = tropic_ecc_erase(PGP_KEYS_AUT_SLOT);
    return (rc == 0) ? PGP_KEYS_OK : PGP_KEYS_CHIP_ERR;
}
