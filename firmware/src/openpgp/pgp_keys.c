/*
 * Phase 7 M4 — OpenPGP key ops, thin wrappers over the TROPIC01 chip.
 * See pgp_keys.h.
 */

#include "pgp_keys.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "tropic/tropic.h"

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

    /* TROPIC01 R-config gates: SH0 needs UAP access for ECC ops on
     * slot 29's 8-slot group (24..31).  Factory default is permissive
     * (all 0xFFFFFFFF) so this should be a no-op. */
    int rc = tropic_ecc_ensure_slot_authorized(PGP_KEYS_SIG_SLOT);
    if (rc != 0) {
        pgp_keys_last_chip_rc = rc;
        pgp_keys_last_chip_stage = (tropic_last_ensure_step == 2) ? 4 : 3;
        return PGP_KEYS_CHIP_ERR;
    }

    /* Erase any existing key first.  TROPIC01's lt_ecc_key_generate
     * returns LT_L3_FAIL (21) when the slot is already occupied —
     * it does NOT auto-overwrite.  The erase wrapper coerces "slot
     * already empty" to success, so calling it unconditionally is safe.
     * Phase 7 M4 HW debug 2026-05-12: caught at first run, slot 29
     * apparently had unexpected content on factory dongle. */
    (void) tropic_ecc_erase(PGP_KEYS_SIG_SLOT);

    /* Now generate the new key. */
    rc = tropic_ecc_generate(PGP_KEYS_SIG_SLOT, CURVE_ED25519);
    if (rc != 0) {
        pgp_keys_last_chip_rc = rc;
        pgp_keys_last_chip_stage = 1;
        return PGP_KEYS_CHIP_ERR;
    }

    rc = tropic_ecc_pubkey_read(PGP_KEYS_SIG_SLOT, pubkey_out,
                                 PGP_KEYS_PUBKEY_LEN);
    if (rc != 0) {
        pgp_keys_last_chip_rc = rc;
        pgp_keys_last_chip_stage = 2;
        return PGP_KEYS_CHIP_ERR;
    }
    pgp_keys_last_chip_rc = 0;
    pgp_keys_last_chip_stage = 0;
    return PGP_KEYS_OK;
}

int pgp_keys_read_sig_pubkey(uint8_t pubkey_out[PGP_KEYS_PUBKEY_LEN])
{
    if (pubkey_out == NULL) return PGP_KEYS_BAD_PARAM;
    int rc = tropic_ecc_pubkey_read(PGP_KEYS_SIG_SLOT, pubkey_out,
                                     PGP_KEYS_PUBKEY_LEN);
    if (rc != 0) {
        /* Either no key or chip error.  Treat all read failures as
         * "no key" for the applet's purposes — gpg expects a clear
         * "no key" SW (0x6A88) rather than a generic error if the
         * slot is empty. */
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
