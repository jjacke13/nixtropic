/*
 * Phase 7 M4 — OpenPGP key generation + Ed25519 signing on TROPIC01.
 *
 * Slot allocation (Phase 7 plan §4.6):
 *   29 — sig key (Ed25519)  — used by PSO:CDS (M4 + M6)
 *   30 — dec key (X25519)   — used by PSO:DEC (M5)
 *   31 — aut key (Ed25519)  — used by INTERNAL AUTHENTICATE (M5)
 *
 * Slots 0..28 are owned by FIDO per Phase 5 design (slots_init).
 *
 * M4 scope: sig key only.  DEC + AUT generation returns SW=0x6A82
 * (function not supported in current state).  M5 implements those.
 *
 * Key material lives on the TROPIC01 chip — STM32 firmware never sees
 * private keys.  All sign operations are chip-side via L3 secure
 * session (lt_ecc_eddsa_sign).  Pubkeys are read on demand from the
 * chip; no caching in flash/RAM (avoids stale-data bugs at the cost of
 * a few ms per READ PUBLIC KEY APDU).
 */

#ifndef NIXTROPIC_OPENPGP_PGP_KEYS_H
#define NIXTROPIC_OPENPGP_PGP_KEYS_H

#include <stdint.h>
#include <stddef.h>

/* Chip ECC slot indices.  Aligns with Phase 7 plan §4.6. */
#define PGP_KEYS_SIG_SLOT  29u
#define PGP_KEYS_DEC_SLOT  30u
#define PGP_KEYS_AUT_SLOT  31u

/* Slot indices used in our own R-mem PGP state (fingerprints,
 * gentimes).  0=sig, 1=dec, 2=aut.  Maps from CRT tag at
 * applet dispatch. */
#define PGP_KEYS_IDX_SIG   0
#define PGP_KEYS_IDX_DEC   1
#define PGP_KEYS_IDX_AUT   2

#define PGP_KEYS_PUBKEY_LEN  32u  /* Ed25519 + X25519 raw size */
#define PGP_KEYS_SIG_LEN     64u  /* Ed25519 signature */

#define PGP_KEYS_OK              0
#define PGP_KEYS_NO_KEY         -1   /* slot empty */
#define PGP_KEYS_CHIP_ERR       -2
#define PGP_KEYS_BAD_PARAM      -3
#define PGP_KEYS_UNSUPPORTED    -4   /* M4 doesn't do this op yet */

/**
 * @brief Generate a fresh Ed25519 key pair on the sig slot (29).
 *        Destroys any existing key on the slot.
 *        Reads back the public key (32 B) into @p pubkey_out.
 *
 *        Caller must have verified PW3 in the current session.  This
 *        function itself does NOT check session state — that's the
 *        applet dispatcher's job.
 */
int pgp_keys_generate_sig(uint8_t pubkey_out[PGP_KEYS_PUBKEY_LEN]);

/**
 * @brief Read the public key from the sig slot (29) without
 *        regenerating.  Returns PGP_KEYS_NO_KEY if the slot is empty.
 */
int pgp_keys_read_sig_pubkey(uint8_t pubkey_out[PGP_KEYS_PUBKEY_LEN]);

/**
 * @brief Sign @p msg with the sig slot Ed25519 key.  Signature is
 *        deterministic per RFC 8032.  Returns PGP_KEYS_NO_KEY if the
 *        slot is empty (key never generated).
 *
 *        Caller must have verified PW1 for the signing app (P2=0x81)
 *        in the current session.  This function itself does NOT check
 *        session state.
 */
int pgp_keys_sign_with_sig(const uint8_t *msg, size_t msg_len,
                            uint8_t sig_out[PGP_KEYS_SIG_LEN]);

/**
 * @brief Destroy the sig slot key.  Used by TERMINATE DF flow (M3) +
 *        manual key replacement (M5).
 */
int pgp_keys_erase_sig(void);

#endif /* NIXTROPIC_OPENPGP_PGP_KEYS_H */
