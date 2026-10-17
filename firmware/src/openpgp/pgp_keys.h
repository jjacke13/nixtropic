/*
 * OpenPGP key generation + signing/ECDH on TROPIC01.
 *
 * Slot allocation (per docs/PHASE-7-PLAN.md §4.6):
 *
 *   29 — sig key (Ed25519, chip-side)  — used by PSO:CDS
 *   30 — UNUSED (dec key is host-side, see below)
 *   31 — aut key (Ed25519, chip-side)  — used by INTERNAL AUTHENTICATE
 *
 * Slots 0..28 are owned by FIDO (see firmware/src/fido_hid/slots.h).
 *
 * Architecture (Trezor Safe 7 pattern, confirmed by sub-agent
 * investigation of libtropic source + TropicSquare docs):
 *
 *   - sig + aut keys: pure chip-side.  lt_ecc_key_generate creates
 *     the keypair on chip slot 29/31; lt_ecc_eddsa_sign computes
 *     EdDSA signatures on-chip.  STM32 NEVER sees the private key.
 *
 *   - dec key (X25519): host-side compute.  TROPIC01 doesn't expose
 *     ECDH at the user-key level (confirmed via libtropic API audit
 *     + TROPIC01.md line 32).  X25519 priv lives in OpenPGP state O3
 *     (R-mem 33/43, encrypted by L3 session); STM32 does
 *     curve25519_donna scalarmult in software via trezor-crypto.
 *     Since Phase 9 M5 it is stored AES-GCM-wrapped under a KEK
 *     from the PW1 M&D binding (pgp_dec.h).
 *
 * Pubkeys are read on demand from the chip / R-mem; no caching in
 * flash/RAM (avoids stale-data bugs at the cost of a few ms per
 * READ PUBLIC KEY APDU).
 *
 * Crypto primitives: Ed25519 per RFC 8032; X25519 per RFC 7748.
 */

#ifndef NIXTROPIC_OPENPGP_PGP_KEYS_H
#define NIXTROPIC_OPENPGP_PGP_KEYS_H

#include <stdint.h>
#include <stddef.h>

/* Chip ECC slot indices. */
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

/* Diagnostic globals — last raw tropic_ecc_* return code + which stage
 * (1 = generate, 2 = pubkey_read).  Set inside pgp_keys_generate_sig
 * etc.  Applet uses these to surface the underlying lt_ret_t via SW
 * during HW debug. */
extern int pgp_keys_last_chip_rc;
extern int pgp_keys_last_chip_stage;

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


/* ===== M5 — DEC (encryption) + AUT (authentication) keys ===== */

/* DEC key (X25519): computed on the STM32 and stored wrapped under the PW1
 * KEK since Phase 9 M5 — see pgp_dec.h. */

int pgp_keys_generate_aut(uint8_t pubkey_out[PGP_KEYS_PUBKEY_LEN]);
int pgp_keys_read_aut_pubkey(uint8_t pubkey_out[PGP_KEYS_PUBKEY_LEN]);
int pgp_keys_sign_with_aut(const uint8_t *msg, size_t msg_len,
                            uint8_t sig_out[PGP_KEYS_SIG_LEN]);

#endif /* NIXTROPIC_OPENPGP_PGP_KEYS_H */
