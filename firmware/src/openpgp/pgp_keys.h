/*
 * OpenPGP key generation + signing/ECDH on TROPIC01.
 *
 * Slot allocation (per docs/PHASE-7-PLAN.md §4.6):
 *
 *   29 — sig key (Ed25519, chip-side)  — used by PSO:CDS
 *   30 — UNUSED (dec key is host-side, see below)
 *   31 — aut key (Ed25519, chip-side)  — used by INTERNAL AUTHENTICATE
 *
 * Slots 0..28 are owned by FIDO per Phase 5 design (slots_init).
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
 *     + TROPIC01.md line 32).  X25519 priv lives in R-mem slot 1
 *     byte 180-211 (encrypted by L3 session); STM32 does
 *     curve25519_donna scalarmult in software via trezor-crypto.
 *     Phase 8 hardens this further with M&D-KEK gating
 *     (docs/PHASE-8-BACKLOG.md §1.2).
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

/**
 * @brief Destroy the sig slot key.  Used by TERMINATE DF flow (M3) +
 *        manual key replacement (M5).
 */
int pgp_keys_erase_sig(void);

/* ===== M5 — DEC (encryption) + AUT (authentication) keys ===== */

/* M5 dec slot — X25519 (Curve25519 ECDH), host-side compute.
 *
 * TROPIC01 doesn't expose ECDH at the user-key level (confirmed by
 * libtropic API audit + TropicSquare's own docs; see TROPIC01.md
 * line 32 "no exposed ECDH").  X25519 hardware exists on-die but is
 * wired exclusively to the L3 secure-channel Noise handshake.
 *
 * Following the Trezor Safe 7 pattern: priv lives in R-mem (chip-
 * persistent), STM32 does curve25519_donna scalarmult in software
 * via trezor_crypto's curve25519-donna (already linked from Phase 3).
 *
 * Trust model M5 ship: priv key plain in R-mem, readable by anyone
 * with SH0 + L3 session — same trust level as PIN hashes today.
 * Acceptable for daily-driver since SH0 is the dev public key and a
 * wire-level attacker can't establish L3 without the chip.
 *
 * M6 audit + close hardens: wraps dec priv with M&D-gated KEK derived
 * from PW1, mirroring Trezor's PIN-encrypted-seed design.  Same M&D
 * framework that hardens PW1/PW3/RC retry counters (Phase 7 plan §3
 * H6, deferred from M3). */

int pgp_keys_generate_dec(uint8_t pubkey_out[PGP_KEYS_PUBKEY_LEN]);
int pgp_keys_read_dec_pubkey(uint8_t pubkey_out[PGP_KEYS_PUBKEY_LEN]);
int pgp_keys_ecdh_dec(const uint8_t peer_pubkey[PGP_KEYS_PUBKEY_LEN],
                      uint8_t shared_out[PGP_KEYS_PUBKEY_LEN]);
int pgp_keys_erase_dec(void);

int pgp_keys_generate_aut(uint8_t pubkey_out[PGP_KEYS_PUBKEY_LEN]);
int pgp_keys_read_aut_pubkey(uint8_t pubkey_out[PGP_KEYS_PUBKEY_LEN]);
int pgp_keys_sign_with_aut(const uint8_t *msg, size_t msg_len,
                            uint8_t sig_out[PGP_KEYS_SIG_LEN]);
int pgp_keys_erase_aut(void);

#endif /* NIXTROPIC_OPENPGP_PGP_KEYS_H */
