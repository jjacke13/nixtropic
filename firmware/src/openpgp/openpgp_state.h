/*
 * OpenPGP applet state on TROPIC01 R-mem slot 33.  Persisted state
 * + accessors for the OpenPGP card surface.
 *
 * Slot 33 layout (256 B) — magic "PG7Q" / schema v5 (current after
 * the Phase-8 R-mem collision fix moved this slot away from slot 1):
 *
 *   offset  size   field
 *   ------  ----   -----
 *      0      4    magic "PG7Q" (0x50,0x47,0x37,0x51)
 *      4      2    schema_version = 5
 *      6      1    pgp_state_present (1 once activated, 2 terminated)
 *      7      1    PW1 retry counter cache (0..3)
 *      8      1    PW3 retry counter cache (0..3)
 *      9      1    RC retry counter cache (0xFF if unset, else 0..3)
 *     10      1    force_verify (DO C4 bit 0; default 1)
 *     11      1    touch_required (alias for D6/D7/D8; default 1)
 *     12      2    reserved
 *     14     40    cardholder name (1 B len + 39 B data) — DO 5B
 *     54      2    language (ISO 639) — DO 5F2D
 *     56      1    sex (ISO 5218) — DO 5F35
 *     57     20    fingerprint sig — DO C7
 *     77     20    fingerprint dec — DO C8
 *     97     20    fingerprint aut — DO C9
 *    117      4    generation time sig (BE u32) — DO CE
 *    121      4    generation time dec — DO CF
 *    125      4    generation time aut — DO D0
 *    129      3    signature counter (BE 24) — DO 93
 *    132     16    PW1 hash (SHA-256[:16])
 *    148     16    PW3 hash (SHA-256[:16])
 *    164     16    RC  hash (SHA-256[:16], all-zero if unset)
 *    180     32    X25519 dec priv key (Trezor Safe 7 host-side pattern)
 *    212      1    PW1 length (M6 audit H2 fix — canonical split boundary)
 *    213      1    PW3 length
 *    214      1    RC  length (0 if unset)
 *    215     41    reserved
 *                                                              ----
 *   total = 256 B (matches TROPIC01 default per-slot size)
 *
 * Magic bumps: PG7K → PG7L → PG7M → PG7N → PG7O → PG7P → PG7Q as schema evolves.  Magic
 * mismatch on read triggers a clean write of defaults
 * (write_activated_defaults), which is the user-visible side effect
 * of every M5/M6 upgrade.
 *
 * Why R-mem and not flash: persistent across power cycles, encrypted
 * on the chip side, accessible only via L3 session — so a firmware
 * reflash that doesn't have the L3 keys can't read prior state.
 */

#ifndef NIXTROPIC_OPENPGP_STATE_H
#define NIXTROPIC_OPENPGP_STATE_H

#include <stdint.h>
#include <stddef.h>

/* Phase 8 collision fix (2026-05-20) — moved from R-mem slot 1 to
 * slot 33.  FIDO per-credential metadata lives at SLOTS_RMEM_SLOT_FOR(0)
 * = slot 1, so any FIDO credential allocation (e.g. webauthn.io
 * registration) was overwriting OpenPGP state.  Slot 33 is clear of
 * the entire FIDO range (per-cred slots 1..32 for SLOTS_MAX=32). */
#define OPENPGP_RMEM_PRIMARY_SLOT    33u
/* 256 bytes — matches Phase 5 slots.c (SLOTS_RMEM_GLOBAL_SIZE).  475
 * was the chip's *max* slot capacity per the inventory doc, but the
 * default per-slot configuration on this silicon is smaller — writes
 * over 256 silently break subsequent reads (caught at Phase 7 M3 HW
 * test 2026-05-12: 0x6F01 mid-VERIFY on the second invocation). */
#define OPENPGP_RMEM_PRIMARY_SIZE    256u

/* PIN retry-counter defaults — match OpenPGP card spec.  Stored in the
 * cache bytes of the primary slot; the actual M&D enforcement lives in chip M&D
 * slots 8..16 (M3). */
#define OPENPGP_PW1_RETRIES_INITIAL  3u
#define OPENPGP_PW3_RETRIES_INITIAL  3u
#define OPENPGP_RC_UNSET             0xFFu

/* Cardholder field sizes (DO 5B, 5F2D, 5F35). */
#define OPENPGP_NAME_MAX             39u  /* + 1 B length prefix */
#define OPENPGP_LANG_LEN             2u
#define OPENPGP_SEX_LEN              1u

/* Fingerprint + generation-time sizes (DO C7/C8/C9, CE/CF/D0). */
#define OPENPGP_FPR_LEN              20u
#define OPENPGP_GENTIME_LEN          4u
#define OPENPGP_SIG_COUNTER_LEN      3u   /* DO 93, BCD encoded */

/* PIN hash storage — SHA-256(PIN)[:16].  Same convention as Phase 5's
 * pin.c.  Stored in R-mem primary slot at v2 layout offsets 132..179. */
#define OPENPGP_PIN_HASH_LEN         16u

/* M5 — X25519 private key for the dec slot.  TROPIC01 doesn't expose
 * ECDH; the priv key lives in R-mem and STM32 does curve25519_donna
 * scalarmult in software (trezor_crypto).  Trust model: priv is plain
 * here (readable by anyone with SH0 + L3 session).  M6 audit + close
 * wraps with M&D-gated KEK derived from PW1 (Trezor Safe 7 pattern). */
#define OPENPGP_DEC_PRIV_LEN         32u

/* PIN indices.  PW1.sig and PW1.dec/auth share the same hash + counter
 * per OpenPGP spec §7.2.2. */
#define OPENPGP_PIN_PW1              0
#define OPENPGP_PIN_PW3              1
#define OPENPGP_PIN_RC               2
#define OPENPGP_PIN_COUNT            3

/* PIN length constraints (spec §4.3). */
#define OPENPGP_PW1_MIN_LEN          6u
#define OPENPGP_PW3_MIN_LEN          8u
#define OPENPGP_RC_MIN_LEN           8u
#define OPENPGP_PIN_MAX_LEN          64u

/**
 * @brief First-call init: ensure R-mem primary slot has the PGP state magic.
 *        Idempotent — safe to call from openpgp_applet open hook.
 *        If the slot is uninitialised (or wrong magic), writes a
 *        default-state v1 layout (pgp_state_present=0, PIN retry
 *        counters at defaults, fingerprints/cardholder empty).
 *
 *        Does NOT generate any keys — that's M4.  Does NOT set any
 *        PW1/PW3 — those are M3.
 *
 * @return 0 on success; negative on chip error.
 */
int openpgp_state_init(void);

/* ---- M2 GET DATA accessors (read-only) ---- */

/**
 * @brief Read the current force_verify flag (DO C4 bit 0).
 * @return 1 if force-verify is enabled (default), 0 if disabled.
 */
uint8_t openpgp_state_force_verify_get(void);

/**
 * @brief Read the global touch_required flag (aliases DO D6/D7/D8).
 * @return 0 = off, 1 = enabled (default), 2 = permanent.
 */
uint8_t openpgp_state_touch_required_get(void);

/**
 * @brief Read PW1 retry counter cache.  0..3.
 */
uint8_t openpgp_state_pw1_retries_get(void);

/**
 * @brief Read PW3 retry counter cache.  0..3.
 */
uint8_t openpgp_state_pw3_retries_get(void);

/**
 * @brief Read RC retry counter cache.  0..3, or 0xFF if RC unset.
 */
uint8_t openpgp_state_rc_retries_get(void);

/**
 * @brief Copy 20 B fingerprint for the requested slot.
 *        slot_idx = 0 (sig), 1 (dec), 2 (aut).
 *        Reads R-mem; returns all-zero if no key generated for slot.
 * @return 0 on success; -1 on bad slot_idx; -2 on chip error.
 */
int openpgp_state_fingerprint_get(int slot_idx, uint8_t out[OPENPGP_FPR_LEN]);

/**
 * @brief Copy 4 B generation timestamp (BE u32) for the requested slot.
 *        slot_idx = 0 (sig), 1 (dec), 2 (aut).
 *        Reads R-mem; returns all-zero if no key generated.
 */
int openpgp_state_gentime_get(int slot_idx, uint8_t out[OPENPGP_GENTIME_LEN]);

/**
 * @brief Copy 3 B signature counter (BCD) — DO 93.
 *        Returns all-zero on fresh state.
 */
int openpgp_state_sig_counter_get(uint8_t out[OPENPGP_SIG_COUNTER_LEN]);

/**
 * @brief Copy cardholder name (DO 5B).  Returns length 0..39 via
 *        *out_len; out buffer must be ≥ OPENPGP_NAME_MAX.
 */
int openpgp_state_name_get(uint8_t out[OPENPGP_NAME_MAX], size_t *out_len);

/**
 * @brief Copy 2 B language (DO 5F2D, ISO 639).  Returns all-zero if unset.
 */
int openpgp_state_lang_get(uint8_t out[OPENPGP_LANG_LEN]);

/**
 * @brief Read 1 B sex (DO 5F35, ISO 5218).  Returns 0x39 ('9' — "not applicable") if unset.
 */
uint8_t openpgp_state_sex_get(void);

/* ---- M3 PIN hash storage + retry counter writers ---- */

/**
 * @brief Read PIN hash (16 B) for the given PIN index.  Returns 0 OK,
 *        -1 bad index, -2 chip error.
 */
int openpgp_state_pin_hash_get(int which, uint8_t out[OPENPGP_PIN_HASH_LEN]);

/**
 * @brief Write PIN hash for the given PIN index.  Caller is responsible
 *        for hashing the raw PIN (SHA-256[:16]).  Returns 0 OK, -1 bad
 *        index, -2 chip error.
 */
int openpgp_state_pin_hash_set(int which,
                               const uint8_t hash[OPENPGP_PIN_HASH_LEN]);

/**
 * @brief Set retry counter for one PIN.  Used by VERIFY (decrement on
 *        wrong, reset to default on correct) and RESET RETRY COUNTER.
 *        Returns 0 OK, -1 bad index, -2 chip error.
 */
int openpgp_state_pin_retries_set(int which, uint8_t v);

/**
 * @brief Get/set the recorded length of a PIN (M6 audit H2 fix —
 *        schema v5 PG7Q).  Used by CHANGE REFERENCE DATA / RESET
 *        RETRY COUNTER to split the APDU body at the canonical
 *        old/new boundary on a single verify attempt.
 *        Returns 0 OK, -1 bad index, -2 chip error.
 *        For RC, length 0 means "unset".
 */
int openpgp_state_pin_len_get(int which, uint8_t *out);
int openpgp_state_pin_len_set(int which, uint8_t v);

/**
 * @brief Get / set pgp_state_present flag.  Set to 1 on ACTIVATE FILE;
 *        zeroed on TERMINATE DF (which wipes all PGP state).
 */
uint8_t openpgp_state_present_get(void);
int     openpgp_state_present_set(uint8_t v);

/* ---- M3 writable DO setters (PUT DATA) ---- */

int openpgp_state_name_set(const uint8_t *data, size_t len);  /* DO 5B */
int openpgp_state_lang_set(const uint8_t data[OPENPGP_LANG_LEN]);  /* DO 5F2D */
int openpgp_state_sex_set(uint8_t v);  /* DO 5F35 */
int openpgp_state_force_verify_set(uint8_t v);  /* DO C4 bit 0 */
int openpgp_state_touch_required_set(uint8_t v);  /* aliases DO D6/D7/D8 */

/* ---- M4 fingerprint + gentime + sig counter writers ---- */

/**
 * @brief Write 20 B fingerprint for the given slot (DO C7/C8/C9).
 *        slot_idx = 0 (sig), 1 (dec), 2 (aut).
 *        Caller responsible for PW3-verified gate.
 */
int openpgp_state_fingerprint_set(int slot_idx,
                                   const uint8_t fpr[OPENPGP_FPR_LEN]);

/**
 * @brief Write 4 B generation timestamp BE u32 (DO CE/CF/D0).
 *        slot_idx = 0 (sig), 1 (dec), 2 (aut).
 */
int openpgp_state_gentime_set(int slot_idx,
                               const uint8_t gt[OPENPGP_GENTIME_LEN]);

/**
 * @brief Increment the 3-byte BCD signature counter (DO 93) by 1.
 *        Called on each successful PSO:CDS.  Overflow wraps to 0
 *        and triggers force_verify (consume PW1.81 again per spec).
 */
int openpgp_state_sig_counter_increment(void);

/* ---- TERMINATE DF / ACTIVATE FILE ---- */

/**
 * @brief Wipe all PGP state in R-mem primary slot (PIN hashes, fingerprints,
 *        cardholder data, etc).  Sets pgp_state_present = 0.  After
 *        TERMINATE, the only valid INS is ACTIVATE FILE.
 *        Does NOT erase chip ECC slots — that happens in M4 GENERATE
 *        path (TERMINATE here also calls into pgp_keys later).
 */
int openpgp_state_terminate(void);

/* ---- M5 dec key X25519 priv storage ---- */

/**
 * @brief Read the 32-byte X25519 private key for the dec slot.
 *        Returns 0 OK, -2 chip error.  Caller must zero `out`
 *        after use.
 */
int openpgp_state_dec_priv_get(uint8_t out[OPENPGP_DEC_PRIV_LEN]);

/**
 * @brief Write the 32-byte X25519 private key for the dec slot.
 *        Caller must clamp (RFC 7748 §5) before passing in.
 *        Returns 0 OK, -2 chip error.
 */
int openpgp_state_dec_priv_set(const uint8_t key[OPENPGP_DEC_PRIV_LEN]);

/**
 * @brief Re-init R-mem primary slot with spec-default PINs ("123456" / "12345678" /
 *        RC unset), default retry counters (3/3/0), touch_required=1,
 *        force_verify=1, sex=0x39.  Sets pgp_state_present = 1.
 *        Called from openpgp_state_init on first boot, AND from
 *        ACTIVATE FILE after TERMINATE DF.
 */
int openpgp_state_activate(void);

#endif /* NIXTROPIC_OPENPGP_STATE_H */
