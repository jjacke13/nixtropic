/*
 * Phase 7 M2 — OpenPGP applet state on TROPIC01 R-mem slot 1.
 *
 * Slot 1 (PGP primary state) layout — schema v4, per
 * docs/PHASE-7-PLAN.md §4.7:
 *
 *   offset  size   field
 *   ------  ----   -----
 *      0      4    magic "PG7K" (0x50,0x47,0x37,0x4B)
 *      4      2    schema_version = 1 (PGP state v1)
 *      6      1    pgp_state_present (1 once initialised by ACTIVATE FILE)
 *      7      1    PW1 retry counter cache (0..3)
 *      8      1    PW3 retry counter cache (0..3)
 *      9      1    RC retry counter cache (0xFF if unset, else 0..3)
 *     10      1    force_verify (DO C4 bit 0; default 1)
 *     11      1    touch_required (alias for D6/D7/D8; default 1)
 *     12      2    reserved (was per-slot UIF — single global flag now)
 *     14     40    cardholder name (1 B len + 39 B data) — DO 5B
 *     54      2    language (ISO 639) — DO 5F2D
 *     56      1    sex (ISO 5218) — DO 5F35
 *     57     20    fingerprint sig — DO C7
 *     77     20    fingerprint dec — DO C8
 *     97     20    fingerprint aut — DO C9
 *    117      4    generation time sig (BE u32) — DO CE
 *    121      4    generation time dec — DO CF
 *    125      4    generation time aut — DO D0
 *    129      3    signature counter (BCD) — DO 93
 *    132    343    reserved
 *                                                              ----
 *   total = 475 B  (matches R-mem slot size on TROPIC01 FW ≥2.0.0)
 *
 * For M2 the only fields read by GET DATA are PW status (force_verify
 * + retry counters) + DO C7/C8/C9 fingerprints (all zero until keys
 * generated in M4) + cardholder fields (all empty/zero by default).
 *
 * Free-form fields (login DO 5E, URL DO 5F50) live in R-mem slot 2 —
 * not in M2 scope; deferred to M3 with PUT DATA.
 */

#ifndef NIXTROPIC_OPENPGP_STATE_H
#define NIXTROPIC_OPENPGP_STATE_H

#include <stdint.h>
#include <stddef.h>

#define OPENPGP_RMEM_PRIMARY_SLOT    1u
#define OPENPGP_RMEM_PRIMARY_SIZE    475u

/* PIN retry-counter defaults — match OpenPGP card spec.  Stored in the
 * cache bytes of slot 1; the actual M&D enforcement lives in chip M&D
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

/**
 * @brief First-call init: ensure R-mem slot 1 has the PGP state magic.
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

#endif /* NIXTROPIC_OPENPGP_STATE_H */
