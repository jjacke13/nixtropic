/*
 * Phase 7 M3 — OpenPGP PIN handling (PW1 / PW3 / RC).
 *
 * VERIFY / CHANGE REFERENCE DATA / RESET RETRY COUNTER over an R-mem
 * persisted PIN hash + retry counter.  Session state ("PW3 has been
 * verified this session") lives in RAM and is cleared on TERMINATE DF
 * or USB reset.
 *
 * SECURITY NOTE — M3 SHIPS WITH SOFTWARE-ONLY RETRY COUNTERS.  The
 * retry counter lives in R-mem on the TROPIC01 chip but is NOT
 * hardware-enforced via MAC-and-Destroy as Phase 5 FIDO PIN is.  An
 * attacker who can reflash the STM32 firmware can bypass the counter.
 *
 * This is a DELIBERATE M3-only compromise.  Phase 7 plan §3 H6 calls
 * for M&D backing of all three PINs (chip slots 8..16).  Wiring M&D
 * into pin_md.c-style cross-PIN logic is substantial code that we're
 * deferring to M6 (audit + close) — M3's value is unblocking the
 * remaining APDU surface (PUT DATA, TERMINATE/ACTIVATE, then M4
 * GENERATE) so we can iterate on real `gpg --card-edit` flows.
 *
 * Until M6, the threat model on a Phase 7-flashed dongle is:
 *   - Wire-level attacker (no STM32 reflash): can't bypass; gets 3
 *     wrong-PIN attempts then 0x6983 forever (until ACTIVATE FILE).
 *   - STM32-reflash attacker: can wipe retry counter, brute-force PIN
 *     hash offline (16-byte hash; tractable for weak PINs but
 *     unreachable for 8-char random PINs).
 *
 * H6 follow-up: M6 will swap the software counter for M&D-backed
 * retries via either (a) refactor pin_md.c to be slot-base-parameter-
 * ised or (b) inline M&D scheme in pgp_pin.c using TROPIC01 chip
 * slots 8..16 directly.  See PHASE-7-PLAN.md §3 row H6.
 */

#ifndef NIXTROPIC_OPENPGP_PGP_PIN_H
#define NIXTROPIC_OPENPGP_PGP_PIN_H

#include <stdint.h>
#include <stddef.h>

#include "openpgp_state.h"   /* OPENPGP_PIN_PW1 / PW3 / RC etc. */

/* Return codes shared with applet so caller can map to SW. */
#define PGP_PIN_OK                       0
#define PGP_PIN_BAD                      -1   /* wrong PIN, counter decremented */
#define PGP_PIN_BLOCKED                  -2   /* counter at 0 — needs reset */
#define PGP_PIN_NOT_SET                  -3   /* RC only — not configured */
#define PGP_PIN_BAD_LEN                  -4
#define PGP_PIN_CHIP_ERR                 -5   /* generic */
/* DEBUG sub-codes — pinpoint which R-mem op failed.  Mapped to
 * distinct SW values by pgp_pin_rc_to_sw so we can diagnose without
 * UART/CDC logging. */
#define PGP_PIN_CHIP_ERR_HASH_GET        -6
#define PGP_PIN_CHIP_ERR_RETRIES_MATCH   -7
#define PGP_PIN_CHIP_ERR_RETRIES_BAD     -8
#define PGP_PIN_CHIP_ERR_HASH_SET        -9

/**
 * @brief Verify a PIN against its stored hash.  Decrements retry on
 *        mismatch, resets to OPENPGP_PW1_RETRIES_INITIAL etc. on match.
 *        Successful VERIFY also flags the PIN as "verified this session".
 *
 * @param which  OPENPGP_PIN_PW1 / PW3 / RC.
 * @param pin    Raw PIN bytes.
 * @param len    Length in bytes (must satisfy min/max for `which`).
 */
int pgp_pin_verify(int which, const uint8_t *pin, size_t len);

/**
 * @brief CHANGE REFERENCE DATA — verify old PIN, set new PIN.  Old PIN
 *        counter decrements on wrong old.  On success the new PIN's
 *        counter is reset to initial.
 */
int pgp_pin_change(int which,
                   const uint8_t *old_pin, size_t old_len,
                   const uint8_t *new_pin, size_t new_len);

/**
 * @brief RESET RETRY COUNTER via Reset Code (RC).  RC must verify
 *        successfully (consumes RC counter on failure); on success
 *        sets the new PW1 + resets PW1 counter.
 */
int pgp_pin_reset_pw1_via_rc(const uint8_t *rc, size_t rc_len,
                             const uint8_t *new_pw1, size_t new_pw1_len);

/**
 * @brief RESET RETRY COUNTER via PW3.  PW3 must already be verified
 *        this session.  Sets new PW1 + resets PW1 counter.
 */
int pgp_pin_reset_pw1_via_pw3(const uint8_t *new_pw1, size_t new_pw1_len);

/**
 * @brief Set Reset Code (RC).  PW3 must be verified this session.
 *        Setting RC of zero-length clears RC (PUT DATA D3 with empty
 *        body is the spec-defined "clear RC" form).
 */
int pgp_pin_set_rc(const uint8_t *rc, size_t rc_len);

/**
 * @brief Check whether the given PIN was verified in this session.
 *        Session is cleared by `pgp_pin_clear_session()` (called on
 *        TERMINATE DF, USB reset, etc).
 */
int pgp_pin_is_verified(int which);

/**
 * @brief Forget all session-verified PINs.  Doesn't affect R-mem state.
 */
void pgp_pin_clear_session(void);

/**
 * @brief Compute SHA-256(pin)[:16] into the caller's buffer.  Exposed
 *        because some applet paths (e.g. CHANGE) need to compare/hash
 *        before persisting.
 */
void pgp_pin_hash(const uint8_t *pin, size_t len,
                  uint8_t out[OPENPGP_PIN_HASH_LEN]);

#endif /* NIXTROPIC_OPENPGP_PGP_PIN_H */
