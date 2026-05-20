/*
 * OpenPGP — MAC-and-Destroy-backed retry counter for PW1 / PW3 / RC.
 *
 * Phase 8 M4.B: provides three independent M&D PIN schemes (one per
 * OpenPGP PIN), each backed by 3 dedicated TROPIC01 M&D slots and its
 * own R-mem state slot.  Replaces the software-only PIN retry logic
 * in `pgp_pin.c` (deferred to M4.C/D wiring) for the post-reflash
 * threat model: an attacker who reflashes the STM32 with malicious
 * firmware still cannot bypass the chip-side slot exhaustion.
 *
 * Slot allocation (verified clear of FIDO's range 0..7 + future
 * room for PIV in §M8):
 *
 *   TROPIC01 M&D slots
 *     0..7     FIDO PIN
 *     8..10    OpenPGP PW1   (3 slots × 3 rounds)
 *     11..13   OpenPGP PW3
 *     14..16   OpenPGP RC
 *
 *   TROPIC01 R-mem slots
 *     0        FIDO global state
 *     1        OpenPGP primary state (collision with FIDO per-cred at
 *              slot 1; pre-existing — see backlog)
 *     1..29    FIDO per-credential metadata
 *     50       OpenPGP PW1 M&D state  (this commit)
 *     51       OpenPGP PW3 M&D state
 *     52       OpenPGP RC  M&D state
 *
 * Each PIN's M&D state slot carries 138 B of useful data in a 256 B
 * R-mem slot:
 *
 *   offset  size   field
 *      0     4     magic "PMD0"
 *      4     2     schema_version = 1
 *      6     2     reserved
 *      8     1     active (1 once setup ran)
 *      9     1     next_slot (0..rounds; rounds = HW lockout)
 *     10    32     verification tag (HMAC-SHA-256)
 *     42    96     ci[3] (master_secret ⊕ k_i for each of 3 slots)
 *    138..255      reserved
 *
 * PIN material length is 16 B (= SHA-256(raw_PIN)[:16], same scheme
 * as FIDO's pin_md so the algorithm is byte-compatible).
 *
 * This module only owns the M&D state.  The OpenPGP "is this PIN
 * verified in the current session" flag lives separately in
 * `pgp_pin.c::s_verified[]` (RAM, cleared on STM32 power-cycle = each
 * fresh USB plug-in).  The M&D verify is invoked from
 * `pgp_pin_verify` for the actual authoritative check; the software
 * counter cache stays for display.
 */

#ifndef NIXTROPIC_OPENPGP_PIN_MD_H
#define NIXTROPIC_OPENPGP_PIN_MD_H

#include <stdint.h>
#include <stddef.h>

#define OPENPGP_PIN_MD_ROUNDS         3u
#define OPENPGP_PIN_MD_MATERIAL_LEN  16u   /* matches FIDO PIN_MD_MATERIAL_LEN */
#define OPENPGP_PIN_MD_TAG_LEN       32u
#define OPENPGP_PIN_MD_CI_LEN        (OPENPGP_PIN_MD_ROUNDS * 32u)

enum openpgp_pin_md_which {
    OPENPGP_PIN_MD_PW1 = 0,
    OPENPGP_PIN_MD_PW3 = 1,
    OPENPGP_PIN_MD_RC  = 2,
    OPENPGP_PIN_MD_COUNT
};

/* Initialise (or re-initialise) the M&D scheme for `which`.  Wipes
 * any prior state for that PIN.  Returns 0 on success, negative on
 * chip / setup error. */
int openpgp_pin_md_setup(enum openpgp_pin_md_which which,
                         const uint8_t pin_material[OPENPGP_PIN_MD_MATERIAL_LEN]);

/* Verify candidate `pin_material` against the M&D state for `which`.
 * On success, sets *out_correct to 1 if PIN was right, 0 if wrong;
 * always advances one slot regardless of correctness (chip-enforced).
 * Returns 0 on success, -1 on chip / state error, -2 if no attempts
 * remain (HW lockout — only TERMINATE+ACTIVATE recovers). */
int openpgp_pin_md_verify(enum openpgp_pin_md_which which,
                          const uint8_t pin_material[OPENPGP_PIN_MD_MATERIAL_LEN],
                          int *out_correct);

/* True iff setup has been run for `which`. */
int openpgp_pin_md_is_active(enum openpgp_pin_md_which which);

/* Remaining wrong-PIN attempts before HW lockout = ROUNDS - next_slot.
 * Returns ROUNDS when state isn't active. */
int openpgp_pin_md_attempts_remaining(enum openpgp_pin_md_which which);

/* Wipe M&D state for every OpenPGP PIN.  Erases the three R-mem
 * slots and re-initialises every M&D chip slot in the 8..16 range
 * with fresh random secrets.  Called by TERMINATE+ACTIVATE.
 * Returns 0 on success, negative on chip error. */
int openpgp_pin_md_factory_reset_all(void);

#endif /* NIXTROPIC_OPENPGP_PIN_MD_H */
