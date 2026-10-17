/*
 * OpenPGP PINs PW1 / PW3 / RC on the M&D kernel v2 (Phase 9 M4,
 * docs/PHASE-9-M4-DESIGN.md §5).
 *
 * Each PIN is one kernel binding (tropic/pin_md_kernel.h), 3 rounds:
 *   PW1  O4 R-mem 50 / 53, M&D ranges 16..18 / 19..21
 *   PW3  O5 R-mem 51 / 54, M&D ranges 22..24 / 25..27
 *   RC   O6 R-mem 52 / 55, M&D range  28..30 (one range: set = clear, then setup)
 * The binding is the only PIN state: no software check, no retry mirror;
 * the PIN length lives in the binding (CHANGE splits its body with it).
 * PIN material = SHA-256(PIN).
 *
 * Guards (§2.5): PW1 / PW3 ABSENT while O3 is OPERATIONAL = ERROR; RC is
 * "not set" while O3 rc_set = 0 (whatever O6 holds), and ABSENT under
 * rc_set = 1 = ERROR.
 *
 * Session state ("PW1.81 verified" …) is not kept here: the applet owns it.
 */
#ifndef NIXTROPIC_OPENPGP_PGP_PIN_H
#define NIXTROPIC_OPENPGP_PGP_PIN_H

#include <stddef.h>
#include <stdint.h>

#define OPENPGP_PIN_PW1   0
#define OPENPGP_PIN_PW3   1
#define OPENPGP_PIN_RC    2

#define OPENPGP_PIN_ROUNDS    3u
#define OPENPGP_PW1_MIN_LEN   6u
#define OPENPGP_PW3_MIN_LEN   8u
#define OPENPGP_RC_MIN_LEN    8u
#define OPENPGP_PIN_MAX_LEN  64u

typedef enum {
    PGP_PIN_ACTIVE,
    PGP_PIN_BLOCKED,
    PGP_PIN_NOT_SET,     /* RC with rc_set 0; PW1/PW3 only while TERMINATED */
    PGP_PIN_ERROR,
} pgp_pin_state_t;

/* Return codes. */
#define PGP_PIN_OK        0
#define PGP_PIN_WRONG    (-1)   /* the attempt is spent */
#define PGP_PIN_BLK      (-2)   /* no attempts left */
#define PGP_PIN_UNSET    (-3)   /* RC not set */
#define PGP_PIN_BAD_LEN  (-4)   /* refused before any attempt */
#define PGP_PIN_ERR      (-5)   /* chip / record error; after a commit the
                                   NEW PIN may be live (kernel, Jan step 2) */

/* `attempts` / `pin_len` (nullable) are 0 unless ACTIVE or BLOCKED. */
pgp_pin_state_t pgp_pin_status(int which, uint8_t *attempts, uint8_t *pin_len);

/* `out_k` (nullable, 32 B): the binding's k = HMAC(s, 0x02) on PGP_PIN_OK, zero
 * otherwise — the M5 KEK source (pgp_dec.h). */
int pgp_pin_verify(int which, const uint8_t *pin, size_t len, uint8_t out_k[32]);

/* CHANGE REFERENCE DATA for PW1 / PW3: old PIN checked (attempt counted),
 * then the new one bound with the same s (k survives, D4). */
int pgp_pin_change(int which, const uint8_t *old_pin, size_t old_len,
                   const uint8_t *new_pin, size_t new_len);

/* New PW1 binding with a fresh s (RESET RETRY COUNTER; the caller has
 * checked RC or PW3). */
int pgp_pin_reset_pw1(const uint8_t *pin, size_t len);
/* The refusals of pgp_pin_reset_pw1 (length, lifecycle, PW1 in ERROR) without
 * binding anything: the M5 preflight before the DEC key is destroyed.  A
 * status read may settle or repair the binding (M4). */
int pgp_pin_reset_pw1_check(const uint8_t *pin, size_t len);

/* PUT DATA D3 (the caller has checked PW3): len 0 clears RC; otherwise RC
 * is cleared, then set: clear O6 → rc_set 0 → setup → rc_set 1. */
int pgp_pin_set_rc(const uint8_t *rc, size_t len);

/* Factory PW1 "123456" / PW3 "12345678", fresh s (bootstrap, ACTIVATE). */
int pgp_pin_bind_factory(void);

/* Retire every range and clear O4, O5, O6 (pgp_wipe).  Also the way out
 * of an uncertain binding. */
int pgp_pin_clear_all(void);

#ifdef NIXTROPIC_HOST_TEST
void pgp_pin_test_reboot(void);
#endif

#endif /* NIXTROPIC_OPENPGP_PGP_PIN_H */
