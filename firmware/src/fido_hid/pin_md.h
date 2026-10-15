/*
 * FIDO PIN state on the M&D kernel v2 (Phase 9 M4, docs/PHASE-9-M4-DESIGN.md
 * §4).  The PIN is object O2: a kernel binding (8 rounds, M&D ranges A 0..7
 * and B 8..15) whose record lives in R-mem 41 / 42.  The binding IS the PIN
 * state: no stored hash, no software counter (D5, D6).  O1's `pin_bound`
 * guard (slots.h) says whether a binding was committed, so an O2 that reads
 * absent while the guard is set is an ERROR, never "no PIN" (§2.5).
 *
 * PIN material = LEFT(SHA-256(PIN), 16): what the platform sends encrypted
 * as pinHashEnc.
 */
#ifndef NIXTROPIC_FIDO_HID_PIN_MD_H
#define NIXTROPIC_FIDO_HID_PIN_MD_H

#include <stdint.h>

#define PIN_MD_MATERIAL_LEN  16u
#define FIDO_PIN_ROUNDS       8u   /* = maxRetries reported by getRetries */

typedef enum {
    FPIN_NOT_SET,   /* no binding, guard 0 */
    FPIN_SET,       /* binding with attempts left */
    FPIN_BLOCKED,   /* binding, no attempts left: authenticatorReset only */
    FPIN_ERROR,     /* unreadable / damaged / guard contradicts: refuse */
} fido_pin_state_t;

/* Current state; *attempts (nullable) = attempts left (0 unless SET). */
fido_pin_state_t fido_pin_state(uint8_t *attempts);

/* First PIN (only from NOT_SET): kernel setup, then one O1 write that sets
 * the guard and auto-enables Force-UV (Phase 6).  A failure after the
 * kernel commit leaves the PIN set with the guard 0; boot repairs that.
 * Returns 0, or -1 (not NOT_SET, or a chip error). */
int fido_pin_set(const uint8_t mat[PIN_MD_MATERIAL_LEN], uint8_t pin_len);

/* Kernel verify.  0 with *correct 1/0; -2 blocked; -1 any error. */
int fido_pin_verify(const uint8_t mat[PIN_MD_MATERIAL_LEN], int *correct);

/* Kernel change (s kept).  0 with *correct 1 (changed) / 0 (wrong old PIN);
 * -2 blocked; -1 any error — which after the commit can mean the NEW PIN is
 * live (pin_md_kernel.h). */
int fido_pin_change(const uint8_t old_mat[PIN_MD_MATERIAL_LEN],
                    const uint8_t new_mat[PIN_MD_MATERIAL_LEN], uint8_t new_pin_len,
                    int *correct);

/* 0 after a PIN-binding write whose outcome is unknown (the pair is
 * uncertain until reboot or reset): the FIDO state is then not ready. */
int fido_pin_usable(void);

/* Reset path: retire both ranges and clear O2 (no readable record needed).
 * The guard is cleared by the fresh O1 written afterwards (fido_state.c). */
int fido_pin_clear(void);

/* Boot: a committed binding whose guard is 0 (cut between setPin's commit
 * and its O1 write) gets the guard and Force-UV, as setPin would have
 * done.  0, or -1 on error. */
int fido_pin_boot(void);

#ifdef NIXTROPIC_HOST_TEST
void fido_pin_test_reboot(void);   /* host tests only: as a reboot does */
#endif

#endif /* NIXTROPIC_FIDO_HID_PIN_MD_H */
