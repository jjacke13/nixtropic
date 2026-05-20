/*
 * MAC-and-Destroy PIN kernel — parameterised algorithm.
 *
 * Extracted from `firmware/src/fido_hid/pin_md.c` (Phase 5 M4) at
 * Phase 8 M4.A so the OpenPGP applet can re-use the same scheme for
 * PW1 / PW3 / RC.  The crypto + chip calls are identical; what differs
 * per caller is:
 *
 *   - which TROPIC01 M&D slot range backs this PIN (slot_base..slot_base+rounds-1)
 *   - which R-mem area holds the {active, next_slot, tag, ci[]} state
 *   - how many wrong attempts before HW lockout (rounds)
 *   - PIN material length (FIDO: 16 B = SHA256(PIN)[:16]; OpenPGP: also 16 B for symmetry)
 *
 * Caller supplies a `pin_md_layout_t` with the slot range and R-mem
 * accessor callbacks, and an unchanging pin_material pointer to a
 * fixed-length hash output.  The kernel does the rest.
 *
 * Same security model as the original FIDO `pin_md.c`:
 *   - Each verify (right or wrong) consumes one M&D slot.
 *   - Correct PIN re-initialises every slot in the range.
 *   - Wrong PIN destroys the slot it just consumed; once
 *     `next_slot == rounds`, no more verifies possible until
 *     `state_set(active=1, next=0, ...)` is called from outside.
 *   - All intermediate keys / secrets memzero'd on every exit.
 *
 * See `docs/PHASE-5-M4-DESIGN.md` for the algorithm proof.
 */

#ifndef NIXTROPIC_TROPIC_PIN_MD_KERNEL_H
#define NIXTROPIC_TROPIC_PIN_MD_KERNEL_H

#include <stdint.h>
#include <stddef.h>

/* Fixed by TROPIC01 protocol (TR01_MAC_AND_DESTROY_DATA_SIZE = 32). */
#define PIN_MD_KERNEL_SLOT_SIZE      32u
/* HMAC-SHA-256 output. */
#define PIN_MD_KERNEL_TAG_LEN        32u
/* Internal master_secret length (also HMAC-SHA-256 output). */
#define PIN_MD_KERNEL_MASTER_LEN     32u
/* Maximum rounds across all callers — sized to FIDO's 8 with headroom. */
#define PIN_MD_KERNEL_ROUNDS_MAX     16u
/* Worst-case ci buffer = ROUNDS_MAX * SLOT_SIZE. */
#define PIN_MD_KERNEL_CI_LEN_MAX     (PIN_MD_KERNEL_ROUNDS_MAX * PIN_MD_KERNEL_SLOT_SIZE)
/* Maximum PIN material length the kernel will read.  Plenty for any
 * SHA-256-truncated hash; callers always pass a fixed length. */
#define PIN_MD_KERNEL_MATERIAL_MAX   32u

typedef struct pin_md_layout_t {
    /* First TROPIC01 M&D slot in the contiguous range we own. */
    uint8_t md_slot_base;
    /* Number of slots, also "wrong attempts before HW lockout". */
    uint8_t rounds;
    /* PIN material length (caller-supplied hash output length). */
    uint8_t pin_material_len;

    /* R-mem state accessors.
     *
     *   state_get   reads {active, next, tag, ci} into caller buffers.
     *               ci is rounds * SLOT_SIZE bytes.
     *               Returns 0 OK, non-zero on chip error.
     *   state_set   writes {active, next, tag, ci} to R-mem.
     *               Returns 0 OK, non-zero on chip error.
     *   state_advance  increments next_slot in R-mem.  Sets *out_new
     *                  to the post-increment value.  Returns 0 / non-zero.
     *
     * The kernel never re-orders these calls; persistence ordering is
     * power-loss-safe (advance committed BEFORE the destructive chip
     * op, so a mid-op crash counts the slot as consumed). */
    int (*state_get)(uint8_t *out_active,
                     uint8_t *out_next_slot,
                     uint8_t  out_tag[PIN_MD_KERNEL_TAG_LEN],
                     uint8_t *out_ci);
    int (*state_set)(uint8_t active,
                     uint8_t next_slot,
                     const uint8_t tag[PIN_MD_KERNEL_TAG_LEN],
                     const uint8_t *ci);
    int (*state_advance)(uint8_t *out_new);
} pin_md_layout_t;

/* Set up the M&D scheme for the configured layout.
 * Generates a fresh master_secret from TROPIC01 TRNG, derives per-slot
 * encryption keys via M&D probes (init / consume / re-init each), XORs
 * master_secret with each derived key into `ci[]`, stores the
 * verification tag.  All intermediates memzero'd before return.
 *
 * Returns 0 on success, -2 on chip / setup error. */
int pin_md_kernel_setup(const pin_md_layout_t *L,
                        const uint8_t *pin_material);

/* Verify candidate pin_material against the M&D state.
 * Advances next_slot BEFORE the destructive op (power-loss-safe).
 * On correct match, re-initialises every slot in the range and
 * resets next_slot=0.
 *
 * Returns 0 on success (out_correct populated; 1=PIN OK, 0=wrong);
 *        -1 on chip / state error;
 *        -2 if no attempts remain (HW lockout — next_slot == rounds). */
int pin_md_kernel_verify(const pin_md_layout_t *L,
                         const uint8_t *pin_material,
                         int *out_correct);

/* True iff state.active != 0 — i.e. setup has been completed at least
 * once.  Used by callers that want a "PIN currently configured?"
 * predicate before calling verify. */
int pin_md_kernel_is_active(const pin_md_layout_t *L);

/* Remaining wrong-PIN attempts before HW lockout = rounds - next_slot.
 * Returns rounds (full count) when state isn't active. */
int pin_md_kernel_attempts_remaining(const pin_md_layout_t *L);

#endif /* NIXTROPIC_TROPIC_PIN_MD_KERNEL_H */
