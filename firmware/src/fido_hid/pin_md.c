/*
 * Phase 5 M4 — MAC-and-Destroy PIN scheme, FIDO front-end.
 *
 * Phase 8 M4.A: the algorithm itself was extracted to
 * `firmware/src/tropic/pin_md_kernel.{c,h}` so the OpenPGP applet
 * (and any future caller) can reuse the same scheme with its own
 * slot range and R-mem layout.  This file is now a thin wrapper:
 * it just provides the FIDO-specific `pin_md_layout_t` (M&D slots
 * 0..7, state in R-mem slot 0 via `slots_global_md_*`) and forwards
 * each `pin_md_setup / verify / is_active / attempts_remaining`
 * to the generic kernel.
 *
 * Wire-compatibility:  byte-for-byte identical to the Phase 5 M4
 * implementation — same TROPIC01 M&D slot range, same R-mem
 * accessors, same crypto constants.  Existing PIN-set state on the
 * chip continues to verify after the refactor.
 */

#include "pin_md.h"
#include "slots.h"

#include "tropic/pin_md_kernel.h"

#include <stdint.h>
#include <stddef.h>

_Static_assert(PIN_MD_KERNEL_SLOT_SIZE == SLOTS_MD_SLOT_SIZE,
               "kernel slot size must match slots.h SLOTS_MD_SLOT_SIZE");
_Static_assert(PIN_MD_KERNEL_TAG_LEN == SLOTS_MD_TAG_LEN,
               "kernel tag len must match slots.h SLOTS_MD_TAG_LEN");

/* ----- Adapter callbacks ----- */

/* FIDO doesn't need a per-call context — the entire state is at a
 * single fixed R-mem slot, addressed by slots_global_md_*.  The ctx
 * parameter is here only for API symmetry with OpenPGP, which uses
 * it to carry the per-PIN R-mem slot index. */

static int adapt_state_get(void *ctx,
                           uint8_t *out_active,
                           uint8_t *out_next_slot,
                           uint8_t  out_tag[PIN_MD_KERNEL_TAG_LEN],
                           uint8_t *out_ci)
{
    (void) ctx;
    int active_int = 0;
    int rc = slots_global_md_get(out_active ? &active_int : NULL,
                                 out_next_slot,
                                 out_tag,
                                 out_ci);
    if (rc != 0) return rc;
    if (out_active) {
        *out_active = active_int ? 1u : 0u;
    }
    return 0;
}

static int adapt_state_set(void *ctx,
                           uint8_t active,
                           uint8_t next_slot,
                           const uint8_t tag[PIN_MD_KERNEL_TAG_LEN],
                           const uint8_t *ci)
{
    (void) ctx;
    return slots_global_md_set((int) active, next_slot, tag, ci);
}

static int adapt_state_advance(void *ctx, uint8_t *out_new)
{
    (void) ctx;
    return slots_global_md_advance(out_new);
}

/* ----- Layout ----- */

static const pin_md_layout_t FIDO_LAYOUT = {
    .md_slot_base    = 0u,
    .rounds          = SLOTS_MD_ROUNDS,
    .pin_material_len = PIN_MD_MATERIAL_LEN,
    .user_ctx        = NULL,
    .state_get       = adapt_state_get,
    .state_set       = adapt_state_set,
    .state_advance   = adapt_state_advance,
};

_Static_assert(SLOTS_MD_ROUNDS <= PIN_MD_KERNEL_ROUNDS_MAX,
               "FIDO ROUNDS exceeds kernel ROUNDS_MAX");

/* ----- Public API ----- */

int pin_md_is_active(void)
{
    return pin_md_kernel_is_active(&FIDO_LAYOUT);
}

int pin_md_attempts_remaining(void)
{
    return pin_md_kernel_attempts_remaining(&FIDO_LAYOUT);
}

int pin_md_setup(const uint8_t pin_material[PIN_MD_MATERIAL_LEN])
{
    return pin_md_kernel_setup(&FIDO_LAYOUT, pin_material);
}

int pin_md_verify(const uint8_t pin_material[PIN_MD_MATERIAL_LEN],
                  int *out_correct)
{
    return pin_md_kernel_verify(&FIDO_LAYOUT, pin_material, out_correct);
}
