/*
 * OpenPGP MAC-and-Destroy PIN scheme — implementation.
 *
 * Glues `tropic/pin_md_kernel` to three OpenPGP-specific
 * `pin_md_layout_t` instances (one per PW1 / PW3 / RC) using R-mem
 * slots 50 / 51 / 52 and TROPIC01 M&D slots 8..10 / 11..13 / 14..16.
 *
 * The R-mem state layout for each PIN is identical (138 B used of
 * a 256 B slot):
 *
 *   0..3      magic   = "PMD0"
 *   4..5      schema  = 1
 *   6..7      reserved
 *   8         active   (1 once setup ran)
 *   9         next_slot
 *  10..41     tag      (32 B)
 *  42..137    ci[3]    (3 * 32 = 96 B)
 *
 * The shared callbacks (`oppgp_state_get / _set / _advance`) use
 * the PIN's R-mem slot index as their `user_ctx` so a single set of
 * function pointers serves all three PINs.
 */

#include "openpgp_pin_md.h"

#include "tropic/pin_md_kernel.h"
#include "tropic/tropic.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "memzero.h"

/* ---- R-mem slot allocation ---- */

#define OPENPGP_RMEM_SLOT_PW1_MD   50u
#define OPENPGP_RMEM_SLOT_PW3_MD   51u
#define OPENPGP_RMEM_SLOT_RC_MD    52u

/* ---- TROPIC01 M&D slot allocation ---- */

#define OPENPGP_MD_SLOT_BASE_PW1    8u
#define OPENPGP_MD_SLOT_BASE_PW3   11u
#define OPENPGP_MD_SLOT_BASE_RC    14u
#define OPENPGP_MD_TOTAL_SLOTS     (3u * OPENPGP_PIN_MD_ROUNDS) /* 9 slots */

/* ---- R-mem layout offsets (per PIN slot) ---- */

#define OFF_MAGIC     0u
#define MAGIC_LEN     4u
static const uint8_t MAGIC[MAGIC_LEN] = { 'P', 'M', 'D', '0' };
#define OFF_SCHEMA    4u
#define SCHEMA_VER    1u
#define OFF_ACTIVE    8u
#define OFF_NEXT      9u
#define OFF_TAG      10u
#define OFF_CI       42u
#define USED_LEN     (OFF_CI + OPENPGP_PIN_MD_CI_LEN)   /* 138 */

#define RMEM_PRIMARY_SIZE  256u

_Static_assert(OPENPGP_PIN_MD_TAG_LEN == PIN_MD_KERNEL_TAG_LEN,
               "OpenPGP M&D tag length must match kernel");
_Static_assert(OPENPGP_PIN_MD_ROUNDS <= PIN_MD_KERNEL_ROUNDS_MAX,
               "OpenPGP M&D rounds exceeds kernel maximum");

/* ---- Shared R-mem state callbacks (ctx = R-mem slot index) ---- */

static uint16_t ctx_to_slot(void *ctx)
{
    /* Cast through uintptr_t so the cast is portable and well-defined
     * for the small integer values we use (50/51/52). */
    return (uint16_t)(uintptr_t) ctx;
}

static int read_payload(uint16_t rmem_slot, uint8_t buf[RMEM_PRIMARY_SIZE])
{
    size_t got = 0;
    int rc = tropic_rmem_read(rmem_slot, buf, RMEM_PRIMARY_SIZE, &got);
    if (rc != 0) return -1;
    if (got < USED_LEN) return -1;
    /* Magic check.  Uninitialised slot returns all-zero / random data
     * → caller's first call will get active=0 and proceed to setup. */
    if (memcmp(&buf[OFF_MAGIC], MAGIC, MAGIC_LEN) != 0) return 1; /* not-init */
    if (buf[OFF_SCHEMA] != 0u || buf[OFF_SCHEMA + 1u] != SCHEMA_VER) {
        return 1; /* unknown schema → treat as not-init */
    }
    return 0;
}

static int oppgp_state_get(void *ctx,
                           uint8_t *out_active,
                           uint8_t *out_next_slot,
                           uint8_t  out_tag[PIN_MD_KERNEL_TAG_LEN],
                           uint8_t *out_ci)
{
    uint16_t slot = ctx_to_slot(ctx);
    uint8_t buf[RMEM_PRIMARY_SIZE];

    int rc = read_payload(slot, buf);
    if (rc < 0) {
        memzero(buf, sizeof buf);
        return -1;
    }

    if (rc == 1) {
        /* Magic mismatch → no state yet.  Fresh defaults. */
        if (out_active)    *out_active = 0u;
        if (out_next_slot) *out_next_slot = 0u;
        if (out_tag)       memset(out_tag, 0, PIN_MD_KERNEL_TAG_LEN);
        if (out_ci)        memset(out_ci,  0, OPENPGP_PIN_MD_CI_LEN);
        memzero(buf, sizeof buf);
        return 0;
    }

    if (out_active)    *out_active    = buf[OFF_ACTIVE];
    if (out_next_slot) *out_next_slot = buf[OFF_NEXT];
    if (out_tag)       memcpy(out_tag, &buf[OFF_TAG], PIN_MD_KERNEL_TAG_LEN);
    if (out_ci)        memcpy(out_ci,  &buf[OFF_CI],  OPENPGP_PIN_MD_CI_LEN);

    memzero(buf, sizeof buf);
    return 0;
}

static int oppgp_state_set(void *ctx,
                           uint8_t active,
                           uint8_t next_slot,
                           const uint8_t tag[PIN_MD_KERNEL_TAG_LEN],
                           const uint8_t *ci)
{
    uint16_t slot = ctx_to_slot(ctx);
    uint8_t buf[RMEM_PRIMARY_SIZE];
    memset(buf, 0, sizeof buf);

    memcpy(&buf[OFF_MAGIC], MAGIC, MAGIC_LEN);
    buf[OFF_SCHEMA]      = 0u;
    buf[OFF_SCHEMA + 1u] = SCHEMA_VER;
    buf[OFF_ACTIVE]      = active;
    buf[OFF_NEXT]        = next_slot;
    if (tag) memcpy(&buf[OFF_TAG], tag, PIN_MD_KERNEL_TAG_LEN);
    if (ci)  memcpy(&buf[OFF_CI],  ci,  OPENPGP_PIN_MD_CI_LEN);

    (void) tropic_rmem_erase(slot);
    int rc = tropic_rmem_write(slot, buf, RMEM_PRIMARY_SIZE);
    memzero(buf, sizeof buf);
    return (rc == 0) ? 0 : -1;
}

static int oppgp_state_advance(void *ctx, uint8_t *out_new)
{
    uint8_t active = 0;
    uint8_t next   = 0;
    uint8_t tag[PIN_MD_KERNEL_TAG_LEN];
    uint8_t ci[OPENPGP_PIN_MD_CI_LEN];

    if (oppgp_state_get(ctx, &active, &next, tag, ci) != 0) {
        memzero(tag, sizeof tag);
        memzero(ci,  sizeof ci);
        return -1;
    }

    uint8_t new_next = (uint8_t)(next + 1u);
    if (out_new) *out_new = new_next;

    int rc = oppgp_state_set(ctx, active, new_next, tag, ci);
    memzero(tag, sizeof tag);
    memzero(ci,  sizeof ci);
    return rc;
}

/* ---- Per-PIN layouts ---- */

static const pin_md_layout_t LAYOUTS[OPENPGP_PIN_MD_COUNT] = {
    [OPENPGP_PIN_MD_PW1] = {
        .md_slot_base     = OPENPGP_MD_SLOT_BASE_PW1,
        .rounds           = OPENPGP_PIN_MD_ROUNDS,
        .pin_material_len = OPENPGP_PIN_MD_MATERIAL_LEN,
        .user_ctx         = (void *)(uintptr_t) OPENPGP_RMEM_SLOT_PW1_MD,
        .state_get        = oppgp_state_get,
        .state_set        = oppgp_state_set,
        .state_advance    = oppgp_state_advance,
    },
    [OPENPGP_PIN_MD_PW3] = {
        .md_slot_base     = OPENPGP_MD_SLOT_BASE_PW3,
        .rounds           = OPENPGP_PIN_MD_ROUNDS,
        .pin_material_len = OPENPGP_PIN_MD_MATERIAL_LEN,
        .user_ctx         = (void *)(uintptr_t) OPENPGP_RMEM_SLOT_PW3_MD,
        .state_get        = oppgp_state_get,
        .state_set        = oppgp_state_set,
        .state_advance    = oppgp_state_advance,
    },
    [OPENPGP_PIN_MD_RC] = {
        .md_slot_base     = OPENPGP_MD_SLOT_BASE_RC,
        .rounds           = OPENPGP_PIN_MD_ROUNDS,
        .pin_material_len = OPENPGP_PIN_MD_MATERIAL_LEN,
        .user_ctx         = (void *)(uintptr_t) OPENPGP_RMEM_SLOT_RC_MD,
        .state_get        = oppgp_state_get,
        .state_set        = oppgp_state_set,
        .state_advance    = oppgp_state_advance,
    },
};

static const pin_md_layout_t *layout_for(enum openpgp_pin_md_which which)
{
    if ((unsigned) which >= (unsigned) OPENPGP_PIN_MD_COUNT) return NULL;
    return &LAYOUTS[which];
}

/* ---- Public API ---- */

int openpgp_pin_md_setup(enum openpgp_pin_md_which which,
                         const uint8_t pin_material[OPENPGP_PIN_MD_MATERIAL_LEN])
{
    const pin_md_layout_t *L = layout_for(which);
    if (!L) return -1;
    return pin_md_kernel_setup(L, pin_material);
}

int openpgp_pin_md_verify(enum openpgp_pin_md_which which,
                          const uint8_t pin_material[OPENPGP_PIN_MD_MATERIAL_LEN],
                          int *out_correct)
{
    const pin_md_layout_t *L = layout_for(which);
    if (!L) return -1;
    return pin_md_kernel_verify(L, pin_material, out_correct);
}

int openpgp_pin_md_is_active(enum openpgp_pin_md_which which)
{
    const pin_md_layout_t *L = layout_for(which);
    if (!L) return 0;
    return pin_md_kernel_is_active(L);
}

int openpgp_pin_md_attempts_remaining(enum openpgp_pin_md_which which)
{
    const pin_md_layout_t *L = layout_for(which);
    if (!L) return 0;
    return pin_md_kernel_attempts_remaining(L);
}

int openpgp_pin_md_factory_reset_all(void)
{
    /* Erase each PIN's R-mem state slot.  Subsequent state_get on
     * any of them will see magic-mismatch and return active=0; next
     * verify call will refuse with -1 (not-active) until setup runs.
     *
     * The TROPIC01 M&D chip slots themselves do NOT get scrubbed
     * here — they are consumed-and-reinitialised lazily by the next
     * setup call.  This matches how FIDO's authenticatorReset works
     * (slots remain in their last state until a fresh setup
     * re-initialises them). */
    int worst_rc = 0;
    if (tropic_rmem_erase(OPENPGP_RMEM_SLOT_PW1_MD) != 0) worst_rc = -1;
    if (tropic_rmem_erase(OPENPGP_RMEM_SLOT_PW3_MD) != 0) worst_rc = -1;
    if (tropic_rmem_erase(OPENPGP_RMEM_SLOT_RC_MD)  != 0) worst_rc = -1;
    return worst_rc;
}
