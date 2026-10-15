/*
 * FIDO PIN state on the M&D kernel v2.  See pin_md.h.
 */
#include "pin_md.h"
#include "slots.h"

#include <stddef.h>

#include "tropic/pin_md_kernel.h"
#include "tropic/rec_pair.h"

static rec_pair_t s_o2 = REC_PAIR(41, 42, 2, 1);

static const pin_md_layout_t FIDO_LAYOUT = {
    .rec = &s_o2, .base = { 0, 8 }, .ranges = 2,
    .rounds = FIDO_PIN_ROUNDS, .mat_len = PIN_MD_MATERIAL_LEN,
};

_Static_assert(FIDO_PIN_ROUNDS <= PIN_MD_KERNEL_ROUNDS_MAX, "FIDO rounds");

fido_pin_state_t fido_pin_state(uint8_t *attempts)
{
    uint8_t att = 0;
    if (attempts != NULL) *attempts = 0;
    int bound = slots_pin_bound();
    if (bound < 0) return FPIN_ERROR;
    switch (pin_md_kernel_status(&FIDO_LAYOUT, &att, NULL)) {
    case PMD_ABSENT:
        return bound ? FPIN_ERROR : FPIN_NOT_SET;
    case PMD_ACTIVE:
        if (attempts != NULL) *attempts = att;
        return FPIN_SET;
    case PMD_BLOCKED:
        return FPIN_BLOCKED;
    default:
        return FPIN_ERROR;
    }
}

int fido_pin_set(const uint8_t mat[PIN_MD_MATERIAL_LEN], uint8_t pin_len)
{
    if (fido_pin_state(NULL) != FPIN_NOT_SET) return -1;
    if (pin_md_kernel_setup(&FIDO_LAYOUT, mat, pin_len, NULL) != PMD_OK) return -1;
    return slots_set_pin_bound(1, 1);
}

static int map_rc(int rc)
{
    if (rc == PMD_OK) return 0;
    return rc == PMD_ERR_BLOCKED ? -2 : -1;
}

int fido_pin_verify(const uint8_t mat[PIN_MD_MATERIAL_LEN], int *correct)
{
    return map_rc(pin_md_kernel_verify(&FIDO_LAYOUT, mat, correct, NULL));
}

int fido_pin_change(const uint8_t old_mat[PIN_MD_MATERIAL_LEN],
                    const uint8_t new_mat[PIN_MD_MATERIAL_LEN], uint8_t new_pin_len,
                    int *correct)
{
    return map_rc(pin_md_kernel_change(&FIDO_LAYOUT, old_mat, new_mat, new_pin_len,
                                       correct, NULL));
}

int fido_pin_usable(void)
{
    return !s_o2.uncertain;
}

int fido_pin_clear(void)
{
    /* Reset is the way out of an uncertain pair (design §6): the clear is a
     * checked retire + erase that needs no record, so it may run now. */
    s_o2.uncertain = false;
    return pin_md_kernel_clear(&FIDO_LAYOUT) == PMD_OK ? 0 : -1;
}

int fido_pin_boot(void)
{
    int bound = slots_pin_bound();
    if (bound < 0) return -1;
    pmd_state_t st = pin_md_kernel_status(&FIDO_LAYOUT, NULL, NULL);
    if (st == PMD_ERROR) return -1;
    if (st == PMD_ABSENT) return bound ? -1 : 0;     /* guard set, binding gone */
    /* Committed, guard missing: only an interrupted first setPin does that;
     * finish it as setPin would (guard + the first-PIN Force-UV). */
    return bound ? 0 : slots_set_pin_bound(1, 1);
}

#ifdef NIXTROPIC_HOST_TEST
void fido_pin_test_reboot(void)
{
    s_o2.uncertain = false;
}
#endif
