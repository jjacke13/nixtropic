/*
 * FIDO persistent state at boot and reset.  See fido_state.h.
 */
#include "fido_state.h"
#include "pin_md.h"
#include "slots.h"

#include <stdint.h>

#include "tropic/tropic.h"

int fido_state_wipe(void)
{
    for (uint8_t i = 0; i < FIDO_SLOTS_MAX; ++i) {
        if (tropic_ecc_erase(i) != 0) return -1;      /* keys first, all of them */
    }
    if (slots_wipe_meta() != 0) return -2;
    if (fido_pin_clear() != 0) return -3;
    if (slots_init_fresh() != 0) return -4;
    /* A post-reset credential starts at signCount 0 (cpp-reviewer 2026-05-11
     * M2); authorised only by the completed wipe above (design §4). */
    if (tropic_mcounter_init(FIDO_SIGNCOUNT_MCOUNTER, FIDO_MCOUNTER_MAX) != 0) return -5;
    return 0;
}

int fido_state_boot(void)
{
    int rc = slots_init();
    if (rc == SLOTS_INIT_ABSENT) return fido_state_wipe();
    if (rc != SLOTS_INIT_OK) return -10;
    if (fido_pin_boot() != 0) return -11;
    /* The counter is never initialised because a read failed (Phase 9 M3):
     * COUNTER_INVALID also means corrupt or disabled. */
    uint32_t v = 0;
    if (tropic_mcounter_get(FIDO_SIGNCOUNT_MCOUNTER, &v) != 0 || v > FIDO_MCOUNTER_MAX) {
        return -12;
    }
    return 0;
}
