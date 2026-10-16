/*
 * OpenPGP lifecycle.  See pgp_lifecycle.h.
 */
#include "pgp_lifecycle.h"
#include "openpgp_state.h"
#include "pgp_keys.h"
#include "pgp_pin.h"

#include <stdint.h>

#include "tropic/tropic.h"

int pgp_lifecycle_wipe(void)
{
    static const uint8_t keys[] = { PGP_KEYS_SIG_SLOT, PGP_KEYS_DEC_SLOT, PGP_KEYS_AUT_SLOT };
    for (unsigned i = 0; i < sizeof keys; ++i) {
        if (tropic_ecc_erase(keys[i]) != 0) return -1;     /* an empty slot answers OK */
    }
    if (openpgp_state_clear() != 0) return -2;             /* DEC key, both copies */
    if (pgp_pin_clear_all() != PGP_PIN_OK) return -3;
    return 0;
}

int pgp_lifecycle_boot(void)
{
    if (tropic_l3_session_ensure() != 0) return -1;
    int st = openpgp_state_load();
    if (st == 0) return 0;
    if (st < 0) return -2;                                 /* damaged / unreadable */
    /* ABSENT: first boot, an interrupted wipe, or both copies damaged.
     * Destroy everything OpenPGP owns before any factory PIN (D8). */
    if (pgp_lifecycle_wipe() != 0) return -3;
    if (pgp_pin_bind_factory() != PGP_PIN_OK) return -4;
    return openpgp_state_init(PGP_LC_OPERATIONAL) == 0 ? 0 : -5;
}

int pgp_lifecycle_terminate(void)
{
    if (pgp_lifecycle_wipe() != 0) return -1;
    return openpgp_state_init(PGP_LC_TERMINATED) == 0 ? 0 : -2;
}

int pgp_lifecycle_activate(void)
{
    /* The wipe happened in the TERMINATE that wrote this clean record. */
    if (openpgp_state_lifecycle() != PGP_LC_TERMINATED) return -1;
    if (pgp_pin_bind_factory() != PGP_PIN_OK) return -2;
    return openpgp_state_activate() == 0 ? 0 : -2;
}
