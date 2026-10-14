/*
 * random32() for trezor-crypto from the STM32 TRNG (Phase 9 M2).  See
 * trezor_rng.h.
 *
 * random32() cannot report an error, and the P-256 code it serves is in the
 * middle of secret arithmetic when it asks.  On a TRNG failure we therefore
 * stop the device right there (rng_fail_stop: system reset) instead of
 * returning a substitute value: no further multiplication runs without real
 * blinding.  After the reset the boot-time TRNG self-test halts the dongle
 * (2-blink code) if the TRNG is broken outright; an intermittent fault can
 * pass that test and reset the dongle again later.  The interrupted request
 * gets no answer (the host must not replay it blindly).  The private scalars
 * themselves come from TROPIC01 (tropic_random), not from here.
 */
#include "platform/trezor_rng.h"

uint32_t random32(void)
{
    uint32_t word = 0;
    if (rng_read((uint8_t *) &word, sizeof word) != 0) {
        rng_fail_stop();
    }
    return word;
}
