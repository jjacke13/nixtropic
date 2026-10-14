/*
 * trezor-crypto randomness hook (Phase 9 M2).
 *
 * trezor-crypto's ecdsa.c calls random32() to randomise the projective Z
 * coordinate of every P-256 point multiplication (side-channel blinding in
 * ClientPIN keyAgreement).  rand.c is built without USE_INSECURE_PRNG, so
 * trezor_rng.c is the only random32().  Kept apart from rng.c so the host
 * tests can link it without the STM32 HAL.
 */
#ifndef NIXTROPIC_TREZOR_RNG_H
#define NIXTROPIC_TREZOR_RNG_H

#include <stddef.h>
#include <stdint.h>

/* platform/rng.c: n bytes from the STM32 TRNG, 0 on success. */
int rng_read(uint8_t *buf, size_t n);

/* platform/rng.c: stop the device (system reset).  Never returns. */
_Noreturn void rng_fail_stop(void);

/* The trezor-crypto rand.h contract. */
uint32_t random32(void);

#endif /* NIXTROPIC_TREZOR_RNG_H */
