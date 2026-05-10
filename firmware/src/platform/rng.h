/*
 * STM32 onboard HAL_RNG init (decision P1.22 + B3).
 *
 * Two callers:
 *   - libtropic's `lt_port_random_bytes` via `device->rng_handle`
 *     (Group D, when we wire up libtropic)
 *   - The P1.22 32-byte HAL_RNG dump over USB CDC (proves host-MCU RNG
 *     is alive on every cold-boot)
 *
 * We expose the singleton handle via `rng_handle()` so multiple consumers
 * use the same one.
 */

#ifndef NIXTROPIC_RNG_H
#define NIXTROPIC_RNG_H

#include <stdint.h>
#include <stddef.h>
#include "stm32u5xx_hal.h"

/**
 * @brief Initialize HAL_RNG and run a 4-byte self-test.
 * @return 0 on success, non-zero on failure.
 */
int rng_init(void);

/**
 * @brief Get pointer to the configured RNG handle for use by libtropic etc.
 * @return Pointer to the static RNG_HandleTypeDef. NULL before rng_init.
 */
RNG_HandleTypeDef *rng_handle(void);

/**
 * @brief Read n bytes of TRNG into buf.
 * @return 0 on success, non-zero if HAL_RNG_GenerateRandomNumber failed.
 */
int rng_read(uint8_t *buf, size_t n);

#endif /* NIXTROPIC_RNG_H */
