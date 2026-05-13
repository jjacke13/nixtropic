/*
 * STM32U5 onboard HAL_RNG — TRNG init + access.
 *
 * Singleton handle (`rng_handle()`) shared by:
 *   - libtropic's `lt_port_random_bytes` (TROPIC01 host-side entropy
 *     before the L3 secure session is up)
 *   - the cold-boot HAL_RNG self-test dump over USB CDC (proves the
 *     STM32 TRNG is alive independently of the secure element)
 *
 * Reference: STM32U5 reference manual RM0456 §27 (RNG), NIST SP 800-90B
 * compliant when clocked from HSI48.
 *
 * NOTE: do NOT use this as the high-assurance entropy source — use
 * TROPIC01's TRNG via `tropic_random()` for FIDO credential keys + PIN
 * KEK material.  This host-MCU RNG is a fallback / boot-bring-up source.
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
