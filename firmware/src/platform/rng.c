/*
 * STM32 onboard HAL_RNG — see rng.h.
 *
 * Note: the U5 RNG can run on either HSI48 or PLL Q. We pick HSI48 here
 * because we're enabling it for USB anyway, and HSI48 is the recommended
 * RNG clock per RM0456 (NIST SP 800-90B compliant). RNG runs on its
 * kernel clock independently of SYSCLK; 48 MHz is fast enough that we
 * don't need to throttle reads.
 */

#include "rng.h"

static RNG_HandleTypeDef s_rng = {0};
static int s_initialized = 0;

int rng_init(void)
{
    /* Select HSI48 as RNG kernel clock. (USB and CRS already use HSI48
     * via usb_clock_init; this is a separate kernel-clock selection.) */
    RCC_PeriphCLKInitTypeDef pclk = {0};
    pclk.PeriphClockSelection = RCC_PERIPHCLK_RNG;
    pclk.RngClockSelection    = RCC_RNGCLKSOURCE_HSI48;
    if (HAL_RCCEx_PeriphCLKConfig(&pclk) != HAL_OK) {
        return 1;
    }

    /* Enable RNG peripheral clock and reset */
    __HAL_RCC_RNG_CLK_ENABLE();

    s_rng.Instance = RNG;
    if (HAL_RNG_Init(&s_rng) != HAL_OK) {
        return 2;
    }

    /* Self-test: read 4 bytes; reject all-zero / all-0xff. */
    uint32_t test = 0;
    if (HAL_RNG_GenerateRandomNumber(&s_rng, &test) != HAL_OK) {
        return 3;
    }
    if (test == 0u || test == 0xFFFFFFFFu) {
        return 4;
    }

    s_initialized = 1;
    return 0;
}

RNG_HandleTypeDef *rng_handle(void)
{
    return s_initialized ? &s_rng : (RNG_HandleTypeDef *) 0;
}

int rng_read(uint8_t *buf, size_t n)
{
    if (!s_initialized || !buf) return 1;

    while (n > 0u) {
        uint32_t word = 0;
        if (HAL_RNG_GenerateRandomNumber(&s_rng, &word) != HAL_OK) {
            return 2;
        }
        size_t take = (n < 4u) ? n : 4u;
        for (size_t i = 0; i < take; ++i) {
            buf[i] = (uint8_t)((word >> (i * 8u)) & 0xFFu);
        }
        buf += take;
        n   -= take;
    }
    return 0;
}
