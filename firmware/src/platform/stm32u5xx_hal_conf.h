/*
 * Minimal STM32U5 HAL configuration for nixtropic firmware.
 *
 * Only the HAL modules we actually use are enabled.  Everything else
 * is deliberately off — keeps build size down and prevents accidental
 * coupling to ST middleware.
 *
 * Enabled: RCC, GPIO, SPI, RNG, PWR, CORTEX, FLASH (for latency
 * config).  Excluded by design: HAL_UART (USB CDC is the console);
 * HAL_PCD (TinyUSB owns USB).
 *
 * Per research/stm32u535-inventory.md §10.3: TS1302 has an 8 MHz HSE
 * crystal X1.  HSI48 + CRS auto-trim provides the USB peripheral
 * kernel clock (see platform/clock.c).
 *
 * Derived from ST's stm32u5xx_hal_conf_template.h (Cube U5 HAL).
 */

#ifndef STM32U5xx_HAL_CONF_H
#define STM32U5xx_HAL_CONF_H

#ifdef __cplusplus
extern "C" {
#endif

/* ##################### Module Selection ##################### */
#define HAL_MODULE_ENABLED

#define HAL_RCC_MODULE_ENABLED
#define HAL_FLASH_MODULE_ENABLED   /* needed by HAL_Init for latency config */
#define HAL_GPIO_MODULE_ENABLED
#define HAL_PWR_MODULE_ENABLED
#define HAL_CORTEX_MODULE_ENABLED  /* SysTick, NVIC */
#define HAL_RNG_MODULE_ENABLED
#define HAL_SPI_MODULE_ENABLED
#define HAL_DMA_MODULE_ENABLED     /* SPI HAL has internal DMA refs even when blocking */
#define HAL_EXTI_MODULE_ENABLED    /* small, GPIO sometimes pulls it in */

/* ##################### Oscillator Values ##################### */
/* TS1302 hardware-defined: 8 MHz HSE crystal X1 between PH0/PH1. */
#if !defined(HSE_VALUE)
#define HSE_VALUE              8000000UL
#endif
#if !defined(HSE_STARTUP_TIMEOUT)
#define HSE_STARTUP_TIMEOUT    100UL
#endif

#if !defined(MSI_VALUE)
#define MSI_VALUE              4000000UL
#endif

#if !defined(HSI_VALUE)
#define HSI_VALUE              16000000UL
#endif

/* HSI48 used by USB FS (Group C). 48 MHz internal RC, CRS-trimmable. */
#if !defined(HSI48_VALUE)
#define HSI48_VALUE            48000000UL
#endif

#if !defined(LSI_VALUE)
#define LSI_VALUE              32000UL
#endif
#if !defined(LSI_STARTUP_TIMEOUT)
#define LSI_STARTUP_TIMEOUT    130UL
#endif

#if !defined(LSE_VALUE)
#define LSE_VALUE              32768UL
#endif
#if !defined(LSE_STARTUP_TIMEOUT)
#define LSE_STARTUP_TIMEOUT    5000UL
#endif

#if !defined(EXTERNAL_SAI1_CLOCK_VALUE)
#define EXTERNAL_SAI1_CLOCK_VALUE  48000UL
#endif
#if !defined(EXTERNAL_SAI2_CLOCK_VALUE)
#define EXTERNAL_SAI2_CLOCK_VALUE  48000UL
#endif

/* ##################### System Configuration ##################### */
#define VDD_VALUE                    3300UL
#define TICK_INT_PRIORITY            ((1UL<<__NVIC_PRIO_BITS) - 1UL)
#define USE_RTOS                     0U
#define PREFETCH_ENABLE              1U

/* No full assert in release; conservative for now */
/* #define USE_FULL_ASSERT    1U */

/* Disable register-callback functionality across HAL modules. Phase 3 M4
 * adds tropic.c (which pulls in stm32u5xx_hal.h) to APP_SOURCES with
 * strict -Wundef enabled; without these explicit `0` defines, the
 * `#if (USE_HAL_*_REGISTER_CALLBACKS == 1)` checks in HAL headers blow up. */
#define USE_HAL_RCC_REGISTER_CALLBACKS    0U
#define USE_HAL_GPIO_REGISTER_CALLBACKS   0U
#define USE_HAL_PWR_REGISTER_CALLBACKS    0U
#define USE_HAL_FLASH_REGISTER_CALLBACKS  0U
#define USE_HAL_CORTEX_REGISTER_CALLBACKS 0U
#define USE_HAL_RNG_REGISTER_CALLBACKS    0U
#define USE_HAL_SPI_REGISTER_CALLBACKS    0U
#define USE_HAL_DMA_REGISTER_CALLBACKS    0U
#define USE_HAL_EXTI_REGISTER_CALLBACKS   0U

/* ##################### Module Headers ##################### */
#ifdef HAL_RCC_MODULE_ENABLED
#include "stm32u5xx_hal_rcc.h"
#endif

#ifdef HAL_GPIO_MODULE_ENABLED
#include "stm32u5xx_hal_gpio.h"
#endif

#ifdef HAL_DMA_MODULE_ENABLED
#include "stm32u5xx_hal_dma.h"
#endif

#ifdef HAL_CORTEX_MODULE_ENABLED
#include "stm32u5xx_hal_cortex.h"
#endif

#ifdef HAL_FLASH_MODULE_ENABLED
#include "stm32u5xx_hal_flash.h"
#endif

#ifdef HAL_PWR_MODULE_ENABLED
#include "stm32u5xx_hal_pwr.h"
#endif

#ifdef HAL_EXTI_MODULE_ENABLED
#include "stm32u5xx_hal_exti.h"
#endif

#ifdef HAL_RNG_MODULE_ENABLED
#include "stm32u5xx_hal_rng.h"
#endif

#ifdef HAL_SPI_MODULE_ENABLED
#include "stm32u5xx_hal_spi.h"
#endif

#ifdef USE_FULL_ASSERT
void assert_failed(uint8_t *file, uint32_t line);
#define assert_param(expr) ((expr) ? (void)0U : assert_failed((uint8_t *)__FILE__, __LINE__))
#else
#define assert_param(expr) ((void)0U)
#endif

#ifdef __cplusplus
}
#endif

#endif /* STM32U5xx_HAL_CONF_H */
