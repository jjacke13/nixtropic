/*
 * Clock subsystem bring-up — STM32U5 RCC + PWR configuration.
 *
 * SYSCLK = 48 MHz from HSE 8 MHz × PLL ×96/16, voltage scale Range 3,
 * flash latency 1 wait state.  Matches the stock TS1302 firmware
 * (`sdk/drv_u5/sys.c:_sys_clock_config`) byte-for-byte so SPI timing
 * to TROPIC01 stays identical.
 *
 * USB peripheral kernel clock comes from HSI48 + CRS auto-trim
 * (clock_init_usb), the standard "no crystal needed" U5 USB-FS recipe
 * per AN5483 §3.3.  HSI48 also clocks RNG (see platform/rng.c).
 *
 * Reference: STM32U5 reference manual RM0456 §11 (RCC).
 */

#ifndef NIXTROPIC_CLOCK_H
#define NIXTROPIC_CLOCK_H

/**
 * @brief Configure HSE → PLL → SYSCLK at 48 MHz.
 *
 * Sets voltage scale Range 3, flash latency 1 wait state, AHB/APB div 1.
 * Calls HAL_RCC_OscConfig and HAL_RCC_ClockConfig.
 *
 * Aborts via blink_set_pattern(1) on failure.
 *
 * @return 0 on success, non-zero on failure.
 */
int clock_init(void);

#endif /* NIXTROPIC_CLOCK_H */
