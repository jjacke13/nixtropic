/*
 * Clock subsystem bring-up.
 *
 * Decision P1.2: SYSCLK = 48 MHz from HSE 8 MHz × PLL ×96/16, Range 3,
 * flash latency 1 wait state. Matches stock TS1302 fw exactly.
 *
 * HSI48 + CRS for USB peripheral added in clock_init_usb() (Group C).
 * Phase 1 Group B brings up SYSCLK only — USB clock comes later.
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
