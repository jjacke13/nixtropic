/*
 * GPIO bring-up.  Per board.h pin assignments.
 *
 * Configures the pins owned at the platform layer: LED (PA9, output),
 * TROPIC01 power switch (PA0, output, default LOW), TROPIC01 GPO
 * ready signal (PB0, input pull-down), SW1 user-presence button
 * (PH3, input pull-up).
 *
 * SPI1 AF mux (PA4/5/6/7) is owned by `platform/spi.c`; USB D+/D-
 * (PA11/PA12) is owned by `usb/usb.c`.
 *
 * GOTCHA: enabling a GPIO bank's RCC clock is NOT enough to use a pin
 * — HAL_GPIO_Init() with explicit Mode/Pull is required.  Caught when
 * wiring up SW1: PH3 sat in silicon-default analog mode because we'd
 * only enabled the GPIOH clock without per-pin init.
 */

#ifndef NIXTROPIC_GPIO_H
#define NIXTROPIC_GPIO_H

#include <stdbool.h>

/**
 * @brief Initialize Phase 1 GPIO pins.
 *
 * Enables clocks for GPIOA, GPIOB, GPIOH. Configures PA9 (LED) as output,
 * PA0 (TROPIC01 power switch) as output (default LOW), PB0 (TROPIC01 GPO)
 * as input pull-down. PH3 (BOOT0/button) clock enabled for future use.
 *
 * SPI1 pins (PA4/5/6/7) and USB pins (PA11/12) are intentionally NOT
 * configured here — done by their owners in later groups.
 */
void gpio_init(void);

/* Platform-pin helpers */
void board_led_on(void);
void board_led_off(void);
void board_led_toggle(void);

void board_tropic_power_on(void);
void board_tropic_power_off(void);

bool board_tropic_gpo_read(void);

#endif /* NIXTROPIC_GPIO_H */
