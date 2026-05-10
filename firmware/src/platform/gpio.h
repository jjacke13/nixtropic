/*
 * GPIO bring-up. Per board.h pin assignments.
 *
 * Phase 1 Group B brings up: LED (PA9), TROPIC01 power switch (PA0),
 * GPO input (PB0). SPI AF mux deferred to whenever libtropic comes in
 * (Group D's lt_init does the SPI peripheral; we do GPIO mux here).
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

/* Phase 1 helpers */
void board_led_on(void);
void board_led_off(void);
void board_led_toggle(void);

void board_tropic_power_on(void);
void board_tropic_power_off(void);

bool board_tropic_gpo_read(void);

#endif /* NIXTROPIC_GPIO_H */
