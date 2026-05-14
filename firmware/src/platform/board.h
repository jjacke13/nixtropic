/*
 * TS1302 board pinout — single source of truth for pin/peripheral
 * mapping.
 *
 * Per research/stm32u535-inventory.md §10.1 and PROJECT.md §4 hardware
 * essentials.  Authoritative reference for: LED (PA9), SW1
 * user-presence button (PH3), TROPIC01 power switch (PA0), TROPIC01
 * GPO ready signal (PB0), TROPIC01 SPI1 (PA4/5/6/7 = NSS/SCK/MISO/MOSI),
 * USB D+/D- (PA12/PA11).
 *
 * If you change a pin assignment here, also update STM32CubeMX's
 * .ioc if you regenerate the HAL init — but we don't regenerate; this
 * file is the canonical source.
 */

#ifndef NIXTROPIC_BOARD_H
#define NIXTROPIC_BOARD_H

#include "stm32u5xx_hal.h"

/* ----- LED (PA9, active-high — drives LED anode through R13=1k) ----- */
#define BOARD_LED_PORT          GPIOA
#define BOARD_LED_PIN           GPIO_PIN_9
#define BOARD_LED_RCC_ENABLE()  __HAL_RCC_GPIOA_CLK_ENABLE()

/* ----- TROPIC01 power switch (PA0, drives IC4 TPS22917 enable) ----- */
#define BOARD_TROPIC_PWR_PORT   GPIOA
#define BOARD_TROPIC_PWR_PIN    GPIO_PIN_0
/* default: chip OFF; drive HIGH to enable load switch */

/* ----- SPI1 (TROPIC01) — pins per AF5 ----- */
#define BOARD_SPI_INSTANCE      SPI1
#define BOARD_SPI_RCC_ENABLE()  __HAL_RCC_SPI1_CLK_ENABLE()
#define BOARD_SPI_PORT          GPIOA
#define BOARD_SPI_SCK_PIN       GPIO_PIN_5    /* PA5 SPI1_SCK  AF5 */
#define BOARD_SPI_MISO_PIN      GPIO_PIN_6    /* PA6 SPI1_MISO AF5 */
#define BOARD_SPI_MOSI_PIN      GPIO_PIN_7    /* PA7 SPI1_MOSI AF5 */
#define BOARD_SPI_CS_PORT       GPIOA
#define BOARD_SPI_CS_PIN        GPIO_PIN_4    /* PA4 soft CS */

/* ----- TROPIC01 GPO line (PB0) — input, pull-down, polled (no IRQ) ----- */
#define BOARD_TROPIC_GPO_PORT   GPIOB
#define BOARD_TROPIC_GPO_PIN    GPIO_PIN_0

/* ----- BOOT0 / SW1 button (PH3) — input, pull-up. User-presence ----- */
#define BOARD_BUTTON_PORT       GPIOH
#define BOARD_BUTTON_PIN        GPIO_PIN_3

/* ----- USB FS pins (PA11/PA12, AF10) — owned by usb/usb.c ----- */
#define BOARD_USB_PORT          GPIOA
#define BOARD_USB_DM_PIN        GPIO_PIN_11
#define BOARD_USB_DP_PIN        GPIO_PIN_12

#endif /* NIXTROPIC_BOARD_H */
