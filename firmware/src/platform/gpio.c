/*
 * GPIO bring-up — see gpio.h. Pin assignments come from board.h.
 */

#include "gpio.h"
#include "board.h"

#include "stm32u5xx_hal.h"

void gpio_init(void)
{
    /* Enable AHB clocks for the GPIO banks we touch. */
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOB_CLK_ENABLE();
    __HAL_RCC_GPIOH_CLK_ENABLE();

    GPIO_InitTypeDef cfg = {0};

    /* PA9 — LED (output, push-pull, no pull, low speed). Default OFF. */
    HAL_GPIO_WritePin(BOARD_LED_PORT, BOARD_LED_PIN, GPIO_PIN_RESET);
    cfg.Pin   = BOARD_LED_PIN;
    cfg.Mode  = GPIO_MODE_OUTPUT_PP;
    cfg.Pull  = GPIO_NOPULL;
    cfg.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(BOARD_LED_PORT, &cfg);

    /* PA0 — TROPIC01 power-switch enable (output, default LOW = chip off). */
    HAL_GPIO_WritePin(BOARD_TROPIC_PWR_PORT, BOARD_TROPIC_PWR_PIN, GPIO_PIN_RESET);
    cfg.Pin   = BOARD_TROPIC_PWR_PIN;
    cfg.Mode  = GPIO_MODE_OUTPUT_PP;
    cfg.Pull  = GPIO_NOPULL;
    cfg.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(BOARD_TROPIC_PWR_PORT, &cfg);

    /* PB0 — TROPIC01 GPO (input, pull-down, no IRQ). */
    cfg.Pin   = BOARD_TROPIC_GPO_PIN;
    cfg.Mode  = GPIO_MODE_INPUT;
    cfg.Pull  = GPIO_PULLDOWN;
    cfg.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(BOARD_TROPIC_GPO_PORT, &cfg);

    /* PH3 — SW1 button (BOOT0 strap at reset; runtime input).  Phase 6 M1
     * requires real user-presence reads.  Topology per
     * research/stm32u535-inventory.md:327 — SW1 pulls PH3 to VCC,
     * external 33 kΩ R1 pull-down to GND.  Pressed = HIGH.  Without
     * this init the pin stays in silicon-default analog mode and
     * HAL_GPIO_ReadPin returns garbage. */
    cfg.Pin   = BOARD_BUTTON_PIN;
    cfg.Mode  = GPIO_MODE_INPUT;
    cfg.Pull  = GPIO_PULLDOWN;          /* belt-and-suspenders with R1 */
    cfg.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(BOARD_BUTTON_PORT, &cfg);
}

void board_led_on(void)
{
    HAL_GPIO_WritePin(BOARD_LED_PORT, BOARD_LED_PIN, GPIO_PIN_SET);
}

void board_led_off(void)
{
    HAL_GPIO_WritePin(BOARD_LED_PORT, BOARD_LED_PIN, GPIO_PIN_RESET);
}

void board_led_toggle(void)
{
    HAL_GPIO_TogglePin(BOARD_LED_PORT, BOARD_LED_PIN);
}

void board_tropic_power_on(void)
{
    HAL_GPIO_WritePin(BOARD_TROPIC_PWR_PORT, BOARD_TROPIC_PWR_PIN, GPIO_PIN_SET);
}

void board_tropic_power_off(void)
{
    HAL_GPIO_WritePin(BOARD_TROPIC_PWR_PORT, BOARD_TROPIC_PWR_PIN, GPIO_PIN_RESET);
}

bool board_tropic_gpo_read(void)
{
    return HAL_GPIO_ReadPin(BOARD_TROPIC_GPO_PORT, BOARD_TROPIC_GPO_PIN) == GPIO_PIN_SET;
}
