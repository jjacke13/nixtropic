/*
 * LED state machine — see led.h for design rationale.
 *
 * Three blink rates are encoded purely by modular arithmetic over a
 * monotonically-incrementing per-state phase counter, so there is no
 * "missed deadline" failure mode if SysTick gets briefly preempted —
 * the next tick that runs computes the right LED level for whatever the
 * current phase value is.
 */

#include "led.h"
#include "board.h"

#include "stm32u5xx_hal.h"

static volatile led_state_t s_state       = LED_HEARTBEAT;
static volatile uint32_t    s_state_ticks = 0u;
static volatile uint32_t    s_blink_phase = 0u;

static void led_write(int on)
{
    HAL_GPIO_WritePin(BOARD_LED_PORT, BOARD_LED_PIN,
                      on ? GPIO_PIN_SET : GPIO_PIN_RESET);
}

void led_set_state(led_state_t s)
{
    s_state       = s;
    s_state_ticks = 0u;
    s_blink_phase = 0u;
}

void led_systick_tick(void)
{
    s_state_ticks += 1u;
    s_blink_phase += 1u;

    switch (s_state) {
    case LED_IDLE:
        led_write(0);
        break;

    case LED_HEARTBEAT:
        /* 1 Hz: 500 ms on, 500 ms off. */
        led_write((s_blink_phase % 1000u) < 500u);
        break;

    case LED_AWAITING_TOUCH:
        /* 2 Hz: 250 ms on, 250 ms off — matches Yubikey muscle memory. */
        led_write((s_blink_phase % 500u) < 250u);
        break;

    case LED_CONFIRMED:
        led_write(1);
        if (s_state_ticks >= 500u) {
            led_set_state(LED_IDLE);
        }
        break;

    case LED_ERROR:
        /* 5 Hz blink for 2 s, then auto IDLE. */
        led_write((s_blink_phase % 200u) < 100u);
        if (s_state_ticks >= 2000u) {
            led_set_state(LED_IDLE);
        }
        break;
    }
}
