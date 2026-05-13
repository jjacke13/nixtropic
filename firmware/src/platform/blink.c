/*
 * LED blink-code state machine — see blink.h for the public API +
 * pattern catalog.
 *
 * Drives the single user LED on TS1302 board pin P1.24 (mapped via
 * firmware/src/platform/board.h) to communicate boot stage + runtime
 * state.  Hand-rolled polling FSM, no IRQ — main loop calls
 * blink_task() once per iteration; timing comes from HAL_GetTick()
 * (1 kHz tick from STM32U5 SysTick).
 *
 * Also driven by the FIDO user-presence flow (firmware/src/fido_hid/
 * user_presence.c) — `blink_pattern(BLINK_USER_TOUCH)` signals
 * "press SW1 within 30 s" during CTAP2 makeCredential/getAssertion.
 *
 * No upstream source — hand-rolled.
 */

#include "blink.h"
#include "gpio.h"

#include "stm32u5xx_hal.h"

#define HEARTBEAT_HALF_MS    500u    /* ~1 Hz */
#define PATTERN_PULSE_ON_MS  100u
#define PATTERN_PULSE_OFF_MS 200u
#define PATTERN_GAP_MS       900u

static blink_mode_t s_mode = BLINK_OFF;
static uint8_t      s_count = 0;
static uint8_t      s_pulse_idx = 0;
static uint8_t      s_phase = 0;     /* 0 = LED off in current step, 1 = LED on */
static uint32_t     s_next_transition_ms = 0;

void blink_set(blink_mode_t mode, uint8_t count)
{
    s_mode  = mode;
    s_count = count;
    s_pulse_idx = 0;
    s_phase = 0;
    s_next_transition_ms = HAL_GetTick();

    /* Apply immediate state for static modes */
    switch (mode) {
        case BLINK_OFF:
            board_led_off();
            break;
        case BLINK_SOLID:
            board_led_on();
            break;
        default:
            /* dynamic — settled by blink_tick */
            board_led_off();
            break;
    }
}

void blink_tick(void)
{
    const uint32_t now = HAL_GetTick();
    if ((int32_t)(now - s_next_transition_ms) < 0) {
        return;  /* not yet */
    }

    switch (s_mode) {
        case BLINK_OFF:
        case BLINK_SOLID:
            /* No periodic transitions; static modes set LED in blink_set. */
            s_next_transition_ms = now + 1000u;
            break;

        case BLINK_HEARTBEAT:
            board_led_toggle();
            s_next_transition_ms = now + HEARTBEAT_HALF_MS;
            break;

        case BLINK_PATTERN:
            if (s_pulse_idx >= s_count) {
                /* Long inter-cycle gap with LED off, then restart. */
                board_led_off();
                s_next_transition_ms = now + PATTERN_GAP_MS;
                s_pulse_idx = 0;
                s_phase = 0;
            } else if (s_phase == 0) {
                /* LED off → LED on (next pulse begins) */
                board_led_on();
                s_phase = 1;
                s_next_transition_ms = now + PATTERN_PULSE_ON_MS;
            } else {
                /* LED on → LED off (between pulses or before gap) */
                board_led_off();
                s_phase = 0;
                s_pulse_idx++;
                s_next_transition_ms = now + PATTERN_PULSE_OFF_MS;
            }
            break;
    }
}
