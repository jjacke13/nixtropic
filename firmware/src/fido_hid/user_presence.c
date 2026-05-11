/*
 * SW1 user-presence — debouncer + blocking check.  Threat-model
 * defenses (C1, H5, M3) per user_presence.h.
 *
 * State machine:
 *
 *   DEB_UP ──raw HIGH──> DEB_GOING_DOWN ──N×HIGH──> DEB_DOWN
 *      ^                       │ (any LOW)              │
 *      │                       └────────────────────────┤
 *      │                                                │
 *      └──N×LOW── DEB_GOING_UP <──raw LOW── DEB_DOWN ───┘
 *
 * N = DEBOUNCE_THRESHOLD_MS = 10 ticks @ 1 kHz = 10 ms.
 *
 * Debounce thresholds are deliberately symmetric (HIGH and LOW both 10
 * ms) so a full release→press cycle takes at least 20 ms — fast enough
 * that humans don't perceive lag, slow enough that any tactile bounce
 * is absorbed.
 */

#include "user_presence.h"
#include "../platform/board.h"
#include "../platform/led.h"

#include "stm32u5xx_hal.h"
#include "tusb.h"

#define DEBOUNCE_THRESHOLD_MS  10u

typedef enum {
    DEB_UP,
    DEB_GOING_DOWN,
    DEB_DOWN,
    DEB_GOING_UP,
} deb_state_t;

static volatile deb_state_t s_deb_state    = DEB_UP;
static volatile uint8_t     s_stable_count = 0u;
static volatile bool        s_pressed      = false;
static volatile bool        s_awaiting     = false;

void user_presence_systick_tick(void)
{
    bool raw = (HAL_GPIO_ReadPin(BOARD_BUTTON_PORT, BOARD_BUTTON_PIN)
                    == GPIO_PIN_SET);

    switch (s_deb_state) {
    case DEB_UP:
        if (raw) {
            s_deb_state    = DEB_GOING_DOWN;
            s_stable_count = 1u;
        }
        break;
    case DEB_GOING_DOWN:
        if (raw) {
            s_stable_count++;
            if (s_stable_count >= DEBOUNCE_THRESHOLD_MS) {
                s_deb_state = DEB_DOWN;
                s_pressed   = true;
            }
        } else {
            s_deb_state    = DEB_UP;
            s_stable_count = 0u;
        }
        break;
    case DEB_DOWN:
        if (!raw) {
            s_deb_state    = DEB_GOING_UP;
            s_stable_count = 1u;
        }
        break;
    case DEB_GOING_UP:
        if (!raw) {
            s_stable_count++;
            if (s_stable_count >= DEBOUNCE_THRESHOLD_MS) {
                s_deb_state = DEB_UP;
                s_pressed   = false;
            }
        } else {
            s_deb_state    = DEB_DOWN;
            s_stable_count = 0u;
        }
        break;
    }
}

bool user_presence_is_pressed(void)
{
    return s_pressed;
}

bool user_presence_is_awaiting(void)
{
    return s_awaiting;
}

up_result_t user_presence_check(uint32_t timeout_ms)
{
    /* C1: refuse fresh-consent if button is already pressed.  No LED, no
     * wait — return UP_FAIL right now.  Caller maps to OPERATION_DENIED. */
    if (s_pressed) {
        led_set_state(LED_ERROR);
        return UP_FAIL;
    }

    s_awaiting = true;
    led_set_state(LED_AWAITING_TOUCH);

    /* H5: two independent flag updates AND'd at the gate.  A single
     * instruction skip via voltage glitching cannot flip both — and the
     * UP_OK constant 0xA5C3 cannot be synthesised by skipping any one
     * load/store.  Cheap defense, well-precedented (Yubico solo-keys). */
    volatile bool ok_a = false;
    volatile bool ok_b = false;

    const uint32_t start = HAL_GetTick();
    while ((HAL_GetTick() - start) < timeout_ms) {
        /* Pump USB so host doesn't time us out.  Pump CTAPHID so a host
         * INIT on another CID can still abort a stuck channel — the
         * is_awaiting guard in ctaphid.c rejects everything else. */
        tud_task();
        if (s_pressed) {
            ok_a = true;
            ok_b = true;
            break;
        }
        HAL_Delay(1);
    }

    s_awaiting = false;

    if (ok_a && ok_b) {
        led_set_state(LED_CONFIRMED);
        return UP_OK;
    }

    /* Timed out without a press.  Show error, return UP_FAIL. */
    led_set_state(LED_ERROR);
    return UP_FAIL;
}
