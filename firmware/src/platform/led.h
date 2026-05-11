/*
 * LED state machine on PA9 — Phase 6 M1.
 *
 * Replaces blink.{h,c} for runtime use after USB enumeration.  Pre-HAL
 * boot-failure codes (`raw_blink_code` in main.c) are independent and
 * remain — they don't go through this module.
 *
 * Drive cadence: 1 ms SysTick callback (see led_systick_tick).
 *
 * Covert-channel constraint (docs/PHASE-6-PLAN.md §3 row M2): LED state
 * MUST NOT change inside any PIN, AES, or HMAC code path.  Only
 * protocol-boundary events drive transitions.  cpp-reviewer audit (M4)
 * scans for that invariant.
 *
 * Auto-decay: LED_CONFIRMED → LED_IDLE after 500 ms, LED_ERROR → LED_IDLE
 * after 2 s.  Callers don't have to clear the state.
 */

#ifndef NIXTROPIC_LED_H
#define NIXTROPIC_LED_H

typedef enum {
    LED_IDLE,             /* off */
    LED_HEARTBEAT,        /* slow 1 Hz blink — boot / pre-USB-enum */
    LED_AWAITING_TOUCH,   /* 2 Hz blink — user_presence_check waiting */
    LED_CONFIRMED,        /* solid for 500 ms then auto IDLE */
    LED_ERROR,            /* 5 Hz blink for 2 s then auto IDLE */
} led_state_t;

/* Set new state; resets state-tick and blink-phase counters. */
void led_set_state(led_state_t s);

/* 1 ms heartbeat from SysTick. */
void led_systick_tick(void);

#endif /* NIXTROPIC_LED_H */
