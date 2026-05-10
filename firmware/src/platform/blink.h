/*
 * LED blink-code module — decision P1.20 (failure indication) + P1.24 (heartbeat).
 *
 * Polled from the main loop via blink_tick() — no SysTick handler of its own,
 * uses HAL_GetTick. Patterns:
 *   BLINK_OFF        — LED off
 *   BLINK_SOLID      — LED steady on (PASS state)
 *   BLINK_HEARTBEAT  — slow ~1 Hz blink during init
 *   BLINK_PATTERN(N) — N short blinks then long pause, repeating
 *                      (used as failure category code per P1.20:
 *                       1=clock 2=RNG 3=USB peripheral 4=USB enum
 *                       5=TROPIC01 pwr 6=lt_init 7=L2 cmd)
 *
 * Requires gpio_init() to have run (PA9 configured as output).
 */

#ifndef NIXTROPIC_BLINK_H
#define NIXTROPIC_BLINK_H

#include <stdint.h>

typedef enum {
    BLINK_OFF,
    BLINK_SOLID,
    BLINK_HEARTBEAT,
    BLINK_PATTERN,
} blink_mode_t;

/**
 * @brief Set the blink mode.
 * @param mode  one of BLINK_OFF / BLINK_SOLID / BLINK_HEARTBEAT / BLINK_PATTERN
 * @param count meaningful only for BLINK_PATTERN; number of pulses per cycle (1..15)
 */
void blink_set(blink_mode_t mode, uint8_t count);

/* Convenience wrappers */
static inline void blink_set_off(void)        { blink_set(BLINK_OFF, 0); }
static inline void blink_set_solid(void)      { blink_set(BLINK_SOLID, 0); }
static inline void blink_set_heartbeat(void)  { blink_set(BLINK_HEARTBEAT, 0); }
static inline void blink_set_pattern(uint8_t n) { blink_set(BLINK_PATTERN, n); }

/**
 * @brief Tick the blink state machine.
 *
 * Call frequently from the main loop. Reads HAL_GetTick() internally;
 * cheap when no transition is due.
 */
void blink_tick(void);

#endif /* NIXTROPIC_BLINK_H */
