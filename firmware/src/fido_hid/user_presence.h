/*
 * SW1 user-presence button — debounced PH3 read.
 *
 * Phase 6 M1: replaces the stub-true `user_presence_check` from Phase 4.
 * SW1 is the only tactile button on the TS1302 dongle, wired to STM32
 * pin PH3.  PH3 is also the BOOT0 strap, sampled by silicon only at
 * reset — so runtime use as a plain GPIO is safe (PROJECT.md §2 #3
 * amendment 2026-05-11).
 *
 * Threat-model defenses (docs/PHASE-6-PLAN.md §3 + §4.1):
 *   - C1: function returns UP_FAIL immediately if SW1 is held at entry.
 *         Only a fresh release→press transition counts as consent.
 *   - H5: sign-canary `up_result_t` return type — a single-instruction
 *         voltage-glitch skip cannot synthesize UP_OK from a UP_FAIL
 *         path.  Callers MUST compare against `UP_OK` explicitly, never
 *         use truthiness on the return value.
 *   - M3: `user_presence_is_awaiting` exposes the wait state so the
 *         CTAPHID layer can refuse non-INIT frames on any CID during
 *         the wait — keeps the CBOR dispatcher single-threaded across
 *         tud_task pumps.
 *
 * Debouncer: 1 ms SysTick callback (`user_presence_systick_tick`)
 * samples PH3.  10 ms stable HIGH → "pressed".  10 ms stable LOW →
 * "released".
 */

#ifndef NIXTROPIC_USER_PRESENCE_H
#define NIXTROPIC_USER_PRESENCE_H

#include <stdbool.h>
#include <stdint.h>

/* Sign-canary enum — see H5 above.  Constants chosen far from 0/1 so
 * accidental zero-init or bool-cast cannot produce UP_OK. */
typedef enum {
    UP_OK   = 0xA5C3,
    UP_FAIL = 0x3C5A,
} up_result_t;

/* Block up to timeout_ms for a release→press transition.  Returns
 * UP_OK only on a fresh press from a confirmed-unpressed baseline. */
up_result_t user_presence_check(uint32_t timeout_ms);

/* Current debounced state.  Non-blocking. */
bool user_presence_is_pressed(void);

/* True while user_presence_check is blocking for user input. */
bool user_presence_is_awaiting(void);

/* Advance debouncer.  Call from SysTick at 1 ms cadence. */
void user_presence_systick_tick(void);

#endif /* NIXTROPIC_USER_PRESENCE_H */
