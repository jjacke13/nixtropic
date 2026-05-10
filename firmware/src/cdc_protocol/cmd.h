/*
 * Command dispatcher for the CDC ↔ SPI passthrough protocol.
 *
 * Stock-compatible command set (minus BUTTON — TS1302's only button is
 * BOOT0/SW1, consumed by DFU entry, not usable at runtime):
 *   HELP, ID, SN, VER, GPO, CS, CS=, PWR, PWR=, CLKDIV, CLKDIV=,
 *   AUTO, AUTO=, RESET
 *
 * Lookup is case-insensitive (matches stock strnicmp). Error messages
 * are byte-exact copies of stock fw's strings (cmd.c:21-24) so any host
 * client parsing them works identically.
 *
 * Returns true if the command was found and dispatched successfully
 * (caller emits trailing "OK\r\n"). Returns false if not found or if
 * a handler reported an error (handler emitted its own ERROR line).
 */

#ifndef NIXTROPIC_CDC_CMD_H
#define NIXTROPIC_CDC_CMD_H

#include <stdbool.h>

bool cmd_dispatch(const char *line);

/* Periodic AUTO-mode tick driver. Call from main loop ~every 100 ms.
 * No-op when AUTO is disabled or CS is currently asserted (matches
 * stock app/main.c:262-268). */
void cmd_auto_tick(void);

#endif /* NIXTROPIC_CDC_CMD_H */
