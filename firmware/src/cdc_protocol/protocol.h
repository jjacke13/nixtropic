/*
 * Phase 2 USB CDC ↔ SPI passthrough protocol — public interface.
 *
 * Replicates the stock TS1302 firmware's ASCII line protocol byte-for-byte:
 *   - Hex-bytes line (e.g. "010202002b98\n") → CS-low + SPI transfer + CS-high
 *     → echo upper-case hex MISO + "\r\n"
 *   - Suffix 'x' or '\\' on a hex line keeps CS asserted across multiple lines
 *   - Commands: HELP, ID, SN, VER, CS, CS=, PWR, PWR=, GPO, CLKDIV, CLKDIV=,
 *     AUTO, AUTO=, RESET. Each terminates with "OK\r\n" or "ERROR: <reason>\r\n"
 *   - Lines starting with '#' are silently skipped (remarks)
 *
 * See docs/PHASE-2-PLAN.md for the full decision table.
 */

#ifndef NIXTROPIC_CDC_PROTOCOL_H
#define NIXTROPIC_CDC_PROTOCOL_H

void cdc_protocol_init(void);
void cdc_protocol_task(void);

#endif /* NIXTROPIC_CDC_PROTOCOL_H */
