/*
 * USB CDC ↔ SPI passthrough — transparent SPI bridge mode.
 *
 * When the dongle runs in "host runs libtropic" mode (i.e. the host
 * PC has its own libtropic build talking SPI byte-by-byte through us
 * to the TROPIC01 chip), this module is the on-firmware transport.
 *
 * Replicates the stock TS1302 firmware's ASCII line protocol byte-
 * for-byte so the upstream `lt-util` and any host-side libtropic
 * binary see identical behaviour from our open firmware:
 *
 *   - Hex-bytes line (e.g. "010202002b98\n") → CS-low + SPI transfer
 *     + CS-high → echo upper-case hex MISO + "\r\n"
 *   - Suffix 'x' or '\\' on a hex line keeps CS asserted across
 *     multiple lines
 *   - Commands: HELP, ID, SN, VER, CS, CS=, PWR, PWR=, GPO, CLKDIV,
 *     CLKDIV=, AUTO, AUTO=, RESET.  Each terminates with "OK\r\n"
 *     or "ERROR: <reason>\r\n"
 *   - Lines starting with '#' are silently skipped (remarks)
 *
 * This compatibility mode coexists with the modern HID-RPC transport
 * (firmware/src/hid_rpc/) — the same dongle exposes both, host picks
 * whichever it understands.
 *
 * Reference: docs/PHASE-2-PLAN.md (full byte-level compatibility
 * decision table) + stock TS1302 firmware `app/main.c:138-196` for
 * the ASCII parser semantics we mirror.
 */

#ifndef NIXTROPIC_CDC_PROTOCOL_H
#define NIXTROPIC_CDC_PROTOCOL_H

void cdc_protocol_init(void);
void cdc_protocol_task(void);

#endif /* NIXTROPIC_CDC_PROTOCOL_H */
