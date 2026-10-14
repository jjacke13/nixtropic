/*
 * Passthrough guard — Phase 9 M1, PHASE-9-PLAN.md §0 rule 1.
 *
 * The debug build's CDC hex passthrough clocks host bytes straight onto
 * the TROPIC01 SPI bus.  The chip takes the first byte after CSN falls as
 * the request ID: L1 GET_RESPONSE or an L2 request.  The guard lets the
 * host start a transaction only with a read-only request:
 *
 *   0xAA GET_RESPONSE   read the chip's pending response
 *   0x01 Get_Info       chip ID, firmware versions, certificate
 *   0x10 Resend         repeat the last response
 *   0xA2 Get_Log        chip debug log
 *
 * Everything else is refused, notably Handshake / Encrypted_Cmd (no
 * host-side L3 session, so no L3 command — pairing-key write or
 * invalidate, R-config, I-config — can be tunnelled through), Sleep
 * (would end the firmware's own session), Startup (maintenance reboot)
 * and the Mutable_FW update / erase requests.
 *
 * Bytes the host sends to continue a frame it started itself (CS kept
 * low with the trailing 'x') are not request IDs and pass.  Whenever the
 * guard cannot be sure that is the case, it treats the bytes as a new
 * frame and checks them.
 *
 * Pure logic, no hardware access: unit-tested on the host
 * (tests/host/test_passthrough_guard.c).
 */

#ifndef NIXTROPIC_CDC_GUARD_H
#define NIXTROPIC_CDC_GUARD_H

#include <stdbool.h>
#include <stdint.h>

/* True iff the host may start a SPI transaction with this byte. */
bool guard_req_allowed(uint8_t req_id);

/* The host moved CS with the CS=0/1 command (either direction). */
void guard_cs_changed(void);

/* Before clocking a host line: may it go out?
 *   asserts_cs  the line asserts CS itself (no leading 'x')
 *   cs_low      CS is asserted right now, before the line
 *   first       first byte of the line */
bool guard_check_transfer(bool asserts_cs, bool cs_low, uint8_t first);

/* After a host line went out: is CS still asserted now?  (Read the pin
 * state; a trailing 'x' on a line clocked with CS high leaves it high.) */
void guard_transfer_done(bool cs_left_low);

#endif /* NIXTROPIC_CDC_GUARD_H */
