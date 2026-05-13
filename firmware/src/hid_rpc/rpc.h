/*
 * lt-rpc — HID-based vendor RPC protocol for talking to nixtropic
 * firmware over a /dev/hidraw* interface (vendor usage page 0xFF00,
 * see usb_descriptors.c).
 *
 * Wire framing is CTAPHID-derived (FIDO U2F HID 1.0 §2.4) — INIT
 * packet carries cmd + total payload length; CONT packets carry
 * continuation chunks.  We use a SINGLE fixed channel ID
 * (0xCAFE0001) rather than CTAPHID's INIT-time CID negotiation,
 * since this is a vendor protocol with one client per dongle.
 *
 * Implemented commands (rpc_cmds.c): PING, GET_RANDOM, CHIP_ID,
 * ECC_GENERATE, ECC_SIGN, ECC_PUBKEY.  Used by host-side test
 * scripts in tools/ and by the validate-phase{1..7} suites.
 *
 * Distinct from the FIDO2 HID interface (usage page 0xF1D0, see
 * firmware/src/fido_hid/) which speaks CTAPHID-proper with a real
 * CTAP2 stack — they're on separate /dev/hidraw* devices.
 */

#ifndef NIXTROPIC_HID_RPC_H
#define NIXTROPIC_HID_RPC_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Initialize the lt-rpc subsystem.
 *
 * Resets the framing state machine; safe to call once at boot.
 */
void hid_rpc_init(void);

/**
 * @brief Pump pending HID work. Drains any queued response packets to
 *        the host as TinyUSB readies the IN endpoint.
 */
void hid_rpc_task(void);

/* ===== Command-handler API (called by rpc.c into rpc_cmds.c) =====
 *
 * The framing layer passes the dispatched command id, the assembled
 * request payload, and a fixed-size response buffer. Handlers return the
 * actual number of bytes written into `resp`. On error the handler should
 * return a negative value (interpreted as -error_code) and the framing
 * layer emits an LT_RPC_CMD_ERROR response.
 */

#define HID_RPC_RESP_MAX  1024

typedef int (*rpc_handler_fn)(const uint8_t *req, size_t req_len,
                              uint8_t *resp, size_t resp_max);

/**
 * @brief Look up a handler for the given command byte (without INIT flag).
 *        Returns NULL if no handler is registered.
 */
rpc_handler_fn hid_rpc_lookup(uint8_t cmd);

#endif /* NIXTROPIC_HID_RPC_H */
