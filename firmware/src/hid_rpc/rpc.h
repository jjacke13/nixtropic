/*
 * lt-rpc — HID-based RPC protocol for talking to nixtropic firmware.
 *
 * Phase 3 M2: CTAPHID-style framing with single fixed channel.
 * Commands: PING (0x01), GET_RANDOM (0x02). More added in M3 + M4.
 *
 * Wire format in lt_rpc_proto.h. State machine in rpc.c assembles INIT +
 * CONT packets from the host into a contiguous request buffer, dispatches
 * to the command handler (rpc_cmds.c), then fragments the response back
 * into HID IN reports.
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
