/*
 * CTAPHID framing layer for the FIDO HID interface (TinyUSB HID
 * instance 1). Mirrors the architecture of hid_rpc/rpc.c (single-channel
 * lt-rpc) but adds multi-CID negotiation: hosts allocate channels via
 * CTAPHID_INIT with the broadcast CID, then talk on their allocated CID.
 *
 * Phase 4 M2 implements: INIT, PING, MSG (returns 6E00), CANCEL, ERROR.
 * CBOR (0x10) is wired to a stub dispatcher that returns
 * CTAP2_ERR_INVALID_COMMAND for everything; M3 fills in real GetInfo.
 *
 * Like lt-rpc, only one transaction is in flight system-wide; if a packet
 * from a different CID arrives mid-assembly, we emit CHANNEL_BUSY.
 */

#ifndef NIXTROPIC_FIDO_HID_CTAPHID_H
#define NIXTROPIC_FIDO_HID_CTAPHID_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Initialize the FIDO HID state machine.
 *        Safe to call once at boot. Resets allocated channel pool.
 */
void fido_hid_init(void);

/**
 * @brief Pump pending HID work. Drains any queued response packets to
 *        the host as TinyUSB readies the instance-1 IN endpoint.
 */
void fido_hid_task(void);

/**
 * @brief Feed one 64-byte HID OUT report into the framing state machine.
 *        Called from tud_hid_set_report_cb when instance == 1.
 */
void fido_hid_handle_packet(const uint8_t *pkt, size_t len);

/* ===== CBOR sub-dispatch (M3 fills in) =====
 *
 * The framing layer (this module) passes a fully-assembled CBOR payload
 * to fido_hid_cbor_dispatch(); the CBOR layer parses the leading
 * command byte and returns a response payload. Negative return means
 * "framing error" — emit CTAPHID_ERROR. A positive/zero return means a
 * normal CTAP2 response (whose first byte is the status code).
 */
int fido_hid_cbor_dispatch(const uint8_t *req, size_t req_len,
                           uint8_t *resp, size_t resp_max);

#endif /* NIXTROPIC_FIDO_HID_CTAPHID_H */
