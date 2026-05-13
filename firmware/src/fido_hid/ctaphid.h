/*
 * CTAPHID framing layer for the FIDO HID interface (TinyUSB HID
 * instance 1, USB usage page 0xF1D0).
 *
 * Implements the FIDO Alliance U2F HID 1.0 transport spec (FIDO U2F
 * HID Protocol Specification, 2017-05-11):
 *   https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/
 *     fido-u2f-hid-protocol-v1.2-ps-20170411.html
 *
 * CTAP2 spec §11.2 reuses this transport unchanged.
 *
 * Implemented commands:
 *   0x86  CTAPHID_INIT      channel allocation + capability echo
 *   0x81  CTAPHID_PING      echo payload (interop test)
 *   0x83  CTAPHID_MSG       U2F APDU passthrough (returns SW=6E00,
 *                           class-not-supported — we're CTAP2-only)
 *   0x10  CTAPHID_CBOR      CTAP2 request → ctap2.c dispatcher
 *   0x11  CTAPHID_CANCEL    abort in-flight transaction
 *   0x12  CTAPHID_KEEPALIVE emitted by us when waiting for SW1 touch
 *   0x3F  CTAPHID_ERROR     non-success transport error
 *
 * Multi-CID negotiation: hosts allocate channels via CTAPHID_INIT
 * with the broadcast CID (0xFFFFFFFF), then talk on their allocated
 * CID.  Single in-flight transaction system-wide; cross-CID packets
 * during assembly → CHANNEL_BUSY (FIDO U2F HID §3.4.3).
 *
 * Architecturally mirrors `firmware/src/hid_rpc/rpc.c` (single-channel
 * vendor RPC) — both use the same INIT/CONT packet shape because
 * lt-rpc was designed CTAPHID-derived from day one.
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
