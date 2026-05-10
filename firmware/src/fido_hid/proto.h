/*
 * CTAPHID wire-format constants for the FIDO HID interface (instance 1).
 *
 * Reference: FIDO Alliance CTAP 2.x, §11.2 "USB HID" (formerly "CTAPHID").
 *
 * Wire format mirrors Phase 3 lt-rpc (which was deliberately CTAPHID-derived):
 *
 *   INIT packet:
 *     byte  0..3   CID       big-endian uint32
 *     byte  4      CMD       0x80 | cmd_id (top bit set marks INIT)
 *     byte  5..6   BCNT      big-endian uint16, total payload length
 *     byte  7..63  DATA      up to 57 bytes
 *
 *   CONT packet:
 *     byte  0..3   CID
 *     byte  4      SEQ       0..0x7F (top bit clear)
 *     byte  5..63  DATA      up to 59 bytes
 *
 * Channel IDs:
 *   - 0xFFFFFFFF is the broadcast CID. Only valid as destination of
 *     CTAPHID_INIT (channel allocation request).
 *   - We allocate fresh CIDs starting at 0x00000001, monotonic.
 *   - Phase 4 caps at 32 simultaneously-allocated channels.
 */

#ifndef NIXTROPIC_FIDO_HID_PROTO_H
#define NIXTROPIC_FIDO_HID_PROTO_H

#define FIDO_HID_REPORT_LEN     64
#define FIDO_HID_INIT_DATA_LEN  57    /* 64 - (4 CID + 1 CMD + 2 BCNT) */
#define FIDO_HID_CONT_DATA_LEN  59    /* 64 - (4 CID + 1 SEQ) */

#define FIDO_HID_CID_BROADCAST  0xFFFFFFFFul

#define FIDO_HID_CMD_INIT_FLAG  0x80u

/* CTAPHID commands (low 7 bits; combined with INIT flag in CMD byte). */
#define FIDO_HID_CMD_PING       0x01u
#define FIDO_HID_CMD_MSG        0x03u    /* U2F APDU passthrough */
#define FIDO_HID_CMD_LOCK       0x04u    /* not implemented */
#define FIDO_HID_CMD_INIT       0x06u
#define FIDO_HID_CMD_WINK       0x08u    /* not implemented (no LED dance) */
#define FIDO_HID_CMD_CBOR       0x10u    /* CTAP2 commands */
#define FIDO_HID_CMD_CANCEL     0x11u
#define FIDO_HID_CMD_KEEPALIVE  0x3Bu    /* server-emitted */
#define FIDO_HID_CMD_ERROR      0x3Fu    /* server-emitted */

/* INIT response payload structure (17 bytes):
 *   byte  0..7    nonce (echo of request nonce)
 *   byte  8..11   allocated CID, big-endian
 *   byte  12      CTAPHID protocol version (2)
 *   byte  13      device version major
 *   byte  14      device version minor
 *   byte  15      device version build
 *   byte  16      capability flags
 */
#define FIDO_HID_INIT_RESP_LEN  17

#define FIDO_HID_PROTOCOL_VER   2u

/* Capability bits (FIDO U2F HID spec §3.2). */
#define FIDO_HID_CAP_WINK       0x01u
#define FIDO_HID_CAP_LOCK       0x02u
#define FIDO_HID_CAP_CBOR       0x04u
#define FIDO_HID_CAP_NMSG       0x08u    /* set => CTAPHID_MSG NOT supported */

/* nixtropic's capability advertisement: CBOR yes, no U2F MSG (we return
 * SW=0x6E00 to MSG requests). No WINK, no LOCK. */
#define FIDO_HID_CAPABILITIES   (FIDO_HID_CAP_CBOR | FIDO_HID_CAP_NMSG)

/* Error codes for CTAPHID_ERROR (1-byte payload). FIDO U2F HID spec §3.4.4. */
#define FIDO_HID_ERR_INVALID_CMD      0x01u
#define FIDO_HID_ERR_INVALID_PAR      0x02u
#define FIDO_HID_ERR_INVALID_LEN      0x03u
#define FIDO_HID_ERR_INVALID_SEQ      0x04u
#define FIDO_HID_ERR_MSG_TIMEOUT      0x05u
#define FIDO_HID_ERR_CHANNEL_BUSY     0x06u
#define FIDO_HID_ERR_LOCK_REQUIRED    0x0Au
#define FIDO_HID_ERR_INVALID_CHANNEL  0x0Bu
#define FIDO_HID_ERR_OTHER            0x7Fu

/* Maximum payload we accept in a single CTAPHID transaction. CTAPHID
 * theoretical max is 7609 B (1 INIT + 128 CONT @ 59); we cap lower to
 * conserve SRAM. CTAP2 messages are typically <2 KB. */
#define FIDO_HID_MAX_PAYLOAD          2048u

/* Device version triple (major.minor.build). Bumped by hand on protocol
 * changes; the FIDO spec only requires plausibility. */
#define FIDO_HID_DEVICE_VER_MAJOR  0u
#define FIDO_HID_DEVICE_VER_MINOR  4u    /* Phase 4 */
#define FIDO_HID_DEVICE_VER_BUILD  0u

/* CID allocation pool. Real authenticators recycle on idle timeout; we
 * just hand out monotonic IDs up to this cap (then refuse new INITs). */
#define FIDO_HID_MAX_CHANNELS         32u

#endif /* NIXTROPIC_FIDO_HID_PROTO_H */
