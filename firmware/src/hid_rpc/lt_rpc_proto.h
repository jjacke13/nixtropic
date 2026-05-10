/*
 * lt-rpc wire-format constants — shared between firmware and host (Python).
 *
 * CTAPHID-derived framing for vendor RPC over 64-byte HID reports. We
 * use a single fixed channel ID for Phase 3; multi-channel CID negotiation
 * (CTAPHID_INIT 0x86) arrives with FIDO2 in Phase 4.
 *
 * INIT packet (first or only):
 *   byte 0..3   CID      0xCAFE0001 BE
 *   byte 4      CMD      0x80 | cmd_id  (top bit set marks INIT)
 *   byte 5..6   BCNT     total payload length, big-endian uint16
 *   byte 7..63  DATA     up to 57 bytes of payload
 *
 * CONT packet (continuation, only when BCNT > 57):
 *   byte 0..3   CID      0xCAFE0001 BE
 *   byte 4      SEQ      0..0x7F (top bit clear); SEQ counts from 0
 *   byte 5..63  DATA     up to 59 bytes of payload
 */

#ifndef NIXTROPIC_LT_RPC_PROTO_H
#define NIXTROPIC_LT_RPC_PROTO_H

#define LT_RPC_HID_REPORT_LEN   64
#define LT_RPC_INIT_DATA_LEN    57   /* 64 - (4 CID + 1 CMD + 2 BCNT) */
#define LT_RPC_CONT_DATA_LEN    59   /* 64 - (4 CID + 1 SEQ) */

#define LT_RPC_CID_DEFAULT      0xCAFE0001UL

#define LT_RPC_CMD_INIT_FLAG    0x80u

/* M2 commands */
#define LT_RPC_CMD_PING         0x01u
#define LT_RPC_CMD_GET_RANDOM   0x02u

/* M3 command */
#define LT_RPC_CMD_CHIP_ID      0x03u

/* M4 commands */
#define LT_RPC_CMD_ECC_GENERATE 0x04u
#define LT_RPC_CMD_ECC_SIGN     0x05u
#define LT_RPC_CMD_ECC_PUBKEY   0x06u

/* Reserved: device-emitted error response */
#define LT_RPC_CMD_ERROR        0x3Fu

/* Error codes inside an ERROR payload (1 byte) */
#define LT_RPC_ERR_INVALID_CMD      0x01u
#define LT_RPC_ERR_INVALID_LEN      0x02u
#define LT_RPC_ERR_BUSY             0x03u
#define LT_RPC_ERR_CID_MISMATCH     0x04u
#define LT_RPC_ERR_OTHER            0xFFu

/* Maximum payload size we accept in a single transaction. CTAPHID's spec
 * is 7609 bytes; we cap lower because TROPIC01 L2/L3 transactions fit in
 * a few KB at most. */
#define LT_RPC_MAX_PAYLOAD          1024

#endif /* NIXTROPIC_LT_RPC_PROTO_H */
