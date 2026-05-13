/*
 * USB CCID 1.1 protocol structures — wire-level message header types,
 * status/error bytes, and slot-status definitions.
 *
 * Reference: "Universal Serial Bus Device Class: Smart Card CCID
 * Specification for Integrated Circuit(s) Cards Interface Devices",
 * Revision 1.1 (USB-IF):
 *   https://www.usb.org/sites/default/files/DWG_Smart-Card_CCID_Rev110.pdf
 *
 * Wire byte order: little-endian for all multi-byte CCID fields.
 * (ISO 7816-4 APDUs inside CCID payloads are their own thing —
 * see firmware/src/ccid/apdu_dispatch.h.)
 *
 * Message structures use __attribute__((packed)) so the layout
 * matches the wire exactly.  All field offsets are spec-mandated.
 */

#ifndef NIXTROPIC_CCID_PROTO_H
#define NIXTROPIC_CCID_PROTO_H

#include <stdint.h>
#include <stddef.h>

/* ---- CCID message types (bMessageType field) ---- */

/* PC → Reader (bulk-out) */
#define CCID_PC_TO_RDR_IccPowerOn       0x62
#define CCID_PC_TO_RDR_IccPowerOff      0x63
#define CCID_PC_TO_RDR_GetSlotStatus    0x65
#define CCID_PC_TO_RDR_XfrBlock         0x6F
#define CCID_PC_TO_RDR_GetParameters    0x6C
#define CCID_PC_TO_RDR_ResetParameters  0x6D
#define CCID_PC_TO_RDR_SetParameters    0x61
#define CCID_PC_TO_RDR_Escape           0x6B
#define CCID_PC_TO_RDR_IccClock         0x6E
#define CCID_PC_TO_RDR_TxData           0x73
#define CCID_PC_TO_RDR_Mechanical       0x71
#define CCID_PC_TO_RDR_Abort            0x72
#define CCID_PC_TO_RDR_SetDataRate      0x73

/* Reader → PC (bulk-in) */
#define CCID_RDR_TO_PC_DataBlock        0x80
#define CCID_RDR_TO_PC_SlotStatus       0x81
#define CCID_RDR_TO_PC_Parameters       0x82
#define CCID_RDR_TO_PC_Escape           0x83
#define CCID_RDR_TO_PC_DataRate         0x84

/* ---- bStatus byte breakdown (CCID spec §6.2.6) ---- */

/* bmICCStatus — bits 1..0 */
#define CCID_ICC_STATUS_ACTIVE          0x00  /* ICC present and active */
#define CCID_ICC_STATUS_PRESENT_INACT   0x01  /* ICC present, inactive */
#define CCID_ICC_STATUS_NOT_PRESENT     0x02  /* No ICC */

/* bmCommandStatus — bits 7..6 */
#define CCID_CMD_STATUS_SUCCESS         0x00
#define CCID_CMD_STATUS_FAILED          0x40
#define CCID_CMD_STATUS_TIME_EXT        0x80

/* bError codes (CCID spec §6.2.6 Table 6.2-2) — abridged */
#define CCID_ERROR_NONE                 0x00
#define CCID_ERROR_CMD_NOT_SUPPORTED    0x00  /* with bmCommandStatus=FAILED */
#define CCID_ERROR_HW_ERROR             0xFB
#define CCID_ERROR_ICC_MUTE             0xFE
#define CCID_ERROR_XFR_PARITY           0xFD
#define CCID_ERROR_BAD_ATR_TS           0xF8

/* ---- Bulk-out message header (10 bytes; same prefix on every PC→RDR cmd) ---- */

typedef struct __attribute__((packed)) {
    uint8_t  bMessageType;
    uint32_t dwLength;          /* LE; payload bytes after this 10-byte header */
    uint8_t  bSlot;
    uint8_t  bSeq;
    uint8_t  abRFU[3];          /* type-specific; e.g. bPowerSelect, bBWI, wLevelParameter */
} ccid_bulk_out_hdr_t;

/* ---- Bulk-in message header (10 bytes; same prefix on every RDR→PC response) ---- */

typedef struct __attribute__((packed)) {
    uint8_t  bMessageType;
    uint32_t dwLength;          /* LE; payload bytes after this 10-byte header */
    uint8_t  bSlot;
    uint8_t  bSeq;              /* echoed from the corresponding request */
    uint8_t  bStatus;           /* bmICCStatus | bmCommandStatus */
    uint8_t  bError;
    uint8_t  bRFU;              /* type-specific; e.g. bChainParameter for DataBlock */
} ccid_bulk_in_hdr_t;

#define CCID_HDR_LEN            10u

/* ---- ATR (Answer to Reset) — returned on PC_to_RDR_IccPowerOn ----
 *
 * Defined as static const inside usb_ccid.c (only one user — no need
 * to publish via extern).  M2 OpenPGP applet may grow the ATR with
 * historical bytes when we want host tools to identify the applet
 * before SELECT.  For M1 we use the minimal valid 4-byte T=1 form;
 * see comment in usb_ccid.c for the breakdown. */

/* ---- Standard ISO 7816 status words (SW1 SW2) ---- */
#define SW_OK                           0x9000
#define SW_WRONG_LENGTH                 0x6700
#define SW_SECURITY_NOT_SATISFIED       0x6982
#define SW_AUTH_BLOCKED                 0x6983
#define SW_CONDITIONS_NOT_SATISFIED     0x6985
#define SW_INCORRECT_DATA               0x6A80
#define SW_FILE_NOT_FOUND               0x6A82
#define SW_INCORRECT_P1P2               0x6A86
#define SW_REF_DATA_NOT_FOUND           0x6A88
#define SW_INS_NOT_SUPPORTED            0x6D00
#define SW_CLA_NOT_SUPPORTED            0x6E00
#define SW_UNKNOWN_ERROR                0x6F00

#endif /* NIXTROPIC_CCID_PROTO_H */
