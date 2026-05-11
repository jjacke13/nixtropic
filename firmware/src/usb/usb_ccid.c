/*
 * Phase 7 M1 — TinyUSB application class driver for USB CCID.
 *
 * Implements the bare minimum to enumerate as a pcsc-lite-detectable
 * CCID reader and round-trip raw APDUs:
 *
 *   PC_to_RDR_IccPowerOn   → RDR_to_PC_DataBlock  (ATR)
 *   PC_to_RDR_IccPowerOff  → RDR_to_PC_SlotStatus
 *   PC_to_RDR_GetSlotStatus → RDR_to_PC_SlotStatus
 *   PC_to_RDR_XfrBlock     → RDR_to_PC_DataBlock  (APDU response via apdu_dispatch)
 *   PC_to_RDR_{Get,Reset,Set}Parameters → RDR_to_PC_Parameters
 *   Anything else          → RDR_to_PC_SlotStatus (FAILED + CMD_NOT_SUPPORTED)
 *
 * M2 extends apdu_dispatch.c with real OpenPGP applet INS handling;
 * this file (the USB transport) doesn't change.
 *
 * State model (single command in flight at a time):
 *
 *    open() ─→ post EP_OUT receive ─→ host writes
 *                                          │
 *                                          ▼
 *                                    process_message()
 *                                          │
 *                                          ▼
 *                                  post EP_IN transmit
 *                                          │
 *                                          ▼ on IN xfer done
 *                                  post next EP_OUT receive
 *
 * pcsc-lite serialises commands per-slot, so we don't need a queue.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "tusb.h"
#include "device/usbd.h"
#include "device/usbd_pvt.h"

#include "usb_ccid.h"
#include "ccid/ccid_proto.h"
#include "ccid/apdu_dispatch.h"

/* Max single CCID message size we accept.  4096 B APDU body + 10 B
 * header + small headroom = round to 4112 for 16-byte alignment.
 * The biggest extended-length APDU we handle is 4096 B; bigger gets
 * rejected at the apdu_dispatch layer with SW=0x6700 (Wrong length). */
#define CCID_MAX_MSG_LEN  4112u

/* ATR returned on PC_to_RDR_IccPowerOn.  Minimal valid T=1 form:
 *   TS=3B, T0=80, TD1=81, TD2=31, TCK=30
 * (XOR(T0..TD2) = 0x30, so TCK=0x30 makes the full XOR zero.) */
static const uint8_t s_atr[] = { 0x3B, 0x80, 0x81, 0x31, 0x30 };
static const uint8_t s_atr_len = sizeof s_atr;

/* T=1 parameters returned on Get/Reset/SetParameters.  Spec §6.2.3 (T=1).
 * Canned values that pcsc-lite accepts as-is. */
static const uint8_t s_t1_params[] = {
    0x11,  /* bmFindexDindex      */
    0x10,  /* bmTCCKST1           */
    0x00,  /* bGuardTimeT1        */
    0x4D,  /* bmWaitingIntegerT1  */
    0x00,  /* bClockStop          */
    0xFE,  /* bIFSC (max IFSC)    */
    0x00,  /* bNadValue           */
};

/* ----- Driver state ----- */

static uint8_t  s_itf_num;
static uint8_t  s_rx_buf[CCID_MAX_MSG_LEN];
static uint8_t  s_tx_buf[CCID_MAX_MSG_LEN];
static uint16_t s_tx_len;

/* ----- Little-endian helpers (CCID uses LE; ISO 7816 uses BE — keep
 *       distinct to avoid mixing) ----- */

static uint32_t le32_load(const uint8_t *p)
{
    return (uint32_t) p[0]
         | ((uint32_t) p[1] << 8)
         | ((uint32_t) p[2] << 16)
         | ((uint32_t) p[3] << 24);
}

static void le32_store(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)( v        & 0xFFu);
    p[1] = (uint8_t)((v >>  8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

/* Build the 10-byte bulk-in header.  Returns bytes written (always 10). */
static uint16_t fill_bulk_in_hdr(uint8_t *out, uint8_t msg_type,
                                  uint32_t payload_len, uint8_t bSeq,
                                  uint8_t bStatus, uint8_t bError, uint8_t bRFU)
{
    out[0] = msg_type;
    le32_store(&out[1], payload_len);
    out[5] = 0;            /* bSlot = 0 (single-slot reader) */
    out[6] = bSeq;
    out[7] = bStatus;
    out[8] = bError;
    out[9] = bRFU;
    return CCID_HDR_LEN;
}

/* ----- Response builders ----- */

static void resp_power_on(uint8_t bSeq)
{
    uint16_t off = fill_bulk_in_hdr(s_tx_buf, CCID_RDR_TO_PC_DataBlock,
                                     (uint32_t) s_atr_len, bSeq,
                                     (uint8_t)(CCID_ICC_STATUS_ACTIVE | CCID_CMD_STATUS_SUCCESS),
                                     CCID_ERROR_NONE, 0);
    memcpy(&s_tx_buf[off], s_atr, s_atr_len);
    s_tx_len = (uint16_t)(off + s_atr_len);
}

static void resp_slot_status(uint8_t bSeq, uint8_t bStatus, uint8_t bError)
{
    fill_bulk_in_hdr(s_tx_buf, CCID_RDR_TO_PC_SlotStatus,
                     0, bSeq, bStatus, bError,
                     0 /* bClockStatus = 00 (running) */);
    s_tx_len = CCID_HDR_LEN;
}

static void resp_parameters(uint8_t bSeq)
{
    uint16_t off = fill_bulk_in_hdr(s_tx_buf, CCID_RDR_TO_PC_Parameters,
                                     (uint32_t) sizeof s_t1_params, bSeq,
                                     (uint8_t)(CCID_ICC_STATUS_ACTIVE | CCID_CMD_STATUS_SUCCESS),
                                     CCID_ERROR_NONE,
                                     0x01 /* bProtocolNum = T=1 */);
    memcpy(&s_tx_buf[off], s_t1_params, sizeof s_t1_params);
    s_tx_len = (uint16_t)(off + sizeof s_t1_params);
}

static void resp_xfr_block(uint8_t bSeq, const uint8_t *apdu, size_t apdu_len)
{
    static uint8_t apdu_resp[APDU_MAX_LEN];
    size_t  apdu_resp_len = 0;

    int rc = apdu_dispatch_process(apdu, apdu_len,
                                    apdu_resp, sizeof apdu_resp, &apdu_resp_len);
    if (rc != 0 || apdu_resp_len < 2u) {
        resp_slot_status(bSeq,
                         (uint8_t)(CCID_ICC_STATUS_ACTIVE | CCID_CMD_STATUS_FAILED),
                         CCID_ERROR_HW_ERROR);
        return;
    }

    if (CCID_HDR_LEN + apdu_resp_len > sizeof s_tx_buf) {
        resp_slot_status(bSeq,
                         (uint8_t)(CCID_ICC_STATUS_ACTIVE | CCID_CMD_STATUS_FAILED),
                         CCID_ERROR_HW_ERROR);
        return;
    }

    uint16_t off = fill_bulk_in_hdr(s_tx_buf, CCID_RDR_TO_PC_DataBlock,
                                     (uint32_t) apdu_resp_len, bSeq,
                                     (uint8_t)(CCID_ICC_STATUS_ACTIVE | CCID_CMD_STATUS_SUCCESS),
                                     CCID_ERROR_NONE, 0);
    memcpy(&s_tx_buf[off], apdu_resp, apdu_resp_len);
    s_tx_len = (uint16_t)(off + apdu_resp_len);
}

/* ----- Dispatch a complete bulk-out message ----- */

static void process_message(const uint8_t *msg, size_t len)
{
    if (len < CCID_HDR_LEN) {
        /* Too short to even read the header — drop. */
        s_tx_len = 0;
        return;
    }

    uint8_t  msg_type = msg[0];
    uint32_t payload_len = le32_load(&msg[1]);
    uint8_t  bSeq = msg[6];

    /* Defense against length-spoofing — declared payload must fit
     * within bytes we actually received. */
    if (payload_len > (uint32_t)(len - CCID_HDR_LEN)) {
        resp_slot_status(bSeq,
                         (uint8_t)(CCID_ICC_STATUS_ACTIVE | CCID_CMD_STATUS_FAILED),
                         CCID_ERROR_HW_ERROR);
        return;
    }

    switch (msg_type) {
    case CCID_PC_TO_RDR_IccPowerOn:
        resp_power_on(bSeq);
        break;

    case CCID_PC_TO_RDR_IccPowerOff:
        resp_slot_status(bSeq,
                         (uint8_t)(CCID_ICC_STATUS_PRESENT_INACT | CCID_CMD_STATUS_SUCCESS),
                         CCID_ERROR_NONE);
        break;

    case CCID_PC_TO_RDR_GetSlotStatus:
        resp_slot_status(bSeq,
                         (uint8_t)(CCID_ICC_STATUS_ACTIVE | CCID_CMD_STATUS_SUCCESS),
                         CCID_ERROR_NONE);
        break;

    case CCID_PC_TO_RDR_XfrBlock:
        resp_xfr_block(bSeq, &msg[CCID_HDR_LEN], (size_t) payload_len);
        break;

    case CCID_PC_TO_RDR_GetParameters:
    case CCID_PC_TO_RDR_ResetParameters:
    case CCID_PC_TO_RDR_SetParameters:
        resp_parameters(bSeq);
        break;

    default:
        resp_slot_status(bSeq,
                         (uint8_t)(CCID_ICC_STATUS_ACTIVE | CCID_CMD_STATUS_FAILED),
                         CCID_ERROR_CMD_NOT_SUPPORTED);
        break;
    }
}

/* ===== TinyUSB class driver callbacks ===== */

static void ccid_init(void)
{
    memset(s_rx_buf, 0, sizeof s_rx_buf);
    memset(s_tx_buf, 0, sizeof s_tx_buf);
    s_tx_len = 0;
    s_itf_num = 0xFFu;
}

static bool ccid_deinit(void)
{
    return true;
}

static void ccid_reset(uint8_t rhport)
{
    (void) rhport;
    ccid_init();
}

static uint16_t ccid_open(uint8_t rhport,
                          tusb_desc_interface_t const *itf_desc,
                          uint16_t max_len)
{
    /* Claim only USB class 0x0B (CCID / Smart Card). */
    if (itf_desc->bInterfaceClass != TUSB_CLASS_SMART_CARD) {
        return 0;
    }

    s_itf_num = itf_desc->bInterfaceNumber;

    uint8_t const *p_desc = tu_desc_next((uint8_t const *) itf_desc);
    uint16_t consumed = (uint16_t) itf_desc->bLength;

    /* CCID functional descriptor (class-specific, type 0x21) — skip.
     * Contents are advisory; usb_descriptors.c emits a sane one. */
    if (consumed < max_len && p_desc[1] == 0x21u) {
        consumed += (uint16_t) p_desc[0];
        p_desc = tu_desc_next(p_desc);
    }

    /* Two bulk endpoints (out then in). */
    int ep_count = itf_desc->bNumEndpoints;
    while (ep_count > 0 && consumed < max_len) {
        if (p_desc[1] != TUSB_DESC_ENDPOINT) {
            break;
        }
        tusb_desc_endpoint_t const *ep_desc =
            (tusb_desc_endpoint_t const *) p_desc;
        if (!usbd_edpt_open(rhport, ep_desc)) {
            return 0;
        }
        consumed += (uint16_t) ep_desc->bLength;
        p_desc = tu_desc_next(p_desc);
        ep_count--;
    }

    /* Arm the first receive — host can now send commands. */
    if (!usbd_edpt_xfer(rhport, USB_CCID_EP_OUT, s_rx_buf, sizeof s_rx_buf)) {
        return 0;
    }

    return consumed;
}

static bool ccid_control_xfer_cb(uint8_t rhport, uint8_t stage,
                                  tusb_control_request_t const *request)
{
    (void) rhport;
    (void) stage;
    (void) request;
    /* CCID class control requests (ABORT, GET_CLOCK_FREQUENCIES,
     * GET_DATA_RATES) — pcsc-lite tolerates missing handlers (falls
     * back to functional-descriptor defaults).  M1 STALLs all of them. */
    return false;
}

static bool ccid_xfer_cb(uint8_t rhport, uint8_t ep_addr,
                          xfer_result_t result, uint32_t xferred_bytes)
{
    (void) result;

    if (ep_addr == USB_CCID_EP_OUT) {
        process_message(s_rx_buf, (size_t) xferred_bytes);
        if (s_tx_len > 0) {
            if (!usbd_edpt_xfer(rhport, USB_CCID_EP_IN, s_tx_buf, s_tx_len)) {
                /* Couldn't queue TX — drop the response, re-arm RX so
                 * the host's retry will land somewhere. */
                s_tx_len = 0;
                usbd_edpt_xfer(rhport, USB_CCID_EP_OUT, s_rx_buf,
                               sizeof s_rx_buf);
            }
        } else {
            /* No response (truly malformed) — re-arm RX immediately. */
            usbd_edpt_xfer(rhport, USB_CCID_EP_OUT, s_rx_buf, sizeof s_rx_buf);
        }
    } else if (ep_addr == USB_CCID_EP_IN) {
        s_tx_len = 0;
        usbd_edpt_xfer(rhport, USB_CCID_EP_OUT, s_rx_buf, sizeof s_rx_buf);
    }

    return true;
}

/* ===== Public class-driver table ===== */

const usbd_class_driver_t usb_ccid_driver = {
#if CFG_TUSB_DEBUG >= 2
    .name = "CCID",
#endif
    .init             = ccid_init,
    .deinit           = ccid_deinit,
    .reset            = ccid_reset,
    .open             = ccid_open,
    .control_xfer_cb  = ccid_control_xfer_cb,
    .xfer_cb          = ccid_xfer_cb,
    .sof              = NULL,
};
