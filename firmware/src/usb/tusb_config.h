/*
 * TinyUSB user configuration for nixtropic — composite device:
 * CDC-ACM + HID×2 (lt-rpc + FIDO) + CCID smart card.
 *
 * CFG_TUSB_MCU = OPT_MCU_STM32U5 is set in the CMake toolchain (drives
 * fsdev_stm32.h's U5 register-name remapping).  We use the **fsdev**
 * driver (the U5 USB-FS peripheral is a Synopsys fsdev variant), NOT
 * dwc2; using the wrong driver enumerates the device incorrectly or
 * not at all.
 *
 * Upstream: TinyUSB (https://github.com/hathach/tinyusb).  Vendored
 * via Nix flake input pinning — see flake.nix.
 */

#ifndef NIXTROPIC_TUSB_CONFIG_H
#define NIXTROPIC_TUSB_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

/* ---- General config ---- */
#define CFG_TUSB_OS                 OPT_OS_NONE
#define CFG_TUSB_DEBUG              0

/* TinyUSB 0.20.0+ requires TUD_OPT_RHPORT defined for the no-arg
 * tusb_init() form to resolve to a real call. Without it, tusb_init()
 * expands to a `_Static_assert(false, ...)` at function scope (compile
 * error: "expected expression before _Static_assert"). U535 has only
 * one root-hub port; rhport 0. */
#define TUD_OPT_RHPORT              0

/* TinyUSB runs without RTOS; all section/align macros default. */
#define CFG_TUSB_MEM_SECTION
#define CFG_TUSB_MEM_ALIGN          __attribute__ ((aligned(4)))

/* ---- Device config ---- */
#define CFG_TUD_ENABLED             1
#define CFG_TUD_MAX_SPEED           OPT_MODE_FULL_SPEED  /* U5 USB FS only */
#define CFG_TUD_ENDPOINT0_SIZE      64

/* Class enable flags */
#define CFG_TUD_CDC                 1
#define CFG_TUD_MSC                 0
#define CFG_TUD_HID                 2   /* Phase 4: instance 0 = lt-rpc, instance 1 = FIDO2 */
#define CFG_TUD_MIDI                0
#define CFG_TUD_VENDOR              0
#define CFG_TUD_VIDEO               0
#define CFG_TUD_AUDIO               0
#define CFG_TUD_DFU                 0
#define CFG_TUD_DFU_RUNTIME         0
#define CFG_TUD_BTH                 0
#define CFG_TUD_NCM                 0
#define CFG_TUD_USBTMC              0
#define CFG_TUD_ECM_RNDIS           0

/* CDC-specific.
 *
 * TX FIFO must hold the largest single hex-passthrough response. Stock-fw
 * protocol echoes 2 hex chars per SPI byte + "\r\n". With SPI_BUF_SIZE
 * = 512 (matches stock fw _SPI_BUF_SIZE), worst-case output is 512*2 + 2
 * = 1026 bytes per hex line. We round up to 2048 for headroom — cost is
 * 2 KB SRAM (we have 192 KB).
 *
 * Phase 2 verified failure (2026-05-10): with 256 B FIFO, chip_id read
 * (~130 byte L1 response → 262 byte hex output) overflowed the FIFO,
 * dropped trailing bytes, host short-read → LT_L1_SPI_ERROR. */
#define CFG_TUD_CDC_RX_BUFSIZE      256
#define CFG_TUD_CDC_TX_BUFSIZE      2048
#define CFG_TUD_CDC_EP_BUFSIZE      64

/* HID-specific (Phase 3). 64-byte raw vendor reports — same shape as
 * CTAPHID. EP buffer size set to one report; full lt-rpc messages are
 * reassembled in software in hid_rpc/rpc.c. */
#define CFG_TUD_HID_EP_BUFSIZE      64

#ifdef __cplusplus
}
#endif

#endif /* NIXTROPIC_TUSB_CONFIG_H */
