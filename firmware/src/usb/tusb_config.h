/*
 * TinyUSB user configuration for nixtropic Phase 1.
 *
 * Per plan decision P1.14: CDC-ACM only, single interface. HID and CCID
 * come in later phases. CFG_TUSB_MCU=OPT_MCU_STM32U5 is set in the
 * CMake toolchain (drives fsdev_stm32.h's U5 register-name remapping).
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
#define CFG_TUD_HID                 0
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

/* CDC-specific */
#define CFG_TUD_CDC_RX_BUFSIZE      64
#define CFG_TUD_CDC_TX_BUFSIZE      256   /* allow some buffering for printf bursts */
#define CFG_TUD_CDC_EP_BUFSIZE      64

#ifdef __cplusplus
}
#endif

#endif /* NIXTROPIC_TUSB_CONFIG_H */
