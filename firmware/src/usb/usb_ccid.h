/*
 * TinyUSB application class driver for USB CCID 1.1 — public glue.
 *
 * Exposes the driver via TinyUSB's `usbd_app_driver_get_cb()` hook
 * (called in usb.c).  Driver implements the 5 standard class-driver
 * callbacks plus the CCID bulk-out → APDU → bulk-in pump.
 *
 * Public surface is intentionally tiny: callers don't talk to the
 * CCID layer directly — they go through the TinyUSB device stack
 * which calls our driver via the registered usbd_class_driver_t.
 *
 * APDU dispatch + the OpenPGP applet itself live in
 * firmware/src/ccid/ + firmware/src/openpgp/.
 */

#ifndef NIXTROPIC_USB_CCID_H
#define NIXTROPIC_USB_CCID_H

#include <stdint.h>
#include "device/usbd_pvt.h"  /* usbd_class_driver_t */

/* Returned to TinyUSB by usbd_app_driver_get_cb() in usb.c. */
extern const usbd_class_driver_t usb_ccid_driver;

/* Bulk endpoint addresses — defined in usb_descriptors.c so the descriptor
 * and the driver agree.  Declared here so usb_ccid.c can post transfers
 * on them without dragging in the descriptor file. */
extern const uint8_t USB_CCID_EP_OUT;
extern const uint8_t USB_CCID_EP_IN;

#endif /* NIXTROPIC_USB_CCID_H */
