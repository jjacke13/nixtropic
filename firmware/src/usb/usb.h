/*
 * USB CDC bring-up — see usb.c.
 *
 * Group C public API:
 *   usb_clock_init()  — HSI48 + CRS for USB peripheral kernel clock
 *   usb_init()        — VDDUSB enable, PA11/12 AF mux, PA12 renumeration trick,
 *                       enable USB peripheral RCC clock, then tusb_init
 *   USB_IRQHandler()  — defined in usb.c, routes to tud_int_handler(0)
 *
 * After usb_init, caller must poll tud_task() in the main loop.
 */

#ifndef NIXTROPIC_USB_H
#define NIXTROPIC_USB_H

/**
 * @brief Configure HSI48 + CRS for USB FS kernel clock.
 *
 * Call after clock_init() (so SYSCLK is at 48 MHz; HSI48 is independent
 * but CRS uses USB SOF as reference for auto-trim, so we want SystemCoreClock
 * accurate first). On U5, USB FS kernel clock can be HSI48 (CRS-trimmed)
 * or PLL Q output. Stock TS1302 fw uses HSI48 + CRS; we mirror that.
 *
 * @return 0 on success, non-zero on failure.
 */
int usb_clock_init(void);

/**
 * @brief Initialize USB peripheral and TinyUSB stack.
 *
 * Must be called after usb_clock_init() and gpio_init(). Steps:
 *   1. Enable VDDUSB (PWR_SVMCR_USV — USB voltage detector enable).
 *   2. Enable USB peripheral RCC clock.
 *   3. PA12 renumeration trick: drive PA12 LOW briefly before AF10.
 *   4. Configure PA11/PA12 to USB AF (AF10).
 *   5. Set NVIC priority for USB IRQ, enable IRQ.
 *   6. Call tusb_init().
 *
 * @return 0 on success, non-zero on failure.
 */
int usb_init(void);

#endif /* NIXTROPIC_USB_H */
