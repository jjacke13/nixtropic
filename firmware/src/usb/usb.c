/*
 * USB peripheral bring-up — see usb.h.
 *
 * Sequence is intentionally explicit (no HAL helper for U5 USB pcd)
 * so we can debug at the register level if anything goes sideways.
 * TinyUSB handles everything from `tusb_init` onward.
 *
 * STM32U5-specific quirks baked in here:
 *   - VDDUSB must be enabled BEFORE the USB peripheral RCC clock,
 *     otherwise PA11/PA12 stay HIGH-Z and the host never sees us.
 *   - PA12 renumeration trick — briefly drive PA12 (USB D+) LOW
 *     before AF mux to force the host to re-enumerate.  Required if
 *     the dongle is reset while the host has it cached as DFU.
 *   - Use the **fsdev** TinyUSB driver (not dwc2) — see tusb_config.h.
 *   - USB_IRQHandler is the correct ISR symbol on U5 (NOT OTG_FS_IRQHandler).
 *
 * Reference: STM32U5 reference manual RM0456 §40 (USB-FS), AN5483
 * (USB-FS without external crystal via HSI48 + CRS).
 */

#include "usb.h"
#include "usb_ccid.h"
#include "platform/board.h"

#include "stm32u5xx_hal.h"
#include "tusb.h"
#include "device/usbd.h"
#include "device/usbd_pvt.h"

/* ----- USB clock (HSI48 + CRS) ----- */

int usb_clock_init(void)
{
    /* HSI48 is the 48 MHz internal RC oscillator. Independent of the
     * 8 MHz HSE that drives SYSCLK. We enable it for USB FS kernel clock,
     * then sync via CRS using USB SOF as reference (auto-trim against
     * the host's USB clock — keeps HSI48 within USB ±500 ppm spec). */

    RCC_OscInitTypeDef osc = {0};
    osc.OscillatorType  = RCC_OSCILLATORTYPE_HSI48;
    osc.HSI48State      = RCC_HSI48_ON;
    osc.PLL.PLLState    = RCC_PLL_NONE;  /* don't touch PLL — already configured */

    if (HAL_RCC_OscConfig(&osc) != HAL_OK) {
        return 1;
    }

    /* Set USB FS kernel clock source = HSI48.
     * On U5 the USB FS shares an "intermediate clock" (ICLK) with RNG and
     * SDMMC1. RCC_PERIPHCLK_ICLK + IclkClockSelection select the source
     * for ALL three peripherals — but RNG separately picks via
     * RCC_PERIPHCLK_RNG/RngClockSelection (handled in rng.c). */
    RCC_PeriphCLKInitTypeDef pclk = {0};
    pclk.PeriphClockSelection = RCC_PERIPHCLK_ICLK;
    pclk.IclkClockSelection   = RCC_ICLK_CLKSOURCE_HSI48;

    if (HAL_RCCEx_PeriphCLKConfig(&pclk) != HAL_OK) {
        return 2;
    }

    /* CRS: synchronize HSI48 against USB SOF. Default settings work for
     * USB FS — the autotrim pulls HSI48 to within USB clock tolerance. */
    __HAL_RCC_CRS_CLK_ENABLE();

    RCC_CRSInitTypeDef crs = {0};
    crs.Prescaler        = RCC_CRS_SYNC_DIV1;
    crs.Source           = RCC_CRS_SYNC_SOURCE_USB;
    crs.Polarity         = RCC_CRS_SYNC_POLARITY_RISING;
    /* HSI48 is 48 MHz; USB SOF every 1 ms = 48000 cycles per SOF. */
    crs.ReloadValue      = RCC_CRS_RELOADVALUE_DEFAULT;  /* 0xBB7F = 48000-1 */
    crs.ErrorLimitValue  = RCC_CRS_ERRORLIMIT_DEFAULT;
    crs.HSI48CalibrationValue = RCC_CRS_HSI48CALIBRATION_DEFAULT;

    HAL_RCCEx_CRSConfig(&crs);

    return 0;
}

/* ----- USB peripheral init ----- */

int usb_init(void)
{
    /* Step 1: enable VDDUSB — the USB voltage monitor / supply must be
     * explicitly enabled BEFORE any USB peripheral access on U5,
     * else the peripheral hangs in reset state.
     * Per inventory §13.5 + stock fw `sys.c:25`. */
    HAL_PWREx_EnableVddUSB();

    /* Step 2: enable USB peripheral RCC clock. On U5 the USB FS DRD is
     * on AHB2 (RCC_AHB2ENR1_USB_FSEN). Macro handles bus selection. */
    __HAL_RCC_USB_FS_CLK_ENABLE();

    /* Step 3: PA12 renumeration trick — drive PA12 LOW as GPIO output
     * for ~50 ms before handing it to USB AF. Forces clean disconnect+
     * reconnect cycle on the host so the new firmware enumerates fresh
     * after a DFU flash without needing physical replug.
     * Per inventory §7 + stock TS1302 `app/main.c:42-47`. */
    GPIO_InitTypeDef cfg = {0};
    cfg.Pin   = BOARD_USB_DP_PIN;
    cfg.Mode  = GPIO_MODE_OUTPUT_PP;
    cfg.Pull  = GPIO_NOPULL;
    cfg.Speed = GPIO_SPEED_FREQ_HIGH;
    HAL_GPIO_Init(BOARD_USB_PORT, &cfg);
    HAL_GPIO_WritePin(BOARD_USB_PORT, BOARD_USB_DP_PIN, GPIO_PIN_RESET);
    HAL_Delay(50);

    /* Step 4: PA11/PA12 → AF10 (USB) */
    cfg.Pin       = BOARD_USB_DM_PIN | BOARD_USB_DP_PIN;
    cfg.Mode      = GPIO_MODE_AF_PP;
    cfg.Pull      = GPIO_NOPULL;
    cfg.Speed     = GPIO_SPEED_FREQ_VERY_HIGH;
    cfg.Alternate = GPIO_AF10_USB;
    HAL_GPIO_Init(BOARD_USB_PORT, &cfg);

    /* Step 5: NVIC — set USB IRQ priority below SysTick, enable. */
    HAL_NVIC_SetPriority(USB_IRQn, 5, 0);
    HAL_NVIC_EnableIRQ(USB_IRQn);

    /* Step 6: hand off to TinyUSB. */
    if (!tusb_init()) {
        return 1;
    }

    return 0;
}

/* ----- USB IRQ handler ----- */

/* CMSIS interrupt name on U535 is USB_IRQHandler (vector 73, see
 * stm32u535xx.h). NOT OTG_FS_IRQHandler — that's for U5 variants with
 * OTG (U575/U585), which we don't have. */
void USB_IRQHandler(void)
{
    tud_int_handler(0);
}

/* ----- Application class driver registration -----
 *
 * Phase 7 M1 adds USB CCID via a TinyUSB application class driver
 * (TinyUSB upstream has no CCID class driver).  We supply the
 * driver via this hook; TinyUSB iterates it alongside its built-in
 * CDC/HID drivers when binding interfaces from the config descriptor.
 *
 * The driver's open() callback claims interfaces whose
 * bInterfaceClass == TUSB_CLASS_SMART_CARD (0x0B). */
static const usbd_class_driver_t s_app_drivers[] = {
    /* index 0: CCID smart-card driver — usb_ccid.c */
    /* Initialised at runtime — TinyUSB API not allowed at static init time. */
    {0}
};

usbd_class_driver_t const *usbd_app_driver_get_cb(uint8_t *driver_count)
{
    /* Single CCID driver, defined in usb_ccid.c.  We return the
     * address of the externed const struct.  driver_count = 1. */
    static usbd_class_driver_t const *const drivers_ptr = &usb_ccid_driver;
    (void) s_app_drivers;  /* placeholder kept for future expansion */
    *driver_count = 1;
    return drivers_ptr;
}
