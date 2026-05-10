/*
 * Phase 2 firmware main — USB CDC ↔ SPI passthrough (stock-protocol-compatible).
 *
 * Boot sequence (LED diagnostic codes mirror Phase 1):
 *   Stage 0  — raw GPIO 4 quick blinks (proves CPU runs our code)
 *   Stage 1  — HAL_Init                          on fail: 6-blink pattern
 *   Stage 2  — clock_init (48 MHz)               on fail: 1-blink pattern
 *   Stage 3  — gpio_init
 *   Stage 4  — spi_init                          on fail: 4-blink pattern
 *   Stage 5  — usb_clock_init (HSI48 + CRS)      on fail: 3-blink pattern
 *   Stage 6  — rng_init                          on fail: 2-blink pattern
 *   Stage 7  — usb_init (tusb_init)              on fail: 3-blink pattern
 *   Stage 8  — boot banner ('#'-prefixed; libtropic clients silently skip)
 *   Stage 9  — main loop: tud_task + cdc_protocol_task
 *
 * Phase 1 work (libtropic L1+L2 round-trip on chip) preserved in tropic/
 * but excluded from build — re-enable in Phase 3 for HID lt-rpc.
 */

#include <stdio.h>
#include <string.h>

#include "stm32u5xx.h"

#include "platform/blink.h"
#include "platform/clock.h"
#include "platform/gpio.h"
#include "platform/rng.h"
#include "platform/spi.h"
#include "usb/usb.h"
#include "cdc_protocol/protocol.h"
#include "hid_rpc/rpc.h"
#include "fido_hid/ctaphid.h"
#include "fido_hid/credstore.h"
#include "tropic/tropic.h"  /* re-enabled in Phase 3 M3 for libtropic on chip */

#include "tusb.h"

void SysTick_Handler(void)
{
    HAL_IncTick();
}

/* ===== Diagnostic raw-GPIO LED for pre-HAL phase ===== */

static void busy_delay(volatile uint32_t cycles)
{
    while (cycles-- > 0u) {
        __NOP();
    }
}

static void raw_led_init(void)
{
    RCC->AHB2ENR1 |= RCC_AHB2ENR1_GPIOAEN;
    (void) RCC->AHB2ENR1;
    uint32_t moder = GPIOA->MODER;
    moder &= ~(0x3UL << (9 * 2));
    moder |=  (0x1UL << (9 * 2));
    GPIOA->MODER = moder;
}

static void raw_led_set(int on)
{
    GPIOA->BSRR = on ? (1UL << 9) : (1UL << (9 + 16));
}

static __attribute__((noreturn)) void raw_blink_code(uint8_t count)
{
    /* At default 4 MHz MSI: ~50 ms ≈ 200000 cycles. After clock_init at
     * 48 MHz, the same count is ~4 ms. Keep proportions sensible enough
     * either way. */
    const uint32_t pulse_on  = 200000u;
    const uint32_t pulse_off = 400000u;
    const uint32_t cycle_gap = 2000000u;

    for (;;) {
        for (uint8_t i = 0; i < count; ++i) {
            raw_led_set(1);
            busy_delay(pulse_on);
            raw_led_set(0);
            busy_delay(pulse_off);
        }
        busy_delay(cycle_gap);
    }
}

/* ===== Boot banner =====
 *
 * Lines starting with '#' are silently skipped by stock-protocol parsers
 * (verified against stock fw cmd.c:400 and against libtropic's
 * libtropic_port_posix_usb_dongle adapter). Humans connecting via `screen`
 * see the banner; libtropic clients ignore it.
 *
 * NIXTROPIC_GIT_REV is injected by Nix at compile time when available;
 * default placeholder when not set so the build still succeeds outside Nix.
 */
#ifndef NIXTROPIC_GIT_REV
#define NIXTROPIC_GIT_REV "unknown"
#endif

#ifndef NIXTROPIC_BUILD_TAG
#define NIXTROPIC_BUILD_TAG "nix-reproducible"
#endif

static void boot_banner(void)
{
    /* Emit banner FIRST so it sits in TinyUSB's TX FIFO while USB is still
     * enumerating. Once enumeration completes the banner drains to the host
     * kernel buffer. lt-util's tcflush(TCIOFLUSH) at open() then wipes the
     * banner before sending its first L2 command, avoiding response pollution.
     *
     * If we pumped tud_task FIRST and emitted the banner second, the banner
     * could land in the host buffer AFTER lt-util's tcflush — polluting
     * lt_get_info_chip_id's response stream and yielding LT_L1_SPI_ERROR.
     * (Verified failure mode 2026-05-10.) */
    printf("# nixtropic phase 4\r\n");
    printf("# build: %s\r\n", NIXTROPIC_BUILD_TAG);
    printf("# git: %s\r\n",   NIXTROPIC_GIT_REV);

    /* Now pump tud_task so the banner has time to drain through USB. */
    uint32_t deadline = HAL_GetTick() + 1500u;
    while ((int32_t)(HAL_GetTick() - deadline) < 0) {
        tud_task();
    }
}

int main(void)
{
    /* Stage 0 — raw blinks (proves CPU running) */
    raw_led_init();
    for (int i = 0; i < 4; ++i) {
        raw_led_set(1); busy_delay(150000);
        raw_led_set(0); busy_delay(150000);
    }
    busy_delay(800000);

    /* Stage 1 — HAL_Init */
    if (HAL_Init() != HAL_OK) {
        raw_blink_code(6);
    }

    /* Stage 2 — clock to 48 MHz */
    if (clock_init() != 0) {
        raw_blink_code(1);
    }

    /* Stage 3 — GPIO (LED, TROPIC01 power switch, TROPIC01 GPO input) */
    gpio_init();

    /* Stage 4 — SPI1 peripheral + AF mux on PA5/6/7 + CS pin on PA4 */
    if (spi_init() != 0) {
        raw_blink_code(4);
    }

    /* Stage 4.5 — Power-cycle TROPIC01: explicit OFF → 20 ms → ON, then
     * 300 ms settle. Mirrors Phase 1 tropic.c:73-83 (which mirrors stock
     * app/main.c:51-54 OFF→ON pattern). gpio_init() left PA0 LOW; spi_init
     * may have taken ~ms more so VCC is fully discharged. Re-assert the
     * power-off explicitly to make the pulse-shape unambiguous. */
    board_tropic_power_off();
    HAL_Delay(20);
    board_tropic_power_on();
    HAL_Delay(300);  /* Maintenance → Application boot transition (TROPIC01 datasheet) */

    /* Stage 5 — HSI48 + CRS for USB */
    if (usb_clock_init() != 0) {
        raw_blink_code(3);
    }

    /* Stage 6 — RNG (kept from Phase 1 for future use; harmless if unused) */
    if (rng_init() != 0) {
        raw_blink_code(2);
    }

    /* Stage 7 — USB peripheral + TinyUSB */
    if (usb_init() != 0) {
        raw_blink_code(3);
    }

    /* Stage 8 — boot banner + protocol init */
    boot_banner();
    cdc_protocol_init();
    hid_rpc_init();
    fido_hid_init();
    credstore_init();

    /* Stage 8.5 — libtropic on chip (M3). Runs power-cycle again + lt_init.
     * If lt_init fails the chip is still powered (power-cycle ran first),
     * so Phase 2 CDC ASCII passthrough still works for lt-util. We log
     * but don't halt — HID CHIP_ID command will return an error to the
     * host if lt_init didn't succeed. */
    tropic_init();

    blink_set_heartbeat();

    /* Stage 9 — main loop */
    for (;;) {
        tud_task();
        cdc_protocol_task();
        hid_rpc_task();
        fido_hid_task();
        blink_tick();
    }
}
