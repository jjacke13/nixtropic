/*
 * nixtropic firmware main — boot sequence + idle loop.
 *
 * Brings up the STM32U5 platform, USB composite device (CDC + HID×2
 * + CCID), and TROPIC01 chip session in stages; the LED reports
 * any boot-stage failure via a numeric blink pattern so a bricked
 * dongle still reports cause without USB.
 *
 * Boot sequence:
 *   Stage 0  — raw GPIO 4 quick blinks (proves CPU runs our code)
 *   Stage 1  — HAL_Init                            on fail: 6-blink
 *   Stage 2  — clock_init (48 MHz SYSCLK)          on fail: 1-blink
 *   Stage 3  — gpio_init (LED, SW1, TROPIC01 pwr)
 *   Stage 4  — spi_init  (SPI1 to TROPIC01)        on fail: 4-blink
 *   Stage 5  — usb_clock_init (HSI48 + CRS)        on fail: 3-blink
 *   Stage 6  — rng_init (HAL_RNG self-test)        on fail: 2-blink
 *   Stage 7  — usb_init (tusb_init, composite)     on fail: 3-blink
 *   Stage 8  — tropic_init (L1+L2+L3 session up)   on fail: 5-blink
 *   Stage 9  — boot banner ('#'-prefixed on CDC; libtropic clients
 *              silently skip — same byte-faithful behaviour as
 *              the stock TS1302 firmware)
 *   Stage 10 — main loop: tud_task() + per-module *_task()
 *
 * After enumeration the LED switches from boot heartbeat to the
 * runtime state machine in platform/led.c (idle/awaiting-touch/
 * confirmed/error states; covert-channel-safe — no LED changes
 * inside crypto code paths).
 *
 * `__attribute__((noreturn)) main(void)` — no return; embedded.
 */

#include <stdio.h>
#include <string.h>

#include "stm32u5xx.h"

#include "platform/blink.h"
#include "platform/clock.h"
#include "platform/gpio.h"
#include "platform/led.h"
#include "platform/rng.h"
#include "platform/spi.h"
#include "usb/usb.h"
#include "cdc_protocol/protocol.h"
#include "hid_rpc/rpc.h"
#include "fido_hid/ctaphid.h"
#include "fido_hid/credstore.h"
#include "fido_hid/slots.h"
#include "fido_hid/pin.h"
#include "fido_hid/user_presence.h"
#include "tropic/tropic.h"  /* libtropic L1+L2+L3 session on chip */

#include "tusb.h"

/* SysTick drives the SW1 debouncer + LED state machine at
 * 1 kHz.  HAL_IncTick must run first (HAL_Delay / HAL_GetTick depend on
 * it); the additional callbacks are cheap and bounded. */
void SysTick_Handler(void)
{
    HAL_IncTick();
    user_presence_systick_tick();
    led_systick_tick();
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
     * 300 ms settle.  Mirrors stock TS1302 firmware `app/main.c:51-54`
     * OFF→ON pattern.  gpio_init() left PA0 LOW; spi_init may have
     * taken ~ms more so VCC is fully discharged.  Re-assert the
     * power-off explicitly to make the pulse-shape unambiguous. */
    board_tropic_power_off();
    HAL_Delay(20);
    board_tropic_power_on();
    HAL_Delay(300);  /* Maintenance → Application boot transition (TROPIC01 datasheet) */

    /* Stage 5 — HSI48 + CRS for USB */
    if (usb_clock_init() != 0) {
        raw_blink_code(3);
    }

    /* Stage 6 — STM32 HW TRNG (used by libtropic L1 + diagnostic dumps) */
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

    /* Stage 8.5 — libtropic on chip.  Runs a second power-cycle then
     * lt_init.  If lt_init fails the chip is still powered (the first
     * power-cycle ran in Stage 4.5), so the CDC ASCII passthrough mode
     * still works for lt-util.  We log but don't halt — HID CHIP_ID
     * command will return an error to the host if lt_init didn't
     * succeed. */
    tropic_init();

    /* Stage 8.6 — Credential store + slot manager.
     * credstore_init opens L3 lazily on first use, calls slots_init
     * internally (reads R-mem slot 0, orphan-scrubs bitmap), and
     * initializes TROPIC01 mcounter 0 to MAX if it's a first boot
     * (used as the shared monotonic signCount).
     *
     * We log on failure but don't halt — FIDO2 paths will simply return
     * CTAP errors to the host. CDC + lt-rpc HID paths remain operational. */
    {
        int rc = credstore_init();
        if (rc != 0) {
            printf("[credstore] init failed: %d (FIDO2 paths will error)\n", rc);
        } else {
            printf("[slots] bitmap=0x%08lx used=%d/32\n",
                   (unsigned long) slots_bitmap(), slots_count_used());
        }
    }

    /* Stage 8.7 — ClientPIN ephemeral keypair.
     * Generates a fresh P-256 keypair from TROPIC01 TRNG for CTAP2 PIN
     * protocol v1 key agreement.  Lives in RAM only; regenerated on
     * every boot AND after each successful setPin/changePin. */
    {
        int rc = pin_init();
        if (rc != 0) {
            printf("[pin] init failed: %d (ClientPIN paths will error)\n", rc);
        } else {
            printf("[pin] ephemeral P-256 key ready; pin_set=%d\n", pin_is_set());
        }
    }

    /* LED state machine takes over.  Boot phase used
     * LED_HEARTBEAT (default initial state); switch to LED_IDLE once
     * everything is up so the off-state advertises "ready, awaiting
     * host request" — same UX cue Yubikey gives. */
    led_set_state(LED_IDLE);

    /* Stage 9 — main loop */
    for (;;) {
        tud_task();
        cdc_protocol_task();
        hid_rpc_task();
        fido_hid_task();
        /* LED + SW1 debouncer now driven by SysTick — no main-loop poll. */
    }
}
