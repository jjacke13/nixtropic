/*
 * Phase 1 firmware main — Group C iteration (USB CDC bring-up).
 *
 * Boot sequence (and LED diagnostic codes per P1.20):
 *   Stage 0  — raw GPIO 4 quick blinks (proves CPU runs our code)
 *   Stage 1  — HAL_Init                          on fail: 6-blink pattern
 *   Stage 2  — clock_init (48 MHz)               on fail: 1-blink pattern
 *   Stage 3  — gpio_init
 *   Stage 4  — usb_clock_init (HSI48 + CRS)      on fail: 3-blink pattern
 *   Stage 5  — rng_init                          on fail: 2-blink pattern
 *   Stage 6  — usb_init (tusb_init)              on fail: 3-blink pattern
 *   Stage 7  — heartbeat + tud_task in main loop
 *
 * After USB CDC enumerates (~1-2 s), `[boot]` line + RNG sample print
 * to /dev/ttyACM*. From then on heartbeat continues; in Group D we'll
 * add the libtropic L2 sweep before going steady.
 */

#include <stdio.h>
#include <string.h>

#include "stm32u5xx.h"

#include "platform/blink.h"
#include "platform/clock.h"
#include "platform/gpio.h"
#include "platform/rng.h"
#include "tropic/tropic.h"
#include "usb/usb.h"

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

/* ===== Boot ===== */

static void boot_print(void)
{
    /* Run tud_task for ~1 sec to let the USB peripheral get past
     * enumeration. We don't wait for tud_cdc_connected — picocom may
     * open the port at any later time, and our _write pushes to FIFO
     * regardless of connection state. */
    uint32_t deadline = HAL_GetTick() + 1000u;
    while ((int32_t)(HAL_GetTick() - deadline) < 0) {
        tud_task();
    }

    printf("\n[boot] nixtropic phase 1 — USB CDC up\n");
    printf("[boot] vid=0xCAFE pid=0x4001\n");

    /* RNG sanity dump per decision P1.22 — proves STM32 host RNG fresh
     * on every cold-boot. (TROPIC01 RNG via lt_random_value_get needs
     * L3 session, deferred to Phase 5.) */
    uint8_t rng[32];
    if (rng_read(rng, sizeof rng) == 0) {
        printf("[hal_rng]");
        for (size_t i = 0; i < sizeof rng; ++i) {
            printf(" %02x", rng[i]);
        }
        printf("\n");
    } else {
        printf("[hal_rng] FAILED\n");
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

    /* Stage 3 — GPIO */
    gpio_init();

    /* Stage 4 — HSI48 + CRS for USB */
    if (usb_clock_init() != 0) {
        raw_blink_code(3);
    }

    /* Stage 5 — RNG */
    if (rng_init() != 0) {
        raw_blink_code(2);
    }

    /* Stage 6 — USB peripheral + TinyUSB */
    if (usb_init() != 0) {
        raw_blink_code(3);
    }

    /* Stage 7 — print boot info. */
    boot_print();
    blink_set_heartbeat();

    /* Stage 8 — TROPIC01 work is DEFERRED to the main loop.
     *
     * Reason: lt_init + L2 sweep can block the CPU for several seconds
     * if SPI calls hit timeouts. During that time tud_task can't run,
     * which starves USB CDC processing — host enumerates the EP but
     * stops getting CDC class responses, eventually drops the device.
     * picocom then can't get past "Terminal ready".
     *
     * Solution: let the main loop pump tud_task for ~1.5 s post-boot
     * (host fully opens /dev/ttyACM*), THEN do TROPIC01 work with
     * tud_task interleaved between each L2 call. */
    bool tropic_work_done = false;
    uint32_t tropic_start_deadline = HAL_GetTick() + 1500u;

    /* Periodic tick line so picocom-after-flash sees activity even if it
     * missed the boot block. */
    uint32_t next_tick_ms = HAL_GetTick() + 2000u;
    uint32_t tick_n = 0;

    for (;;) {
        tud_task();
        blink_tick();

        /* Once: do TROPIC01 init + L2 sweep, with tud_task between
         * each major step so CDC keeps draining. */
        if (!tropic_work_done && (int32_t)(HAL_GetTick() - tropic_start_deadline) >= 0) {
            tropic_work_done = true;

            tud_task();
            int trc = tropic_init();
            tud_task();

            if (trc != 0) {
                printf("[boot] tropic_init failed (%d)\n", trc);
                blink_set_pattern((uint8_t)(trc == 1 ? 5 : 6));
            } else {
                int sweep_errors = tropic_l2_sweep();
                tud_task();

                if (sweep_errors != 0) {
                    printf("[boot] L2 sweep had %d errors\n", sweep_errors);
                    blink_set_pattern(7);
                } else {
                    printf("[boot] PHASE1 OK — Group D HW round-trip passed\n");
                    /* heartbeat already running */
                }
            }
            tud_cdc_write_flush();
        }

        if ((int32_t)(HAL_GetTick() - next_tick_ms) >= 0) {
            uint8_t r = 0;
            (void) rng_read(&r, 1);
            printf("[tick %lu rng %02x]\n", (unsigned long) tick_n, r);
            tick_n++;
            next_tick_ms += 2000u;
        }
    }
}
