/*
 * USB CDC ↔ SPI passthrough — line dispatch, hex passthrough, AUTO tick, LED.
 *
 * Hex line semantics (verbatim from stock app/main.c:138-196):
 *   - Optional leading 'x' or '\\' suppresses CS-assert (CS already low)
 *   - Sequence of upper/lower hex pairs, optionally space-separated
 *   - Optional trailing 'x' or '\\' suppresses CS-release (keep CS low)
 *   - Default: assert CS, transfer, release CS
 *
 * Output: same byte-count echoed as upper-case hex pairs + "\r\n".
 *
 * Errors match stock byte-for-byte:
 *   - "ERROR: invalid parameter\r\n"
 *   - "ERROR: missing parameter\r\n"
 *   - "ERROR: illegal parameter\r\n"
 *   - "ERROR: unknown command\r\n"
 *   - "ERROR: USB RX overflow !\r\n" (emitted from parser.c)
 *
 * LED state (P2.20): solid ON when CDC host connected, heartbeat otherwise.
 * Tracked via tud_cdc_connected(); transitions applied via blink_set_*.
 *
 * AUTO mode: 100 ms tick driver in cmd_auto_tick. Inhibited while CS is
 * asserted (matches stock app/main.c:264).
 */

#include "protocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "stm32u5xx_hal.h"
#include "tusb.h"

#include "cmd.h"
#include "hex.h"
#include "parser.h"
#include "platform/blink.h"
#include "platform/spi.h"

#define SPI_BUF_SIZE 512  /* matches stock fw _SPI_BUF_SIZE */

static const char ERR_SPI_FAIL[] = "ERROR: SPI transfer failed\r\n";

static uint32_t s_next_tick_ms  = 0u;
static bool     s_was_connected = false;

static void cdc_write_str(const char *s)
{
    tud_cdc_write(s, strlen(s));
}

static void cdc_flush(void)
{
    tud_cdc_write_flush();
}

static bool is_skip_cs_char(char c)
{
    return c == 'x' || c == '\\';
}

static bool is_hex_digit(char c)
{
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static const char *skip_spaces(const char *p)
{
    /* Permissive: skip ' ', '\t', '\r'. Avoids spurious "ERROR: illegal
     * parameter" if any TTY layer leaked a '\r' past our parser. */
    while (*p == ' ' || *p == '\t' || *p == '\r') {
        p++;
    }
    return p;
}

/* Hex passthrough. Returns true if line was consumed as a hex transfer.
 * Returns false if line doesn't look like hex — caller falls through to
 * cmd_dispatch. Mirrors stock app/main.c:144 _parse_hex behavior exactly. */
static bool try_hex_passthrough(const char *line)
{
    const char *p = line;
    bool skip_cs_assert = false;

    if (is_skip_cs_char(*p)) {
        skip_cs_assert = true;
        p++;
    }

    if (!is_hex_digit(*p)) {
        return false;
    }

    static uint8_t tx[SPI_BUF_SIZE];
    static uint8_t rx[SPI_BUF_SIZE];
    size_t n = 0u;

    while (n < SPI_BUF_SIZE) {
        p = skip_spaces(p);
        if (!is_hex_digit(*p)) {
            break;
        }
        uint8_t b;
        if (hex_byte(p, &b) != 0) {
            break;
        }
        tx[n++] = b;
        p += 2;
    }

    /* If we didn't successfully parse any complete hex byte, this line
     * isn't a SPI transfer — fall through to cmd_dispatch. Critical for
     * commands like "CS=0", "CS=1", "CLKDIV=16", "AUTO=1" — their first
     * char ('C', 'A') is a hex digit, so the loop entry passes, but
     * hex_byte fails on the non-hex second char and breaks with n=0.
     * Without this check we'd assert+release CS for nothing and emit
     * only "\r\n" (2 bytes) when the host expects "OK\r\n" (4 bytes),
     * yielding a short read on the host's side and LT_L1_SPI_ERROR. */
    if (n == 0u) {
        return false;
    }

    bool skip_cs_release = is_skip_cs_char(*p);

    if (!skip_cs_assert) {
        spi_cs_assert();
    }

    int xfer_rc = spi_transfer(tx, rx, n);

    if (!skip_cs_release) {
        spi_cs_release();
    }

    if (xfer_rc != 0) {
        cdc_write_str(ERR_SPI_FAIL);
        cdc_flush();
        return true;
    }

    static char out[SPI_BUF_SIZE * 2 + 2];
    for (size_t i = 0; i < n; ++i) {
        hex_emit_byte(&out[i * 2], rx[i]);
    }
    out[n * 2]     = '\r';
    out[n * 2 + 1] = '\n';

    /* Write with retry: tud_cdc_write returns the actual bytes accepted
     * by the FIFO, which may be less than requested if the FIFO doesn't
     * have room. Loop with flush+pump between retries so all bytes go out. */
    size_t       to_write = n * 2u + 2u;
    const char  *src      = out;
    while (to_write > 0u) {
        uint32_t w = tud_cdc_write(src, (uint32_t) to_write);
        src      += w;
        to_write -= w;
        if (to_write > 0u) {
            tud_cdc_write_flush();
            tud_task();  /* drain over USB so FIFO frees up */
        }
    }
    cdc_flush();
    return true;
}

static void handle_line(const char *line)
{
    while (*line == ' ') {
        line++;
    }
    if (*line == '\0') return;
    if (*line == '#')  return;

    if (try_hex_passthrough(line)) return;

    (void) cmd_dispatch(line);
}

static void apply_led_state(void)
{
    bool connected = tud_cdc_connected();
    if (connected != s_was_connected) {
        if (connected) {
            blink_set_solid();
        } else {
            blink_set_heartbeat();
        }
        s_was_connected = connected;
    }
}

void cdc_protocol_init(void)
{
    parser_init(handle_line);
    s_next_tick_ms  = HAL_GetTick();
    s_was_connected = false;
}

void cdc_protocol_task(void)
{
    /* Drain CDC RX FIFO into the line parser. Non-blocking. */
    while (tud_cdc_available() > 0u) {
        uint8_t b = 0;
        uint32_t got = tud_cdc_read(&b, 1);
        if (got == 0u) {
            break;
        }
        parser_feed(b);
    }

    /* 100 ms tick: AUTO mode + LED state. */
    uint32_t now = HAL_GetTick();
    if ((int32_t)(now - s_next_tick_ms) >= 0) {
        cmd_auto_tick();
        apply_led_state();
        s_next_tick_ms = now + 100u;
    }
}
