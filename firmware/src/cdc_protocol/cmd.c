/*
 * Command dispatcher — see cmd.h.
 *
 * Mirrors stock fw app/cmd.c semantics:
 *   - Case-insensitive command lookup
 *   - Three error categories: invalid (bad arg), missing (no arg where
 *     required), illegal (junk after command word). Strings byte-exact
 *     with stock so any host parser sees the same wire bytes.
 *   - Successful handlers return true → caller emits "OK\r\n".
 *   - Failed handlers emit their own ERROR line and return false.
 */

#include "cmd.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "stm32u5xx_hal.h"
#include "tusb.h"

#include "hex.h"
#include "platform/gpio.h"
#include "platform/spi.h"

/* ---- Identity strings ---- */

#ifndef NIXTROPIC_GIT_REV
#define NIXTROPIC_GIT_REV "unknown"
#endif

#define ID_STRING  "nixtropic-phase2"
#define SN_STRING  "nixtropic-phase2-ts0001"
#define VER_STRING "FW " NIXTROPIC_GIT_REV ", HW TS1302, https://github.com/jjacke13/nixtropic"

/* ---- Stock-byte-exact error strings (terminal newline included) ---- */

static const char ERR_INVALID[] = "ERROR: invalid parameter\r\n";
static const char ERR_MISSING[] = "ERROR: missing parameter\r\n";
static const char ERR_ILLEGAL[] = "ERROR: illegal parameter\r\n";
static const char ERR_UNKNOWN[] = "ERROR: unknown command\r\n";

/* ---- Module state ---- */

/* TROPIC01 powered ON at boot (matches stock fw HW_CHIP_PWR_ON in
 * app/main.c:54). main.c calls board_tropic_power_on() at boot; this
 * default keeps cmd_pwr's GET in sync without requiring an init call. */
static bool    s_pwr_state    = true;
static bool    s_auto_enabled = false;
static uint8_t s_auto_get     = 0xAAu;  /* MSG_HDR_GET_RESP per stock cmd.c:178 */
static uint8_t s_auto_no_resp = 0xFFu;  /* MSG_VALUE_NO_RESP per stock cmd.c:179 */

/* ---- Output helpers ---- */

static void out_str(const char *s)
{
    tud_cdc_write(s, strlen(s));
}

static void out_flush(void)
{
    tud_cdc_write_flush();
}

static void emit_uint(uint32_t v)
{
    /* Manual decimal emit so we don't pull printf's full conversion path. */
    char buf[12];
    int  n = 0;
    if (v == 0u) {
        buf[n++] = '0';
    } else {
        char tmp[12];
        int  t = 0;
        while (v > 0u) {
            tmp[t++] = (char) ('0' + (v % 10u));
            v /= 10u;
        }
        while (t > 0) {
            buf[n++] = tmp[--t];
        }
    }
    tud_cdc_write(buf, (uint32_t) n);
}

static void emit_hex_byte(uint8_t b)
{
    char tmp[2];
    hex_emit_byte(tmp, b);
    tud_cdc_write(tmp, 2);
}

/* ---- Argument parsing helpers ---- */

static const char *skip_spaces(const char *p)
{
    /* Skip ' ', '\t', '\r' — TTY layers occasionally leak a stray '\r'
     * past our parser if input doesn't have a clean '\r\n' pair. Stock fw
     * cmd.c skips only ' ', but being permissive here costs nothing and
     * avoids "ERROR: illegal parameter" when input has trailing whitespace. */
    while (*p == ' ' || *p == '\t' || *p == '\r') {
        p++;
    }
    return p;
}

static int parse_bool(const char **pp, bool *out)
{
    char c = **pp;
    if (c == '0') {
        *out = false;
    } else if (c == '1') {
        *out = true;
    } else {
        return -1;
    }
    (*pp)++;
    return 0;
}

static int parse_uint(const char **pp, uint32_t *out)
{
    if (**pp < '0' || **pp > '9') {
        return -1;
    }
    uint32_t v = 0u;
    while (**pp >= '0' && **pp <= '9') {
        v = v * 10u + (uint32_t)(**pp - '0');
        (*pp)++;
    }
    *out = v;
    return 0;
}

static int parse_hex_byte(const char **pp, uint8_t *out)
{
    if (hex_byte(*pp, out) != 0) {
        return -1;
    }
    *pp += 2;
    return 0;
}

/* ---- Command handlers (return true on success, false on error) ---- */

/* Forward-declare the table for HELP. */
typedef bool (*cmd_get_fn)(void);
typedef bool (*cmd_set_fn)(const char *args);

typedef struct {
    const char *text;
    cmd_get_fn  get;
    cmd_set_fn  set;
} cmd_entry_t;

static const cmd_entry_t CMDS[];

static bool cmd_help(void)
{
    out_str("Tropicsquare-compatible USB/SPI interface (nixtropic phase 2)\r\n");
    out_str("Type HEX characters to make SPI transfer (i.e. \"1122aabb\")\r\n");
    out_str("Supported commands:\r\n");
    for (int i = 0; CMDS[i].text != NULL; ++i) {
        out_str("  ");
        out_str(CMDS[i].text);
        out_str("\r\n");
    }
    return true;
}

static bool cmd_id(void)
{
    out_str("ID: " ID_STRING "\r\n");
    return true;
}

static bool cmd_sn(void)
{
    out_str("SN: " SN_STRING "\r\n");
    return true;
}

static bool cmd_ver(void)
{
    out_str("VER: " VER_STRING "\r\n");
    return true;
}

static bool cmd_gpo(void)
{
    out_str("GPO: ");
    out_str(board_tropic_gpo_read() ? "1" : "0");
    out_str("\r\n");
    return true;
}

static bool cmd_cs(void)
{
    out_str("CS: ");
    out_str(spi_cs_is_asserted() ? "1" : "0");
    out_str("\r\n");
    return true;
}

static bool cmd_cs_set(const char *args)
{
    bool b;
    if (parse_bool(&args, &b) != 0) {
        out_str(ERR_INVALID);
        return false;
    }
    if (b) {
        spi_cs_assert();
    } else {
        spi_cs_release();
    }
    return true;
}

static bool cmd_pwr(void)
{
    out_str("PWR: ");
    out_str(s_pwr_state ? "1" : "0");
    out_str("\r\n");
    return true;
}

static bool cmd_pwr_set(const char *args)
{
    bool b;
    if (parse_bool(&args, &b) != 0) {
        out_str(ERR_INVALID);
        return false;
    }
    if (b) {
        board_tropic_power_on();
    } else {
        board_tropic_power_off();
    }
    s_pwr_state = b;
    return true;
}

static bool cmd_clkdiv(void)
{
    out_str("CLKDIV: ");
    emit_uint(spi_get_prescaler_div());
    out_str("\r\n");
    return true;
}

static bool cmd_clkdiv_set(const char *args)
{
    uint32_t v;
    if (parse_uint(&args, &v) != 0) {
        out_str(ERR_INVALID);
        return false;
    }
    if (spi_set_prescaler_div(v) != 0) {
        out_str(ERR_INVALID);
        return false;
    }
    return true;
}

static bool cmd_auto(void)
{
    if (!s_auto_enabled) {
        out_str("AUTO: 0\r\n");
        return true;
    }
    out_str("AUTO: 1, ");
    emit_hex_byte(s_auto_get);
    out_str(", ");
    emit_hex_byte(s_auto_no_resp);
    out_str("\r\n");
    return true;
}

static bool cmd_auto_set(const char *args)
{
    bool en;
    if (parse_bool(&args, &en) != 0) {
        out_str(ERR_INVALID);
        return false;
    }
    uint8_t get_resp = 0xAAu;
    uint8_t no_resp  = 0xFFu;

    args = skip_spaces(args);
    if (*args == ',') {
        args++;
        args = skip_spaces(args);
        if (parse_hex_byte(&args, &get_resp) != 0) {
            out_str(ERR_INVALID);
            return false;
        }
        args = skip_spaces(args);
        if (*args == ',') {
            args++;
            args = skip_spaces(args);
            if (parse_hex_byte(&args, &no_resp) != 0) {
                out_str(ERR_INVALID);
                return false;
            }
        }
    }

    s_auto_enabled = en;
    s_auto_get     = get_resp;
    s_auto_no_resp = no_resp;
    return true;
}

static bool cmd_reset(void)
{
    out_str("RESET\r\n");
    out_flush();
    HAL_Delay(10);
    NVIC_SystemReset();
    return true;  /* unreached */
}

/* ---- Command table ---- */

static const cmd_entry_t CMDS[] = {
    {"AUTO",   cmd_auto,   cmd_auto_set},
    {"CLKDIV", cmd_clkdiv, cmd_clkdiv_set},
    {"CS",     cmd_cs,     cmd_cs_set},
    {"GPO",    cmd_gpo,    NULL},
    {"HELP",   cmd_help,   NULL},
    {"ID",     cmd_id,     NULL},
    {"PWR",    cmd_pwr,    cmd_pwr_set},
    {"RESET",  cmd_reset,  NULL},
    {"SN",     cmd_sn,     NULL},
    {"VER",    cmd_ver,    NULL},
    {NULL,     NULL,       NULL},
};

/* ---- Dispatcher ---- */

static int strnicmp_local(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        char x = a[i];
        char y = b[i];
        if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = (char)(y - 'A' + 'a');
        if (x != y) return (int) x - (int) y;
        if (x == '\0') return 0;
    }
    return 0;
}

static bool is_ident_char(char c)
{
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '_';
}

bool cmd_dispatch(const char *line)
{
    for (int i = 0; CMDS[i].text != NULL; ++i) {
        size_t l = strlen(CMDS[i].text);
        if (strnicmp_local(line, CMDS[i].text, l) != 0) continue;
        if (is_ident_char(line[l])) continue;  /* prefix match, not full word */

        const char *p = line + l;
        p = skip_spaces(p);

        if (*p == '=') {
            if (CMDS[i].set == NULL) {
                out_str(ERR_INVALID);
                out_flush();
                return false;
            }
            p++;
            p = skip_spaces(p);
            bool ok = CMDS[i].set(p);
            if (ok) {
                out_str("OK\r\n");
            }
            out_flush();
            return ok;
        }

        if (*p != '?' && *p != '\0') {
            out_str(ERR_ILLEGAL);
            out_flush();
            return false;
        }

        if (CMDS[i].get == NULL) {
            out_str(ERR_MISSING);
            out_flush();
            return false;
        }

        bool ok = CMDS[i].get();
        if (ok) {
            out_str("OK\r\n");
        }
        out_flush();
        return ok;
    }

    out_str(ERR_UNKNOWN);
    out_flush();
    return false;
}

/* ---- AUTO mode tick ---- */

void cmd_auto_tick(void)
{
    if (!s_auto_enabled) return;
    if (spi_cs_is_asserted()) return;  /* stock app/main.c:264 */

    /* Send get_resp byte; if response != no_resp, drain a 4-byte L2
     * header followed by length+data+CRC, emit hex. Mirrors stock
     * app/main.c:_spi_auto_task. */
    spi_cs_assert();

    uint8_t buf[260];   /* L2 max is ~252 + 4 hdr + 2 crc */
    uint8_t tx0 = s_auto_get;
    uint8_t rx0;
    if (spi_transfer(&tx0, &rx0, 1) != 0) {
        spi_cs_release();
        return;
    }

    /* Read header byte. Stock does two reads here — one for get_resp echo,
     * one for status byte. We follow exactly. */
    uint8_t tx_zero = 0u;
    uint8_t status;
    if (spi_transfer(&tx_zero, &status, 1) != 0) {
        spi_cs_release();
        return;
    }
    buf[0] = status;

    if (status == s_auto_no_resp) {
        spi_cs_release();
        return;
    }

    /* Read length. */
    uint8_t len;
    if (spi_transfer(&tx_zero, &len, 1) != 0) {
        spi_cs_release();
        return;
    }
    buf[1] = len;

    /* Read len + 2 (CRC) bytes. Total bytes after status: len+2; total
     * including header status: 2 + len + 2. */
    size_t total = (size_t) len + 2u;
    if (total > sizeof buf - 2u) {
        spi_cs_release();
        return;
    }
    for (size_t i = 0; i < total; ++i) {
        if (spi_transfer(&tx_zero, &buf[2 + i], 1) != 0) {
            spi_cs_release();
            return;
        }
    }

    spi_cs_release();

    /* Emit as upper-case hex + "\r\n". */
    char out[(2 + 252 + 2) * 2 + 2];
    size_t emit_n = total + 2u;
    for (size_t i = 0; i < emit_n; ++i) {
        hex_emit_byte(&out[i * 2], buf[i]);
    }
    out[emit_n * 2]     = '\r';
    out[emit_n * 2 + 1] = '\n';
    tud_cdc_write(out, (uint32_t)(emit_n * 2 + 2));
    out_flush();
}
