/*
 * Line buffer + dispatch — see parser.h.
 *
 * Buffer size 1024 bytes covers the largest plausible single hex line:
 * stock TR01_L1_LEN_MAX = 252 bytes → ~506 hex chars + suffix marker
 * + newline. 1024 leaves comfortable margin.
 *
 * On overflow we emit a stock-byte-exact "ERROR: USB RX overflow !"
 * message (matches stock app/cmd.c error string) and discard further
 * bytes until '\n', so the host's next line is parsed cleanly.
 */

#include "parser.h"

#include <string.h>

#include "tusb.h"

#define LINE_BUF_SIZE 1024

static char           s_line[LINE_BUF_SIZE];
static size_t         s_idx     = 0;
static parser_line_cb s_cb      = NULL;
static bool           s_overflow = false;

static void emit_overflow_error(void)
{
    static const char msg[] = "ERROR: USB RX overflow !\r\n";
    tud_cdc_write(msg, sizeof msg - 1u);
    tud_cdc_write_flush();
}

void parser_init(parser_line_cb cb)
{
    s_cb       = cb;
    s_idx      = 0;
    s_overflow = false;
    memset(s_line, 0, sizeof s_line);
}

void parser_feed(uint8_t byte)
{
    if (byte == '\n') {
        if (s_overflow) {
            emit_overflow_error();
        } else {
            /* Strip trailing \r if present. */
            if (s_idx > 0 && s_line[s_idx - 1u] == '\r') {
                s_idx--;
            }
            s_line[s_idx] = '\0';
            if (s_cb != NULL) {
                s_cb(s_line);
            }
        }
        s_idx      = 0;
        s_overflow = false;
        return;
    }

    if (s_idx >= LINE_BUF_SIZE - 1u) {
        s_overflow = true;
        return;
    }

    s_line[s_idx++] = (char) byte;
}
