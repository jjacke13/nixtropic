/*
 * Hex helpers — see hex.h.
 */

#include "hex.h"

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_byte(const char *src, uint8_t *out)
{
    int hi = hex_nibble(src[0]);
    int lo = hex_nibble(src[1]);
    if (hi < 0 || lo < 0) {
        return -1;
    }
    *out = (uint8_t) (((unsigned) hi << 4) | (unsigned) lo);
    return 0;
}

void hex_emit_byte(char *dest, uint8_t byte)
{
    static const char alphabet[] = "0123456789ABCDEF";
    dest[0] = alphabet[(byte >> 4) & 0xFu];
    dest[1] = alphabet[byte & 0xFu];
}
