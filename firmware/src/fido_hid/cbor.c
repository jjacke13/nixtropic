/*
 * CBOR (RFC 8949) encoder + minimal decoder helpers.
 *
 * Only the data types CTAP2 uses: unsigned ints, negative ints, byte
 * strings, text strings, arrays, maps, false/true/null. No floats, no
 * indefinite-length, no tags. Canonical-encoding rule (shortest
 * length-prefix) enforced by the encoder; canonical key ordering is the
 * caller's responsibility — we don't sort.
 */

#include "cbor.h"

#include <string.h>

/* CBOR major types in the top 3 bits of the initial byte. */
#define CBOR_MT_UINT        0u
#define CBOR_MT_NEGINT      1u
#define CBOR_MT_BYTE_STR    2u
#define CBOR_MT_TEXT_STR    3u
#define CBOR_MT_ARRAY       4u
#define CBOR_MT_MAP         5u
#define CBOR_MT_SIMPLE      7u

#define CBOR_SIMPLE_FALSE   20u
#define CBOR_SIMPLE_TRUE    21u
#define CBOR_SIMPLE_NULL    22u

void cbor_writer_init(cbor_writer_t *w, uint8_t *buf, size_t cap)
{
    w->buf = buf;
    w->cap = cap;
    w->pos = 0;
    w->err = 0;
}

int cbor_writer_error(const cbor_writer_t *w) { return w->err; }
size_t cbor_writer_len(const cbor_writer_t *w) { return w->pos; }

static int put_byte(cbor_writer_t *w, uint8_t b)
{
    if (w->err) return -1;
    if (w->pos >= w->cap) { w->err = 1; return -1; }
    w->buf[w->pos++] = b;
    return 0;
}

static int put_bytes(cbor_writer_t *w, const uint8_t *p, size_t n)
{
    if (w->err) return -1;
    if (n > w->cap - w->pos) { w->err = 1; return -1; }
    if (n > 0u) memcpy(&w->buf[w->pos], p, n);
    w->pos += n;
    return 0;
}

/* Emit a "head": major type in top 3 bits + length-prefix in shortest form. */
static int put_head(cbor_writer_t *w, uint8_t mt, uint64_t v)
{
    uint8_t mt_bits = (uint8_t)(mt << 5);
    if (v < 24u) {
        return put_byte(w, (uint8_t)(mt_bits | (uint8_t) v));
    } else if (v <= 0xFFu) {
        if (put_byte(w, (uint8_t)(mt_bits | 24u)) < 0) return -1;
        return put_byte(w, (uint8_t) v);
    } else if (v <= 0xFFFFu) {
        if (put_byte(w, (uint8_t)(mt_bits | 25u)) < 0) return -1;
        uint8_t b[2] = { (uint8_t)(v >> 8), (uint8_t) v };
        return put_bytes(w, b, 2);
    } else if (v <= 0xFFFFFFFFu) {
        if (put_byte(w, (uint8_t)(mt_bits | 26u)) < 0) return -1;
        uint8_t b[4] = {
            (uint8_t)(v >> 24), (uint8_t)(v >> 16),
            (uint8_t)(v >> 8),  (uint8_t) v,
        };
        return put_bytes(w, b, 4);
    } else {
        if (put_byte(w, (uint8_t)(mt_bits | 27u)) < 0) return -1;
        uint8_t b[8] = {
            (uint8_t)(v >> 56), (uint8_t)(v >> 48),
            (uint8_t)(v >> 40), (uint8_t)(v >> 32),
            (uint8_t)(v >> 24), (uint8_t)(v >> 16),
            (uint8_t)(v >> 8),  (uint8_t) v,
        };
        return put_bytes(w, b, 8);
    }
}

int cbor_write_uint(cbor_writer_t *w, uint64_t v)
{
    return put_head(w, CBOR_MT_UINT, v);
}

int cbor_write_negint(cbor_writer_t *w, int64_t v)
{
    if (v >= 0) { w->err = 1; return -1; }
    /* CBOR encodes negative integer n as unsigned (-1 - n). */
    uint64_t u = (uint64_t)(-(v + 1));
    return put_head(w, CBOR_MT_NEGINT, u);
}

int cbor_write_byte_string(cbor_writer_t *w, const uint8_t *bytes, size_t len)
{
    if (put_head(w, CBOR_MT_BYTE_STR, (uint64_t) len) < 0) return -1;
    return put_bytes(w, bytes, len);
}

int cbor_write_text(cbor_writer_t *w, const char *s)
{
    size_t n = strlen(s);
    if (put_head(w, CBOR_MT_TEXT_STR, (uint64_t) n) < 0) return -1;
    return put_bytes(w, (const uint8_t *) s, n);
}

int cbor_write_array_header(cbor_writer_t *w, size_t count)
{
    return put_head(w, CBOR_MT_ARRAY, (uint64_t) count);
}

int cbor_write_map_header(cbor_writer_t *w, size_t count)
{
    return put_head(w, CBOR_MT_MAP, (uint64_t) count);
}

int cbor_write_bool(cbor_writer_t *w, bool v)
{
    uint8_t mt_bits = (uint8_t)(CBOR_MT_SIMPLE << 5);
    uint8_t simple  = v ? CBOR_SIMPLE_TRUE : CBOR_SIMPLE_FALSE;
    return put_byte(w, (uint8_t)(mt_bits | simple));
}

int cbor_write_null(cbor_writer_t *w)
{
    uint8_t mt_bits = (uint8_t)(CBOR_MT_SIMPLE << 5);
    return put_byte(w, (uint8_t)(mt_bits | CBOR_SIMPLE_NULL));
}

/* ===== Decoder helpers ===== */

void cbor_reader_init(cbor_reader_t *r, const uint8_t *buf, size_t len)
{
    r->buf = buf;
    r->len = len;
    r->pos = 0;
    r->err = 0;
}

int cbor_reader_peek_major(const cbor_reader_t *r)
{
    if (r->pos >= r->len) return -1;
    return (int)((r->buf[r->pos] >> 5) & 0x7u);
}
