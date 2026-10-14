/*
 * Host tests for firmware/src/fido_hid/cbor.c.  Phase 9 M0 baseline;
 * M3 adds the nesting-depth and length-bound cases.
 */
#include <string.h>

#include "check.h"
#include "fido_hid/cbor.h"

static void test_roundtrip(void)
{
    uint8_t buf[64];
    cbor_writer_t w;
    cbor_writer_init(&w, buf, sizeof buf);
    cbor_write_map_header(&w, 2);
    cbor_write_uint(&w, 1);
    cbor_write_text(&w, "abc");
    cbor_write_uint(&w, 2);
    cbor_write_array_header(&w, 2);
    cbor_write_uint(&w, 7);
    cbor_write_negint(&w, -8);
    CHECK(cbor_writer_error(&w) == 0);

    cbor_reader_t r;
    size_t n, len;
    uint64_t v;
    const uint8_t *p;
    cbor_reader_init(&r, buf, cbor_writer_len(&w));
    CHECK(cbor_reader_read_map_header(&r, &n) == 0 && n == 2);
    CHECK(cbor_reader_read_uint(&r, &v) == 0 && v == 1);
    CHECK(cbor_reader_read_text(&r, &p, &len) == 0 && len == 3 && memcmp(p, "abc", 3) == 0);
    CHECK(cbor_reader_read_uint(&r, &v) == 0 && v == 2);
    CHECK(cbor_reader_skip(&r) == 0);           /* the nested array */
    CHECK(r.pos == r.len);
}

static void test_writer_overflow(void)
{
    uint8_t buf[2];
    cbor_writer_t w;
    cbor_writer_init(&w, buf, sizeof buf);
    cbor_write_text(&w, "too long");
    CHECK(cbor_writer_error(&w) != 0);
}

static void test_truncated(void)
{
    /* text(5) "ab" — claims 5 bytes, has 2 */
    static const uint8_t t[] = { 0x65, 'a', 'b' };
    cbor_reader_t r;
    const uint8_t *p;
    size_t len;
    cbor_reader_init(&r, t, sizeof t);
    CHECK(cbor_reader_read_text(&r, &p, &len) == -1);

    /* map(1) with no entries present */
    static const uint8_t m[] = { 0xa1 };
    cbor_reader_init(&r, m, sizeof m);
    CHECK(cbor_reader_skip(&r) == -1);

    cbor_reader_init(&r, m, 0);
    CHECK(cbor_reader_peek_major(&r) == -1);
}

static void test_indefinite_rejected(void)
{
    static const uint8_t t[] = { 0x9f, 0x01, 0xff };   /* [_ 1] */
    cbor_reader_t r;
    cbor_reader_init(&r, t, sizeof t);
    CHECK(cbor_reader_skip(&r) == -1);
}

int main(void)
{
    test_roundtrip();
    test_writer_overflow();
    test_truncated();
    test_indefinite_rejected();
    return check_done("cbor");
}
