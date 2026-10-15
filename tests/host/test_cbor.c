/*
 * Host tests for firmware/src/fido_hid/cbor.c.  Phase 9 M0 baseline;
 * M3 adds whole-message validation (depth, bounds) and the skip() cap.
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

/* Phase 9 M3: whole-message validation (CTAP §8: at most 4 nesting levels). */
static void test_validate(void)
{
    /* {1: [{2: [3]}]} — 4 levels: accepted */
    static const uint8_t ok4[] = { 0xa1, 0x01, 0x81, 0xa1, 0x02, 0x81, 0x03 };
    CHECK(cbor_validate(ok4, sizeof ok4) == 0);

    /* {1: [{2: [[3]]}]} — 5 levels: rejected */
    static const uint8_t deep5[] = { 0xa1, 0x01, 0x81, 0xa1, 0x02, 0x81, 0x81, 0x03 };
    CHECK(cbor_validate(deep5, sizeof deep5) == -1);

    /* scalars and strings at the top level are fine */
    static const uint8_t s[] = { 0x63, 'a', 'b', 'c' };
    CHECK(cbor_validate(s, sizeof s) == 0);

    /* one item, then a stray byte */
    static const uint8_t trailing[] = { 0xa0, 0x00 };
    CHECK(cbor_validate(trailing, sizeof trailing) == -1);

    /* empty input */
    CHECK(cbor_validate(trailing, 0) == -1);

    /* byte string longer than the buffer */
    static const uint8_t longbs[] = { 0xa1, 0x01, 0x45, 0x00, 0x00 };
    CHECK(cbor_validate(longbs, sizeof longbs) == -1);

    /* array claiming 2^32 items in 9 bytes: rejected without looping */
    static const uint8_t huge[] = { 0x9b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
    CHECK(cbor_validate(huge, sizeof huge) == -1);

    /* map claiming more pairs than bytes left */
    static const uint8_t bigmap[] = { 0xb8, 0xff, 0x01, 0x02 };
    CHECK(cbor_validate(bigmap, sizeof bigmap) == -1);

    /* map with a key and no value */
    static const uint8_t halfmap[] = { 0xa1, 0x01 };
    CHECK(cbor_validate(halfmap, sizeof halfmap) == -1);

    /* tag 1 (major type 6) */
    static const uint8_t tag[] = { 0xc1, 0x01 };
    CHECK(cbor_validate(tag, sizeof tag) == -1);

    /* indefinite-length map */
    static const uint8_t indef[] = { 0xbf, 0x01, 0x02, 0xff };
    CHECK(cbor_validate(indef, sizeof indef) == -1);

    /* lone break byte */
    static const uint8_t brk[] = { 0xff };
    CHECK(cbor_validate(brk, sizeof brk) == -1);

    /* true / false / null and a float are scalars */
    static const uint8_t simple[] = { 0x84, 0xf5, 0xf4, 0xf6, 0xf9, 0x3c, 0x00 };
    CHECK(cbor_validate(simple, sizeof simple) == 0);
}

/* skip() has its own recursion cap: deep nesting fails instead of
 * exhausting the stack, even without a cbor_validate() first. */
static void test_skip_depth_cap(void)
{
    uint8_t deep[300];
    memset(deep, 0x81, sizeof deep);       /* [[[[ ... */
    deep[sizeof deep - 1] = 0x00;
    cbor_reader_t r;
    cbor_reader_init(&r, deep, sizeof deep);
    CHECK(cbor_reader_skip(&r) == -1);

    static const uint8_t ok[] = { 0x81, 0x81, 0x81, 0x00 };
    cbor_reader_init(&r, ok, sizeof ok);
    CHECK(cbor_reader_skip(&r) == 0 && r.pos == sizeof ok);
}

int main(void)
{
    test_roundtrip();
    test_writer_overflow();
    test_truncated();
    test_indefinite_rejected();
    test_validate();
    test_skip_depth_cap();
    return check_done("cbor");
}
