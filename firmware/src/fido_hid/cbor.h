/*
 * Minimal CBOR (RFC 8949) encoder for CTAP2 responses.
 *
 * Hand-rolled rather than vendoring tinycbor — CTAP2 messages are small
 * and we only encode the data types CTAP2 uses. Decoder for request
 * parsing lives next to this in cbor.c (M4 onwards).
 *
 * Encoded output uses CTAP2's "canonical CBOR" rule per CTAP §6: shortest
 * length-prefix encoding; map keys in canonical order (caller's
 * responsibility); arrays and maps with definite length.
 *
 * All writers return the number of bytes written or a negative value on
 * overflow. The caller advances a position cursor (or just sums returns).
 *
 * Convention: a "writer" function appends to a buffer at `*pos` and
 * advances `*pos` on success. On overflow it returns -1 and leaves *pos
 * pointing at the failed write so the caller can detect it.
 */

#ifndef NIXTROPIC_FIDO_HID_CBOR_H
#define NIXTROPIC_FIDO_HID_CBOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   pos;
    int      err;          /* sticky: nonzero once any write failed */
} cbor_writer_t;

void cbor_writer_init(cbor_writer_t *w, uint8_t *buf, size_t cap);
int  cbor_writer_error(const cbor_writer_t *w);
size_t cbor_writer_len(const cbor_writer_t *w);

/* Primitives. Each returns 0 on success, -1 on overflow (and sets w->err). */
int cbor_write_uint(cbor_writer_t *w, uint64_t v);
int cbor_write_negint(cbor_writer_t *w, int64_t v);   /* v must be < 0 */
int cbor_write_byte_string(cbor_writer_t *w, const uint8_t *bytes, size_t len);
int cbor_write_text(cbor_writer_t *w, const char *s);
int cbor_write_array_header(cbor_writer_t *w, size_t count);
int cbor_write_map_header(cbor_writer_t *w, size_t count);
int cbor_write_bool(cbor_writer_t *w, bool v);
int cbor_write_null(cbor_writer_t *w);

/* ===== Minimal decoder (M4 will extend) ===== */

typedef struct {
    const uint8_t *buf;
    size_t         len;
    size_t         pos;
    int            err;
} cbor_reader_t;

void cbor_reader_init(cbor_reader_t *r, const uint8_t *buf, size_t len);

/* Peek the major type at current position without advancing. Returns
 * the major type (0..7) or -1 if past end. */
int cbor_reader_peek_major(const cbor_reader_t *r);

#endif /* NIXTROPIC_FIDO_HID_CBOR_H */
