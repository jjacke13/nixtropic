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

/* ===== Decoder ===== */

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

/* Read the next CBOR head: returns the major type and the embedded
 * length / value. Advances the position. Returns 0 on success, -1 on
 * any error (truncated, indefinite-length, etc.) and sets r->err. */
int cbor_reader_read_head(cbor_reader_t *r, uint8_t *mt, uint64_t *v);

/* Read an unsigned integer (mt 0). Returns 0/-1. */
int cbor_reader_read_uint(cbor_reader_t *r, uint64_t *v);

/* Read a byte string (mt 2). Sets *ptr to a pointer into the buffer
 * and *len to the byte count. Returns 0/-1. */
int cbor_reader_read_bytes(cbor_reader_t *r, const uint8_t **ptr, size_t *len);

/* Read a text string (mt 3). Same pointer-into-buffer return as
 * read_bytes. Caller treats the bytes as UTF-8 if it cares. */
int cbor_reader_read_text(cbor_reader_t *r, const uint8_t **ptr, size_t *len);

/* Read an array header (mt 4). Returns the element count via *count. */
int cbor_reader_read_array_header(cbor_reader_t *r, size_t *count);

/* Read a map header (mt 5). Returns the key/value pair count. */
int cbor_reader_read_map_header(cbor_reader_t *r, size_t *count);

/* Skip exactly one CBOR data item (recursively, for containers). Used
 * for ignoring unknown / non-relevant map entries. Returns 0/-1. */
int cbor_reader_skip(cbor_reader_t *r);

#endif /* NIXTROPIC_FIDO_HID_CBOR_H */
