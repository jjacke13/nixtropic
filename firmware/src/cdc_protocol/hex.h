/*
 * Hex parsing/emitting helpers for the CDC ↔ SPI passthrough protocol.
 *
 * Stock fw (and our matching host adapter, libtropic_port_posix_usb_dongle.c)
 * emits upper-case hex pairs with no separators on the wire. We accept both
 * upper and lower case on input (stock cmd.c is case-insensitive via
 * strnicmp) but always emit upper case to match stock byte-for-byte.
 */

#ifndef NIXTROPIC_CDC_HEX_H
#define NIXTROPIC_CDC_HEX_H

#include <stdint.h>

/* Parse one hex byte from src[0..1]. Returns 0 on success and writes *out.
 * Returns -1 if either character is not a hex digit. */
int hex_byte(const char *src, uint8_t *out);

/* Emit one byte as 2 upper-case hex chars into dest[0..1].
 * Does NOT write a null terminator. */
void hex_emit_byte(char *dest, uint8_t byte);

#endif /* NIXTROPIC_CDC_HEX_H */
