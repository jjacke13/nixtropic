/*
 * Line-oriented parser for CDC RX.
 *
 * Accumulates incoming bytes into a 1024-byte static line buffer. On '\n'
 * the line (with trailing '\r' stripped) is dispatched via the registered
 * callback. Lines longer than the buffer trigger an overflow error message
 * and are discarded.
 */

#ifndef NIXTROPIC_CDC_PARSER_H
#define NIXTROPIC_CDC_PARSER_H

#include <stdint.h>

typedef void (*parser_line_cb)(const char *line);

void parser_init(parser_line_cb cb);
void parser_feed(uint8_t byte);

#endif /* NIXTROPIC_CDC_PARSER_H */
