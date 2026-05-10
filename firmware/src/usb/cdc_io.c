/*
 * CDC TX glue — printf retarget to /dev/ttyACM*.
 *
 * Newlib's _write is the syscall that printf/vprintf eventually call.
 * We override it to push bytes into TinyUSB's CDC TX FIFO. tud_task()
 * polled in main loop drains the FIFO over USB.
 *
 * Lines/newlines flush; non-newline bursts are flushed when 64 B
 * accumulated (matches CDC bulk EP packet size).
 *
 * Note: writes are non-blocking — if the host isn't reading and the
 * FIFO fills, excess bytes are silently dropped. For console use
 * during bring-up that's fine; we'd revisit if we ever need lossless
 * logging.
 */

#include <unistd.h>
#include <sys/types.h>

#include "tusb.h"

ssize_t _write(int fd, const void *buf, size_t count)
{
    (void) fd;

    /* Push to TinyUSB's CDC TX FIFO regardless of connection state.
     * Pre-connect: bytes accumulate in the FIFO; once host opens
     * /dev/ttyACM* and TinyUSB's USB IN endpoint drains, they flow.
     * If FIFO fills and we're not connected, we just drop — better
     * than blocking forever waiting for a consumer that may never come. */
    /* Translate '\n' → '\r\n' on the fly so picocom (which doesn't do
     * input mapping by default) shows columns aligned. We track bytes
     * we've consumed from the user buffer separately from bytes we've
     * actually written to the FIFO. */
    const uint8_t *p = (const uint8_t *) buf;
    size_t consumed = 0;
    int last_char = -1;

    while (consumed < count) {
        uint32_t avail = tud_cdc_write_available();
        if (avail == 0) {
            if (tud_cdc_connected()) {
                tud_cdc_write_flush();
                tud_task();
                avail = tud_cdc_write_available();
                if (avail == 0) break;
            } else {
                break;
            }
        }

        uint8_t c = p[consumed];
        if (c == '\n' && last_char != '\r') {
            /* Need 2 bytes of FIFO room to do CR+LF atomically. */
            if (avail < 2) {
                /* Not enough room right now; flush + retry one cycle. */
                tud_cdc_write_flush();
                if (tud_cdc_connected()) tud_task();
                continue;
            }
            uint8_t crlf[2] = { '\r', '\n' };
            uint32_t n = tud_cdc_write(crlf, 2);
            if (n != 2) break;  /* shouldn't happen; defensive */
        } else {
            uint32_t n = tud_cdc_write(&c, 1);
            if (n != 1) break;
        }

        last_char = c;
        consumed++;
    }

    if (consumed > 0 && p[consumed - 1] == '\n') {
        tud_cdc_write_flush();
    }

    return (ssize_t) consumed;
}
