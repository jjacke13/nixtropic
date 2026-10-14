/*
 * CDC TX glue — printf retarget to /dev/ttyACM*.
 *
 * Newlib's _write is the syscall that printf/vprintf eventually call.
 * We override it to push bytes into TinyUSB's CDC TX FIFO. tud_task()
 * polled in main loop drains the FIFO over USB; _write itself never
 * calls it (Phase 9 M2).
 *
 * Note: writes are non-blocking — if the host isn't reading and the
 * FIFO fills, excess bytes are silently dropped. For console use
 * during bring-up that's fine; we'd revisit if we ever need lossless
 * logging.
 *
 * Release build (no CDC interface): _write accepts and discards every
 * byte, so printf is a no-op and never blocks.
 */

#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>

#include "tusb.h"

#if !NIXTROPIC_DEBUG

ssize_t _write(int fd, const void *buf, size_t count)
{
    (void) fd;
    (void) buf;
    return (ssize_t) count;
}

#else

ssize_t _write(int fd, const void *buf, size_t count)
{
    (void) fd;

    /* Copy into TinyUSB's CDC TX FIFO; the main loop's tud_task() drains
     * it.  Never call tud_task() from here (Phase 9 M2, jan review):
     * printf runs inside chip operations, and tud_task() can dispatch a
     * whole FIDO or CCID request, chip calls included, in the middle of
     * another one.  When the FIFO (2 KB) is full the rest of the message
     * is dropped: this is a debug log.  Before the host opens the port
     * the bytes wait in the FIFO.  '\n' becomes "\r\n" for picocom.
     * Always reports the full count, so newlib never flags stdout as
     * failed. */
    static const uint8_t crlf[2] = { '\r', '\n' };
    const uint8_t *p = (const uint8_t *) buf;

    for (size_t i = 0; i < count; ++i) {
        const bool add_cr = (p[i] == '\n') && (i == 0 || p[i - 1] != '\r');
        const uint32_t need = add_cr ? 2u : 1u;
        if (tud_cdc_write_available() < need) {
            break;
        }
        (void) tud_cdc_write(add_cr ? crlf : &p[i], need);
    }
    tud_cdc_write_flush();
    return (ssize_t) count;
}

#endif /* NIXTROPIC_DEBUG */
