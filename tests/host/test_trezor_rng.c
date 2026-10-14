/*
 * Host tests for firmware/src/platform/trezor_rng.c (Phase 9 M2): random32()
 * passes TRNG words through, and on a TRNG failure it stops (rng_fail_stop)
 * instead of returning any value — no P-256 arithmetic continues without
 * real blinding.  The TRNG and the stop are faked here.
 */
#include <setjmp.h>
#include <string.h>

#include "check.h"
#include "platform/trezor_rng.h"

static jmp_buf stop_env;
static int fail_at;      /* 1-based rng_read call that fails; 0 = never */
static int reads;
static int stops;

int rng_read(uint8_t *buf, size_t n)
{
    reads++;
    if (reads == fail_at) {
        return 2;
    }
    uint32_t word = 0xA5000000u + (uint32_t) reads;
    memcpy(buf, &word, n < sizeof word ? n : sizeof word);
    return 0;
}

_Noreturn void rng_fail_stop(void)
{
    stops++;
    longjmp(stop_env, 1);
}

int main(void)
{
    /* Healthy TRNG: the words come straight through. */
    fail_at = 0;
    reads = 0;
    CHECK(random32() == 0xA5000001u);
    CHECK(random32() == 0xA5000002u);
    CHECK(stops == 0);

    /* Failure on the 3rd read, as if mid-way through a multiplication:
     * random32() must stop there and never hand back a value. */
    fail_at = 3;
    reads = 0;
    volatile int returned = 0;
    if (setjmp(stop_env) == 0) {
        (void) random32();
        (void) random32();
        (void) random32();
        returned = 1;
    }
    CHECK(stops == 1);
    CHECK(reads == 3);
    CHECK(returned == 0);

    return check_done("trezor_rng");
}
