/*
 * Host tests for firmware/src/cdc_protocol/guard.c (Phase 9 M1): the
 * debug passthrough lets a host start a chip request only with a
 * read-only request ID.  Each case replays the CS / line sequence that
 * protocol.c and cmd.c would feed the guard.
 */
#include "check.h"
#include "cdc_protocol/guard.h"

/* A host line as protocol.c sees it: does the guard let it out?  If it
 * does, CS ends up as the line leaves it (no trailing 'x' -> released). */
static bool cs;   /* simulated CS pin: true = asserted */

static bool line(bool lead_x, uint8_t first, bool trail_x)
{
    if (!guard_check_transfer(!lead_x, cs, first)) return false;
    if (!lead_x) cs = true;
    if (!trail_x) cs = false;
    guard_transfer_done(cs);
    return true;
}

static void cs_cmd(bool assert)
{
    cs = assert;
    guard_cs_changed();
}

static void reset(void)
{
    cs = false;
    guard_cs_changed();
}

static void test_allowlist(void)
{
    CHECK(guard_req_allowed(0xAA));   /* GET_RESPONSE */
    CHECK(guard_req_allowed(0x01));   /* Get_Info */
    CHECK(guard_req_allowed(0x10));   /* Resend */
    CHECK(guard_req_allowed(0xA2));   /* Get_Log */

    CHECK(!guard_req_allowed(0x02));  /* Handshake */
    CHECK(!guard_req_allowed(0x04));  /* Encrypted_Cmd */
    CHECK(!guard_req_allowed(0x08));  /* Encrypted_Session_Abt */
    CHECK(!guard_req_allowed(0x20));  /* Sleep */
    CHECK(!guard_req_allowed(0xB0));  /* Mutable_FW_Update (FW >= 2.0) */
    CHECK(!guard_req_allowed(0xB1));  /* Mutable_FW_Update (older) */
    CHECK(!guard_req_allowed(0xB2));  /* Mutable_FW_Erase */
    CHECK(!guard_req_allowed(0xB3));  /* Startup */
    CHECK(!guard_req_allowed(0x00));
    CHECK(!guard_req_allowed(0xFF));

    int allowed = 0;
    for (int b = 0; b < 256; b++) allowed += guard_req_allowed((uint8_t) b);
    CHECK(allowed == 4);              /* nothing else slipped in */
}

static void test_plain_lines(void)
{
    reset();
    CHECK(line(false, 0x01, false));  /* "01 .."  */
    CHECK(!line(false, 0xB3, false)); /* "B3 .."  */
    CHECK(!cs);                       /* refused line left CS alone */
}

static void test_continuation(void)
{
    /* "01 .. x" then "x B3 .." : B3 is the 2nd+ byte of a Get_Info frame. */
    reset();
    CHECK(line(false, 0x01, true));
    CHECK(cs);
    CHECK(line(true, 0xB3, false));
    CHECK(!cs);
}

static void test_new_frame_after_release(void)
{
    /* "01 .." (CS released) then "x B3": not a continuation. */
    reset();
    CHECK(line(false, 0x01, false));
    CHECK(!line(true, 0xB3, false));
}

static void test_reassert_while_low(void)
{
    /* "01 .. x" then "B3 ..": the line asserts CS itself; checked even
     * though CS was already low (conservative). */
    reset();
    CHECK(line(false, 0x01, true));
    CHECK(!line(false, 0xB3, false));
}

static void test_cs_command(void)
{
    /* "CS=1" then "x B3 .." : the host opened the frame by command. */
    reset();
    cs_cmd(true);
    CHECK(!line(true, 0xB3, false));
    CHECK(line(true, 0xAA, true));    /* allowed start ... */
    CHECK(line(true, 0x55, false));   /* ... then its continuation */

    /* "01 .. x", "CS=0", "CS=1", "x B3": a new frame, checked. */
    reset();
    CHECK(line(false, 0x01, true));
    cs_cmd(false);
    cs_cmd(true);
    CHECK(!line(true, 0xB3, false));
}

static void test_cs_dropped_elsewhere(void)
{
    /* "01 .. x", then the firmware's own chip traffic releases CS, then
     * "x B3": CS is high, so not a continuation. */
    reset();
    CHECK(line(false, 0x01, true));
    cs = false;                       /* firmware released CS */
    CHECK(!line(true, 0xB3, false));
}

static void test_cs_left_low_elsewhere(void)
{
    /* "01 .." (CS released), then the firmware's own chip traffic leaves
     * CS asserted (an error path), then "x B3": CS is low, but the host
     * did not start this frame, so B3 is checked. */
    reset();
    CHECK(line(false, 0x01, false));
    cs = true;                        /* firmware left CS asserted */
    CHECK(!line(true, 0xB3, false));
}

static void test_trailing_x_with_cs_high(void)
{
    /* "x 01 x" with CS high clocks nothing the chip reads and leaves CS
     * high: the next "x B3" must still be checked. */
    reset();
    CHECK(line(true, 0x01, true));
    CHECK(!cs);
    CHECK(!line(true, 0xB3, false));
}

int main(void)
{
    test_allowlist();
    test_plain_lines();
    test_continuation();
    test_new_frame_after_release();
    test_reassert_while_low();
    test_cs_command();
    test_cs_dropped_elsewhere();
    test_cs_left_low_elsewhere();
    test_trailing_x_with_cs_high();
    return check_done("passthrough_guard");
}
