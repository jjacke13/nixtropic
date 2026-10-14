/*
 * Passthrough guard — see guard.h.
 */

#include "guard.h"

#include "lt_l1.h"              /* TR01_L1_GET_RESPONSE_REQ_ID */
#include "lt_l2_api_structs.h"  /* TR01_L2_*_REQ_ID */

/* True while the host is inside a frame it started itself: it asserted
 * CS, clocked a checked first byte, and CS has stayed low since.  Only
 * then are further bytes a continuation and not a request ID. */
static bool s_in_host_frame = false;

bool guard_req_allowed(uint8_t req_id)
{
    switch (req_id) {
    case TR01_L1_GET_RESPONSE_REQ_ID:
    case TR01_L2_GET_INFO_REQ_ID:
    case TR01_L2_RESEND_REQ_ID:
    case TR01_L2_GET_LOG_REQ_ID:
        return true;
    default:
        return false;
    }
}

void guard_cs_changed(void)
{
    s_in_host_frame = false;
}

bool guard_check_transfer(bool asserts_cs, bool cs_low, uint8_t first)
{
    bool continuation = !asserts_cs && cs_low && s_in_host_frame;
    return continuation || guard_req_allowed(first);
}

void guard_transfer_done(bool cs_left_low)
{
    s_in_host_frame = cs_left_low;
}
