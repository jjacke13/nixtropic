/*
 * Which libtropic results leave the L3 secure session usable (Phase 9 M2).
 *
 * libtropic v3 keeps its own session flag (h->l3.session_status) but does
 * not clear it on every failure: when an L2 send/receive fails after the
 * request was encrypted, the host IVs no longer match the chip's while the
 * flag stays ON (SDK3 libtropic.c:1326-1334, libtropic_l2.c:156-222).  The
 * firmware then fails every later L3 call until a replug.
 *
 * Rule: only a result the chip returned inside the session, decrypted and
 * authenticated, keeps the session.  Everything else (transport, L2 status,
 * host-side L3 parse errors, unknown result byte) ends it on the host side
 * and the next call re-handshakes.  A new handshake replaces the chip's old
 * session (TROPIC01 app v2.0.0 main/ts_l2.c:81-106).
 *
 * The list is explicit on purpose: the lt_ret_t numbering mixes chip
 * results (13..24, 28) with host errors (25..27) and an unknown-result
 * code (29), so a range check is wrong.
 */
#ifndef NIXTROPIC_TROPIC_L3_RESULT_H
#define NIXTROPIC_TROPIC_L3_RESULT_H

#include <stdbool.h>

#include "libtropic_common.h"

static inline bool l3_result_keeps_session(lt_ret_t r)
{
    switch (r) {
    case LT_OK:                            /* chip RESULT_OK decodes to 0 */
    case LT_L3_SLOT_NOT_EMPTY:
    case LT_L3_SLOT_EXPIRED:
    case LT_L3_INVALID_KEY:
    case LT_L3_UPDATE_ERR:
    case LT_L3_COUNTER_INVALID:
    case LT_L3_SLOT_EMPTY:
    case LT_L3_SLOT_INVALID:
    case LT_L3_FAIL:
    case LT_L3_UNAUTHORIZED:
    case LT_L3_INVALID_CMD:
    case LT_L3_HARDWARE_FAIL:
    case LT_L3_R_MEM_DATA_READ_SLOT_EMPTY: /* authenticated empty read */
        return true;
    default:
        return false;
    }
}

/* Wrapper return convention: 0 on success, -code on error.  drop(r) runs
 * exactly once when the result ends the session.  tropic.c passes a
 * function that aborts the libtropic session; the host test passes a
 * counter. */
static inline int l3_result_finish(lt_ret_t r, void (*drop)(lt_ret_t))
{
    if (r == LT_OK) {
        return 0;
    }
    if (!l3_result_keeps_session(r)) {
        drop(r);
    }
    return -(int) r;
}

#endif /* NIXTROPIC_TROPIC_L3_RESULT_H */
