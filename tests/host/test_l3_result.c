/*
 * Host tests for firmware/src/tropic/l3_result.h (Phase 9 M2): which
 * libtropic results keep the L3 session and which end it.  The verdicts
 * come from the TROPIC01 app v2.0.0 source review (jan, 2026-10-14).
 */
#include "check.h"
#include "tropic/l3_result.h"

static int drops;
static lt_ret_t dropped_with;

static void count_drop(lt_ret_t r)
{
    drops++;
    dropped_with = r;
}

/* l3_done in tropic.c: success, a kept chip result, a dropped error. */
static void test_finish(void)
{
    drops = 0;
    CHECK(l3_result_finish(LT_OK, count_drop) == 0);
    CHECK(drops == 0);

    CHECK(l3_result_finish(LT_L3_SLOT_EMPTY, count_drop) == -(int) LT_L3_SLOT_EMPTY);
    CHECK(drops == 0);

    /* Original error comes back unchanged; the session is dropped once. */
    CHECK(l3_result_finish(LT_L2_TAG_ERR, count_drop) == -(int) LT_L2_TAG_ERR);
    CHECK(drops == 1 && dropped_with == LT_L2_TAG_ERR);
}

int main(void)
{
    test_finish();

    /* The chip answered inside the session: IVs still in step. */
    CHECK(l3_result_keeps_session(LT_OK));
    CHECK(l3_result_keeps_session(LT_L3_FAIL));
    CHECK(l3_result_keeps_session(LT_L3_UNAUTHORIZED));
    CHECK(l3_result_keeps_session(LT_L3_SLOT_EMPTY));
    CHECK(l3_result_keeps_session(LT_L3_SLOT_NOT_EMPTY));
    CHECK(l3_result_keeps_session(LT_L3_HARDWARE_FAIL));
    CHECK(l3_result_keeps_session(LT_L3_R_MEM_DATA_READ_SLOT_EMPTY));

    /* Transport and L2 failures: request and IVs may be out of step. */
    CHECK(!l3_result_keeps_session(LT_L1_SPI_ERROR));
    CHECK(!l3_result_keeps_session(LT_L1_INT_TIMEOUT));
    CHECK(!l3_result_keeps_session(LT_L1_CHIP_ALARM_MODE));
    CHECK(!l3_result_keeps_session(LT_L2_NO_SESSION));
    CHECK(!l3_result_keeps_session(LT_L2_TAG_ERR));
    CHECK(!l3_result_keeps_session(LT_L2_CRC_ERR));
    CHECK(!l3_result_keeps_session(LT_L2_IN_CRC_ERR));
    CHECK(!l3_result_keeps_session(LT_L2_GEN_ERR));
    CHECK(!l3_result_keeps_session(LT_L2_NO_RESP));
    CHECK(!l3_result_keeps_session(LT_CRYPTO_ERR));

    /* Host-side L3 errors sit between the chip results in the enum
     * (25..27), and an unknown result byte (29) proves nothing: a range
     * check 13..29 would wrongly keep all four. */
    CHECK(!l3_result_keeps_session(LT_L3_DATA_LEN_ERROR));
    CHECK(!l3_result_keeps_session(LT_L3_RES_SIZE_ERROR));
    CHECK(!l3_result_keeps_session(LT_L3_BUFFER_TOO_SMALL));
    CHECK(!l3_result_keeps_session(LT_L3_RESULT_UNKNOWN));

    /* RESULT_OK decodes to LT_OK; LT_L3_OK is never a real answer. */
    CHECK(!l3_result_keeps_session(LT_L3_OK));

    return check_done("l3_result");
}
