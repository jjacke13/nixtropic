/*
 * Host tests for firmware/src/tropic/pin_md_legacy.c against the mock chip.
 * Phase 9 M0 baseline: pins down today's behaviour so M4 changes show up.
 */
#include <string.h>

#include "check.h"
#include "mock_tropic.h"
#include "tropic/pin_md_legacy.h"

#define ROUNDS 3u

/* In-memory stand-in for the caller's R-mem state record. */
static struct {
    uint8_t active, next;
    uint8_t tag[PIN_MD_LEGACY_TAG_LEN];
    uint8_t ci[ROUNDS * PIN_MD_LEGACY_SLOT_SIZE];
    unsigned sets;
} st;

static int st_get(void *ctx, uint8_t *active, uint8_t *next, uint8_t *tag, uint8_t *ci)
{
    (void) ctx;
    if (active) *active = st.active;
    if (next) *next = st.next;
    if (tag) memcpy(tag, st.tag, sizeof st.tag);
    if (ci) memcpy(ci, st.ci, sizeof st.ci);
    return 0;
}

static int st_set(void *ctx, uint8_t active, uint8_t next, const uint8_t *tag, const uint8_t *ci)
{
    (void) ctx;
    st.active = active;
    st.next = next;
    memcpy(st.tag, tag, sizeof st.tag);
    memcpy(st.ci, ci, sizeof st.ci);
    st.sets++;
    return 0;
}

static int st_advance(void *ctx, uint8_t *out_new)
{
    (void) ctx;
    st.next++;
    if (out_new) *out_new = st.next;
    return 0;
}

static const pin_md_legacy_layout_t L = {
    .md_slot_base = 8, .rounds = ROUNDS, .pin_material_len = 16,
    .user_ctx = NULL, .state_get = st_get, .state_set = st_set, .state_advance = st_advance,
};

static const uint8_t PIN[16]   = { 0x63, 0x6f, 0x72, 0x72, 0x65, 0x63, 0x74, 0x2d, 0x70, 0x69, 0x6e, 0x2d, 0x30, 0x30, 0x30, 0x31 };  /* "correct-pin-0001" */
static const uint8_t WRONG[16] = { 0x77, 0x72, 0x6f, 0x6e, 0x67, 0x2d, 0x70, 0x69, 0x6e, 0x2d, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31 };  /* "wrong-pin-000001" */

static void fresh(void)
{
    mock_reset(1);
    memset(&st, 0, sizeof st);
}

static int verify(const uint8_t *pin, int *correct)
{
    *correct = -1;
    return pin_md_legacy_verify(&L, pin, correct);
}

static void test_setup_then_correct(void)
{
    int ok;
    fresh();
    CHECK(pin_md_legacy_setup(&L, PIN) == 0);
    CHECK(pin_md_legacy_is_active(&L));
    CHECK(verify(PIN, &ok) == 0 && ok == 1);
    CHECK(pin_md_legacy_attempts_remaining(&L) == (int) ROUNDS);
    CHECK(verify(PIN, &ok) == 0 && ok == 1);   /* slots were re-initialised */
}

static void test_wrong_then_correct_restores(void)
{
    int ok;
    fresh();
    CHECK(pin_md_legacy_setup(&L, PIN) == 0);
    CHECK(verify(WRONG, &ok) == 0 && ok == 0);
    CHECK(verify(WRONG, &ok) == 0 && ok == 0);
    CHECK(pin_md_legacy_attempts_remaining(&L) == (int) ROUNDS - 2);
    CHECK(verify(PIN, &ok) == 0 && ok == 1);
    CHECK(pin_md_legacy_attempts_remaining(&L) == (int) ROUNDS);
    CHECK(verify(PIN, &ok) == 0 && ok == 1);
}

static void test_lockout(void)
{
    int ok;
    fresh();
    CHECK(pin_md_legacy_setup(&L, PIN) == 0);
    for (unsigned i = 0; i < ROUNDS; ++i) {
        CHECK(verify(WRONG, &ok) == 0 && ok == 0);
    }
    CHECK(pin_md_legacy_attempts_remaining(&L) == 0);
    CHECK(verify(PIN, &ok) == -2);              /* even the right PIN */
}

/* Fault injection: an M&D failure during setup is reported, and the
 * binding is not marked active. */
static void test_setup_fault_reported(void)
{
    fresh();
    mock_fail_nth(MOCK_OP_MAC_AND_DESTROY, 2, -21, false);
    CHECK(pin_md_legacy_setup(&L, PIN) == -2);
    CHECK(!pin_md_legacy_is_active(&L));
    CHECK(st.sets == 0);
}

/* Fault injection: the attempt is counted before the destructive call, so
 * a failure (or power cut) during verify still costs an attempt. */
static void test_verify_fault_counts_attempt(void)
{
    int ok;
    fresh();
    CHECK(pin_md_legacy_setup(&L, PIN) == 0);
    mock_fail_nth(MOCK_OP_MAC_AND_DESTROY, 1, -21, false);
    CHECK(verify(PIN, &ok) == -1 && ok == 0);
    CHECK(pin_md_legacy_attempts_remaining(&L) == (int) ROUNDS - 1);
}

int main(void)
{
    test_setup_then_correct();
    test_wrong_then_correct_restores();
    test_lockout();
    test_setup_fault_reported();
    test_verify_fault_counts_attempt();
    return check_done("pin_md_legacy");
}
