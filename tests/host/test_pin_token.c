/*
 * Host tests for firmware/src/fido_hid/pin_token.c (Phase 9 M3):
 * permissions, permissions RP ID, timers, consumption, reset.
 */
#include <string.h>

#include "check.h"
#include "fido_hid/pin_token.h"
#include "hmac.h"

static const uint8_t TOKEN[PUAT_TOKEN_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8 };
static const uint8_t MSG[32] = { 0x5A };
static uint8_t RP_A[PUAT_RP_HASH_LEN] = { 0xAA };
static uint8_t RP_B[PUAT_RP_HASH_LEN] = { 0xBB };

static void param_for(const uint8_t *token, uint8_t out[PUAT_PARAM_LEN])
{
    uint8_t mac[32];
    hmac_sha256(token, PUAT_TOKEN_LEN, MSG, sizeof MSG, mac);
    memcpy(out, mac, PUAT_PARAM_LEN);
}

static void test_verify(void)
{
    uint8_t p[PUAT_PARAM_LEN];
    param_for(TOKEN, p);

    puat_reset();
    CHECK(puat_verify(p, sizeof p, MSG, sizeof MSG, 0) == -1);   /* no token */
    CHECK(puat_token() == NULL);

    puat_begin(TOKEN, PUAT_PERM_MC | PUAT_PERM_GA, NULL, 1000);
    CHECK(puat_verify(p, sizeof p, MSG, sizeof MSG, 1000) == 0);
    CHECK(puat_user_verified());
    CHECK(puat_token() != NULL);

    uint8_t bad[PUAT_PARAM_LEN];
    memcpy(bad, p, sizeof bad);
    bad[0] ^= 1u;
    CHECK(puat_verify(bad, sizeof bad, MSG, sizeof MSG, 1000) == -1);
    CHECK(puat_verify(p, 15, MSG, sizeof MSG, 1000) == -1);          /* wrong length */
    CHECK(puat_verify(p, 0, MSG, sizeof MSG, 1000) == -1);
}

static void test_permissions(void)
{
    puat_begin(TOKEN, PUAT_PERM_MC | PUAT_PERM_GA | 0xC0u, NULL, 0);
    CHECK(puat_has_perm(PUAT_PERM_MC) && puat_has_perm(PUAT_PERM_GA));
    CHECK(!puat_has_perm(PUAT_PERM_CM) && !puat_has_perm(PUAT_PERM_ACFG));
    CHECK(!puat_has_perm(0x40u));                /* unknown bits dropped */
    CHECK(!puat_has_perm(0));

    puat_begin(TOKEN, PUAT_PERM_ACFG, NULL, 0);
    CHECK(puat_has_perm(PUAT_PERM_ACFG) && !puat_has_perm(PUAT_PERM_GA));

    /* consume: a touch-tested operation leaves nothing */
    puat_begin(TOKEN, PUAT_PERM_MC | PUAT_PERM_GA | PUAT_PERM_CM, NULL, 0);
    puat_consume();
    CHECK(!puat_has_perm(PUAT_PERM_MC) && !puat_has_perm(PUAT_PERM_GA)
          && !puat_has_perm(PUAT_PERM_CM));
    CHECK(!puat_user_verified());
}

static void test_rp_binding(void)
{
    /* bound at issue */
    puat_begin(TOKEN, PUAT_PERM_GA, RP_A, 0);
    CHECK(puat_has_rp() && puat_rp_matches(RP_A) && !puat_rp_matches(RP_B));
    puat_bind_rp(RP_B);                           /* no rebinding */
    CHECK(puat_rp_matches(RP_A) && !puat_rp_matches(RP_B));

    /* bound on first use */
    puat_begin(TOKEN, PUAT_PERM_GA, NULL, 0);
    CHECK(!puat_has_rp() && puat_rp_matches(RP_A) && puat_rp_matches(RP_B));
    puat_bind_rp(RP_B);
    CHECK(puat_has_rp() && puat_rp_matches(RP_B) && !puat_rp_matches(RP_A));

    /* a new token starts unbound */
    puat_begin(TOKEN, PUAT_PERM_GA, NULL, 0);
    CHECK(!puat_has_rp());
}

static void test_timers(void)
{
    uint8_t p[PUAT_PARAM_LEN];
    param_for(TOKEN, p);

    /* unused for longer than the initial limit: gone */
    puat_begin(TOKEN, PUAT_PERM_GA, NULL, 5000);
    CHECK(puat_verify(p, sizeof p, MSG, sizeof MSG, 5000 + PUAT_INITIAL_USE_MS + 1) == -1);
    CHECK(!puat_has_perm(PUAT_PERM_GA) && puat_token() == NULL);

    /* used in time: lives past the initial limit, dies at the max life */
    puat_begin(TOKEN, PUAT_PERM_GA, NULL, 5000);
    CHECK(puat_verify(p, sizeof p, MSG, sizeof MSG, 5000 + PUAT_INITIAL_USE_MS) == 0);
    CHECK(puat_verify(p, sizeof p, MSG, sizeof MSG, 5000 + PUAT_MAX_LIFE_MS) == 0);
    CHECK(puat_verify(p, sizeof p, MSG, sizeof MSG, 5000 + PUAT_MAX_LIFE_MS + 1) == -1);

    /* SysTick wrap-around */
    puat_begin(TOKEN, PUAT_PERM_GA, NULL, 0xFFFFFF00u);
    CHECK(puat_verify(p, sizeof p, MSG, sizeof MSG, 0x00000100u) == 0);

    /* a failed verify does not stop the initial timer */
    puat_begin(TOKEN, PUAT_PERM_GA, NULL, 0);
    uint8_t bad[PUAT_PARAM_LEN] = { 0 };
    CHECK(puat_verify(bad, sizeof bad, MSG, sizeof MSG, 10) == -1);
    CHECK(puat_verify(p, sizeof p, MSG, sizeof MSG, PUAT_INITIAL_USE_MS + 1) == -1);
}

static void test_reset(void)
{
    uint8_t p[PUAT_PARAM_LEN];
    param_for(TOKEN, p);
    puat_begin(TOKEN, PUAT_PERM_GA | PUAT_PERM_CM, RP_A, 0);
    puat_reset();
    CHECK(puat_verify(p, sizeof p, MSG, sizeof MSG, 1) == -1);
    CHECK(!puat_has_perm(PUAT_PERM_GA) && !puat_has_rp() && !puat_user_verified());

    /* a second token replaces the first: the old param no longer verifies */
    static const uint8_t TOKEN2[PUAT_TOKEN_LEN] = { 9 };
    puat_begin(TOKEN, PUAT_PERM_GA, NULL, 0);
    puat_begin(TOKEN2, PUAT_PERM_GA, NULL, 0);
    CHECK(puat_verify(p, sizeof p, MSG, sizeof MSG, 1) == -1);
}

int main(void)
{
    test_verify();
    test_permissions();
    test_rp_binding();
    test_timers();
    test_reset();
    return check_done("pin_token");
}
