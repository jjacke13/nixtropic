/*
 * Host tests for the M&D kernel v2 (firmware/src/tropic/pin_md_kernel.c,
 * Phase 9 M4 step 2) against the mock chip: the API cases, retirement
 * against a replayed old record, the attempt bound (I2), the last-slot
 * exception, and a single-fault sweep (every chip call, every fault kind)
 * over setup, verify, change, reset-setup and clear (design §7: I1, I4, I5).
 */
#include <string.h>

#include "check.h"
#include "mock_tropic.h"
#include "tropic/pin_md_kernel.h"
#include "tropic/tropic.h"

#define ROUNDS 3u
#define MAT 16u

static rec_pair_t R = REC_PAIR(41, 42, 2, 1);
static const pin_md_layout_t L = {
    .rec = &R, .base = { 0, 8 }, .ranges = 2, .rounds = ROUNDS, .mat_len = MAT,
};
static rec_pair_t RC_R = REC_PAIR(52, 55, 6, 1);
static const pin_md_layout_t RC = {
    .rec = &RC_R, .base = { 28, 0 }, .ranges = 1, .rounds = ROUNDS, .mat_len = MAT,
};

/* MAT bytes of material each (+1 for the literal's NUL, not used). */
static const uint8_t PIN[MAT + 1]   = "correct-pin-0001";
static const uint8_t NEW[MAT + 1]   = "the-new-pin-0002";
static const uint8_t WRONG[MAT + 1] = "wrong-pin-000001";

static void fresh(void)
{
    mock_reset(1);
    R.uncertain = false;
    RC_R.uncertain = false;
}

static void reboot(void)
{
    R.uncertain = false;
    RC_R.uncertain = false;
}

/* 1 = right (k copied out), 0 = wrong, <0 = the kernel's error code. */
static int try_pin(const uint8_t *mat, uint8_t k[32])
{
    int ok = -1;
    int rc = pin_md_kernel_verify(&L, mat, &ok, k);
    return rc == PMD_OK ? ok : rc;
}

static pmd_state_t state(uint8_t *attempts)
{
    return pin_md_kernel_status(&L, attempts, NULL);
}

static bool zero32(const uint8_t *k)
{
    static const uint8_t z[32];
    return memcmp(k, z, 32) == 0;
}

static void test_setup_verify(void)
{
    uint8_t k1[32], k[32], att = 0, len = 0;
    fresh();
    CHECK(state(&att) == PMD_ABSENT);
    CHECK(try_pin(PIN, k) == PMD_ERR_ABSENT);
    CHECK(pin_md_kernel_setup(&L, PIN, 4, k1) == PMD_OK && !zero32(k1));
    CHECK(pin_md_kernel_status(&L, &att, &len) == PMD_ACTIVE && att == ROUNDS && len == 4);
    CHECK(try_pin(PIN, k) == 1 && memcmp(k, k1, 32) == 0);
    memset(k, 0xaa, sizeof k);
    CHECK(try_pin(WRONG, k) == 0 && zero32(k));          /* k wiped on a wrong PIN */
    CHECK(state(&att) == PMD_ACTIVE && att == ROUNDS - 1);
    CHECK(try_pin(PIN, k) == 1 && memcmp(k, k1, 32) == 0);
    CHECK(state(&att) == PMD_ACTIVE && att == ROUNDS);
}

static void test_lockout(void)
{
    uint8_t k[32], att = 9;
    fresh();
    CHECK(pin_md_kernel_setup(&L, PIN, 4, NULL) == PMD_OK);
    for (unsigned i = 0; i < ROUNDS; ++i) CHECK(try_pin(WRONG, k) == 0);
    CHECK(state(&att) == PMD_BLOCKED && att == 0);
    CHECK(try_pin(PIN, k) == PMD_ERR_BLOCKED);
}

/* Change keeps k (I4), flips the range, and the old PIN stops working. */
static void test_change(void)
{
    uint8_t k1[32], k[32], len = 0;
    int ok = -1;
    fresh();
    CHECK(pin_md_kernel_setup(&L, PIN, 4, k1) == PMD_OK);
    CHECK(pin_md_kernel_change(&L, WRONG, NEW, 6, &ok, k) == PMD_OK && ok == 0 && zero32(k));
    CHECK(pin_md_kernel_change(&L, PIN, NEW, 6, &ok, k) == PMD_OK && ok == 1);
    CHECK(memcmp(k, k1, 32) == 0);
    CHECK(pin_md_kernel_status(&L, NULL, &len) == PMD_ACTIVE && len == 6);
    CHECK(try_pin(PIN, k) == 0);
    CHECK(try_pin(NEW, k) == 1 && memcmp(k, k1, 32) == 0);
    CHECK(pin_md_kernel_change(&L, NEW, PIN, 4, &ok, k) == PMD_OK && ok == 1);   /* back to A */
    CHECK(try_pin(PIN, k) == 1 && memcmp(k, k1, 32) == 0);
}

/* A reset-style setup over a blocked PIN: fresh s, so a new k. */
static void test_setup_over_blocked(void)
{
    uint8_t k1[32], k2[32], k[32];
    fresh();
    CHECK(pin_md_kernel_setup(&L, PIN, 4, k1) == PMD_OK);
    for (unsigned i = 0; i < ROUNDS; ++i) CHECK(try_pin(WRONG, k) == 0);
    CHECK(pin_md_kernel_setup(&L, NEW, 6, k2) == PMD_OK && memcmp(k1, k2, 32) != 0);
    CHECK(try_pin(NEW, k) == 1 && memcmp(k, k2, 32) == 0);
    CHECK(try_pin(PIN, k) == 0);
}

/* Raw copy of the record (as an attacker with L3 access could take it). */
static size_t snapshot(uint8_t *out)
{
    size_t n = 0;
    CHECK(tropic_rmem_read(41, out, 475, &n) == 0);
    return n;
}

static void replay(const uint8_t *rec, size_t n)
{
    for (uint16_t s = 41; s <= 42; ++s) {
        CHECK(tropic_rmem_erase(s) == 0);
        CHECK(tropic_rmem_write(s, rec, n) == 0);
    }
}

/* After a change, the old record + old PIN no longer open s (§3.4). */
static void test_retired_range_refuses_replay(void)
{
    uint8_t old[475], k[32];
    int ok;
    fresh();
    CHECK(pin_md_kernel_setup(&L, PIN, 4, NULL) == PMD_OK);
    size_t n = snapshot(old);
    CHECK(pin_md_kernel_change(&L, PIN, NEW, 4, &ok, NULL) == PMD_OK && ok == 1);
    replay(old, n);
    reboot();
    CHECK(state(NULL) == PMD_ACTIVE);
    CHECK(try_pin(PIN, k) == 0);
}

static void test_clear(void)
{
    uint8_t old[475], k[32];
    fresh();
    CHECK(pin_md_kernel_setup(&L, PIN, 4, NULL) == PMD_OK);
    size_t n = snapshot(old);
    CHECK(pin_md_kernel_clear(&L) == PMD_OK);
    CHECK(state(NULL) == PMD_ABSENT);
    replay(old, n);
    reboot();
    CHECK(try_pin(PIN, k) == 0);                          /* range retired */
}

/* RC has one range: setup again only after clear (§3.3). */
static void test_one_range(void)
{
    int ok = -1;
    fresh();
    CHECK(pin_md_kernel_setup(&RC, PIN, 8, NULL) == PMD_OK);
    CHECK(pin_md_kernel_setup(&RC, NEW, 8, NULL) == PMD_ERR);
    CHECK(pin_md_kernel_verify(&RC, PIN, &ok, NULL) == PMD_OK && ok == 1);
    CHECK(pin_md_kernel_clear(&RC) == PMD_OK);
    CHECK(pin_md_kernel_status(&RC, NULL, NULL) == PMD_ABSENT);
    CHECK(pin_md_kernel_setup(&RC, NEW, 8, NULL) == PMD_OK);
    CHECK(pin_md_kernel_verify(&RC, NEW, &ok, NULL) == PMD_OK && ok == 1);
}

/* Read error / damaged record: ERROR, nothing written, no M&D; clear recovers. */
static void test_error_fails_closed(void)
{
    uint8_t k[32];
    fresh();
    CHECK(pin_md_kernel_setup(&L, PIN, 4, NULL) == PMD_OK);
    unsigned w = mock_calls(MOCK_OP_RMEM_WRITE), m = mock_calls(MOCK_OP_MAC_AND_DESTROY);
    mock_fail_nth(MOCK_OP_RMEM_READ, 1, -1, false);
    CHECK(state(NULL) == PMD_ERROR);
    mock_fail_nth(MOCK_OP_RMEM_READ, 1, -1, false);
    CHECK(try_pin(PIN, k) == PMD_ERR);
    mock_fail_nth(MOCK_OP_RMEM_READ, 1, -1, false);
    CHECK(pin_md_kernel_setup(&L, NEW, 4, NULL) == PMD_ERR);
    CHECK(mock_calls(MOCK_OP_RMEM_WRITE) == w && mock_calls(MOCK_OP_MAC_AND_DESTROY) == m);

    mock_rmem_damage(41, MOCK_DAMAGE_GARBLE);
    mock_rmem_damage(42, MOCK_DAMAGE_GARBLE);
    CHECK(state(NULL) == PMD_ERROR);
    CHECK(pin_md_kernel_setup(&L, NEW, 4, NULL) == PMD_ERR);
    CHECK(pin_md_kernel_clear(&L) == PMD_OK);
    CHECK(state(NULL) == PMD_ABSENT);
}

/* A record whose fields are out of range is ERROR, not a binding. */
static void test_record_fields_checked(void)
{
    uint8_t p[4 + 32 + ROUNDS * 32];
    static const uint8_t bad[][3] = {
        { 2, 0, 0 },          /* range B+1 */
        { 0, 2, 0 },          /* retire_pending not 0/1 */
        { 0, 0, ROUNDS + 1 }, /* next beyond rounds */
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        fresh();
        memset(p, 0, sizeof p);
        memcpy(p, bad[i], 3);
        CHECK(rec_pair_init(&R, p, sizeof p) == REC_OK);
        CHECK(state(NULL) == PMD_ERROR);
    }
    fresh();
    CHECK(rec_pair_init(&R, p, sizeof p - 1) == REC_OK);                 /* wrong length */
    CHECK(state(NULL) == PMD_ERROR);
    fresh();
    p[0] = 0; p[1] = 1; p[2] = 0;
    CHECK(rec_pair_init(&RC_R, p, sizeof p) == REC_OK);                  /* pending on one range */
    CHECK(pin_md_kernel_status(&RC, NULL, NULL) == PMD_ERROR);
}

/* A retirement that fails after the commit is finished by the next call. */
static void test_settle_finishes_retirement(void)
{
    uint8_t k[32];
    int ok = -1;
    fresh();
    CHECK(pin_md_kernel_setup(&L, PIN, 4, NULL) == PMD_OK);
    /* change = verify (1 + 3 restore) + setup (9) + retire (3): fail the first retire call */
    mock_fail_nth(MOCK_OP_MAC_AND_DESTROY, 1 + ROUNDS + 3 * ROUNDS + 1, -1, false);
    CHECK(pin_md_kernel_change(&L, PIN, NEW, 4, &ok, NULL) == PMD_OK && ok == 1);
    unsigned m = mock_calls(MOCK_OP_MAC_AND_DESTROY);
    CHECK(state(NULL) == PMD_ACTIVE);
    CHECK(mock_calls(MOCK_OP_MAC_AND_DESTROY) == m + ROUNDS);           /* settled */
    CHECK(state(NULL) == PMD_ACTIVE);
    CHECK(mock_calls(MOCK_OP_MAC_AND_DESTROY) == m + ROUNDS);           /* once */
    CHECK(try_pin(NEW, k) == 1);
}

/* I2: however the reservation is faulted, wrong guesses that reach the
 * chip never exceed `rounds`. */
static void test_attempt_bound(void)
{
    static const struct { mock_op_t op; int rc; bool exec; } faults[] = {
        { MOCK_OP_RMEM_WRITE, -1, false }, { MOCK_OP_RMEM_WRITE, -1, true },
        { MOCK_OP_RMEM_ERASE, -1, false }, { MOCK_OP_RMEM_ERASE, -1, true },
        { MOCK_OP_RMEM_READ, -1, false },  { MOCK_OP_MAC_AND_DESTROY, -1, true },
    };
    for (size_t f = 0; f < sizeof faults / sizeof faults[0]; ++f) {
        for (unsigned n = 1; n <= 4; ++n) {
            uint8_t k[32];
            unsigned evaluated = 0;
            fresh();
            CHECK(pin_md_kernel_setup(&L, PIN, 4, NULL) == PMD_OK);
            for (int i = 0; i < 20; ++i) {
                if (i % 2 == 0) mock_fail_nth(faults[f].op, n, faults[f].rc, faults[f].exec);
                unsigned m = mock_calls(MOCK_OP_MAC_AND_DESTROY);
                int r = try_pin(WRONG, k);
                evaluated += mock_calls(MOCK_OP_MAC_AND_DESTROY) - m;
                reboot();
                if (r == PMD_ERR_BLOCKED) break;
            }
            mock_disarm();
            CHECK(evaluated <= ROUNDS);
            CHECK(try_pin(PIN, k) == PMD_ERR_BLOCKED);
        }
    }
}

/* ---- single-fault sweep ---- */

enum action { A_SETUP, A_RIGHT, A_WRONG, A_CHANGE, A_RESET, A_CLEAR, A_LAST, A_COUNT };
enum fault { F_ERR, F_LOST, F_GARBLE, F_MASK, F_COUNT };

static uint8_t s_k1[32];      /* k of the "before" binding (PIN) */
static uint8_t s_old[475];    /* raw "before" record, for the replay check */
static size_t  s_old_n;

static void before(enum action a)
{
    uint8_t k[32];
    fresh();
    if (a == A_SETUP) return;
    CHECK(pin_md_kernel_setup(&L, PIN, 4, s_k1) == PMD_OK);
    if (a == A_LAST) {
        for (unsigned i = 0; i + 1 < ROUNDS; ++i) CHECK(try_pin(WRONG, k) == 0);
    }
    s_old_n = snapshot(s_old);
}

/* Returns the action's result; *ok = verify/change correctness; k = out_k. */
static int act(enum action a, int *ok, uint8_t k[32])
{
    *ok = -1;
    switch (a) {
    case A_SETUP:  return pin_md_kernel_setup(&L, PIN, 4, k);
    case A_RIGHT:
    case A_LAST:   return pin_md_kernel_verify(&L, PIN, ok, k);
    case A_WRONG:  return pin_md_kernel_verify(&L, WRONG, ok, k);
    case A_CHANGE: return pin_md_kernel_change(&L, PIN, NEW, 6, ok, k);
    case A_RESET:  return pin_md_kernel_setup(&L, NEW, 6, k);
    default:       return pin_md_kernel_clear(&L);
    }
}

static void arm(mock_op_t op, unsigned n, enum fault f)
{
    switch (f) {
    case F_ERR:    mock_fail_nth(op, n, -1, false); break;
    case F_LOST:   mock_fail_nth(op, n, -1, true); break;
    case F_GARBLE: mock_tear_nth(op, n, -1, MOCK_DAMAGE_GARBLE); break;
    default:       mock_tear_nth(op, n, -1, MOCK_DAMAGE_MASKED); break;
    }
}

static unsigned clean_calls(enum action a, mock_op_t op)
{
    uint8_t k[32];
    int ok;
    before(a);
    unsigned c0 = mock_calls(op);
    CHECK(act(a, &ok, k) == PMD_OK);
    return mock_calls(op) - c0;
}

/* Which of PIN / NEW opens the binding now (bit 0 = PIN, bit 1 = NEW);
 * k of the one that did.  Costs at most one attempt per wrong try. */
static unsigned who_works(uint8_t k[32])
{
    uint8_t kk[32];
    unsigned w = 0;
    if (try_pin(PIN, kk) == 1) { w |= 1u; memcpy(k, kk, 32); }
    if (try_pin(NEW, kk) == 1) { w |= 2u; memcpy(k, kk, 32); }
    return w;
}

static void check_after(enum action a, enum fault f, mock_op_t op, unsigned n,
                        int acted, int ok, const uint8_t *k_out)
{
    uint8_t k[32], att = 0;
    bool tear = f == F_GARBLE || f == F_MASK;
    reboot();
    pmd_state_t st = state(&att);
    bool good = true;
    switch (a) {
    case A_SETUP:
        if (st == PMD_ACTIVE) {
            good = who_works(k) == 1u && (acted != PMD_OK || memcmp(k, k_out, 32) == 0);
        } else {
            good = acted != PMD_OK && (st == PMD_ABSENT || (tear && st == PMD_ERROR));
        }
        break;
    case A_RIGHT:
    case A_WRONG:                                   /* more than one slot left */
        good = st == PMD_ACTIVE && att >= ROUNDS - 1u && who_works(k) == 1u
            && memcmp(k, s_k1, 32) == 0;
        if (acted == PMD_OK && a == A_RIGHT) good = good && ok == 1 && memcmp(k_out, s_k1, 32) == 0;
        break;
    case A_CHANGE: {                                /* I1 + I4 */
        unsigned w = st == PMD_ACTIVE ? who_works(k) : 0u;
        good = (w == 1u || w == 2u) && memcmp(k, s_k1, 32) == 0;
        if (acted == PMD_OK && ok == 1) good = good && w == 2u;
        if (w == 2u) {                              /* old record replayed: refused */
            replay(s_old, s_old_n);
            reboot();
            good = good && try_pin(PIN, k) != 1;
        }
        break;
    }
    case A_RESET: {
        unsigned w = st == PMD_ACTIVE ? who_works(k) : 0u;
        good = w == 1u ? memcmp(k, s_k1, 32) == 0 && acted != PMD_OK
             : w == 2u ? acted != PMD_OK || memcmp(k, k_out, 32) == 0
             : false;
        if (w == 2u) {
            replay(s_old, s_old_n);
            reboot();
            good = good && try_pin(PIN, k) != 1;
        }
        break;
    }
    case A_CLEAR:                                   /* destructive: fails closed */
        good = acted != PMD_OK || st == PMD_ABSENT;
        if (st == PMD_ACTIVE) good = good && who_works(k) != 2u;
        break;
    default:     /* A_LAST: done, untouched (attempt never reserved), or BLOCKED */
        good = st == PMD_BLOCKED
            || (st == PMD_ACTIVE && (att == ROUNDS || att == 1u) && who_works(k) == 1u
                && memcmp(k, s_k1, 32) == 0);
        if (acted == PMD_OK) good = good && ok == 1 && st == PMD_ACTIVE;
        break;
    }
    CHECK(good);
    if (!good) fprintf(stderr, "  action %d fault %d op %d call %u: acted %d ok %d state %d att %u\n",
                       a, f, op, n, acted, ok, st, att);
}

static void sweep(enum action a)
{
    static const mock_op_t ops[] = {
        MOCK_OP_RANDOM, MOCK_OP_RMEM_READ, MOCK_OP_RMEM_WRITE, MOCK_OP_RMEM_ERASE,
        MOCK_OP_MAC_AND_DESTROY,
    };
    for (size_t o = 0; o < sizeof ops / sizeof ops[0]; ++o) {
        mock_op_t op = ops[o];
        bool rmem_mut = op == MOCK_OP_RMEM_WRITE || op == MOCK_OP_RMEM_ERASE;
        unsigned calls = clean_calls(a, op);
        for (unsigned n = 1; n <= calls; ++n) {
            for (int f = 0; f < F_COUNT; ++f) {
                if (!rmem_mut && f >= F_GARBLE) continue;
                if (op == MOCK_OP_RMEM_READ && f == F_LOST) continue;   /* reads change nothing */
                uint8_t k[32];
                int ok;
                before(a);
                unsigned w0 = mock_calls(MOCK_OP_RMEM_WRITE) + mock_calls(MOCK_OP_RMEM_ERASE)
                            + mock_calls(MOCK_OP_MAC_AND_DESTROY);
                arm(op, n, (enum fault) f);
                memset(k, 0xaa, sizeof k);
                int acted = act(a, &ok, k);
                if (a != A_CLEAR && (acted != PMD_OK || ok == 0)) CHECK(zero32(k));  /* no k */
                if (op == MOCK_OP_RMEM_READ && n == 1 && a != A_CLEAR) {  /* I5 */
                    CHECK(acted == PMD_ERR && mock_calls(MOCK_OP_RMEM_WRITE)
                          + mock_calls(MOCK_OP_RMEM_ERASE) + mock_calls(MOCK_OP_MAC_AND_DESTROY) == w0);
                }
                check_after(a, (enum fault) f, op, n, acted, ok, k);
            }
        }
    }
}

int main(void)
{
    test_setup_verify();
    test_lockout();
    test_change();
    test_setup_over_blocked();
    test_retired_range_refuses_replay();
    test_clear();
    test_one_range();
    test_error_fails_closed();
    test_record_fields_checked();
    test_settle_finishes_retirement();
    test_attempt_bound();
    for (int a = 0; a < A_COUNT; ++a) sweep((enum action) a);
    return check_done("pin_md_kernel");
}
