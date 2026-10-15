/*
 * Host tests for the M&D kernel v2 (firmware/src/tropic/pin_md_kernel.c,
 * Phase 9 M4 step 2) against the mock chip: the API cases, a right PIN
 * re-keying every slot, retirement against a replayed old record (also
 * immediately after an acknowledged change), settle failures, the attempt
 * bound (I2), the last-slot exception, and a single-fault sweep (every chip
 * call, every fault kind) over setup, verify, change, reset-setup, clear
 * (range A live, range B live, retirement pending) and the one-range RC
 * layout (design §7: I1, I4, I5).
 */
#include <string.h>

#include "check.h"
#include "mock_tropic.h"
#include "tropic/pin_md_kernel.h"
#include "tropic/tropic.h"

#define ROUNDS 3u
#define MAT 16u
/* M&D call of the first retirement inside a change: verify (1 + ROUNDS
 * restore), setup (3 per slot), then retire. */
#define CHANGE_FIRST_RETIRE (1u + ROUNDS + 3u * ROUNDS + 1u)

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

static void reboot(void)
{
    R.uncertain = false;
    RC_R.uncertain = false;
}

static void fresh(void)
{
    mock_reset(1);
    reboot();
}

/* 1 = right (k copied out), 0 = wrong, <0 = the kernel's error code. */
static int try_on(const pin_md_layout_t *Lx, const uint8_t *mat, uint8_t k[32])
{
    int ok = -1;
    int rc = pin_md_kernel_verify(Lx, mat, &ok, k);
    return rc == PMD_OK ? ok : rc;
}

static int try_pin(const uint8_t *mat, uint8_t k[32])
{
    return try_on(&L, mat, k);
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

/* Raw copy of copy A of a record (as an attacker with L3 access could take it). */
static size_t snapshot(const rec_pair_t *p, uint8_t *out)
{
    size_t n = 0;
    CHECK(tropic_rmem_read(p->slot_a, out, 475, &n) == 0);
    return n;
}

static void replay(const rec_pair_t *p, const uint8_t *rec, size_t n)
{
    const uint16_t slots[2] = { p->slot_a, p->slot_b };
    for (size_t i = 0; i < 2; ++i) {
        CHECK(tropic_rmem_erase(slots[i]) == 0);
        CHECK(tropic_rmem_write(slots[i], rec, n) == 0);
    }
}

/* A right PIN opens the binding through every slot: after m wrong tries the
 * next right one goes through slot m, so each slot must have been re-keyed. */
static bool all_slots_open(const pin_md_layout_t *Lx, const uint8_t *mat)
{
    uint8_t k[32];
    if (try_on(Lx, mat, k) != 1) return false;
    for (unsigned m = 1; m < Lx->rounds; ++m) {
        for (unsigned i = 0; i < m; ++i) {
            if (try_on(Lx, WRONG, k) != 0) return false;
        }
        if (try_on(Lx, mat, k) != 1) return false;
    }
    return true;
}

/* ---- API cases ---- */

static void test_setup_verify(void)
{
    uint8_t k1[32], k[32], att = 99, len = 99;
    fresh();
    CHECK(pin_md_kernel_status(&L, &att, &len) == PMD_ABSENT && att == 0 && len == 0);
    CHECK(try_pin(PIN, k) == PMD_ERR_ABSENT);
    CHECK(pin_md_kernel_setup(&L, PIN, 4, k1) == PMD_OK && !zero32(k1));
    CHECK(pin_md_kernel_status(&L, &att, &len) == PMD_ACTIVE && att == ROUNDS && len == 4);
    CHECK(try_pin(PIN, k) == 1 && memcmp(k, k1, 32) == 0);
    memset(k, 0xaa, sizeof k);
    CHECK(try_pin(WRONG, k) == 0 && zero32(k));          /* k wiped on a wrong PIN */
    CHECK(state(&att) == PMD_ACTIVE && att == ROUNDS - 1);
    CHECK(try_pin(PIN, k) == 1 && memcmp(k, k1, 32) == 0);
    CHECK(state(&att) == PMD_ACTIVE && att == ROUNDS);
    CHECK(try_pin(PIN, k) == 1);                          /* through slot 0 again */
}

/* After j wrong tries, the right PIN (through slot j) re-keys every slot. */
static void test_restore_every_slot(void)
{
    uint8_t k[32];
    for (unsigned j = 0; j < ROUNDS; ++j) {
        fresh();
        CHECK(pin_md_kernel_setup(&L, PIN, 4, NULL) == PMD_OK);
        for (unsigned i = 0; i < j; ++i) CHECK(try_pin(WRONG, k) == 0);
        CHECK(try_pin(PIN, k) == 1);
        CHECK(all_slots_open(&L, PIN));
    }
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

/* Change keeps k (I4), flips the range, the old PIN stops working, and the
 * old range is retired with fresh TRNG data (one draw per slot). */
static void test_change(void)
{
    uint8_t k1[32], k[32], len = 0;
    int ok = -1;
    fresh();
    CHECK(pin_md_kernel_setup(&L, PIN, 4, k1) == PMD_OK);
    CHECK(pin_md_kernel_change(&L, WRONG, NEW, 6, &ok, k) == PMD_OK && ok == 0 && zero32(k));
    unsigned r0 = mock_calls(MOCK_OP_RANDOM);
    CHECK(pin_md_kernel_change(&L, PIN, NEW, 6, &ok, k) == PMD_OK && ok == 1);
    CHECK(mock_calls(MOCK_OP_RANDOM) == r0 + ROUNDS);
    CHECK(memcmp(k, k1, 32) == 0);
    CHECK(pin_md_kernel_status(&L, NULL, &len) == PMD_ACTIVE && len == 6);
    CHECK(try_pin(PIN, k) == 0);
    CHECK(try_pin(NEW, k) == 1 && memcmp(k, k1, 32) == 0);
    CHECK(pin_md_kernel_change(&L, NEW, PIN, 4, &ok, k) == PMD_OK && ok == 1);   /* back to A */
    CHECK(try_pin(PIN, k) == 1 && memcmp(k, k1, 32) == 0);
    CHECK(all_slots_open(&L, PIN));
}

/* A reset-style setup over a blocked PIN: fresh s, so a new k. */
static void test_setup_over_blocked(void)
{
    uint8_t k1[32], k2[32], k[32];
    fresh();
    CHECK(pin_md_kernel_setup(&L, PIN, 4, k1) == PMD_OK);
    for (unsigned i = 0; i < ROUNDS; ++i) CHECK(try_pin(WRONG, k) == 0);
    unsigned r0 = mock_calls(MOCK_OP_RANDOM);
    CHECK(pin_md_kernel_setup(&L, NEW, 6, k2) == PMD_OK && memcmp(k1, k2, 32) != 0);
    CHECK(mock_calls(MOCK_OP_RANDOM) == r0 + 1u + ROUNDS);       /* s + retirement */
    CHECK(try_pin(NEW, k) == 1 && memcmp(k, k2, 32) == 0);
    CHECK(try_pin(PIN, k) == 0);
}

/* The tag compare covers all 32 bytes. */
static void test_tag_last_bit(void)
{
    uint8_t p[REC_PAYLOAD_MAX], k[32];
    size_t n = 0;
    fresh();
    CHECK(pin_md_kernel_setup(&L, PIN, 4, NULL) == PMD_OK);
    CHECK(rec_pair_read(&R, p, sizeof p, &n, NULL) == REC_OK);
    p[4 + 31] ^= 0x01;
    CHECK(rec_pair_write(&R, p, n) == REC_OK);
    CHECK(try_pin(PIN, k) == 0);
}

/* After an acknowledged change, the old record + old PIN no longer open s —
 * immediately, before any settle (§3.4). */
static void test_retired_range_refuses_replay(void)
{
    uint8_t old[475], k[32];
    int ok;
    fresh();
    CHECK(pin_md_kernel_setup(&L, PIN, 4, NULL) == PMD_OK);
    size_t n = snapshot(&R, old);
    CHECK(pin_md_kernel_change(&L, PIN, NEW, 4, &ok, NULL) == PMD_OK && ok == 1);
    replay(&R, old, n);
    CHECK(try_pin(PIN, k) == 0);
}

/* A failed retirement: change reports an error and no k, the new PIN is
 * live; settle failures keep it pending; the next good settle retires it. */
static void test_retire_failure(void)
{
    uint8_t old[475], k[32];
    int ok = -1;
    fresh();
    CHECK(pin_md_kernel_setup(&L, PIN, 4, NULL) == PMD_OK);
    size_t n = snapshot(&R, old);
    mock_fail_nth(MOCK_OP_MAC_AND_DESTROY, CHANGE_FIRST_RETIRE, -1, false);
    memset(k, 0xaa, sizeof k);
    CHECK(pin_md_kernel_change(&L, PIN, NEW, 4, &ok, k) == PMD_ERR && ok == 0 && zero32(k));
    mock_fail_nth(MOCK_OP_MAC_AND_DESTROY, 1, -1, false);
    CHECK(state(NULL) == PMD_ERROR);
    mock_fail_nth(MOCK_OP_MAC_AND_DESTROY, 1, -1, true);        /* retired, reply lost */
    CHECK(state(NULL) == PMD_ERROR);
    unsigned m = mock_calls(MOCK_OP_MAC_AND_DESTROY);
    CHECK(state(NULL) == PMD_ACTIVE);
    CHECK(mock_calls(MOCK_OP_MAC_AND_DESTROY) == m + ROUNDS);   /* still pending: all again */
    CHECK(state(NULL) == PMD_ACTIVE);
    CHECK(mock_calls(MOCK_OP_MAC_AND_DESTROY) == m + ROUNDS);   /* done once */
    CHECK(try_pin(NEW, k) == 1);
    replay(&R, old, n);
    CHECK(try_pin(PIN, k) == 0);
}

/* Clear retires every range: with A live, with B live, and with a
 * retirement still pending; the replayed records stay dead. */
static void test_clear(void)
{
    uint8_t a_rec[475], b_rec[475], k[32];
    int ok;
    for (int scenario = 0; scenario < 3; ++scenario) {
        size_t nb = 0;
        fresh();
        CHECK(pin_md_kernel_setup(&L, PIN, 4, NULL) == PMD_OK);
        size_t na = snapshot(&R, a_rec);
        if (scenario == 1) {
            CHECK(pin_md_kernel_change(&L, PIN, NEW, 4, &ok, NULL) == PMD_OK);
            nb = snapshot(&R, b_rec);
        } else if (scenario == 2) {
            mock_fail_nth(MOCK_OP_MAC_AND_DESTROY, CHANGE_FIRST_RETIRE, -1, false);
            CHECK(pin_md_kernel_change(&L, PIN, NEW, 4, &ok, NULL) == PMD_ERR);
            nb = snapshot(&R, b_rec);
        }
        CHECK(pin_md_kernel_clear(&L) == PMD_OK);
        CHECK(state(NULL) == PMD_ABSENT);
        replay(&R, a_rec, na);
        reboot();
        CHECK(try_pin(PIN, k) == 0);
        if (nb != 0) {
            replay(&R, b_rec, nb);
            reboot();
            CHECK(try_pin(NEW, k) == 0);
        }
    }
}

/* RC has one range: setup again only after clear, no change (§3.3). */
static void test_one_range(void)
{
    int ok = -1;
    fresh();
    CHECK(pin_md_kernel_setup(&RC, PIN, 8, NULL) == PMD_OK);
    CHECK(pin_md_kernel_setup(&RC, NEW, 8, NULL) == PMD_ERR);
    unsigned m = mock_calls(MOCK_OP_MAC_AND_DESTROY);
    CHECK(pin_md_kernel_change(&RC, PIN, NEW, 8, &ok, NULL) == PMD_ERR && ok == 0);
    CHECK(mock_calls(MOCK_OP_MAC_AND_DESTROY) == m);
    CHECK(pin_md_kernel_verify(&RC, PIN, &ok, NULL) == PMD_OK && ok == 1);
    CHECK(pin_md_kernel_clear(&RC) == PMD_OK);
    CHECK(pin_md_kernel_status(&RC, NULL, NULL) == PMD_ABSENT);
    CHECK(pin_md_kernel_setup(&RC, NEW, 8, NULL) == PMD_OK);
    CHECK(pin_md_kernel_verify(&RC, NEW, &ok, NULL) == PMD_OK && ok == 1);
}

/* Overlapping A/B ranges are refused before any chip call. */
static void test_bad_layout(void)
{
    static const uint8_t bases[][2] = { { 0, 0 }, { 0, 2 }, { 2, 0 }, { 126, 0 } };   /* overlaps; past slot 127 */
    for (size_t i = 0; i < sizeof bases / sizeof bases[0]; ++i) {
        pin_md_layout_t bad = L;
        int ok;
        bad.base[0] = bases[i][0];
        bad.base[1] = bases[i][1];
        fresh();
        CHECK(pin_md_kernel_setup(&bad, PIN, 4, NULL) == PMD_ERR);
        CHECK(pin_md_kernel_status(&bad, NULL, NULL) == PMD_ERROR);
        CHECK(pin_md_kernel_change(&bad, PIN, NEW, 4, &ok, NULL) == PMD_ERR);
        CHECK(pin_md_kernel_clear(&bad) == PMD_ERR);
        CHECK(mock_mutations() == 0 && mock_calls(MOCK_OP_RMEM_READ) == 0);
    }
    /* Exactly adjacent (like FIDO 0-7 / 8-15) and ending at slot 127: accepted. */
    static const uint8_t good[][2] = { { 0, 3 }, { 3, 0 }, { 125, 0 } };
    for (size_t i = 0; i < sizeof good / sizeof good[0]; ++i) {
        pin_md_layout_t ok_layout = L;
        ok_layout.base[0] = good[i][0];
        ok_layout.base[1] = good[i][1];
        fresh();
        CHECK(pin_md_kernel_setup(&ok_layout, PIN, 4, NULL) == PMD_OK);
        CHECK(all_slots_open(&ok_layout, PIN));
    }
}

/* Read error / damaged record: ERROR, nothing written, no M&D; clear recovers. */
static void test_error_fails_closed(void)
{
    uint8_t k[32];
    fresh();
    CHECK(pin_md_kernel_setup(&L, PIN, 4, NULL) == PMD_OK);
    unsigned mut = mock_mutations();
    mock_fail_nth(MOCK_OP_RMEM_READ, 1, -1, false);
    CHECK(state(NULL) == PMD_ERROR);
    mock_fail_nth(MOCK_OP_RMEM_READ, 1, -1, false);
    CHECK(try_pin(PIN, k) == PMD_ERR);
    mock_fail_nth(MOCK_OP_RMEM_READ, 1, -1, false);
    CHECK(pin_md_kernel_setup(&L, NEW, 4, NULL) == PMD_ERR);
    CHECK(mock_mutations() == mut);

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

/* ---- fault injection ---- */

enum fault { F_ERR, F_LOST, F_GARBLE, F_MASK, F_COUNT };

static void arm(mock_op_t op, unsigned n, enum fault f)
{
    switch (f) {
    case F_ERR:    mock_fail_nth(op, n, -1, false); break;
    case F_LOST:   mock_fail_nth(op, n, -1, true); break;
    case F_GARBLE: mock_tear_nth(op, n, -1, MOCK_DAMAGE_GARBLE); break;
    default:       mock_tear_nth(op, n, -1, MOCK_DAMAGE_MASKED); break;
    }
}

static bool fault_applies(mock_op_t op, int f)
{
    bool rmem_mut = op == MOCK_OP_RMEM_WRITE || op == MOCK_OP_RMEM_ERASE;
    if (f >= F_GARBLE) return rmem_mut;
    return !(op == MOCK_OP_RMEM_READ && f == F_LOST);        /* reads change nothing */
}

static const mock_op_t OPS[] = {
    MOCK_OP_RANDOM, MOCK_OP_RMEM_READ, MOCK_OP_RMEM_WRITE, MOCK_OP_RMEM_ERASE,
    MOCK_OP_MAC_AND_DESTROY,
};
#define N_OPS (sizeof OPS / sizeof OPS[0])

/* I2: however the reservations are faulted (every other try, every kind),
 * wrong guesses that reach the chip never exceed `rounds`. */
static void test_attempt_bound(void)
{
    for (size_t o = 0; o < N_OPS; ++o) {
        for (int f = 0; f < F_COUNT; ++f) {
            if (!fault_applies(OPS[o], f)) continue;
            for (unsigned n = 1; n <= 6; ++n) {
                uint8_t k[32];
                unsigned evaluated = 0;
                fresh();
                CHECK(pin_md_kernel_setup(&L, PIN, 4, NULL) == PMD_OK);
                for (int i = 0; i < 30; ++i) {
                    if (i % 2 == 0) arm(OPS[o], n, (enum fault) f);
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
}

/* ---- single-fault sweep ---- */

enum action {
    A_SETUP, A_RIGHT, A_WRONG, A_CHANGE, A_RESET, A_CLEAR, A_CLEAR_B, A_CLEAR_PENDING,
    A_LAST, A_RC_SETUP, A_RC_CLEAR, A_COUNT
};

static uint8_t s_k1[32];      /* k of the "before" binding (PIN) */
static uint8_t s_old[475];    /* raw "before" record (range A / RC) */
static size_t  s_old_n;
static uint8_t s_brec[475];   /* raw record after a change (range B live) */
static size_t  s_brec_n;

static bool is_clear(enum action a)
{
    return a == A_CLEAR || a == A_CLEAR_B || a == A_CLEAR_PENDING || a == A_RC_CLEAR;
}

static void before(enum action a)
{
    uint8_t k[32];
    int ok;
    fresh();
    s_brec_n = 0;
    if (a == A_SETUP || a == A_RC_SETUP) return;
    if (a == A_RC_CLEAR) {
        CHECK(pin_md_kernel_setup(&RC, PIN, 8, NULL) == PMD_OK);
        s_old_n = snapshot(&RC_R, s_old);
        return;
    }
    CHECK(pin_md_kernel_setup(&L, PIN, 4, s_k1) == PMD_OK);
    s_old_n = snapshot(&R, s_old);
    if (a == A_LAST) {
        for (unsigned i = 0; i + 1 < ROUNDS; ++i) CHECK(try_pin(WRONG, k) == 0);
    } else if (a == A_CLEAR_B) {
        CHECK(pin_md_kernel_change(&L, PIN, NEW, 4, &ok, NULL) == PMD_OK);
        s_brec_n = snapshot(&R, s_brec);
    } else if (a == A_CLEAR_PENDING) {
        mock_fail_nth(MOCK_OP_MAC_AND_DESTROY, CHANGE_FIRST_RETIRE, -1, false);
        CHECK(pin_md_kernel_change(&L, PIN, NEW, 4, &ok, NULL) == PMD_ERR);
        s_brec_n = snapshot(&R, s_brec);
    }
}

static int act(enum action a, int *ok, uint8_t k[32])
{
    *ok = -1;
    switch (a) {
    case A_SETUP:    return pin_md_kernel_setup(&L, PIN, 4, k);
    case A_RIGHT:
    case A_LAST:     return pin_md_kernel_verify(&L, PIN, ok, k);
    case A_WRONG:    return pin_md_kernel_verify(&L, WRONG, ok, k);
    case A_CHANGE:   return pin_md_kernel_change(&L, PIN, NEW, 6, ok, k);
    case A_RESET:    return pin_md_kernel_setup(&L, NEW, 6, k);
    case A_RC_SETUP: return pin_md_kernel_setup(&RC, PIN, 8, k);
    case A_RC_CLEAR: return pin_md_kernel_clear(&RC);
    default:         return pin_md_kernel_clear(&L);
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

/* The old record replayed (no settle in between) does not open with PIN. */
static bool old_replay_refused(void)
{
    uint8_t k[32];
    replay(&R, s_old, s_old_n);
    reboot();
    return try_pin(PIN, k) != 1;
}

/* A_LAST: faults that stop before the reservation reaches either copy leave
 * the attempt untouched.  Reservation = settle (reads 1-2), then the pair
 * write: its reads 3-4, erase/write/read-back of A, then B. */
static bool before_reservation(mock_op_t op, unsigned n, enum fault f)
{
    return (op == MOCK_OP_RMEM_READ && n <= 4u) || (op == MOCK_OP_RMEM_ERASE && n == 1u)
        || (op == MOCK_OP_RMEM_WRITE && n == 1u && f != F_LOST);
}

static bool check_clear(enum action a, int acted, pmd_state_t st)
{
    uint8_t k[32];
    if (acted == PMD_OK && st != PMD_ABSENT) return false;
    if (st != PMD_ABSENT) {                           /* interrupted: a second clear recovers */
        const pin_md_layout_t *Lx = a == A_RC_CLEAR ? &RC : &L;
        return pin_md_kernel_clear(Lx) == PMD_OK
            && pin_md_kernel_status(Lx, NULL, NULL) == PMD_ABSENT;
    }
    if (a == A_RC_CLEAR) {                            /* absent = every range retired */
        int ok = -1;
        replay(&RC_R, s_old, s_old_n);
        reboot();
        return pin_md_kernel_verify(&RC, PIN, &ok, k) != PMD_OK || ok != 1;
    }
    bool good = old_replay_refused();
    if (s_brec_n != 0) {
        replay(&R, s_brec, s_brec_n);
        reboot();
        good = good && try_pin(NEW, k) != 1;
    }
    return good;
}

static void check_after(enum action a, enum fault f, mock_op_t op, unsigned n,
                        int acted, int ok, const uint8_t *k_out)
{
    uint8_t k[32], att = 0;
    bool tear = f == F_GARBLE || f == F_MASK;
    reboot();
    pmd_state_t st = a == A_RC_SETUP || a == A_RC_CLEAR
                   ? pin_md_kernel_status(&RC, &att, NULL) : state(&att);
    bool good = true;
    switch (a) {
    case A_SETUP:
        if (st == PMD_ACTIVE) {
            good = who_works(k) == 1u && (acted != PMD_OK || memcmp(k, k_out, 32) == 0)
                && all_slots_open(&L, PIN);
        } else {
            good = acted != PMD_OK && (st == PMD_ABSENT || (tear && st == PMD_ERROR));
        }
        break;
    case A_RC_SETUP:
        if (st == PMD_ACTIVE) {
            good = try_on(&RC, PIN, k) == 1 && (acted != PMD_OK || memcmp(k, k_out, 32) == 0)
                && all_slots_open(&RC, PIN);
        } else {
            good = acted != PMD_OK && (st == PMD_ABSENT || (tear && st == PMD_ERROR));
        }
        break;
    case A_RIGHT:
    case A_WRONG:                                   /* more than one slot left */
        good = st == PMD_ACTIVE && att >= ROUNDS - 1u && try_pin(PIN, k) == 1
            && memcmp(k, s_k1, 32) == 0 && all_slots_open(&L, PIN);
        if (acted == PMD_OK && a == A_RIGHT) good = good && ok == 1 && memcmp(k_out, s_k1, 32) == 0;
        break;
    case A_CHANGE: {                                /* I1 + I4 */
        unsigned w = st == PMD_ACTIVE ? who_works(k) : 0u;
        good = (w == 1u || w == 2u) && memcmp(k, s_k1, 32) == 0
            && all_slots_open(&L, w == 1u ? PIN : NEW);
        if (acted == PMD_OK && ok == 1) good = good && w == 2u;
        if (w == 2u) good = good && old_replay_refused();
        break;
    }
    case A_RESET: {
        unsigned w = st == PMD_ACTIVE ? who_works(k) : 0u;
        good = w == 1u ? memcmp(k, s_k1, 32) == 0 && acted != PMD_OK
             : w == 2u ? acted != PMD_OK || memcmp(k, k_out, 32) == 0
             : false;
        if (w != 0u) good = good && all_slots_open(&L, w == 1u ? PIN : NEW);
        if (w == 2u) good = good && old_replay_refused();
        break;
    }
    case A_LAST:
        if (before_reservation(op, n, f)) {
            good = st == PMD_ACTIVE && att == 1u && try_pin(PIN, k) == 1
                && memcmp(k, s_k1, 32) == 0;
        } else {
            good = st == PMD_BLOCKED
                || (st == PMD_ACTIVE && att == ROUNDS && try_pin(PIN, k) == 1
                    && memcmp(k, s_k1, 32) == 0 && all_slots_open(&L, PIN));
        }
        if (acted == PMD_OK) good = good && ok == 1 && st == PMD_ACTIVE;
        break;
    default:
        good = check_clear(a, acted, st);
        break;
    }
    CHECK(good);
    if (!good) fprintf(stderr, "  action %d fault %d op %d call %u: acted %d ok %d state %d att %u\n",
                       a, f, op, n, acted, ok, st, att);
}

/* Jan: an acknowledged change/reset has already revoked the old binding —
 * replay right after it, before anything settles. */
static void check_immediate_replay(enum action a, mock_op_t op, unsigned n, enum fault f)
{
    uint8_t k[32];
    int ok;
    before(a);
    arm(op, n, f);
    if (act(a, &ok, k) != PMD_OK) return;
    replay(&R, s_old, s_old_n);
    CHECK(try_pin(PIN, k) != 1);
}

static void sweep(enum action a)
{
    for (size_t o = 0; o < N_OPS; ++o) {
        mock_op_t op = OPS[o];
        unsigned calls = clean_calls(a, op);
        for (unsigned n = 1; n <= calls; ++n) {
            for (int f = 0; f < F_COUNT; ++f) {
                if (!fault_applies(op, f)) continue;
                uint8_t k[32];
                int ok;
                before(a);
                arm(op, n, (enum fault) f);
                memset(k, 0xaa, sizeof k);
                int acted = act(a, &ok, k);
                if (!is_clear(a) && (acted != PMD_OK || ok == 0)) CHECK(zero32(k));   /* no k */
                if (op == MOCK_OP_RMEM_READ) {     /* I5: nothing changes after a read error */
                    CHECK(acted == PMD_ERR && mock_mutations() == mock_mutations_at_fault());
                }
                check_after(a, (enum fault) f, op, n, acted, ok, k);
                if ((a == A_CHANGE || a == A_RESET) && acted == PMD_OK) {
                    check_immediate_replay(a, op, n, (enum fault) f);
                }
            }
        }
    }
}

int main(void)
{
    test_setup_verify();
    test_restore_every_slot();
    test_lockout();
    test_change();
    test_setup_over_blocked();
    test_tag_last_bit();
    test_retired_range_refuses_replay();
    test_retire_failure();
    test_clear();
    test_one_range();
    test_bad_layout();
    test_error_fails_closed();
    test_record_fields_checked();
    test_attempt_bound();
    for (int a = 0; a < A_COUNT; ++a) sweep((enum action) a);
    return check_done("pin_md_kernel");
}
