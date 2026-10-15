/*
 * Host tests for the FIDO persistent state of Phase 9 M4 step 3:
 * slots.c (O1 pair, orphan scrub), pin_md.c (PIN on kernel v2 + guard) and
 * fido_state.c (boot rules, checked wipe) against the mock chip.
 *
 * Covers: first boot, PIN set / verify / change across reboots, the guard
 * repair after a cut inside setPin, O2 lost under a set guard, the old
 * v0.2/M3 layout (refused until authenticatorReset; no automatic migration),
 * a masked old slot 0, read errors, orphan scrub, a single-fault sweep over
 * the reset wipe ("never credentials without the PIN", the counter only
 * after a completed wipe, a second reset always recovers), and that FIDO
 * never touches OpenPGP's M&D slots or R-mem objects.
 */
#include <string.h>

#include "check.h"
#include "mock_tropic.h"
#include "sha2.h"
#include "fido_hid/fido_state.h"
#include "fido_hid/pin_md.h"
#include "fido_hid/slots.h"
#include "tropic/tropic.h"

static void reboot(void)
{
    slots_test_reboot();
    fido_pin_test_reboot();
}

static void fresh_chip(void)
{
    mock_reset(1);
    reboot();
}

static void mat(const char *pin, uint8_t out[PIN_MD_MATERIAL_LEN])
{
    uint8_t h[32];
    sha256_Raw((const uint8_t *) pin, (uint32_t) strlen(pin), h);
    memcpy(out, h, PIN_MD_MATERIAL_LEN);
}

static int verify(const char *pin)
{
    uint8_t m[PIN_MD_MATERIAL_LEN];
    int ok = -1;
    mat(pin, m);
    int rc = fido_pin_verify(m, &ok);
    return rc == 0 ? ok : rc;
}

static int set_pin(const char *pin)
{
    uint8_t m[PIN_MD_MATERIAL_LEN];
    mat(pin, m);
    return fido_pin_set(m, (uint8_t) strlen(pin));
}

static int change_pin(const char *old_pin, const char *new_pin)
{
    uint8_t a[PIN_MD_MATERIAL_LEN], b[PIN_MD_MATERIAL_LEN];
    int ok = -1;
    mat(old_pin, a);
    mat(new_pin, b);
    int rc = fido_pin_change(a, b, (uint8_t) strlen(new_pin), &ok);
    return rc == 0 ? ok : rc;
}

/* A credential the way credstore makes one: metadata + bitmap, then a key. */
static int add_cred(void)
{
    uint8_t rp[32] = { 1 }, id[SLOTS_CRED_ID_LEN];
    int idx = -1;
    if (slots_alloc(rp, SLOTS_ALG_ED25519, 0, NULL, 0, 1, 0, id, &idx) != 0) return -1;
    mock_ecc_put((uint8_t) idx);
    return idx;
}

static bool slot_empty(uint16_t slot)
{
    uint8_t b[8];
    size_t n = 0;
    int rc = tropic_rmem_read(slot, b, sizeof b, &n);
    return rc == TROPIC_ERR_RMEM_SLOT_EMPTY || (rc == 0 && n == 0u);
}

/* Any FIDO key or metadata left on the chip. */
static bool creds_left(void)
{
    for (uint8_t i = 0; i < FIDO_SLOTS_MAX; ++i) {
        if (mock_ecc_present(i) || !slot_empty(SLOTS_RMEM_SLOT_FOR(i))) return true;
    }
    return false;
}

static bool counter_at_start(void)
{
    uint32_t v = 0;
    return tropic_mcounter_get(FIDO_SIGNCOUNT_MCOUNTER, &v) == 0 && v == FIDO_MCOUNTER_MAX;
}

static void test_first_boot(void)
{
    uint8_t att = 9;
    fresh_chip();
    mock_ecc_put(3);                                   /* a stray key: wiped */
    CHECK(fido_state_boot() == 0);
    CHECK(!mock_ecc_present(3) && counter_at_start());
    CHECK(fido_pin_state(&att) == FPIN_NOT_SET && att == 0);
    CHECK(slots_force_uv_get() == 0 && slots_pin_bound() == 0 && slots_bitmap() == 0u);
    reboot();
    unsigned e = mock_calls(MOCK_OP_ECC_ERASE);
    CHECK(fido_state_boot() == 0);
    CHECK(mock_calls(MOCK_OP_ECC_ERASE) == e);         /* no second wipe */
}

/* A counter that cannot be read is never re-initialised by boot (M3). */
static void test_counter_never_reinit(void)
{
    uint32_t v = 0;
    fresh_chip();
    CHECK(fido_state_boot() == 0);
    CHECK(tropic_mcounter_init(FIDO_SIGNCOUNT_MCOUNTER, 77u) == 0);
    reboot();
    mock_fail_nth(MOCK_OP_MCOUNTER, 1, TROPIC_ERR_COUNTER_INVALID, false);
    CHECK(fido_state_boot() != 0);
    CHECK(tropic_mcounter_get(FIDO_SIGNCOUNT_MCOUNTER, &v) == 0 && v == 77u);
}

static void test_pin_lifecycle(void)
{
    uint8_t att = 0;
    fresh_chip();
    CHECK(fido_state_boot() == 0);
    CHECK(set_pin("1234") == 0);
    CHECK(set_pin("9999") == -1);                      /* only from NOT_SET */
    CHECK(fido_pin_state(&att) == FPIN_SET && att == FIDO_PIN_ROUNDS);
    CHECK(slots_pin_bound() == 1 && slots_force_uv_get() == 1);   /* first-PIN auto-enable */
    CHECK(verify("0000") == 0);
    CHECK(fido_pin_state(&att) == FPIN_SET && att == FIDO_PIN_ROUNDS - 1);
    reboot();
    CHECK(fido_state_boot() == 0);
    CHECK(verify("1234") == 1);
    CHECK(fido_pin_state(&att) == FPIN_SET && att == FIDO_PIN_ROUNDS);
    CHECK(change_pin("0000", "5678") == 0);
    CHECK(change_pin("1234", "5678") == 1);
    reboot();
    CHECK(fido_state_boot() == 0);
    CHECK(verify("1234") == 0 && verify("5678") == 1);
    for (unsigned i = 0; i < FIDO_PIN_ROUNDS; ++i) CHECK(verify("0000") == 0);
    CHECK(fido_pin_state(&att) == FPIN_BLOCKED && att == 0);
    CHECK(verify("5678") == -2);
}

/* Cut between setPin's kernel commit and its O1 write: boot sets the guard. */
static void test_guard_repair(void)
{
    fresh_chip();
    CHECK(fido_state_boot() == 0);
    unsigned w = mock_calls(MOCK_OP_RMEM_WRITE);
    (void) w;
    /* setPin = kernel setup (O2 init: 2 record writes), then O1 (2 writes). */
    mock_fail_nth(MOCK_OP_RMEM_WRITE, 3, -1, false);
    CHECK(set_pin("1234") == -1);
    reboot();
    CHECK(fido_state_boot() == 0);
    CHECK(slots_pin_bound() == 1 && slots_force_uv_get() == 0);   /* guard set, alwaysUv off */
    CHECK(fido_pin_state(NULL) == FPIN_SET && verify("1234") == 1);
}

/* O2 lost while the guard says a PIN exists: never "PIN not set". */
static void test_lost_binding(void)
{
    fresh_chip();
    CHECK(fido_state_boot() == 0);
    CHECK(set_pin("1234") == 0);
    CHECK(add_cred() == 0);
    for (uint16_t s = 41; s <= 42; ++s) CHECK(tropic_rmem_erase(s) == 0);
    reboot();
    CHECK(fido_state_boot() != 0);                      /* FIDO refuses */
    CHECK(fido_pin_state(NULL) == FPIN_ERROR);
    CHECK(set_pin("0000") == -1);
    CHECK(mock_ecc_present(0));                         /* nothing wiped by itself */
    CHECK(fido_state_wipe() == 0);                      /* authenticatorReset */
    CHECK(!creds_left() && fido_pin_state(NULL) == FPIN_NOT_SET);
}

/* The old layout: slot 0 "NX7K" v4 (392 B), credentials, a key, an old PIN
 * in its M&D slots.  Refused until reset; nothing changes by itself. */
static void put_old_layout(bool masked)
{
    uint8_t g[392] = { 'N', 'X', '7', 'K', 0, 4 };
    uint8_t c[256] = { 'N', 'X', 'C', 'R', 4, 8 };
    g[9] = 0x07;                                        /* bitmap: slots 0..2 */
    g[10] = 1;                                          /* old pin_set */
    for (uint16_t s = 0; s <= 3; ++s) {
        CHECK(tropic_rmem_write(s, s == 0 ? g : c, s == 0 ? sizeof g : sizeof c) == 0);
    }
    for (uint8_t i = 0; i < 3; ++i) mock_ecc_put(i);
    CHECK(tropic_mcounter_init(FIDO_SIGNCOUNT_MCOUNTER, 1000u) == 0);
    if (masked) mock_rmem_damage(0, MOCK_DAMAGE_MASKED);
}

static void test_old_layout_refused_until_reset(void)
{
    fresh_chip();
    put_old_layout(false);
    unsigned m = mock_mutations();
    CHECK(fido_state_boot() != 0);
    CHECK(mock_mutations() == m);                       /* no wipe, no write */
    CHECK(fido_pin_state(NULL) == FPIN_ERROR && slots_force_uv_get() == 1);
    CHECK(mock_ecc_present(0) && !counter_at_start());
    CHECK(fido_state_wipe() == 0);
    CHECK(!creds_left() && counter_at_start());
    reboot();
    CHECK(fido_state_boot() == 0 && fido_pin_state(NULL) == FPIN_NOT_SET);
}

/* Old slot 0 masked (reads empty), slot 40 empty: O1 ABSENT after one fault
 * — boot wipes everything (checked) before anything is fresh (Jan). */
static void test_masked_old_layout(void)
{
    fresh_chip();
    put_old_layout(true);
    CHECK(fido_state_boot() == 0);
    CHECK(!creds_left() && counter_at_start() && fido_pin_state(NULL) == FPIN_NOT_SET);
}

static void test_read_error_refuses(void)
{
    for (unsigned n = 1; n <= 4; ++n) {
        fresh_chip();
        CHECK(fido_state_boot() == 0);
        CHECK(set_pin("1234") == 0);
        reboot();
        mock_fail_nth(MOCK_OP_RMEM_READ, n, -1, false);
        unsigned m = mock_mutations();
        CHECK(fido_state_boot() != 0);
        CHECK(mock_mutations() == m);
        mock_disarm();
    }
}

static void test_orphan_scrub(void)
{
    fresh_chip();
    CHECK(fido_state_boot() == 0);
    CHECK(add_cred() == 0 && add_cred() == 1 && add_cred() == 2);
    CHECK(tropic_rmem_erase(SLOTS_RMEM_SLOT_FOR(0)) == 0);         /* empty: bit goes */
    mock_rmem_damage(SLOTS_RMEM_SLOT_FOR(1), MOCK_DAMAGE_GARBLE);  /* damaged: bit stays */
    reboot();
    CHECK(fido_state_boot() == 0);
    CHECK(slots_bitmap() == 0x6u);
    reboot();
    mock_fail_nth(MOCK_OP_RMEM_READ, 4, -1, false);     /* O1 (2 reads), then slot 1, slot 2 */
    CHECK(fido_state_boot() == 0);
    CHECK((slots_bitmap() & 0x4u) != 0u);               /* a read error keeps the bit */
}

/* FIDO never touches OpenPGP's M&D slots (16..30) or R-mem objects. */
static void test_other_app_untouched(void)
{
    uint8_t before[15][32], now[32], sentinel[9] = "pgp-objx";
    static const uint16_t pgp_rmem[] = { 33, 43, 50, 51, 52, 53, 54, 55 };
    fresh_chip();
    for (size_t i = 0; i < sizeof pgp_rmem / sizeof pgp_rmem[0]; ++i) {
        CHECK(tropic_rmem_write(pgp_rmem[i], sentinel, sizeof sentinel) == 0);
    }
    for (uint8_t i = 0; i < 15; ++i) mock_mad_peek((uint8_t) (16 + i), before[i]);
    CHECK(fido_state_boot() == 0);
    CHECK(set_pin("1234") == 0);
    CHECK(change_pin("1234", "5678") == 1);
    CHECK(change_pin("5678", "1234") == 1);
    CHECK(verify("0000") == 0 && verify("1234") == 1);
    CHECK(fido_state_wipe() == 0);
    for (uint8_t i = 0; i < 15; ++i) {
        mock_mad_peek((uint8_t) (16 + i), now);
        CHECK(memcmp(now, before[i], 32) == 0);
    }
    for (size_t i = 0; i < sizeof pgp_rmem / sizeof pgp_rmem[0]; ++i) {
        uint8_t b[16];
        size_t n = 0;
        CHECK(tropic_rmem_read(pgp_rmem[i], b, sizeof b, &n) == 0 && n == sizeof sentinel
              && memcmp(b, sentinel, n) == 0);
    }
}

/* ---- reset wipe, single-fault sweep ---- */

enum fault { F_ERR, F_LOST, F_GARBLE, F_MASK, F_SILENT, F_COUNT };

static void arm(mock_op_t op, unsigned n, enum fault f)
{
    switch (f) {
    case F_ERR:    mock_fail_nth(op, n, -1, false); break;
    case F_LOST:   mock_fail_nth(op, n, -1, true); break;
    case F_GARBLE: mock_tear_nth(op, n, -1, MOCK_DAMAGE_GARBLE); break;
    case F_MASK:   mock_tear_nth(op, n, -1, MOCK_DAMAGE_MASKED); break;
    default:       mock_tear_nth(op, n, 0, MOCK_DAMAGE_GARBLE); break;   /* "OK", data left */
    }
}

static void wipe_before(void)
{
    fresh_chip();
    CHECK(fido_state_boot() == 0);
    CHECK(set_pin("1234") == 0);
    CHECK(add_cred() == 0 && add_cred() == 1);
    CHECK(tropic_mcounter_init(FIDO_SIGNCOUNT_MCOUNTER, 5000u) == 0);   /* signatures made */
}

static void test_wipe_sweep(void)
{
    static const mock_op_t ops[] = {
        MOCK_OP_ECC_ERASE, MOCK_OP_RMEM_READ, MOCK_OP_RMEM_WRITE, MOCK_OP_RMEM_ERASE,
        MOCK_OP_MAC_AND_DESTROY, MOCK_OP_RANDOM, MOCK_OP_MCOUNTER,
    };
    for (size_t o = 0; o < sizeof ops / sizeof ops[0]; ++o) {
        mock_op_t op = ops[o];
        wipe_before();
        unsigned c0 = mock_calls(op);
        CHECK(fido_state_wipe() == 0);
        unsigned calls = mock_calls(op) - c0;
        bool rmem_mut = op == MOCK_OP_RMEM_WRITE || op == MOCK_OP_RMEM_ERASE;
        for (unsigned n = 1; n <= calls; ++n) {
            for (int f = 0; f < F_COUNT; ++f) {
                if (f >= F_GARBLE && !rmem_mut) continue;
                if (f == F_LOST && op == MOCK_OP_RMEM_READ) continue;
                wipe_before();
                arm(op, n, (enum fault) f);
                int rc = fido_state_wipe();
                mock_disarm();
                reboot();
                int booted = fido_state_boot();
                fido_pin_state_t st = fido_pin_state(NULL);
                bool good = true;
                /* Never credentials without the PIN. */
                if (booted == 0 && st == FPIN_NOT_SET) good = !creds_left();
                /* The counter starts again only after a completed wipe. */
                if (counter_at_start()) good = good && !creds_left();
                if (rc == 0) good = good && booted == 0 && st == FPIN_NOT_SET && !creds_left();
                /* While any credential remains, the old PIN still guards it
                 * (keys and metadata go before the PIN; a cut inside the PIN
                 * clear may leave a dead PIN over nothing — fails closed). */
                if (booted == 0 && st == FPIN_SET && creds_left()) good = good && verify("1234") == 1;
                /* Another reset always recovers. */
                reboot();
                good = good && fido_state_wipe() == 0 && !creds_left() && counter_at_start();
                reboot();
                good = good && fido_state_boot() == 0 && fido_pin_state(NULL) == FPIN_NOT_SET;
                CHECK(good);
                if (!good) fprintf(stderr, "  wipe fault %d op %d call %u: rc %d boot %d state %d\n",
                                   f, op, n, rc, booted, st);
            }
        }
    }
}

int main(void)
{
    test_first_boot();
    test_counter_never_reinit();
    test_pin_lifecycle();
    test_guard_repair();
    test_lost_binding();
    test_old_layout_refused_until_reset();
    test_masked_old_layout();
    test_read_error_refuses();
    test_orphan_scrub();
    test_other_app_untouched();
    test_wipe_sweep();
    return check_done("fido_state");
}
