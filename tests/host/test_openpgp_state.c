/*
 * Host tests for the OpenPGP persistent state of Phase 9 M4 step 4:
 * openpgp_state.c (O3 pair), pgp_pin.c (PW1 / PW3 / RC on kernel v2 +
 * guards) and pgp_lifecycle.c (bootstrap, wipe, TERMINATE, ACTIVATE)
 * against the mock chip.
 *
 * Covers: first boot, PINs across reboots, RC and its guard, a lost
 * binding under the guard, TERMINATE / ACTIVATE, the DEC key gone from
 * both O3 copies, the old v0.2/M3 layout (refused until TERMINATE; no
 * automatic migration) plain and masked, read errors, an uncertain O3,
 * that OpenPGP never touches FIDO's M&D slots or R-mem objects, both
 * applications' resets in either order, and a single-fault sweep over
 * bootstrap, TERMINATE, ACTIVATE and PUT DATA D3 ("no key under a factory
 * PIN", TERMINATE + ACTIVATE always recover).
 */
#include <stdbool.h>
#include <string.h>

#include "check.h"
#include "mock_tropic.h"
#include "fido_hid/fido_state.h"
#include "fido_hid/pin_md.h"
#include "fido_hid/slots.h"
#include "openpgp/openpgp_state.h"
#include "openpgp/pgp_lifecycle.h"
#include "openpgp/pgp_pin.h"
#include "tropic/rec_pair.h"
#include "tropic/tropic.h"

#define PW1 OPENPGP_PIN_PW1
#define PW3 OPENPGP_PIN_PW3
#define RC  OPENPGP_PIN_RC

static const uint8_t DEC_PAT[OPENPGP_DEC_PRIV_LEN] = {
    0xD1, 0xEC, 0x0F, 0xFE, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 0x40,
};

static void reboot(void)
{
    openpgp_state_test_reboot();
    pgp_pin_test_reboot();
    slots_test_reboot();
    fido_pin_test_reboot();
}

static void fresh_chip(void)
{
    mock_reset(1);
    reboot();
}

static int v(int which, const char *pin)
{
    return pgp_pin_verify(which, (const uint8_t *) pin, strlen(pin));
}

static int chg(int which, const char *a, const char *b)
{
    return pgp_pin_change(which, (const uint8_t *) a, strlen(a), (const uint8_t *) b, strlen(b));
}

static int set_rc(const char *rc)
{
    return pgp_pin_set_rc((const uint8_t *) rc, strlen(rc));
}

static pgp_pin_state_t st(int which, uint8_t *att, uint8_t *len)
{
    return pgp_pin_status(which, att, len);
}

static bool raw_contains(uint16_t slot, const uint8_t *pat, size_t n)
{
    uint8_t b[444];
    size_t got = 0;
    if (tropic_rmem_read(slot, b, sizeof b, &got) != 0) return false;
    for (size_t i = 0; i + n <= got; ++i) {
        if (memcmp(&b[i], pat, n) == 0) return true;
    }
    return false;
}

static bool slot_empty(uint16_t slot)
{
    uint8_t b[8];
    size_t n = 0;
    int rc = tropic_rmem_read(slot, b, sizeof b, &n);
    return rc == TROPIC_ERR_RMEM_SLOT_EMPTY || (rc == 0 && n == 0u);
}

/* Any OpenPGP key: ECC 29..31, or the DEC key in an O3 copy. */
static bool keys_left(void)
{
    return mock_ecc_present(29) || mock_ecc_present(30) || mock_ecc_present(31)
        || raw_contains(33, DEC_PAT, sizeof DEC_PAT) || raw_contains(43, DEC_PAT, sizeof DEC_PAT);
}

/* A card in use: keys, the DEC key, own PW1 / PW3, an RC. */
static void put_in_use(void)
{
    fresh_chip();
    CHECK(pgp_lifecycle_boot() == 0);
    CHECK(openpgp_state_dec_priv_set(DEC_PAT) == 0);
    mock_ecc_put(29);
    mock_ecc_put(31);
    CHECK(chg(PW1, "123456", "pw1-own") == PGP_PIN_OK);
    CHECK(chg(PW3, "12345678", "pw3-own-pin") == PGP_PIN_OK);
    CHECK(set_rc("rc-code-1") == PGP_PIN_OK);
}

/* The v0.2/M3 layout: PG7R schema 6 in slot 33, PMD0 bindings in 50..52,
 * keys in 29 and 31. */
static void put_old_layout(bool masked)
{
    uint8_t st33[256] = { 'P', 'G', '7', 'R', 0, 6, 1, 3, 3, 0xFF };
    uint8_t pmd[256] = { 'P', 'M', 'D', '0', 0, 1, 0, 0, 1, 0 };
    memcpy(&st33[180], DEC_PAT, sizeof DEC_PAT);
    CHECK(tropic_rmem_write(33, st33, sizeof st33) == 0);
    for (uint16_t s = 50; s <= 52; ++s) CHECK(tropic_rmem_write(s, pmd, sizeof pmd) == 0);
    mock_ecc_put(29);
    mock_ecc_put(31);
    if (masked) mock_rmem_damage(33, MOCK_DAMAGE_MASKED);
}

static void test_first_boot(void)
{
    uint8_t att = 0, len = 0, lang[2], name[OPENPGP_NAME_MAX];
    fresh_chip();
    for (uint8_t k = 29; k <= 31; ++k) mock_ecc_put(k);      /* stray keys: wiped */
    CHECK(pgp_lifecycle_boot() == 0);
    CHECK(openpgp_state_lifecycle() == PGP_LC_OPERATIONAL && !keys_left());
    CHECK(st(PW1, &att, &len) == PGP_PIN_ACTIVE && att == 3 && len == 6);
    CHECK(st(PW3, &att, &len) == PGP_PIN_ACTIVE && att == 3 && len == 8);
    CHECK(st(RC, &att, &len) == PGP_PIN_NOT_SET && att == 0 && len == 0);
    uint8_t k[OPENPGP_DEC_PRIV_LEN];
    CHECK(openpgp_state_dec_priv_get(k) == -1);              /* none yet */
    CHECK(openpgp_state_dec_priv_set(DEC_PAT) == 0 && openpgp_state_dec_priv_get(k) == 0
          && memcmp(k, DEC_PAT, sizeof k) == 0);
    openpgp_state_lang(lang);
    CHECK(openpgp_state_c4_multi() == 1 && openpgp_state_uif() == 1 && openpgp_state_sex() == 0x39
          && lang[0] == 'e' && lang[1] == 'n' && openpgp_state_name(name) == 0);
    reboot();
    unsigned e = mock_calls(MOCK_OP_ECC_ERASE);
    CHECK(pgp_lifecycle_boot() == 0);
    CHECK(mock_calls(MOCK_OP_ECC_ERASE) == e);               /* no second wipe */
    CHECK(v(PW1, "123456") == PGP_PIN_OK && v(PW3, "12345678") == PGP_PIN_OK);
}

static void test_pins(void)
{
    uint8_t att = 0, len = 0;
    char long_pin[66];
    fresh_chip();
    CHECK(pgp_lifecycle_boot() == 0);
    CHECK(v(PW1, "000000") == PGP_PIN_WRONG);
    CHECK(st(PW1, &att, NULL) == PGP_PIN_ACTIVE && att == 2);
    reboot();
    CHECK(pgp_lifecycle_boot() == 0);
    CHECK(v(PW1, "123456") == PGP_PIN_OK && st(PW1, &att, NULL) == PGP_PIN_ACTIVE && att == 3);
    CHECK(chg(PW1, "123456", "6543210") == PGP_PIN_OK);
    reboot();
    CHECK(pgp_lifecycle_boot() == 0);
    CHECK(st(PW1, &att, &len) == PGP_PIN_ACTIVE && len == 7);
    CHECK(v(PW1, "123456") == PGP_PIN_WRONG && v(PW1, "6543210") == PGP_PIN_OK);
    CHECK(chg(PW3, "00000000", "pw3-new-pin") == PGP_PIN_WRONG);
    CHECK(st(PW3, &att, NULL) == PGP_PIN_ACTIVE && att == 2);
    CHECK(chg(PW3, "12345678", "pw3-new-pin") == PGP_PIN_OK);
    CHECK(st(PW3, &att, &len) == PGP_PIN_ACTIVE && att == 3 && len == 11);
    /* Lengths are refused before any attempt is spent. */
    memset(long_pin, 'x', 65);
    long_pin[65] = 0;
    CHECK(v(PW1, "12345") == PGP_PIN_BAD_LEN && v(PW3, "1234567") == PGP_PIN_BAD_LEN);
    CHECK(v(PW1, long_pin) == PGP_PIN_BAD_LEN && chg(PW1, "6543210", "12345") == PGP_PIN_BAD_LEN);
    CHECK(st(PW1, &att, NULL) == PGP_PIN_ACTIVE && att == 3);
    for (int i = 0; i < 3; ++i) CHECK(v(PW1, "000000") == PGP_PIN_WRONG);
    CHECK(st(PW1, &att, NULL) == PGP_PIN_BLOCKED && att == 0);
    CHECK(v(PW1, "6543210") == PGP_PIN_BLK && chg(PW1, "6543210", "1111111") == PGP_PIN_BLK);
    CHECK(pgp_pin_reset_pw1((const uint8_t *) "abcdef", 6) == PGP_PIN_OK);
    CHECK(v(PW1, "abcdef") == PGP_PIN_OK && v(PW3, "pw3-new-pin") == PGP_PIN_OK);
}

static void test_rc(void)
{
    uint8_t att = 0, len = 0;
    fresh_chip();
    CHECK(pgp_lifecycle_boot() == 0);
    CHECK(v(RC, "rcrcrcrc") == PGP_PIN_UNSET);
    CHECK(set_rc("rcrc") == PGP_PIN_BAD_LEN);
    CHECK(set_rc("rcrcrcrc") == PGP_PIN_OK && openpgp_state_rc_set() == 1);
    CHECK(st(RC, &att, &len) == PGP_PIN_ACTIVE && att == 3 && len == 8);
    CHECK(v(RC, "xxxxxxxx") == PGP_PIN_WRONG && st(RC, &att, NULL) == PGP_PIN_ACTIVE && att == 2);
    CHECK(v(RC, "rcrcrcrc") == PGP_PIN_OK && st(RC, &att, NULL) == PGP_PIN_ACTIVE && att == 3);
    CHECK(set_rc("second-rc") == PGP_PIN_OK);
    CHECK(v(RC, "rcrcrcrc") == PGP_PIN_WRONG && v(RC, "second-rc") == PGP_PIN_OK);
    CHECK(set_rc("") == PGP_PIN_OK && openpgp_state_rc_set() == 0);
    CHECK(st(RC, NULL, NULL) == PGP_PIN_NOT_SET && slot_empty(52) && slot_empty(55));
    /* Guard: O6 gone under rc_set 1 = ERROR, never "not set"; PUT DATA D3
     * clears first, so the admin sets it again. */
    CHECK(set_rc("rcrcrcrc") == PGP_PIN_OK);
    CHECK(tropic_rmem_erase(52) == 0 && tropic_rmem_erase(55) == 0);
    reboot();
    CHECK(pgp_lifecycle_boot() == 0);
    CHECK(st(RC, NULL, NULL) == PGP_PIN_ERROR && v(RC, "rcrcrcrc") == PGP_PIN_ERR);
    CHECK(set_rc("rcrcrcrc") == PGP_PIN_OK && v(RC, "rcrcrcrc") == PGP_PIN_OK);
    /* rc_set 0 over a leftover O6 (a cut before the guard): not set. */
    CHECK(openpgp_state_set_rc_set(0) == 0);
    CHECK(st(RC, NULL, NULL) == PGP_PIN_NOT_SET && v(RC, "rcrcrcrc") == PGP_PIN_UNSET);
}

/* PW1 binding lost while O3 says OPERATIONAL: ERROR; TERMINATE recovers. */
static void test_lost_binding(void)
{
    fresh_chip();
    CHECK(pgp_lifecycle_boot() == 0);
    CHECK(tropic_rmem_erase(50) == 0 && tropic_rmem_erase(53) == 0);
    reboot();
    CHECK(pgp_lifecycle_boot() == 0);
    CHECK(st(PW1, NULL, NULL) == PGP_PIN_ERROR && v(PW1, "123456") == PGP_PIN_ERR);
    CHECK(pgp_pin_reset_pw1((const uint8_t *) "abcdef", 6) == PGP_PIN_OK);   /* admin may rebind */
    CHECK(v(PW1, "abcdef") == PGP_PIN_OK);
    CHECK(tropic_rmem_erase(51) == 0 && tropic_rmem_erase(54) == 0);         /* now PW3 */
    reboot();
    CHECK(pgp_lifecycle_boot() == 0 && st(PW3, NULL, NULL) == PGP_PIN_ERROR);
    CHECK(pgp_lifecycle_terminate() == 0 && pgp_lifecycle_activate() == 0);
    CHECK(v(PW3, "12345678") == PGP_PIN_OK && v(PW1, "123456") == PGP_PIN_OK);
}

static void test_terminate_activate(void)
{
    put_in_use();
    CHECK(raw_contains(33, DEC_PAT, sizeof DEC_PAT) && raw_contains(43, DEC_PAT, sizeof DEC_PAT));
    CHECK(pgp_lifecycle_activate() == -1);                   /* only from TERMINATED */
    CHECK(pgp_lifecycle_terminate() == 0);
    CHECK(openpgp_state_lifecycle() == PGP_LC_TERMINATED && !keys_left());
    for (uint16_t s = 50; s <= 55; ++s) CHECK(slot_empty(s));
    CHECK(st(PW1, NULL, NULL) == PGP_PIN_NOT_SET && st(PW3, NULL, NULL) == PGP_PIN_NOT_SET);
    CHECK(openpgp_state_set_name((const uint8_t *) "A", 1) != 0 && openpgp_state_set_rc_set(1) != 0);
    reboot();
    unsigned e = mock_calls(MOCK_OP_ECC_ERASE);
    CHECK(pgp_lifecycle_boot() == 0 && openpgp_state_lifecycle() == PGP_LC_TERMINATED);
    CHECK(mock_calls(MOCK_OP_ECC_ERASE) == e);               /* TERMINATED is not ABSENT */
    CHECK(pgp_lifecycle_activate() == 0 && openpgp_state_lifecycle() == PGP_LC_OPERATIONAL);
    CHECK(v(PW1, "123456") == PGP_PIN_OK && v(PW3, "12345678") == PGP_PIN_OK);
    CHECK(st(RC, NULL, NULL) == PGP_PIN_NOT_SET && openpgp_state_c4_multi() == 1);
    CHECK(pgp_lifecycle_activate() == -1 && openpgp_state_activate() != 0);
}

/* The wipe's hard barriers (D8): a failed step stops it — no PIN is
 * cleared while the DEC key may remain, no TERMINATED over a live PIN. */
static void test_wipe_barriers(void)
{
    put_in_use();
    mock_fail_nth(MOCK_OP_RMEM_ERASE, 1, -1, false);         /* O3 copy B */
    CHECK(pgp_lifecycle_terminate() != 0);
    CHECK(v(PW1, "pw1-own") == PGP_PIN_OK && v(PW3, "pw3-own-pin") == PGP_PIN_OK);
    put_in_use();
    mock_fail_nth(MOCK_OP_MAC_AND_DESTROY, 1, -1, false);    /* retiring PW1 */
    CHECK(pgp_lifecycle_terminate() != 0 && openpgp_state_lifecycle() != PGP_LC_TERMINATED);
    reboot();
    CHECK(pgp_lifecycle_boot() == 0 && !keys_left());        /* O3 gone: bootstrap */
}

static void test_old_layout(void)
{
    fresh_chip();
    put_old_layout(false);
    unsigned m = mock_mutations();
    CHECK(pgp_lifecycle_boot() != 0);
    CHECK(mock_mutations() == m && openpgp_state_lifecycle() == PGP_LC_ERROR);
    CHECK(v(PW3, "12345678") == PGP_PIN_ERR && pgp_lifecycle_activate() == -1);
    CHECK(mock_mutations() == m && keys_left());             /* refused, nothing changed */
    reboot();
    CHECK(pgp_lifecycle_boot() != 0 && mock_mutations() == m);
    CHECK(pgp_lifecycle_terminate() == 0 && !keys_left());
    CHECK(pgp_lifecycle_activate() == 0 && v(PW1, "123456") == PGP_PIN_OK);
    reboot();
    CHECK(pgp_lifecycle_boot() == 0 && openpgp_state_lifecycle() == PGP_LC_OPERATIONAL);
}

/* Old slot 33 masked, slot 43 empty: O3 ABSENT after one fault — the
 * bootstrap wipes everything (checked) before the factory PINs (Jan). */
static void test_masked_old_layout(void)
{
    fresh_chip();
    put_old_layout(true);
    CHECK(pgp_lifecycle_boot() == 0);
    CHECK(!mock_ecc_present(29) && !mock_ecc_present(31));
    CHECK(v(PW1, "123456") == PGP_PIN_OK && v(PW3, "12345678") == PGP_PIN_OK);
}

static void test_read_error(void)
{
    for (unsigned n = 1; n <= 2; ++n) {
        fresh_chip();
        CHECK(pgp_lifecycle_boot() == 0);
        reboot();
        mock_fail_nth(MOCK_OP_RMEM_READ, n, -1, false);
        unsigned m = mock_mutations();
        CHECK(pgp_lifecycle_boot() != 0 && openpgp_state_lifecycle() == PGP_LC_ERROR);
        CHECK(mock_mutations() == m);
        mock_disarm();
        CHECK(pgp_lifecycle_boot() == 0);                    /* the retry in the same boot */
        CHECK(openpgp_state_lifecycle() == PGP_LC_OPERATIONAL);
    }
}

/* A failed O3 write: everything refuses until reboot, but TERMINATE (the
 * way out) works in the same boot. */
static void test_uncertain_o3(void)
{
    put_in_use();
    mock_fail_nth(MOCK_OP_RMEM_WRITE, 1, -1, true);
    CHECK(openpgp_state_set_name((const uint8_t *) "Alice", 5) != 0);
    CHECK(openpgp_state_lifecycle() == PGP_LC_ERROR && openpgp_state_set_sex(0x31) != 0);
    CHECK(openpgp_state_c4_multi() == 0 && openpgp_state_uif() == 1);   /* strict defaults */
    CHECK(pgp_lifecycle_terminate() == 0 && !keys_left());
    CHECK(pgp_lifecycle_activate() == 0 && v(PW1, "123456") == PGP_PIN_OK);
    /* A failed PW1 reservation: PW1 refuses until reboot; TERMINATE still
     * works in the same boot. */
    put_in_use();
    mock_fail_nth(MOCK_OP_RMEM_WRITE, 1, -1, true);
    CHECK(v(PW1, "pw1-own") == PGP_PIN_ERR && st(PW1, NULL, NULL) == PGP_PIN_ERROR);
    CHECK(pgp_lifecycle_terminate() == 0 && pgp_lifecycle_activate() == 0);
    CHECK(v(PW1, "123456") == PGP_PIN_OK);
    /* The same for RC: PUT DATA D3 is its way out. */
    put_in_use();
    mock_fail_nth(MOCK_OP_RMEM_WRITE, 1, -1, true);
    CHECK(v(RC, "rc-code-1") == PGP_PIN_ERR && st(RC, NULL, NULL) == PGP_PIN_ERROR);
    CHECK(set_rc("rc-code-9") == PGP_PIN_OK && v(RC, "rc-code-9") == PGP_PIN_OK);
}

static void test_state_fields(void)
{
    static const uint8_t bad[][4] = {
        { 0, 0, 1, 1 },          /* lifecycle 0 */
        { 3, 0, 1, 1 },          /* lifecycle 3 */
        { 1, 2, 1, 1 },          /* rc_set 2 */
        { 1, 0, 2, 1 },          /* C4 2 */
        { 1, 0, 1, 3 },          /* UIF 3 */
    };
    uint8_t name[OPENPGP_NAME_MAX];
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        uint8_t rec[154] = { 0 };
        rec_pair_t o3 = REC_PAIR(33, 43, 3, 1);
        memcpy(rec, bad[i], 4);
        rec[46] = 0x39;
        fresh_chip();
        CHECK(rec_pair_init(&o3, rec, sizeof rec) == REC_OK);
        CHECK(pgp_lifecycle_boot() != 0 && openpgp_state_lifecycle() == PGP_LC_ERROR);
    }
    fresh_chip();
    CHECK(pgp_lifecycle_boot() == 0);
    CHECK(openpgp_state_set_name((const uint8_t *) "Alice", 5) == 0);
    CHECK(openpgp_state_set_sex(0x33) == -1 && openpgp_state_set_uif(3) == -1);
    CHECK(openpgp_state_set_uif(2) == 0 && openpgp_state_set_uif(0) == -3);
    CHECK(openpgp_state_sig_counter_increment() == 0 && openpgp_state_sig_counter_increment() == 0);
    reboot();
    CHECK(pgp_lifecycle_boot() == 0);
    uint8_t ctr[3];
    openpgp_state_sig_counter(ctr);
    CHECK(openpgp_state_name(name) == 5 && memcmp(name, "Alice", 5) == 0);
    CHECK(ctr[0] == 0 && ctr[1] == 0 && ctr[2] == 2 && openpgp_state_uif() == 2);
}

/* OpenPGP never touches FIDO's M&D slots (0..15) or R-mem 0..29, 40..42. */
static void test_fido_untouched(void)
{
    uint8_t before[16][32], now[32], sentinel[9] = "fido-obj";
    fresh_chip();
    for (uint16_t s = 0; s <= 42; ++s) {
        if (s <= 29 || s >= 40) CHECK(tropic_rmem_write(s, sentinel, sizeof sentinel) == 0);
    }
    for (uint8_t i = 0; i < 16; ++i) mock_mad_peek(i, before[i]);
    for (uint8_t k = 0; k <= 28; ++k) mock_ecc_put(k);
    CHECK(pgp_lifecycle_boot() == 0);
    CHECK(chg(PW1, "123456", "pw1-own") == PGP_PIN_OK && v(PW1, "000000") == PGP_PIN_WRONG);
    CHECK(set_rc("rc-code-1") == PGP_PIN_OK && set_rc("") == PGP_PIN_OK);
    CHECK(pgp_pin_reset_pw1((const uint8_t *) "abcdef", 6) == PGP_PIN_OK);
    CHECK(pgp_lifecycle_terminate() == 0 && pgp_lifecycle_activate() == 0);
    for (uint8_t i = 0; i < 16; ++i) {
        mock_mad_peek(i, now);
        CHECK(memcmp(now, before[i], 32) == 0);
    }
    for (uint16_t s = 0; s <= 42; ++s) {
        if (s > 29 && s < 40) continue;
        CHECK(raw_contains(s, sentinel, sizeof sentinel));
    }
    for (uint8_t k = 0; k <= 28; ++k) CHECK(mock_ecc_present(k));
}

/* Both applications on the old layout; their resets in either order bring
 * both up fresh (the release note: FIDO reset + OpenPGP factory reset). */
static void put_fido_old_layout(void)
{
    uint8_t g[392] = { 'N', 'X', '7', 'K', 0, 4 };
    uint8_t c[256] = { 'N', 'X', 'C', 'R', 4, 8 };
    g[9] = 0x03;
    CHECK(tropic_rmem_write(0, g, sizeof g) == 0);
    CHECK(tropic_rmem_write(1, c, sizeof c) == 0 && tropic_rmem_write(2, c, sizeof c) == 0);
    mock_ecc_put(0);
    mock_ecc_put(1);
}

static void test_both_resets_either_order(void)
{
    for (int order = 0; order < 2; ++order) {
        fresh_chip();
        put_fido_old_layout();
        put_old_layout(false);
        CHECK(fido_state_boot() != 0 && pgp_lifecycle_boot() != 0);
        if (order == 0) {
            CHECK(fido_state_wipe() == 0);
            CHECK(pgp_lifecycle_boot() != 0);                /* still refused */
            CHECK(pgp_lifecycle_terminate() == 0 && pgp_lifecycle_activate() == 0);
        } else {
            CHECK(pgp_lifecycle_terminate() == 0 && pgp_lifecycle_activate() == 0);
            reboot();
            CHECK(fido_state_boot() != 0);                   /* still refused */
            CHECK(fido_state_wipe() == 0);
        }
        reboot();
        CHECK(fido_state_boot() == 0 && fido_pin_state(NULL) == FPIN_NOT_SET);
        CHECK(pgp_lifecycle_boot() == 0 && v(PW1, "123456") == PGP_PIN_OK);
        CHECK(!keys_left() && !mock_ecc_present(0) && !mock_ecc_present(1));
    }
}

/* ---- single-fault sweep: bootstrap, TERMINATE, ACTIVATE, PUT DATA D3 ---- */

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

enum op { OP_BOOTSTRAP, OP_TERMINATE, OP_ACTIVATE, OP_SET_RC, OP_COUNT };

static void before(enum op o)
{
    put_in_use();
    if (o == OP_BOOTSTRAP) {                 /* O3 lost (both copies), keys and PINs stay */
        CHECK(tropic_rmem_erase(33) == 0 && tropic_rmem_erase(43) == 0);
        reboot();
    }
    if (o == OP_ACTIVATE) CHECK(pgp_lifecycle_terminate() == 0);
}

static int run(enum op o)
{
    switch (o) {
    case OP_BOOTSTRAP: return pgp_lifecycle_boot();
    case OP_TERMINATE: return pgp_lifecycle_terminate();
    case OP_ACTIVATE:  return pgp_lifecycle_activate();
    default:           return set_rc("rc-code-2");
    }
}

/* After the fault and a reboot: what must hold. */
static bool invariants(enum op o, int rc)
{
    int booted = pgp_lifecycle_boot();
    pgp_lifecycle_t lc = openpgp_state_lifecycle();
    bool good = true;
    /* Never a key under a factory PIN or no PIN (I3). */
    if (keys_left()) {
        good = good && lc != PGP_LC_TERMINATED && v(PW1, "123456") != PGP_PIN_OK
                    && v(PW3, "12345678") != PGP_PIN_OK;
    }
    if (rc == 0) {
        switch (o) {
        case OP_TERMINATE: good = good && booted == 0 && lc == PGP_LC_TERMINATED; break;
        case OP_SET_RC:    good = good && v(RC, "rc-code-2") == PGP_PIN_OK
                                       && v(PW1, "pw1-own") == PGP_PIN_OK; break;
        default:           good = good && booted == 0 && lc == PGP_LC_OPERATIONAL
                                       && !keys_left() && v(PW1, "123456") == PGP_PIN_OK; break;
        }
    }
    if (o == OP_SET_RC && lc == PGP_LC_OPERATIONAL) {        /* the admin sets it again */
        good = good && set_rc("rc-code-3") == PGP_PIN_OK && v(RC, "rc-code-3") == PGP_PIN_OK;
    }
    /* TERMINATE + ACTIVATE always recover. */
    good = good && pgp_lifecycle_terminate() == 0 && !keys_left() && pgp_lifecycle_activate() == 0;
    reboot();
    return good && pgp_lifecycle_boot() == 0 && v(PW1, "123456") == PGP_PIN_OK
                && v(PW3, "12345678") == PGP_PIN_OK;
}

static void test_sweep(void)
{
    static const mock_op_t ops[] = {
        MOCK_OP_ECC_ERASE, MOCK_OP_RMEM_READ, MOCK_OP_RMEM_WRITE, MOCK_OP_RMEM_ERASE,
        MOCK_OP_MAC_AND_DESTROY, MOCK_OP_RANDOM,
    };
    for (int o = 0; o < OP_COUNT; ++o) {
        for (size_t i = 0; i < sizeof ops / sizeof ops[0]; ++i) {
            mock_op_t op = ops[i];
            before((enum op) o);
            unsigned c0 = mock_calls(op);
            CHECK(run((enum op) o) == 0);
            unsigned calls = mock_calls(op) - c0;
            bool rmem_mut = op == MOCK_OP_RMEM_WRITE || op == MOCK_OP_RMEM_ERASE;
            for (unsigned n = 1; n <= calls; ++n) {
                for (int f = 0; f < F_COUNT; ++f) {
                    if (f >= F_GARBLE && !rmem_mut) continue;
                    if (f == F_LOST && op == MOCK_OP_RMEM_READ) continue;
                    before((enum op) o);
                    arm(op, n, (enum fault) f);
                    int rc = run((enum op) o);
                    mock_disarm();
                    reboot();
                    bool good = invariants((enum op) o, rc);
                    CHECK(good);
                    if (!good) fprintf(stderr, "  sweep op %d fault %d chip-op %d call %u: rc %d\n",
                                       o, f, op, n, rc);
                }
            }
        }
    }
}

int main(void)
{
    test_first_boot();
    test_pins();
    test_rc();
    test_lost_binding();
    test_terminate_activate();
    test_wipe_barriers();
    test_old_layout();
    test_masked_old_layout();
    test_read_error();
    test_uncertain_o3();
    test_state_fields();
    test_fido_untouched();
    test_both_resets_either_order();
    test_sweep();
    return check_done("openpgp_state");
}
