/*
 * Host tests for the OpenPGP applet's PIN semantics (Phase 9 M4 step 4,
 * design §5, D9, D11) through openpgp_applet_dispatch, against the mock
 * chip.  Key operations (pgp_keys.c) and the touch button are stubbed:
 * this tests who may sign / decrypt / administer, not the crypto.
 *
 * Covers: PW1.81 / PW1.82 / PW3 kept apart; VERIFY status and P1=FF; DO C4
 * byte 0 (00 = one signature per VERIFY, 01 = until reset) and its default;
 * the events that clear access (card reset, SELECT of another AID, change
 * and reset of that PIN, a wrong VERIFY); CHANGE split by the stored length;
 * RESET RETRY COUNTER by RC and by PW3; PUT DATA gates; the signature counter
 * counted before signing; TERMINATE with or without PW3; ACTIVATE only from
 * TERMINATED; an unreadable state refusing all but SELECT, VERIFY 83 and
 * TERMINATE; a boot read error retried with the next APDU.
 */
#include <stdbool.h>
#include <string.h>

#include "check.h"
#include "mock_tropic.h"
#include "fido_hid/user_presence.h"
#include "openpgp/openpgp_aid.h"
#include "openpgp/openpgp_applet.h"
#include "openpgp/openpgp_state.h"
#include "openpgp/pgp_lifecycle.h"
#include "openpgp/pgp_keys.h"
#include "openpgp/pgp_pin.h"
#include "tropic/tropic.h"

/* ---- stubs ---- */

static unsigned s_signs, s_touches;
static bool s_touch_ok = true;

up_result_t user_presence_check(uint32_t timeout_ms)
{
    (void) timeout_ms;
    s_touches++;
    return s_touch_ok ? UP_OK : UP_FAIL;
}

static int fake_sig(uint8_t sig[PGP_KEYS_SIG_LEN])
{
    s_signs++;
    memset(sig, 0x5A, PGP_KEYS_SIG_LEN);
    return PGP_KEYS_OK;
}

int pgp_keys_sign_with_sig(const uint8_t *m, size_t n, uint8_t sig[PGP_KEYS_SIG_LEN])
{
    (void) m; (void) n;
    return fake_sig(sig);
}

int pgp_keys_sign_with_aut(const uint8_t *m, size_t n, uint8_t sig[PGP_KEYS_SIG_LEN])
{
    (void) m; (void) n;
    return fake_sig(sig);
}

static int fake_pub(uint8_t pub[PGP_KEYS_PUBKEY_LEN])
{
    memset(pub, 1, PGP_KEYS_PUBKEY_LEN);
    return PGP_KEYS_OK;
}

int pgp_keys_generate_sig(uint8_t p[PGP_KEYS_PUBKEY_LEN]) { return fake_pub(p); }
int pgp_keys_generate_aut(uint8_t p[PGP_KEYS_PUBKEY_LEN]) { return fake_pub(p); }
int pgp_keys_read_sig_pubkey(uint8_t p[PGP_KEYS_PUBKEY_LEN]) { return fake_pub(p); }
int pgp_keys_read_aut_pubkey(uint8_t p[PGP_KEYS_PUBKEY_LEN]) { return fake_pub(p); }

/* ---- APDU helpers ---- */

static uint8_t s_out[512];
static size_t s_out_len;

static uint16_t apdu(uint8_t ins, uint8_t p1, uint8_t p2, const void *data, size_t len)
{
    uint8_t in[300] = { 0x00, ins, p1, p2 };
    size_t n = 4;
    if (data != NULL) {
        in[4] = (uint8_t) len;
        memcpy(&in[5], data, len);
        n = 5 + len;
    }
    s_out_len = 0;
    if (openpgp_applet_dispatch(in, n, s_out, sizeof s_out, &s_out_len) != 0 || s_out_len < 2) {
        return 0;
    }
    return (uint16_t) ((s_out[s_out_len - 2] << 8) | s_out[s_out_len - 1]);
}

static uint16_t verify(uint8_t p2, const char *pin)
{
    return apdu(0x20, 0x00, p2, pin, strlen(pin));
}

static uint16_t verify_status(uint8_t p2)
{
    return apdu(0x20, 0x00, p2, NULL, 0);
}

/* CHANGE REFERENCE DATA / RESET RETRY COUNTER: body = a || b. */
static uint16_t two(uint8_t ins, uint8_t p1, uint8_t p2, const char *a, const char *b)
{
    char body[160];
    size_t la = strlen(a), lb = strlen(b);
    memcpy(body, a, la);
    memcpy(body + la, b, lb);
    return apdu(ins, p1, p2, body, la + lb);
}

static uint16_t put(uint16_t tag, const void *data, size_t len)
{
    static const uint8_t none[1];
    return apdu(0xDA, (uint8_t) (tag >> 8), (uint8_t) tag, data != NULL ? data : none, len);
}

static uint16_t select_pgp(void)
{
    return apdu(0xA4, 0x04, 0x00, OPENPGP_AID, OPENPGP_AID_LEN);
}

static uint16_t cds(void)
{
    static const uint8_t h[32] = { 1 };
    return apdu(0x2A, 0x9E, 0x9A, h, sizeof h);
}

static uint16_t dec(void)
{
    uint8_t b[39] = { 0xA6, 37, 0x7F, 0x49, 34, 0x86, 32 };
    memset(&b[7], 9, 32);
    return apdu(0x2A, 0x80, 0x86, b, sizeof b);
}

static uint16_t int_auth(void)
{
    static const uint8_t c[16] = { 7 };
    return apdu(0x88, 0x00, 0x00, c, sizeof c);
}

static uint16_t get_c4(uint8_t c4[7])
{
    uint16_t sw = apdu(0xCA, 0x00, 0xC4, NULL, 0);
    if (sw == 0x9000 && s_out_len == 9) memcpy(c4, s_out, 7);
    else memset(c4, 0xEE, 7);
    return sw;
}

static void reboot(void)
{
    openpgp_state_test_reboot();
    pgp_pin_test_reboot();
    pgp_lifecycle_test_reboot();
    openpgp_applet_card_reset();
}

static uint16_t gen_dec(void)
{
    static const uint8_t crt[2] = { 0xB8, 0x00 };
    return apdu(0x47, 0x80, 0x00, crt, sizeof crt);
}

static uint16_t read_dec_pub(void)
{
    static const uint8_t crt[2] = { 0xB8, 0x00 };
    return apdu(0x47, 0x81, 0x00, crt, sizeof crt);
}

/* A factory card with a DEC key (M5: generated under the PW1 KEK), no
 * access status left. */
static void fresh(void)
{
    mock_reset(1);
    reboot();
    s_touch_ok = true;
    CHECK(select_pgp() == 0x9000);
    CHECK(verify(0x83, "12345678") == 0x9000 && verify(0x82, "123456") == 0x9000
          && gen_dec() == 0x9000);
    openpgp_applet_card_reset();
}

/* ---- tests ---- */

static void test_defaults_and_status(void)
{
    static const uint8_t want[7] = { 0x01, 0x40, 0x40, 0x40, 3, 0, 3 };
    uint8_t c4[7];
    fresh();
    CHECK(get_c4(c4) == 0x9000 && memcmp(c4, want, 7) == 0);
    CHECK(verify_status(0x81) == 0x63C3 && verify_status(0x83) == 0x63C3);
    CHECK(verify(0x81, "000000") == 0x63C2);
    CHECK(get_c4(c4) == 0x9000 && c4[4] == 2);
    CHECK(verify(0x81, "12345") == 0x6700);                  /* no attempt spent */
    CHECK(verify(0x81, "123456") == 0x9000 && verify_status(0x81) == 0x9000);
    CHECK(get_c4(c4) == 0x9000 && c4[4] == 3);
    CHECK(verify(0x84, "123456") == 0x6A86 && apdu(0x20, 0x01, 0x81, "123456", 6) == 0x6A86);
}

static void test_81_82_apart(void)
{
    fresh();
    CHECK(verify(0x82, "123456") == 0x9000 && cds() == 0x6982);   /* 82 does not sign */
    openpgp_applet_card_reset();
    CHECK(verify(0x81, "123456") == 0x9000);
    CHECK(cds() == 0x9000 && dec() == 0x6982 && int_auth() == 0x6982);
    CHECK(verify(0x82, "123456") == 0x9000);
    CHECK(dec() == 0x9000 && int_auth() == 0x9000 && cds() == 0x9000);
    CHECK(apdu(0x20, 0xFF, 0x82, NULL, 0) == 0x9000);        /* P1=FF: 82 only */
    CHECK(dec() == 0x6982 && cds() == 0x9000 && verify_status(0x82) == 0x63C3);
    CHECK(verify(0x82, "123456") == 0x9000);
    CHECK(verify(0x82, "000000") == 0x63C2);                 /* a wrong PW1: both gone */
    CHECK(cds() == 0x6982 && dec() == 0x6982);
    /* PW3 does not open PW1 operations, PW1 does not open admin ones. */
    CHECK(verify(0x81, "123456") == 0x9000 && put(0x005B, "A", 1) == 0x6982);
    CHECK(verify(0x83, "12345678") == 0x9000 && dec() == 0x6982);
}

static void test_clearing_events(void)
{
    static const uint8_t other_aid[] = { 0xA0, 0x00, 0x00, 0x03, 0x08 };
    fresh();
    CHECK(verify(0x81, "123456") == 0x9000 && verify(0x82, "123456") == 0x9000);
    CHECK(verify(0x83, "12345678") == 0x9000);
    openpgp_applet_card_reset();                             /* IccPowerOff/On, USB reset */
    CHECK(cds() == 0x6982 && dec() == 0x6982 && put(0x005B, "A", 1) == 0x6982);
    CHECK(verify(0x81, "123456") == 0x9000 && verify(0x83, "12345678") == 0x9000);
    CHECK(apdu(0xA4, 0x04, 0x00, other_aid, sizeof other_aid) == 0x6A82);
    CHECK(cds() == 0x6982 && put(0x005B, "A", 1) == 0x6982);
    CHECK(select_pgp() == 0x9000 && verify(0x81, "123456") == 0x9000);
    CHECK(select_pgp() == 0x9000 && cds() == 0x9000);        /* our own AID again: kept */
}

static void test_c4(void)
{
    static const uint8_t zero = 0, one = 1;
    uint8_t c4[7];
    fresh();
    CHECK(put(0x00C4, &zero, 1) == 0x6982);
    CHECK(verify(0x83, "12345678") == 0x9000 && put(0x00C4, &zero, 1) == 0x9000);
    CHECK(get_c4(c4) == 0x9000 && c4[0] == 0);
    CHECK(verify(0x81, "123456") == 0x9000);
    CHECK(cds() == 0x9000 && cds() == 0x6982);               /* one signature per VERIFY */
    CHECK(verify(0x81, "123456") == 0x9000 && cds() == 0x9000);
    reboot();
    CHECK(select_pgp() == 0x9000 && get_c4(c4) == 0x9000 && c4[0] == 0);   /* persisted */
    CHECK(verify(0x83, "12345678") == 0x9000 && put(0x00C4, &one, 1) == 0x9000);
    CHECK(verify(0x81, "123456") == 0x9000 && cds() == 0x9000 && cds() == 0x9000);
}

static void test_sig_counter_and_touch(void)
{
    uint8_t want[3] = { 0, 0, 2 };
    fresh();
    CHECK(verify(0x81, "123456") == 0x9000);
    unsigned t = s_touches;
    CHECK(cds() == 0x9000 && cds() == 0x9000 && s_touches == t + 2);
    CHECK(apdu(0xCA, 0x00, 0x93, NULL, 0) == 0x9000 && s_out_len == 5 && memcmp(s_out, want, 3) == 0);
    s_touch_ok = false;
    unsigned s = s_signs;
    CHECK(cds() == 0x6982 && s_signs == s);
    s_touch_ok = true;
    /* A counter that cannot be written means no signature; O3 is then
     * uncertain → only the way out until reboot. */
    mock_fail_nth(MOCK_OP_RMEM_WRITE, 1, -1, false);
    CHECK(cds() == 0x6F00 && s_signs == s);
    mock_disarm();
    CHECK(apdu(0xCA, 0x00, 0xC4, NULL, 0) == 0x6F00 && cds() == 0x6F00);
    /* O3 unreadable but PW3 fine: TERMINATE still needs PW3 (Jan step 4 HIGH). */
    mock_ecc_put(29);
    CHECK(apdu(0xE6, 0x00, 0x00, NULL, 0) == 0x6982 && mock_ecc_present(29));
    CHECK(verify(0x83, "12345678") == 0x9000 && apdu(0xE6, 0x00, 0x00, NULL, 0) == 0x9000);
    CHECK(!mock_ecc_present(29));
    CHECK(apdu(0x44, 0x00, 0x00, NULL, 0) == 0x9000 && verify(0x81, "123456") == 0x9000);
}

static void test_change(void)
{
    uint8_t c4[7];
    fresh();
    CHECK(two(0x24, 0x00, 0x81, "000000", "654321") == 0x63C2);
    CHECK(two(0x24, 0x00, 0x82, "123456", "654321") == 0x6A86);
    CHECK(apdu(0x24, 0x00, 0x81, "123", 3) == 0x6700);
    CHECK(two(0x24, 0x00, 0x81, "123456", "12345") == 0x6700);      /* new too short */
    CHECK(get_c4(c4) == 0x9000 && c4[4] == 2);                       /* no attempt spent */
    CHECK(verify(0x81, "123456") == 0x9000 && cds() == 0x9000);
    CHECK(two(0x24, 0x00, 0x81, "123456", "6543210") == 0x9000);
    CHECK(cds() == 0x6982);                                          /* change drops PW1 access */
    CHECK(verify(0x81, "123456") == 0x63C2 && verify(0x81, "6543210") == 0x9000);
    /* The next change splits at the new length (7). */
    CHECK(two(0x24, 0x00, 0x81, "6543210", "abcdef") == 0x9000 && verify(0x82, "abcdef") == 0x9000);
    CHECK(verify(0x83, "12345678") == 0x9000);
    CHECK(two(0x24, 0x00, 0x83, "12345678", "admin-pin-2") == 0x9000);
    CHECK(put(0x005B, "A", 1) == 0x6982 && verify(0x83, "admin-pin-2") == 0x9000);
}

static void test_reset_retry_counter(void)
{
    uint8_t c4[7];
    fresh();
    for (int i = 0; i < 3; ++i) verify(0x81, "000000");
    CHECK(verify(0x81, "123456") == 0x6983);
    CHECK(apdu(0x2C, 0x02, 0x81, "abcdef", 6) == 0x6982);           /* PW3 not verified */
    CHECK(two(0x2C, 0x00, 0x81, "rcrcrcrc", "abcdef") == 0x6985);   /* RC not set */
    CHECK(verify(0x83, "12345678") == 0x9000);
    CHECK(apdu(0x2C, 0x02, 0x81, "abcdef", 6) == 0x9000 && verify(0x81, "abcdef") == 0x9000);
    CHECK(cds() == 0x9000 && apdu(0x2C, 0x02, 0x81, "abcdef", 6) == 0x9000);
    CHECK(cds() == 0x6982);                                          /* the reset drops PW1 access */
    CHECK(verify(0x81, "abcdef") == 0x9000);
    CHECK(put(0x00D3, "rcrc", 4) == 0x6700);
    CHECK(put(0x00D3, "rcrcrcrc", 8) == 0x9000 && get_c4(c4) == 0x9000 && c4[5] == 3);
    for (int i = 0; i < 3; ++i) verify(0x81, "000000");
    CHECK(two(0x2C, 0x00, 0x81, "xxxxxxxx", "12345") == 0x6700);    /* no RC attempt */
    CHECK(get_c4(c4) == 0x9000 && c4[5] == 3);
    CHECK(two(0x2C, 0x00, 0x81, "xxxxxxxx", "newpin") == 0x63C2);
    CHECK(two(0x2C, 0x00, 0x81, "rcrcrcrc", "newpin") == 0x9000);
    CHECK(verify(0x81, "newpin") == 0x9000 && get_c4(c4) == 0x9000 && c4[4] == 3 && c4[5] == 3);
    CHECK(apdu(0x2C, 0x01, 0x81, "abcdef", 6) == 0x6A86 && apdu(0x2C, 0x02, 0x82, "abcdef", 6) == 0x6A86);
    CHECK(verify(0x83, "12345678") == 0x9000 && put(0x00D3, NULL, 0) == 0x9000);
    CHECK(get_c4(c4) == 0x9000 && c4[5] == 0);
}

static void test_put_data_gates(void)
{
    static const uint8_t two_b = 2, zero = 0, three = 3, bad_sex = 0x33;
    static const uint8_t crt[2] = { 0xB6, 0x00 };
    uint8_t name[40];
    memset(name, 'n', sizeof name);
    fresh();
    CHECK(put(0x005B, "A", 1) == 0x6982 && apdu(0x47, 0x80, 0x00, crt, 2) == 0x6982);
    CHECK(apdu(0x47, 0x81, 0x00, crt, 2) == 0x9000);                /* reading a public key: open */
    CHECK(verify(0x83, "12345678") == 0x9000);
    CHECK(apdu(0x47, 0x80, 0x00, crt, 2) == 0x9000);
    CHECK(put(0x005B, name, 40) == 0x6700 && put(0x005B, "Alice", 5) == 0x9000);
    CHECK(put(0x5F35, &bad_sex, 1) == 0x6A80 && put(0x00D6, &three, 1) == 0x6A80);
    CHECK(put(0x00D6, &two_b, 1) == 0x9000 && put(0x00D7, &zero, 1) == 0x6985);   /* permanent */
    CHECK(apdu(0xCA, 0x00, 0x5B, NULL, 0) == 0x9000 && s_out_len == 7 && memcmp(s_out, "Alice", 5) == 0);
}

static void test_terminate_activate(void)
{
    uint8_t c4[7];
    fresh();
    CHECK(apdu(0xE6, 0x00, 0x00, NULL, 0) == 0x6982);               /* PW3 active, not verified */
    CHECK(two(0x24, 0x00, 0x81, "123456", "654321") == 0x9000);
    CHECK(apdu(0x44, 0x00, 0x00, NULL, 0) == 0x9000);               /* operational: no-op */
    CHECK(verify(0x81, "654321") == 0x9000);
    CHECK(verify(0x83, "12345678") == 0x9000 && put(0x005B, "Alice", 5) == 0x9000);
    CHECK(apdu(0xE6, 0x00, 0x00, NULL, 0) == 0x9000);
    CHECK(apdu(0xCA, 0x00, 0x6E, NULL, 0) == 0x6285 && verify(0x81, "123456") == 0x6285);
    CHECK(cds() == 0x6285 && select_pgp() == 0x9000);
    CHECK(apdu(0x44, 0x00, 0x00, NULL, 0) == 0x9000);
    CHECK(cds() == 0x6982);                                          /* access gone */
    CHECK(verify(0x81, "123456") == 0x9000 && get_c4(c4) == 0x9000 && c4[0] == 1);
    CHECK(apdu(0xCA, 0x00, 0x5B, NULL, 0) == 0x9000 && s_out_len == 2);
    /* PW3 blocked: TERMINATE without it (§7.2.16). */
    for (int i = 0; i < 3; ++i) verify(0x83, "00000000");
    CHECK(verify(0x83, "12345678") == 0x6983);
    CHECK(apdu(0xE6, 0x00, 0x00, NULL, 0) == 0x9000);
    CHECK(apdu(0x44, 0x00, 0x00, NULL, 0) == 0x9000 && verify(0x83, "12345678") == 0x9000);
}

/* The v0.2/M3 record in slot 33: only SELECT, VERIFY 83 and TERMINATE. */
static void test_unreadable_state(void)
{
    uint8_t old[256] = { 'P', 'G', '7', 'R', 0, 6, 1, 3, 3, 0xFF };
    uint8_t c4[7];
    mock_reset(1);
    CHECK(tropic_rmem_write(33, old, sizeof old) == 0);
    reboot();
    CHECK(select_pgp() == 0x9000);
    CHECK(get_c4(c4) == 0x6F00 && verify(0x81, "123456") == 0x6F00);
    CHECK(cds() == 0x6F00 && put(0x005B, "A", 1) == 0x6F00);
    CHECK(apdu(0x44, 0x00, 0x00, NULL, 0) == 0x6F00);               /* no ACTIVATE over unknown */
    CHECK(verify(0x83, "12345678") == 0x6F00);                       /* reaches the PIN: unreadable */
    CHECK(apdu(0xE6, 0x00, 0x00, NULL, 0) == 0x9000);
    CHECK(apdu(0x44, 0x00, 0x00, NULL, 0) == 0x9000);
    CHECK(get_c4(c4) == 0x9000 && c4[0] == 1 && c4[4] == 3 && c4[6] == 3);
}

/* A read error at the first APDU: refused, then retried with the next. */
static void test_boot_retry(void)
{
    uint8_t c4[7];
    fresh();
    reboot();
    mock_fail_nth(MOCK_OP_RMEM_READ, 1, -1, false);
    CHECK(select_pgp() == 0x9000);                                   /* boot failed */
    CHECK(get_c4(c4) == 0x9000 && c4[4] == 3);                       /* retried */
}

/* cpp-reviewer step 4 (LOW 7): what clears and what must survive. */
static void test_flag_edges(void)
{
    static const uint8_t zero = 0, two_v = 2;
    fresh();
    CHECK(verify(0x81, "123456") == 0x9000);
    CHECK(two(0x24, 0x00, 0x81, "000000", "654321") == 0x63C2);    /* a wrong old PIN */
    CHECK(cds() == 0x6982);                                          /* drops PW1 access too */
    CHECK(verify(0x83, "12345678") == 0x9000 && verify(0x81, "000000") == 0x63C1);
    CHECK(put(0x005B, "A", 1) == 0x9000);                           /* a wrong PW1 keeps PW3 */
    CHECK(verify(0x81, "123456") == 0x9000 && verify(0x83, "00000000") == 0x63C2);
    CHECK(cds() == 0x9000 && put(0x005B, "A", 1) == 0x6982);        /* a wrong PW3 keeps PW1 only */
    CHECK(verify(0x83, "12345678") == 0x9000 && put(0x00C4, &two_v, 1) == 0x6A80);
    CHECK(put(0x00C4, &zero, 1) == 0x9000 && verify(0x81, "123456") == 0x9000);
    s_touch_ok = false;                                              /* C4 00: consumed before touch */
    CHECK(cds() == 0x6982);
    s_touch_ok = true;
    CHECK(cds() == 0x6982 && verify(0x81, "123456") == 0x9000 && cds() == 0x9000);
}

/* cpp-reviewer step 4 (LOW 5, 6): APDU framing. */
static void test_framing(void)
{
    static const uint8_t get_c4_le[5] = { 0x00, 0xCA, 0x00, 0xC4, 0x00 };   /* case 2, Le 00 */
    static const uint8_t ext_d3[9] = { 0x00, 0xDA, 0x00, 0xD3, 0x00, 0x00, 0x02, 'a', 'b' };
    static const uint8_t short_dec[5] = { 0xA6, 0x81, 0x00, 0x7F, 0x49 };
    uint8_t c4[7];
    fresh();
    s_out_len = 0;
    CHECK(openpgp_applet_dispatch(get_c4_le, sizeof get_c4_le, s_out, sizeof s_out, &s_out_len) == 0
          && s_out_len == 9 && s_out[0] == 0x01 && s_out[7] == 0x90 && s_out[8] == 0x00);
    CHECK(verify(0x83, "12345678") == 0x9000 && put(0x00D3, "rcrcrcrc", 8) == 0x9000);
    s_out_len = 0;
    CHECK(openpgp_applet_dispatch(ext_d3, sizeof ext_d3, s_out, sizeof s_out, &s_out_len) == 0
          && s_out_len == 2 && s_out[0] == 0x67 && s_out[1] == 0x00);    /* not "clear the RC" */
    CHECK(get_c4(c4) == 0x9000 && c4[5] == 3);
    CHECK(verify(0x82, "123456") == 0x9000 && apdu(0x2A, 0x80, 0x86, short_dec, 5) == 0x6700);
}

/* cpp-reviewer step 4 (MED 2): a boot that keeps failing is tried at most
 * three times per power cycle, not for every APDU a host polls with. */
static void test_boot_bound(void)
{
    uint8_t old[256] = { 'P', 'G', '7', 'R', 0, 6, 1, 3, 3, 0xFF };
    uint8_t c4[7];
    mock_reset(1);
    CHECK(tropic_rmem_write(33, old, sizeof old) == 0);
    reboot();
    unsigned r = mock_calls(MOCK_OP_RMEM_READ);
    for (int i = 0; i < 6; ++i) CHECK(get_c4(c4) == 0x6F00);
    CHECK(mock_calls(MOCK_OP_RMEM_READ) - r == 3u * 2u);             /* 3 boots × 2 copies */
    CHECK(apdu(0xE6, 0x00, 0x00, NULL, 0) == 0x9000);               /* the way out still works */
    CHECK(apdu(0x44, 0x00, 0x00, NULL, 0) == 0x9000 && get_c4(c4) == 0x9000);
}

/* ---- single-fault sweep through the APDU entry point (Jan step 4) ----
 *
 * One fault at every chip call of one APDU, a reboot, and then only what a
 * user can send: gpg's factory-reset sequence (wrong VERIFY 81 / 83 until
 * blocked, TERMINATE, ACTIVATE).  It must always end in a usable card with
 * factory PINs and no key; and no key may ever sit under a factory PIN. */

/* A DEC key in an O3 copy: an O3 record (NXR1, obj 3) whose public key
 * field (payload 122..153, after the 12-byte header) is not zero. */
static bool dec_in(uint16_t slot)
{
    uint8_t b[444];
    size_t got = 0;
    if (tropic_rmem_read(slot, b, sizeof b, &got) != 0 || got < 12u + 154u) return false;
    if (memcmp(b, "NXR1", 4) != 0 || b[4] != 3u) return false;
    uint8_t acc = 0;
    for (size_t i = 12u + 122u; i < 12u + 154u; ++i) acc |= b[i];
    return acc != 0u;
}

static bool keys_left(void)
{
    return mock_ecc_present(29) || mock_ecc_present(31) || dec_in(33) || dec_in(43);
}

static bool gpg_factory_reset(void)
{
    reboot();
    if (select_pgp() != 0x9000) return false;
    for (int i = 0; i < 4; ++i) (void) verify(0x81, "@@@@@@@@");
    for (int i = 0; i < 4; ++i) (void) verify(0x83, "@@@@@@@@");
    uint16_t t = apdu(0xE6, 0x00, 0x00, NULL, 0);
    if (t != 0x9000 && t != 0x6285) return false;           /* 6285: already terminated */
    return apdu(0x44, 0x00, 0x00, NULL, 0) == 0x9000 && !keys_left()
        && verify(0x81, "123456") == 0x9000 && verify(0x83, "12345678") == 0x9000;
}

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

enum op { A_ACTIVATE, A_TERMINATE, A_CDS, A_VERIFY, A_CHANGE, A_SET_RC, A_PUT,
           A_GEN_DEC, A_RESET_RC, A_RESET_PW3, A_BOOTSTRAP, A_COUNT };

/* A card in use (own PINs, an RC, keys, the DEC key), then what the APDU needs. */
static void before(enum op o)
{
    fresh();
    CHECK(verify(0x83, "12345678") == 0x9000);
    CHECK(two(0x24, 0x00, 0x83, "12345678", "admin-own-1") == 0x9000);
    CHECK(two(0x24, 0x00, 0x81, "123456", "pw1-own") == 0x9000);
    CHECK(verify(0x83, "admin-own-1") == 0x9000 && put(0x00D3, "rc-code-1", 9) == 0x9000);
    mock_ecc_put(29);
    mock_ecc_put(31);
    openpgp_applet_card_reset();
    switch (o) {
    case A_ACTIVATE:
        CHECK(verify(0x83, "admin-own-1") == 0x9000 && apdu(0xE6, 0x00, 0x00, NULL, 0) == 0x9000);
        break;
    case A_TERMINATE: case A_SET_RC: case A_PUT: case A_RESET_PW3:
        CHECK(verify(0x83, "admin-own-1") == 0x9000);
        break;
    case A_GEN_DEC:
        CHECK(verify(0x83, "admin-own-1") == 0x9000 && verify(0x82, "pw1-own") == 0x9000);
        break;
    case A_CDS:
        CHECK(verify(0x81, "pw1-own") == 0x9000);
        break;
    case A_BOOTSTRAP:                    /* O3 lost (both copies), keys and PINs stay */
        CHECK(tropic_rmem_erase(33) == 0 && tropic_rmem_erase(43) == 0);
        reboot();
        break;
    default:
        break;
    }
}

static uint16_t send(enum op o)
{
    switch (o) {
    case A_ACTIVATE:  return apdu(0x44, 0x00, 0x00, NULL, 0);
    case A_TERMINATE: return apdu(0xE6, 0x00, 0x00, NULL, 0);
    case A_CDS:       return cds();
    case A_VERIFY:    return verify(0x81, "pw1-own");
    case A_CHANGE:    return two(0x24, 0x00, 0x81, "pw1-own", "pw1-new");
    case A_SET_RC:    return put(0x00D3, "rc-code-2", 9);
    case A_PUT:       return put(0x005B, "Alice", 5);
    case A_GEN_DEC:   return gen_dec();
    case A_RESET_RC:  return two(0x2C, 0x00, 0x81, "rc-code-1", "newpin1");
    case A_RESET_PW3: return apdu(0x2C, 0x02, 0x81, "newpin1", 7);
    default:          return select_pgp();
    }
}

/* M5 after one fault: a key never lives under a fresh s (a reset's new PIN
 * sees no key), and a stored key opens under the PIN it was sealed for. */
static bool m5_ok(enum op o)
{
    if ((o == A_RESET_RC || o == A_RESET_PW3) && verify(0x82, "newpin1") == 0x9000) {
        return read_dec_pub() == 0x6A88;
    }
    bool pw1 = (o == A_CHANGE && verify(0x82, "pw1-new") == 0x9000)
            || verify(0x82, "pw1-own") == 0x9000;
    if (!pw1) return true;                      /* no usable PW1: nothing to open */
    return read_dec_pub() != 0x9000 || dec() == 0x9000;
}

static void test_apdu_sweep(void)
{
    static const mock_op_t ops[] = {
        MOCK_OP_ECC_ERASE, MOCK_OP_RMEM_READ, MOCK_OP_RMEM_WRITE, MOCK_OP_RMEM_ERASE,
        MOCK_OP_MAC_AND_DESTROY, MOCK_OP_RANDOM,
    };
    for (int o = 0; o < A_COUNT; ++o) {
        for (size_t i = 0; i < sizeof ops / sizeof ops[0]; ++i) {
            mock_op_t op = ops[i];
            before((enum op) o);
            unsigned c0 = mock_calls(op);
            CHECK(send((enum op) o) == 0x9000);
            unsigned calls = mock_calls(op) - c0;
            bool rmem_mut = op == MOCK_OP_RMEM_WRITE || op == MOCK_OP_RMEM_ERASE;
            for (unsigned n = 1; n <= calls; ++n) {
                for (int f = 0; f < F_COUNT; ++f) {
                    if (f >= F_GARBLE && !rmem_mut) continue;
                    if (f == F_LOST && op == MOCK_OP_RMEM_READ) continue;
                    before((enum op) o);
                    arm(op, n, (enum fault) f);
                    uint16_t sw = send((enum op) o);
                    mock_disarm();
                    reboot();
                    bool good = select_pgp() == 0x9000 && m5_ok((enum op) o);
                    if (keys_left()) {          /* never a key under a factory PIN */
                        good = good && verify(0x81, "123456") != 0x9000
                                    && verify(0x83, "12345678") != 0x9000;
                    }
                    good = good && gpg_factory_reset();
                    CHECK(good);
                    if (!good) fprintf(stderr, "  apdu sweep op %d fault %d chip-op %d call %u: sw %04x\n",
                                       o, f, op, n, sw);
                }
            }
        }
    }
}

/* ---- M5: the DEC key wrapped under the PW1 KEK (docs/PHASE-9-M5-DESIGN.md) ---- */

static bool kek_zero(void)
{
    return openpgp_applet_test_kek_zero() != 0;
}

/* gpg on a fresh card verifies 81, never 82, before generating (J1). */
static void test_m5_fresh_card_gpg_order(void)
{
    mock_reset(1);
    reboot();
    s_touch_ok = true;
    CHECK(select_pgp() == 0x9000 && read_dec_pub() == 0x6A88);
    CHECK(verify(0x83, "12345678") == 0x9000 && gen_dec() == 0x6982);   /* PW3 alone: no KEK */
    CHECK(read_dec_pub() == 0x6A88 && kek_zero());
    CHECK(verify(0x81, "123456") == 0x9000 && !kek_zero() && gen_dec() == 0x9000);
    CHECK(read_dec_pub() == 0x9000 && dec() == 0x6982);                /* 81 is never 82 */
    CHECK(verify(0x82, "123456") == 0x9000 && dec() == 0x9000 && s_out_len == 32 + 2);
    openpgp_applet_card_reset();
    CHECK(kek_zero() && read_dec_pub() == 0x9000);                      /* public key: no PIN */
}

/* The KEK lives exactly while 81 or 82 is set (E5, §3); PW3 events leave it. */
static void test_m5_kek_lifetime(void)
{
    static const uint8_t other_aid[] = { 0xA0, 0x00, 0x00, 0x03, 0x08 };
    static const uint8_t zero = 0;
    fresh();
    CHECK(kek_zero());
    CHECK(verify(0x81, "123456") == 0x9000 && verify(0x82, "123456") == 0x9000);
    CHECK(apdu(0x20, 0xFF, 0x81, NULL, 0) == 0x9000 && !kek_zero() && dec() == 0x9000);
    CHECK(apdu(0x20, 0xFF, 0x82, NULL, 0) == 0x9000 && kek_zero());
    CHECK(verify(0x82, "123456") == 0x9000 && verify(0x83, "12345678") == 0x9000);
    CHECK(verify(0x83, "00000000") == 0x63C2 && !kek_zero() && dec() == 0x9000);   /* wrong 83 */
    CHECK(verify(0x83, "12345678") == 0x9000 && apdu(0x20, 0xFF, 0x83, NULL, 0) == 0x9000);
    CHECK(!kek_zero() && dec() == 0x9000);
    CHECK(verify(0x82, "000000") == 0x63C2 && kek_zero());                         /* wrong PW1 */
    CHECK(verify(0x82, "123456") == 0x9000);
    openpgp_applet_card_reset();
    CHECK(kek_zero());
    CHECK(verify(0x82, "123456") == 0x9000);
    CHECK(apdu(0xA4, 0x04, 0x00, other_aid, sizeof other_aid) == 0x6A82 && kek_zero());
    CHECK(select_pgp() == 0x9000 && verify(0x82, "123456") == 0x9000);
    CHECK(two(0x24, 0x00, 0x81, "123456", "pw1-new") == 0x9000 && kek_zero());   /* change */
    /* C4 00: the CDS that consumes 81 ends the KEK when 82 is not set. */
    CHECK(verify(0x83, "12345678") == 0x9000 && put(0x00C4, &zero, 1) == 0x9000);
    CHECK(verify(0x81, "pw1-new") == 0x9000 && !kek_zero() && cds() == 0x9000 && kek_zero());
    CHECK(gen_dec() == 0x6982);
    /* TERMINATE / ACTIVATE. */
    CHECK(verify(0x82, "pw1-new") == 0x9000 && apdu(0xE6, 0x00, 0x00, NULL, 0) == 0x9000);
    CHECK(kek_zero() && apdu(0x44, 0x00, 0x00, NULL, 0) == 0x9000 && kek_zero());
    CHECK(read_dec_pub() == 0x6A88);                                 /* the key went with it */
}

/* A PW1 change keeps decryption (same s, E7); a reset destroys the key (E8). */
static void test_m5_change_keeps_reset_destroys(void)
{
    uint8_t pub[64];
    fresh();
    CHECK(read_dec_pub() == 0x9000);
    memcpy(pub, s_out, s_out_len < sizeof pub ? s_out_len : sizeof pub);
    CHECK(two(0x24, 0x00, 0x81, "123456", "pw1-new") == 0x9000);
    CHECK(verify(0x82, "pw1-new") == 0x9000 && dec() == 0x9000);
    CHECK(read_dec_pub() == 0x9000 && memcmp(pub, s_out, 16) == 0);
    /* Reset by PW3. */
    CHECK(verify(0x83, "12345678") == 0x9000 && apdu(0x2C, 0x02, 0x81, "abcdef", 6) == 0x9000);
    CHECK(kek_zero() && read_dec_pub() == 0x6A88);
    CHECK(verify(0x82, "abcdef") == 0x9000 && dec() == 0x6A88);
    /* A new key under the new PIN works; reset by RC destroys it too. */
    CHECK(gen_dec() == 0x9000 && dec() == 0x9000);
    CHECK(put(0x00D3, "rcrcrcrc", 8) == 0x9000);
    CHECK(two(0x2C, 0x00, 0x81, "rcrcrcrc", "newpin") == 0x9000 && read_dec_pub() == 0x6A88);
    CHECK(verify(0x82, "newpin") == 0x9000 && dec() == 0x6A88);
}

/* J2: every refusal of the reset comes before the destroy. */
static void test_m5_reset_preflight(void)
{
    char long_pin[66];
    memset(long_pin, 'p', sizeof long_pin - 1);
    long_pin[sizeof long_pin - 1] = '\0';
    fresh();
    CHECK(apdu(0x2C, 0x02, 0x81, "abcdef", 6) == 0x6982 && read_dec_pub() == 0x9000);
    CHECK(verify(0x83, "12345678") == 0x9000);
    CHECK(apdu(0x2C, 0x02, 0x81, "a", 1) == 0x6700 && read_dec_pub() == 0x9000);
    CHECK(apdu(0x2C, 0x02, 0x81, long_pin, 65) == 0x6700 && read_dec_pub() == 0x9000);
    CHECK(put(0x00D3, "rcrcrcrc", 8) == 0x9000);
    CHECK(two(0x2C, 0x00, 0x81, "rcrcrcrc", "12345") == 0x6700 && read_dec_pub() == 0x9000);
    CHECK(two(0x2C, 0x00, 0x81, "xxxxxxxx", "newpin") == 0x63C2 && read_dec_pub() == 0x9000);
    CHECK(verify(0x82, "123456") == 0x9000 && dec() == 0x9000);
    /* The destroy fails: the reset stops, the old PIN and the key stay. */
    CHECK(verify(0x83, "12345678") == 0x9000);
    mock_fail_nth(MOCK_OP_RMEM_WRITE, 1, -1, false);
    CHECK(apdu(0x2C, 0x02, 0x81, "abcdef", 6) == 0x6F00);
    mock_disarm();
    reboot();
    CHECK(select_pgp() == 0x9000 && read_dec_pub() == 0x9000);
    CHECK(verify(0x82, "123456") == 0x9000 && dec() == 0x9000);
}

/* A damaged wrap: 6F00, nothing usable, the PW1 session ends (§3). */
static void test_m5_damaged_wrap(void)
{
    openpgp_dec_rec_t r;
    fresh();
    CHECK(openpgp_state_dec_get(&r) == 0);
    r.ct[0] ^= 1u;
    CHECK(openpgp_state_dec_set(&r) == 0);
    CHECK(verify(0x81, "123456") == 0x9000 && verify(0x82, "123456") == 0x9000);
    CHECK(dec() == 0x6F00 && s_out_len == 2 && kek_zero());   /* SW only */
    CHECK(cds() == 0x6982 && dec() == 0x6982);
}

/* Only auth_grant / auth_drop touch the access status (design §4). */
static void test_m5_single_auth_path(void)
{
    FILE *f = fopen("firmware/src/openpgp/openpgp_applet.c", "r");
    char line[512];
    unsigned and_eq = 0, or_eq = 0, assign = 0;
    CHECK(f != NULL);
    if (f == NULL) return;
    while (fgets(line, sizeof line, f) != NULL) {
        if (strstr(line, "s_auth &=") != NULL) and_eq++;
        if (strstr(line, "s_auth |=") != NULL) or_eq++;
        if (strstr(line, "s_auth = ") != NULL) assign++;
    }
    fclose(f);
    CHECK(and_eq == 1 && or_eq == 1 && assign == 0);
}

int main(void)
{
    test_m5_fresh_card_gpg_order();
    test_m5_kek_lifetime();
    test_m5_change_keeps_reset_destroys();
    test_m5_reset_preflight();
    test_m5_damaged_wrap();
    test_m5_single_auth_path();
    test_defaults_and_status();
    test_81_82_apart();
    test_clearing_events();
    test_c4();
    test_sig_counter_and_touch();
    test_change();
    test_reset_retry_counter();
    test_put_data_gates();
    test_terminate_activate();
    test_unreadable_state();
    test_boot_retry();
    test_flag_edges();
    test_framing();
    test_boot_bound();
    test_apdu_sweep();
    return check_done("openpgp_applet");
}
