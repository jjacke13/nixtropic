/*
 * Host test of the CTAP2 ClientPIN handlers (firmware/src/fido_hid/pin.c,
 * Phase 9 M4 step 3) driven like a platform: real P-256 key agreement,
 * AES-256-CBC PIN encryption and pinUvAuthParam, on the mock chip with the
 * FIDO state, kernel v2 and record pairs underneath.
 *
 * Checks: setPin / getRetries; changePin per CTAP 2.1 §6.5.5.6 (design
 * D10) — a bad pinUvAuthParam costs no attempt, a wrong old PIN costs one,
 * a policy-violating new PIN is reported only after a correct old PIN; the
 * in-boot 3-strike rule; BLOCKED; an unreadable binding answers OTHER, never
 * "8 retries"; and (Jan, step 3 HIGH) no PIN token outlives a changePin
 * whose kernel call failed after the new PIN was committed.  Plus the CTAP
 * dispatcher's readiness gate (Jan, step 3): after an ambiguous O2 write
 * only GetInfo and authenticatorReset get through (the other handlers are
 * stubs here that record being reached).
 */
#include <string.h>

#include "check.h"
#include "mock_tropic.h"
#include "aes/aes.h"
#include "ecdsa.h"
#include "hmac.h"
#include "nist256p1.h"
#include "sha2.h"
#include "fido_hid/cbor.h"
#include "fido_hid/credmgmt.h"
#include "fido_hid/credstore.h"
#include "fido_hid/ctaphid.h"
#include "fido_hid/user_presence.h"
#include "fido_hid/ctap2.h"
#include "fido_hid/fido_state.h"
#include "fido_hid/pin.h"
#include "fido_hid/pin_md.h"
#include "fido_hid/slots.h"
#include "tropic/tropic.h"

uint32_t mock_tick;

/* Handlers the gate must keep out; each records that it was reached. */
static int s_reached;
static int stub(int cmd_byte, uint8_t *resp)
{
    s_reached = cmd_byte;
    resp[0] = CTAP2_OK;
    return 1;
}
int ctap2_make_credential(const uint8_t *q, size_t n, uint8_t *resp, size_t m)
{ (void) q; (void) n; (void) m; return stub(0x01, resp); }
int ctap2_get_assertion(const uint8_t *q, size_t n, uint8_t *resp, size_t m)
{ (void) q; (void) n; (void) m; return stub(0x02, resp); }
int ctap2_get_next_assertion(uint8_t *resp, size_t m) { (void) m; return stub(0x08, resp); }
int credmgmt_handle_cbor(const uint8_t *q, size_t n, uint8_t *resp, size_t m)
{ (void) q; (void) n; (void) m; return stub(0x0A, resp); }
int ctap2_config(const uint8_t *q, size_t n, uint8_t *resp, size_t m)
{ (void) q; (void) n; (void) m; return stub(0x0D, resp); }
void ctap2_assertion_reset(void) {}
void credmgmt_reset_iterator(void) {}
up_result_t user_presence_check(uint32_t timeout_ms) { (void) timeout_ms; return UP_OK; }

/* trezor rand.c draws from random32(); the firmware supplies it from the
 * TRNG.  Deterministic here (it only blinds the point multiplication). */
uint32_t random32(void)
{
    static uint32_t x = 0x2545F491u;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    return x;
}

static const uint8_t PLAT_PRIV[32] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                       0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0f, 0x1e,
                                       0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96,
                                       0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0, 0x01, 0x02 };
static uint8_t plat_pub[65];
static uint8_t shared[32];
static uint8_t resp[1024];
static size_t  resp_len;

static uint8_t cmd(const uint8_t *req, size_t n)
{
    int r = pin_handle_cbor(req, n, resp, sizeof resp);
    resp_len = r > 0 ? (size_t) r : 0u;
    return resp[0];
}

static void write_cose(cbor_writer_t *w)
{
    cbor_write_map_header(w, 5);
    cbor_write_uint(w, 1);   cbor_write_uint(w, 2);
    cbor_write_uint(w, 3);   cbor_write_negint(w, -25);
    cbor_write_negint(w, -1); cbor_write_uint(w, 1);
    cbor_write_negint(w, -2); cbor_write_byte_string(w, &plat_pub[1], 32);
    cbor_write_negint(w, -3); cbor_write_byte_string(w, &plat_pub[33], 32);
}

/* getKeyAgreement, then shared = SHA-256(ECDH(platform, authenticator).x). */
static void key_agreement(void)
{
    uint8_t req[16], auth_pub[65] = { 0x04 }, point[65];
    cbor_writer_t w;
    cbor_writer_init(&w, req, sizeof req);
    cbor_write_map_header(&w, 2);
    cbor_write_uint(&w, 1); cbor_write_uint(&w, 1);
    cbor_write_uint(&w, 2); cbor_write_uint(&w, 2);
    CHECK(cmd(req, cbor_writer_len(&w)) == CTAP2_OK);

    cbor_reader_t r;
    size_t n = 0;
    uint8_t mt; uint64_t key;
    cbor_reader_init(&r, &resp[1], resp_len - 1u);
    CHECK(cbor_reader_read_map_header(&r, &n) == 0 && n == 1u);
    CHECK(cbor_reader_read_head(&r, &mt, &key) == 0 && key == 1u);
    CHECK(cbor_reader_read_map_header(&r, &n) == 0);
    for (size_t i = 0; i < n; ++i) {
        const uint8_t *p; size_t L;
        CHECK(cbor_reader_read_head(&r, &mt, &key) == 0);
        if (mt == 1u && (key == 1u || key == 2u)) {
            CHECK(cbor_reader_read_bytes(&r, &p, &L) == 0 && L == 32u);
            memcpy(&auth_pub[key == 1u ? 1 : 33], p, 32);
        } else {
            CHECK(cbor_reader_skip(&r) == 0);
        }
    }
    CHECK(ecdh_multiply(&nist256p1, PLAT_PRIV, auth_pub, point) == 0);
    sha256_Raw(&point[1], 32, shared);
}

static void enc(const uint8_t *in, size_t len, uint8_t *out)
{
    aes_encrypt_ctx c;
    uint8_t iv[16] = { 0 };
    aes_encrypt_key256(shared, &c);
    aes_cbc_encrypt(in, out, (int) len, iv, &c);
}

static void dec(const uint8_t *in, size_t len, uint8_t *out)
{
    aes_decrypt_ctx c;
    uint8_t iv[16] = { 0 };
    aes_decrypt_key256(shared, &c);
    aes_cbc_decrypt(in, out, (int) len, iv, &c);
}

static void auth16(const uint8_t *msg, size_t len, uint8_t out[16])
{
    uint8_t full[32];
    hmac_sha256(shared, 32, msg, (uint32_t) len, full);
    memcpy(out, full, 16);
}

static void new_pin_enc(const char *pin, uint8_t out[64])
{
    uint8_t padded[64] = { 0 };
    memcpy(padded, pin, strlen(pin));
    enc(padded, 64, out);
}

static void pin_hash_enc(const char *pin, uint8_t out[16])
{
    uint8_t h[32];
    sha256_Raw((const uint8_t *) pin, (uint32_t) strlen(pin), h);
    enc(h, 16, out);
}

static uint8_t set_pin(const char *pin)
{
    uint8_t req[300], npe[64], pa[16];
    cbor_writer_t w;
    key_agreement();
    new_pin_enc(pin, npe);
    auth16(npe, 64, pa);
    cbor_writer_init(&w, req, sizeof req);
    cbor_write_map_header(&w, 5);
    cbor_write_uint(&w, 1); cbor_write_uint(&w, 1);
    cbor_write_uint(&w, 2); cbor_write_uint(&w, 3);
    cbor_write_uint(&w, 3); write_cose(&w);
    cbor_write_uint(&w, 4); cbor_write_byte_string(&w, pa, 16);
    cbor_write_uint(&w, 5); cbor_write_byte_string(&w, npe, 64);
    return cmd(req, cbor_writer_len(&w));
}

static uint8_t change_pin(const char *old_pin, const char *new_pin, bool bad_auth)
{
    uint8_t req[320], npe[64], phe[16], msg[80], pa[16];
    cbor_writer_t w;
    key_agreement();
    new_pin_enc(new_pin, npe);
    pin_hash_enc(old_pin, phe);
    memcpy(msg, npe, 64);
    memcpy(&msg[64], phe, 16);
    auth16(msg, sizeof msg, pa);
    if (bad_auth) pa[0] ^= 0x01;
    cbor_writer_init(&w, req, sizeof req);
    cbor_write_map_header(&w, 6);
    cbor_write_uint(&w, 1); cbor_write_uint(&w, 1);
    cbor_write_uint(&w, 2); cbor_write_uint(&w, 4);
    cbor_write_uint(&w, 3); write_cose(&w);
    cbor_write_uint(&w, 4); cbor_write_byte_string(&w, pa, 16);
    cbor_write_uint(&w, 5); cbor_write_byte_string(&w, npe, 64);
    cbor_write_uint(&w, 6); cbor_write_byte_string(&w, phe, 16);
    return cmd(req, cbor_writer_len(&w));
}

static uint8_t get_token(const char *pin)
{
    uint8_t req[200], phe[16];
    cbor_writer_t w;
    key_agreement();
    pin_hash_enc(pin, phe);
    cbor_writer_init(&w, req, sizeof req);
    cbor_write_map_header(&w, 4);
    cbor_write_uint(&w, 1); cbor_write_uint(&w, 1);
    cbor_write_uint(&w, 2); cbor_write_uint(&w, 5);
    cbor_write_uint(&w, 3); write_cose(&w);
    cbor_write_uint(&w, 6); cbor_write_byte_string(&w, phe, 16);
    uint8_t st = cmd(req, cbor_writer_len(&w));
    if (st == CTAP2_OK) {                       /* the token decrypts to 32 bytes */
        uint8_t tok[32];
        CHECK(resp_len == 1u + 4u + 32u);       /* status, a1 02 58 20, token */
        dec(&resp[5], 32, tok);
    }
    return st;
}

/* getRetries: the count, or 0xFF if the command failed. */
static int retries(void)
{
    static const uint8_t req[] = { 0xa2, 0x01, 0x01, 0x02, 0x01 };
    if (cmd(req, sizeof req) != CTAP2_OK) return -(int) resp[0];
    return resp[resp_len - 1];                  /* {3: n}, n < 24 */
}

static void boot(void)
{
    slots_test_reboot();
    fido_pin_test_reboot();
    CHECK(fido_state_boot() == 0);
    pin_reset_ram();                            /* power cycle: RAM state gone */
}

static void fresh(void)
{
    mock_reset(1);
    CHECK(ecdsa_get_public_key65(&nist256p1, PLAT_PRIV, plat_pub) == 0);
    CHECK(pin_init() == 0);
    boot();
}

static void test_set_and_retries(void)
{
    fresh();
    CHECK(retries() == (int) FIDO_PIN_ROUNDS);   /* no PIN: maxRetries */
    CHECK(set_pin("12") == CTAP2_ERR_PIN_POLICY_VIOLATION);
    CHECK(set_pin("1234") == CTAP2_OK);
    CHECK(set_pin("5678") == CTAP2_ERR_PIN_AUTH_INVALID);
    CHECK(retries() == (int) FIDO_PIN_ROUNDS);
    CHECK(get_token("1234") == CTAP2_OK && pin_token_is_valid());
}

/* D10: a bad pinUvAuthParam is answered before any attempt is spent. */
static void test_change_order(void)
{
    fresh();
    CHECK(set_pin("1234") == CTAP2_OK);
    CHECK(change_pin("1234", "5678", true) == CTAP2_ERR_PIN_AUTH_INVALID);
    CHECK(change_pin("0000", "5678", true) == CTAP2_ERR_PIN_AUTH_INVALID);  /* wrong PIN, bad MAC */
    CHECK(retries() == (int) FIDO_PIN_ROUNDS);                          /* nothing spent */
    CHECK(change_pin("0000", "12", false) == CTAP2_ERR_PIN_INVALID);    /* old first */
    CHECK(retries() == (int) FIDO_PIN_ROUNDS - 1);
    CHECK(change_pin("1234", "12", false) == CTAP2_ERR_PIN_POLICY_VIOLATION);
    CHECK(retries() == (int) FIDO_PIN_ROUNDS);                          /* right PIN restored */
    CHECK(get_token("1234") == CTAP2_OK);                               /* unchanged */
    CHECK(change_pin("1234", "5678", false) == CTAP2_OK);
    CHECK(!pin_token_is_valid());                                       /* old token dead */
    CHECK(get_token("1234") == CTAP2_ERR_PIN_INVALID);
    CHECK(get_token("5678") == CTAP2_OK);
}

/* CTAP §6.5.5.7: three wrong PINs in one boot block PIN use until a power cycle. */
static void test_three_strikes(void)
{
    fresh();
    CHECK(set_pin("1234") == CTAP2_OK);
    CHECK(get_token("0000") == CTAP2_ERR_PIN_INVALID);
    CHECK(get_token("0000") == CTAP2_ERR_PIN_INVALID);
    CHECK(get_token("0000") == CTAP2_ERR_PIN_AUTH_BLOCKED);
    CHECK(get_token("1234") == CTAP2_ERR_PIN_AUTH_BLOCKED);
    CHECK(change_pin("1234", "5678", false) == CTAP2_ERR_PIN_AUTH_BLOCKED);
    CHECK(retries() == (int) FIDO_PIN_ROUNDS - 3);
    boot();
    CHECK(get_token("1234") == CTAP2_OK);
    /* Wrong old PINs in changePin count toward the same rule. */
    CHECK(change_pin("0000", "5678", false) == CTAP2_ERR_PIN_INVALID);
    CHECK(get_token("0000") == CTAP2_ERR_PIN_INVALID);
    CHECK(change_pin("0000", "5678", false) == CTAP2_ERR_PIN_AUTH_BLOCKED);
    CHECK(get_token("1234") == CTAP2_ERR_PIN_AUTH_BLOCKED);
}

static void test_blocked(void)
{
    fresh();
    CHECK(set_pin("1234") == CTAP2_OK);
    for (unsigned i = 0; i < FIDO_PIN_ROUNDS; ++i) {
        if (i % 2 == 0) boot();
        uint8_t st = get_token("0000");
        CHECK(st == (i + 1 == FIDO_PIN_ROUNDS ? CTAP2_ERR_PIN_BLOCKED : CTAP2_ERR_PIN_INVALID));
    }
    CHECK(retries() == 0);
    CHECK(get_token("1234") == CTAP2_ERR_PIN_BLOCKED);
    CHECK(change_pin("1234", "5678", false) == CTAP2_ERR_PIN_BLOCKED);
}

/* An unreadable binding is never "no PIN" or "full retries". */
static void test_unreadable_binding(void)
{
    fresh();
    CHECK(set_pin("1234") == CTAP2_OK);
    mock_rmem_damage(41, MOCK_DAMAGE_GARBLE);
    mock_rmem_damage(42, MOCK_DAMAGE_GARBLE);
    slots_test_reboot();
    fido_pin_test_reboot();
    CHECK(fido_state_boot() != 0);              /* FIDO refuses (the dispatcher gate) ... */
    pin_reset_ram();
    CHECK(retries() == -(int) CTAP2_ERR_OTHER); /* ... and the handlers fail closed too */
    CHECK(set_pin("5678") == CTAP2_ERR_OTHER);
    CHECK(change_pin("1234", "5678", false) == CTAP2_ERR_OTHER);
    CHECK(get_token("1234") == CTAP2_ERR_OTHER);
    CHECK(pin_is_set());
}

/* Jan step 3 HIGH: the change fails after its commit (first retirement
 * call): an error, no token survives, the NEW PIN is the live one. */
static void test_no_token_after_failed_change(void)
{
    fresh();
    CHECK(set_pin("1234") == CTAP2_OK);
    CHECK(get_token("1234") == CTAP2_OK && pin_token_is_valid());
    /* change: verify (1 + 8 restore), setup (3 x 8), then the retirement. */
    mock_fail_nth(MOCK_OP_MAC_AND_DESTROY, 1u + 8u + 24u + 1u, -1, false);
    CHECK(change_pin("1234", "5678", false) == CTAP2_ERR_OTHER);
    CHECK(!pin_token_is_valid());
    boot();
    CHECK(get_token("1234") == CTAP2_ERR_PIN_INVALID);
    CHECK(get_token("5678") == CTAP2_OK);
}

/* One CTAP2 command through the real dispatcher: an empty parameter map
 * (none for GetInfo); ClientPIN = getKeyAgreement. */
static uint8_t dispatch(uint8_t cmd_byte)
{
    uint8_t req[8] = { cmd_byte, 0xa0 };
    size_t n = 2;
    if (cmd_byte == 0x04) n = 1;
    if (cmd_byte == 0x06) {
        static const uint8_t ka[] = { 0x06, 0xa2, 0x01, 0x01, 0x02, 0x02 };
        memcpy(req, ka, sizeof ka);
        n = sizeof ka;
    }
    s_reached = 0;
    (void) fido_hid_cbor_dispatch(req, n, resp, sizeof resp);
    return resp[0];
}

static void test_dispatch_gate(void)
{
    static const uint8_t gated[] = { 0x01, 0x02, 0x06, 0x08, 0x0A, 0x0D };
    fresh();
    CHECK(credstore_init() == 0 && credstore_ready());
    CHECK(dispatch(0x01) == CTAP2_OK && s_reached == 0x01);
    CHECK(dispatch(0x06) == CTAP2_OK);
    CHECK(set_pin("1234") == CTAP2_OK);
    mock_fail_nth(MOCK_OP_RMEM_WRITE, 1, -1, true);      /* changePin's reservation, copy A */
    CHECK(change_pin("1234", "5678", false) == CTAP2_ERR_OTHER);
    CHECK(!credstore_ready());
    for (size_t i = 0; i < sizeof gated; ++i) {
        CHECK(dispatch(gated[i]) == CTAP2_ERR_NOT_ALLOWED && s_reached == 0);
    }
    CHECK(dispatch(0x04) == CTAP2_OK);                    /* GetInfo answers */
    mock_tick = 20000u;                                   /* Reset only in the 10 s window */
    CHECK(dispatch(0x07) == CTAP2_ERR_NOT_ALLOWED);
    mock_tick = 0u;
    CHECK(dispatch(0x07) == CTAP2_OK && credstore_ready());
    CHECK(dispatch(0x01) == CTAP2_OK && s_reached == 0x01);
}

int main(void)
{
    test_set_and_retries();
    test_change_order();
    test_three_strikes();
    test_blocked();
    test_unreadable_binding();
    test_no_token_after_failed_change();
    test_dispatch_gate();
    return check_done("fido_pin_cmd");
}
