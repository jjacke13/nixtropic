/*
 * Host tests for firmware/src/fido_hid/ctap2_parse.c (Phase 9 M3):
 * MakeCredential / GetAssertion requests, valid and broken.
 */
#include <string.h>

#include "check.h"
#include "fido_hid/cbor.h"
#include "fido_hid/ctap2.h"
#include "fido_hid/ctap2_parse.h"

static uint8_t buf[512];
static cbor_writer_t w;
static const uint8_t z16[16];

static void begin(size_t entries)
{
    cbor_writer_init(&w, buf, sizeof buf);
    cbor_write_map_header(&w, entries);
}

static void put_hash(size_t n)
{
    static const uint8_t h[40] = { 0x11 };
    cbor_write_byte_string(&w, h, n);
}

static void put_rp(void)
{
    cbor_write_map_header(&w, 2);
    cbor_write_text(&w, "id");
    cbor_write_text(&w, "example.com");
    cbor_write_text(&w, "name");
    cbor_write_text(&w, "Example");
}

static void put_user(size_t id_len)
{
    static const uint8_t uid[80] = { 0x22 };
    cbor_write_map_header(&w, 2);
    cbor_write_text(&w, "id");
    cbor_write_byte_string(&w, uid, id_len);
    cbor_write_text(&w, "name");
    cbor_write_text(&w, "alice");
}

static void put_param(int64_t alg, const char *type)
{
    cbor_write_map_header(&w, 2);
    cbor_write_text(&w, "alg");
    if (alg < 0) cbor_write_negint(&w, alg); else cbor_write_uint(&w, (uint64_t) alg);
    cbor_write_text(&w, "type");
    cbor_write_text(&w, type);
}

static void put_descriptor(uint8_t tag, const char *type)
{
    uint8_t id[18];
    memset(id, tag, sizeof id);
    cbor_write_map_header(&w, 2);
    cbor_write_text(&w, "id");
    cbor_write_byte_string(&w, id, sizeof id);
    cbor_write_text(&w, "type");
    cbor_write_text(&w, type);
}

/* MakeCredential with keys 1..4, then `extra` more entries the caller writes. */
static void mc_base(size_t extra, size_t user_id_len)
{
    begin(4 + extra);
    cbor_write_uint(&w, 1); put_hash(32);
    cbor_write_uint(&w, 2); put_rp();
    cbor_write_uint(&w, 3); put_user(user_id_len);
    cbor_write_uint(&w, 4);
    cbor_write_array_header(&w, 2);
    put_param(-7, "public-key");
    put_param(-8, "public-key");
}

static int mc(ctap2_mc_req_t *req)
{
    CHECK(cbor_writer_error(&w) == 0);
    size_t n = cbor_writer_len(&w);
    CHECK(cbor_validate(buf, n) == 0);
    return ctap2_parse_make_cred(buf, n, req);
}

static int ga(ctap2_ga_req_t *req)
{
    CHECK(cbor_writer_error(&w) == 0);
    return ctap2_parse_get_assertion(buf, cbor_writer_len(&w), req);
}

static void test_mc_valid(void)
{
    ctap2_mc_req_t r;
    mc_base(0, 16);
    CHECK(mc(&r) == 0);
    CHECK(r.alg == -8);                       /* ES256 listed first, skipped */
    CHECK(r.rp_id_len == 11 && memcmp(r.rp_id, "example.com", 11) == 0);
    CHECK(r.user_id_len == 16 && r.user_id[0] == 0x22);
    CHECK(r.client_hash[0] == 0x11);
    CHECK(!r.exclude.present && !r.want_cred_props);
    CHECK(r.opt.rk == CTAP2_OPT_ABSENT && r.opt.up == CTAP2_OPT_ABSENT
          && r.opt.uv == CTAP2_OPT_ABSENT);
    CHECK(!r.pin_uv.has_param && r.pin_uv.protocol == CTAP2_OPT_ABSENT);
}

static void test_mc_algorithms(void)
{
    ctap2_mc_req_t r;

    /* only ES256 → unsupported */
    begin(4);
    cbor_write_uint(&w, 1); put_hash(32);
    cbor_write_uint(&w, 2); put_rp();
    cbor_write_uint(&w, 3); put_user(8);
    cbor_write_uint(&w, 4); cbor_write_array_header(&w, 1); put_param(-7, "public-key");
    CHECK(mc(&r) == CTAP2_ERR_UNSUPPORTED_ALGORITHM);

    /* -8 under a type other than public-key does not count */
    begin(4);
    cbor_write_uint(&w, 1); put_hash(32);
    cbor_write_uint(&w, 2); put_rp();
    cbor_write_uint(&w, 3); put_user(8);
    cbor_write_uint(&w, 4); cbor_write_array_header(&w, 1); put_param(-8, "other");
    CHECK(mc(&r) == CTAP2_ERR_UNSUPPORTED_ALGORITHM);

    /* -8 - 2^32 used to truncate to -8 through an int cast */
    begin(4);
    cbor_write_uint(&w, 1); put_hash(32);
    cbor_write_uint(&w, 2); put_rp();
    cbor_write_uint(&w, 3); put_user(8);
    cbor_write_uint(&w, 4); cbor_write_array_header(&w, 1);
    put_param(-8 - 4294967296LL, "public-key");
    CHECK(mc(&r) == CTAP2_ERR_UNSUPPORTED_ALGORITHM);

    /* an entry without "type" is malformed, even after a good one */
    begin(4);
    cbor_write_uint(&w, 1); put_hash(32);
    cbor_write_uint(&w, 2); put_rp();
    cbor_write_uint(&w, 3); put_user(8);
    cbor_write_uint(&w, 4); cbor_write_array_header(&w, 2);
    put_param(-8, "public-key");
    cbor_write_map_header(&w, 1); cbor_write_text(&w, "alg"); cbor_write_negint(&w, -7);
    CHECK(mc(&r) == CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
}

static void test_mc_members(void)
{
    ctap2_mc_req_t r;

    /* user missing */
    begin(3);
    cbor_write_uint(&w, 1); put_hash(32);
    cbor_write_uint(&w, 2); put_rp();
    cbor_write_uint(&w, 4); cbor_write_array_header(&w, 1); put_param(-8, "public-key");
    CHECK(mc(&r) == CTAP2_ERR_MISSING_PARAMETER);

    /* user.id longer than 64 bytes */
    mc_base(0, 65);
    CHECK(mc(&r) == CTAP1_ERR_INVALID_LENGTH);
    mc_base(0, 64);
    CHECK(mc(&r) == 0);

    /* clientDataHash of 31 bytes */
    begin(4);
    cbor_write_uint(&w, 1); put_hash(31);
    cbor_write_uint(&w, 2); put_rp();
    cbor_write_uint(&w, 3); put_user(8);
    cbor_write_uint(&w, 4); cbor_write_array_header(&w, 1); put_param(-8, "public-key");
    CHECK(mc(&r) == CTAP1_ERR_INVALID_LENGTH);

    /* rp.id as bytes instead of text */
    begin(4);
    cbor_write_uint(&w, 1); put_hash(32);
    cbor_write_uint(&w, 2); cbor_write_map_header(&w, 1);
    cbor_write_text(&w, "id"); cbor_write_byte_string(&w, (const uint8_t *) "x", 1);
    cbor_write_uint(&w, 3); put_user(8);
    cbor_write_uint(&w, 4); cbor_write_array_header(&w, 1); put_param(-8, "public-key");
    CHECK(mc(&r) == CTAP2_ERR_CBOR_UNEXPECTED_TYPE);

    /* enterpriseAttestation is refused */
    mc_base(1, 8);
    cbor_write_uint(&w, 10); cbor_write_uint(&w, 1);
    CHECK(mc(&r) == CTAP1_ERR_INVALID_PARAMETER);

    /* a text top-level key */
    mc_base(1, 8);
    cbor_write_text(&w, "x"); cbor_write_uint(&w, 1);
    CHECK(mc(&r) == CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
}

static void test_mc_options_and_pin(void)
{
    ctap2_mc_req_t r;

    mc_base(3, 8);
    cbor_write_uint(&w, 7);
    cbor_write_map_header(&w, 3);
    cbor_write_text(&w, "rk"); cbor_write_bool(&w, true);
    cbor_write_text(&w, "up"); cbor_write_bool(&w, false);
    cbor_write_text(&w, "zz"); cbor_write_uint(&w, 5);      /* unknown: ignored */
    cbor_write_uint(&w, 8); cbor_write_byte_string(&w, z16, 0);
    cbor_write_uint(&w, 9); cbor_write_uint(&w, 1);
    CHECK(mc(&r) == 0);
    CHECK(r.opt.rk == 1 && r.opt.up == 0 && r.opt.uv == CTAP2_OPT_ABSENT);
    CHECK(r.pin_uv.has_param && r.pin_uv.param_len == 0 && r.pin_uv.protocol == 1);

    /* an option value that is not a boolean */
    mc_base(1, 8);
    cbor_write_uint(&w, 7);
    cbor_write_map_header(&w, 1);
    cbor_write_text(&w, "uv"); cbor_write_uint(&w, 1);
    CHECK(mc(&r) == CTAP2_ERR_CBOR_UNEXPECTED_TYPE);

    /* huge pinUvAuthProtocol is reported as 0xFFFF, not truncated to 1 */
    mc_base(1, 8);
    cbor_write_uint(&w, 9); cbor_write_uint(&w, 0x10001u);
    CHECK(mc(&r) == 0 && r.pin_uv.protocol == 0xFFFF);

    /* extensions: credProps recognised */
    mc_base(1, 8);
    cbor_write_uint(&w, 6);
    cbor_write_map_header(&w, 1);
    cbor_write_text(&w, "credProps"); cbor_write_bool(&w, true);
    CHECK(mc(&r) == 0 && r.want_cred_props == 1);
}

static void test_mc_exclude_list(void)
{
    ctap2_mc_req_t r;
    mc_base(1, 8);
    cbor_write_uint(&w, 5);
    cbor_write_array_header(&w, 3);
    put_descriptor(0xA1, "public-key");
    put_descriptor(0xB2, "other-type");
    put_descriptor(0xC3, "public-key");
    CHECK(mc(&r) == 0 && r.exclude.present);

    ctap2_cred_iter_t it;
    const uint8_t *id;
    size_t id_len;
    ctap2_cred_iter_init(&it, &r.exclude);
    CHECK(ctap2_cred_iter_next(&it, &id, &id_len) == 1 && id_len == 18 && id[0] == 0xA1);
    CHECK(ctap2_cred_iter_next(&it, &id, &id_len) == 1 && id[0] == 0xC3);
    CHECK(ctap2_cred_iter_next(&it, &id, &id_len) == 0);

    /* descriptor without "id" */
    mc_base(1, 8);
    cbor_write_uint(&w, 5);
    cbor_write_array_header(&w, 1);
    cbor_write_map_header(&w, 1);
    cbor_write_text(&w, "type"); cbor_write_text(&w, "public-key");
    CHECK(mc(&r) == CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
}

static void test_ga(void)
{
    ctap2_ga_req_t r;

    /* rpId + hash only: no allowList */
    begin(2);
    cbor_write_uint(&w, 1); cbor_write_text(&w, "example.com");
    cbor_write_uint(&w, 2); put_hash(32);
    CHECK(ga(&r) == 0 && !r.allow.present && r.rp_id_len == 11);
    ctap2_cred_iter_t it;
    const uint8_t *id;
    size_t id_len;
    ctap2_cred_iter_init(&it, &r.allow);
    CHECK(ctap2_cred_iter_next(&it, &id, &id_len) == 0);

    /* full request */
    begin(5);
    cbor_write_uint(&w, 1); cbor_write_text(&w, "example.com");
    cbor_write_uint(&w, 2); put_hash(32);
    cbor_write_uint(&w, 3); cbor_write_array_header(&w, 2);
    put_descriptor(0x01, "public-key"); put_descriptor(0x02, "public-key");
    cbor_write_uint(&w, 5); cbor_write_map_header(&w, 1);
    cbor_write_text(&w, "up"); cbor_write_bool(&w, false);
    cbor_write_uint(&w, 6); cbor_write_byte_string(&w, z16, sizeof z16);
    CHECK(ga(&r) == 0);
    CHECK(r.allow.present && r.opt.up == 0 && r.pin_uv.param_len == 16
          && r.pin_uv.protocol == CTAP2_OPT_ABSENT);
    ctap2_cred_iter_init(&it, &r.allow);
    CHECK(ctap2_cred_iter_next(&it, &id, &id_len) == 1 && id[0] == 0x01);
    CHECK(ctap2_cred_iter_next(&it, &id, &id_len) == 1 && id[0] == 0x02);
    CHECK(ctap2_cred_iter_next(&it, &id, &id_len) == 0);

    /* rpId missing */
    begin(1);
    cbor_write_uint(&w, 2); put_hash(32);
    CHECK(ga(&r) == CTAP2_ERR_MISSING_PARAMETER);

    /* rpId as a number */
    begin(2);
    cbor_write_uint(&w, 1); cbor_write_uint(&w, 7);
    cbor_write_uint(&w, 2); put_hash(32);
    CHECK(ga(&r) == CTAP2_ERR_CBOR_UNEXPECTED_TYPE);

    /* the top level is not a map */
    cbor_writer_init(&w, buf, sizeof buf);
    cbor_write_array_header(&w, 0);
    CHECK(ga(&r) == CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
}

int main(void)
{
    test_mc_valid();
    test_mc_algorithms();
    test_mc_members();
    test_mc_options_and_pin();
    test_mc_exclude_list();
    test_ga();
    return check_done("ctap2_parse");
}
