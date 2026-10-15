/*
 * CTAP2 request parsing — see ctap2_parse.h.
 *
 * Error mapping (CTAP §8): a member of the wrong CBOR type, or a
 * structure missing a required member, is CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
 * a missing top-level parameter is CTAP2_ERR_MISSING_PARAMETER.  Unknown
 * map keys are skipped.
 */

#include "ctap2_parse.h"
#include "ctap2.h"

#include <stdint.h>
#include <string.h>

#define MT_UINT    0
#define MT_NEGINT  1
#define MT_BYTES   2
#define MT_TEXT    3
#define MT_ARRAY   4
#define MT_MAP     5
#define MT_SIMPLE  7

#define TRY(expr) do { int rc_ = (expr); if (rc_ != 0) return rc_; } while (0)

/* ----- Typed readers: wrong type → UNEXPECTED_TYPE ----- */

static int want(const cbor_reader_t *r, int mt)
{
    return (cbor_reader_peek_major(r) == mt) ? 0 : (int) CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
}

static int rd_text(cbor_reader_t *r, const uint8_t **p, size_t *n)
{
    TRY(want(r, MT_TEXT));
    return cbor_reader_read_text(r, p, n) == 0 ? 0 : (int) CTAP2_ERR_INVALID_CBOR;
}

static int rd_bytes(cbor_reader_t *r, const uint8_t **p, size_t *n)
{
    TRY(want(r, MT_BYTES));
    return cbor_reader_read_bytes(r, p, n) == 0 ? 0 : (int) CTAP2_ERR_INVALID_CBOR;
}

static int rd_map(cbor_reader_t *r, size_t *n)
{
    TRY(want(r, MT_MAP));
    return cbor_reader_read_map_header(r, n) == 0 ? 0 : (int) CTAP2_ERR_INVALID_CBOR;
}

static int rd_array(cbor_reader_t *r, size_t *n)
{
    TRY(want(r, MT_ARRAY));
    return cbor_reader_read_array_header(r, n) == 0 ? 0 : (int) CTAP2_ERR_INVALID_CBOR;
}

static int rd_skip(cbor_reader_t *r)
{
    return cbor_reader_skip(r) == 0 ? 0 : (int) CTAP2_ERR_INVALID_CBOR;
}

/* Unsigned integer; values above 0xFFFF are reported as 0xFFFF. */
static int rd_small_uint(cbor_reader_t *r, int *out)
{
    uint64_t v;
    TRY(want(r, MT_UINT));
    if (cbor_reader_read_uint(r, &v) != 0) return (int) CTAP2_ERR_INVALID_CBOR;
    *out = (v > 0xFFFFu) ? 0xFFFF : (int) v;
    return 0;
}

/* Signed integer (COSE algorithm id).  Values outside int32 range are
 * clamped; no supported algorithm is near the limits. */
static int rd_int(cbor_reader_t *r, int32_t *out)
{
    uint8_t mt;
    uint64_t v;
    int peek = cbor_reader_peek_major(r);
    if (peek != MT_UINT && peek != MT_NEGINT) return (int) CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    if (cbor_reader_read_head(r, &mt, &v) != 0) return (int) CTAP2_ERR_INVALID_CBOR;
    if (v > 0x7FFFFFFFu) {
        *out = (mt == MT_UINT) ? INT32_MAX : INT32_MIN;
    } else {
        *out = (mt == MT_UINT) ? (int32_t) v : (int32_t)(-1 - (int64_t) v);
    }
    return 0;
}

static int rd_bool(cbor_reader_t *r, int *out)
{
    uint8_t mt;
    uint64_t v;
    TRY(want(r, MT_SIMPLE));
    if (cbor_reader_read_head(r, &mt, &v) != 0) return (int) CTAP2_ERR_INVALID_CBOR;
    if (v == 20u) { *out = 0; return 0; }
    if (v == 21u) { *out = 1; return 0; }
    return (int) CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
}

/* Top-level parameter keys are unsigned integers. */
static int rd_param_key(cbor_reader_t *r, uint64_t *key)
{
    TRY(want(r, MT_UINT));
    return cbor_reader_read_uint(r, key) == 0 ? 0 : (int) CTAP2_ERR_INVALID_CBOR;
}

static int key_is(const uint8_t *k, size_t n, const char *s)
{
    size_t sl = strlen(s);
    return n == sl && memcmp(k, s, sl) == 0;
}

/* ----- Members ----- */

static int rd_client_hash(cbor_reader_t *r, uint8_t out[32])
{
    const uint8_t *p;
    size_t n;
    TRY(rd_bytes(r, &p, &n));
    if (n != 32u) return (int) CTAP1_ERR_INVALID_LENGTH;
    memcpy(out, p, 32);
    return 0;
}

/* PublicKeyCredentialRpEntity: { "id": text, ... } — id required. */
static int rd_rp(cbor_reader_t *r, const uint8_t **id, size_t *id_len)
{
    size_t m;
    int got = 0;
    TRY(rd_map(r, &m));
    for (size_t i = 0; i < m; ++i) {
        const uint8_t *k;
        size_t kl;
        TRY(rd_text(r, &k, &kl));
        if (key_is(k, kl, "id")) {
            TRY(rd_text(r, id, id_len));
            got = 1;
        } else {
            TRY(rd_skip(r));
        }
    }
    return got ? 0 : (int) CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
}

/* PublicKeyCredentialUserEntity: { "id": bytes ≤ 64, ... } — id required. */
static int rd_user(cbor_reader_t *r, const uint8_t **id, size_t *id_len)
{
    size_t m;
    int got = 0;
    TRY(rd_map(r, &m));
    for (size_t i = 0; i < m; ++i) {
        const uint8_t *k;
        size_t kl;
        TRY(rd_text(r, &k, &kl));
        if (key_is(k, kl, "id")) {
            TRY(rd_bytes(r, id, id_len));
            got = 1;
        } else {
            TRY(rd_skip(r));
        }
    }
    if (!got) return (int) CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    return (*id_len <= CTAP2_USER_ID_MAX) ? 0 : (int) CTAP1_ERR_INVALID_LENGTH;
}

/* pubKeyCredParams: every entry must have an integer "alg" and a text
 * "type"; the first "public-key" entry with an algorithm we support is
 * chosen (CTAP §6.1.2 step 3): EdDSA or ES256, in the host's order.  All
 * entries are checked. */
static int rd_cred_params(cbor_reader_t *r, int *chosen)
{
    size_t n;
    *chosen = 0;
    TRY(rd_array(r, &n));
    for (size_t i = 0; i < n; ++i) {
        size_t m;
        int32_t alg = 0;
        int got_alg = 0, got_type = 0, public_key = 0;
        TRY(rd_map(r, &m));
        for (size_t j = 0; j < m; ++j) {
            const uint8_t *k;
            size_t kl;
            TRY(rd_text(r, &k, &kl));
            if (key_is(k, kl, "alg")) {
                TRY(rd_int(r, &alg));
                got_alg = 1;
            } else if (key_is(k, kl, "type")) {
                const uint8_t *t;
                size_t tl;
                TRY(rd_text(r, &t, &tl));
                public_key = key_is(t, tl, "public-key");
                got_type = 1;
            } else {
                TRY(rd_skip(r));
            }
        }
        if (!got_alg || !got_type) return (int) CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        if (*chosen == 0 && public_key
            && (alg == CTAP2_COSE_ALG_EDDSA || alg == CTAP2_COSE_ALG_ES256)) {
            *chosen = (int) alg;
        }
    }
    return 0;
}

/* One PublicKeyCredentialDescriptor: "id" (bytes) and "type" (text)
 * required.  Reports the id and whether type is "public-key". */
static int rd_descriptor(cbor_reader_t *r, const uint8_t **id, size_t *id_len,
                         int *public_key)
{
    size_t m;
    int got_id = 0, got_type = 0;
    TRY(rd_map(r, &m));
    for (size_t j = 0; j < m; ++j) {
        const uint8_t *k;
        size_t kl;
        TRY(rd_text(r, &k, &kl));
        if (key_is(k, kl, "id")) {
            TRY(rd_bytes(r, id, id_len));
            got_id = 1;
        } else if (key_is(k, kl, "type")) {
            const uint8_t *t;
            size_t tl;
            TRY(rd_text(r, &t, &tl));
            *public_key = key_is(t, tl, "public-key");
            got_type = 1;
        } else {
            TRY(rd_skip(r));
        }
    }
    return (got_id && got_type) ? 0 : (int) CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
}

static int rd_cred_list(cbor_reader_t *r, ctap2_cred_list_t *out)
{
    size_t start = r->pos;
    size_t n;
    TRY(rd_array(r, &n));
    for (size_t i = 0; i < n; ++i) {
        const uint8_t *id;
        size_t id_len;
        int pk = 0;
        TRY(rd_descriptor(r, &id, &id_len, &pk));
    }
    out->present = 1;
    out->ptr = &r->buf[start];
    out->len = r->pos - start;
    return 0;
}

/* options: text keys, boolean values for the ones we know; unknown
 * options are ignored (CTAP §6.1.2 step 5). */
static int rd_options(cbor_reader_t *r, ctap2_options_t *opt)
{
    size_t m;
    TRY(rd_map(r, &m));
    for (size_t i = 0; i < m; ++i) {
        const uint8_t *k;
        size_t kl;
        TRY(rd_text(r, &k, &kl));
        if (key_is(k, kl, "rk")) {
            TRY(rd_bool(r, &opt->rk));
        } else if (key_is(k, kl, "up")) {
            TRY(rd_bool(r, &opt->up));
        } else if (key_is(k, kl, "uv")) {
            TRY(rd_bool(r, &opt->uv));
        } else {
            TRY(rd_skip(r));
        }
    }
    return 0;
}

/* extensions: text keys; only credProps is recognised (Phase 8 M2). */
static int rd_extensions(cbor_reader_t *r, int *want_cred_props)
{
    size_t m;
    TRY(rd_map(r, &m));
    for (size_t i = 0; i < m; ++i) {
        const uint8_t *k;
        size_t kl;
        TRY(rd_text(r, &k, &kl));
        if (key_is(k, kl, "credProps")) {
            *want_cred_props = 1;
        }
        TRY(rd_skip(r));
    }
    return 0;
}

static int rd_pin_uv_param(cbor_reader_t *r, ctap2_pin_uv_t *pu)
{
    TRY(rd_bytes(r, &pu->param, &pu->param_len));
    pu->has_param = 1;
    return 0;
}

static void init_common(ctap2_options_t *opt, ctap2_pin_uv_t *pu)
{
    opt->rk = CTAP2_OPT_ABSENT;
    opt->up = CTAP2_OPT_ABSENT;
    opt->uv = CTAP2_OPT_ABSENT;
    memset(pu, 0, sizeof *pu);
    pu->protocol = CTAP2_OPT_ABSENT;
}

/* ----- MakeCredential (CTAP §6.1) ----- */

int ctap2_parse_make_cred(const uint8_t *req, size_t len, ctap2_mc_req_t *out)
{
    memset(out, 0, sizeof *out);
    init_common(&out->opt, &out->pin_uv);

    cbor_reader_t r;
    cbor_reader_init(&r, req, len);
    size_t n;
    int got_hash = 0, got_rp = 0, got_user = 0, got_params = 0;
    TRY(rd_map(&r, &n));
    for (size_t i = 0; i < n; ++i) {
        uint64_t key;
        TRY(rd_param_key(&r, &key));
        switch (key) {
        case 1: TRY(rd_client_hash(&r, out->client_hash)); got_hash = 1; break;
        case 2: TRY(rd_rp(&r, &out->rp_id, &out->rp_id_len)); got_rp = 1; break;
        case 3: TRY(rd_user(&r, &out->user_id, &out->user_id_len)); got_user = 1; break;
        case 4: TRY(rd_cred_params(&r, &out->alg)); got_params = 1; break;
        case 5: TRY(rd_cred_list(&r, &out->exclude)); break;
        case 6: TRY(rd_extensions(&r, &out->want_cred_props)); break;
        case 7: TRY(rd_options(&r, &out->opt)); break;
        case 8: TRY(rd_pin_uv_param(&r, &out->pin_uv)); break;
        case 9: TRY(rd_small_uint(&r, &out->pin_uv.protocol)); break;
        case 10:
            /* enterpriseAttestation: not supported (CTAP §6.1.2 step 9.1). */
            return (int) CTAP1_ERR_INVALID_PARAMETER;
        default: TRY(rd_skip(&r)); break;
        }
    }
    if (!got_hash || !got_rp || !got_user || !got_params) {
        return (int) CTAP2_ERR_MISSING_PARAMETER;
    }
    if (out->alg == 0) {
        return (int) CTAP2_ERR_UNSUPPORTED_ALGORITHM;
    }
    return 0;
}

/* ----- GetAssertion (CTAP §6.2) ----- */

int ctap2_parse_get_assertion(const uint8_t *req, size_t len, ctap2_ga_req_t *out)
{
    memset(out, 0, sizeof *out);
    init_common(&out->opt, &out->pin_uv);

    cbor_reader_t r;
    cbor_reader_init(&r, req, len);
    size_t n;
    int got_rp = 0, got_hash = 0;
    TRY(rd_map(&r, &n));
    for (size_t i = 0; i < n; ++i) {
        uint64_t key;
        TRY(rd_param_key(&r, &key));
        switch (key) {
        case 1: TRY(rd_text(&r, &out->rp_id, &out->rp_id_len)); got_rp = 1; break;
        case 2: TRY(rd_client_hash(&r, out->client_hash)); got_hash = 1; break;
        case 3: TRY(rd_cred_list(&r, &out->allow)); break;
        case 5: TRY(rd_options(&r, &out->opt)); break;
        case 6: TRY(rd_pin_uv_param(&r, &out->pin_uv)); break;
        case 7: TRY(rd_small_uint(&r, &out->pin_uv.protocol)); break;
        default: TRY(rd_skip(&r)); break;   /* 4 = extensions: none supported */
        }
    }
    if (!got_rp || !got_hash) {
        return (int) CTAP2_ERR_MISSING_PARAMETER;
    }
    return 0;
}

/* ----- Credential list walk ----- */

void ctap2_cred_iter_init(ctap2_cred_iter_t *it, const ctap2_cred_list_t *list)
{
    it->left = 0;
    cbor_reader_init(&it->r, list->present ? list->ptr : NULL,
                     list->present ? list->len : 0u);
    size_t n;
    if (list->present && cbor_reader_read_array_header(&it->r, &n) == 0) {
        it->left = n;
    }
}

int ctap2_cred_iter_next(ctap2_cred_iter_t *it, const uint8_t **id, size_t *id_len)
{
    while (it->left > 0u) {
        it->left--;
        int pk = 0;
        if (rd_descriptor(&it->r, id, id_len, &pk) != 0) {
            it->left = 0;           /* cannot happen for a parsed list */
            return 0;
        }
        if (pk) return 1;
    }
    return 0;
}
