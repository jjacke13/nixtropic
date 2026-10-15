/*
 * CTAP2 ClientPIN protocol v1 — implementation.
 *
 * Spec: CTAP2.1 §5.5.4 (key agreement + token life-cycle) + §6.5
 * (CBOR command surface).  pinUvAuthProtocol "version 1":
 *
 *   - Key agreement: P-256 ECDH (NIST FIPS 186-5)
 *   - Encryption:    AES-256-CBC with IV=0
 *   - MAC:           HMAC-SHA-256 (RFC 2104), output truncated to 16 B
 *
 * All crypto from trezor-crypto (vendored via libtropic — same
 * primitives used for L3 Noise IK + Ed25519 sign).
 *
 * Threat-model defensive choices baked into this file:
 *   - All secret comparisons use ct_memcmp (constant-time).
 *   - shared_key + ephemeral private key live ONLY on the stack;
 *     wiped before return (memzero / memset).
 *   - pinUvAuthToken is RAM-only and only generated AFTER successful
 *     PIN verification.  Token is regenerated on every getPinToken.
 *   - Ephemeral P-256 keypair regenerates after every successful PIN
 *     op for forward secrecy (compromise of one shared_key doesn't
 *     leak prior or subsequent shared_keys).
 *   - PIN entry deliberately omitted from log/printf statements
 *     (timing side channels via UART).
 *
 * Retry-counter design (two backstops):
 *   - In-boot consec_fails (3 max, RAM): forces power-cycle after
 *     3 wrong PINs even if persistent counter has retries left.
 *     CTAP2 §5.5.4 mandates.
 *   - Persistent retries: the MAC-and-Destroy binding itself (Phase 9 M4,
 *     pin_md.c on kernel v2) — 8 chip slots, retries = slots left.  No
 *     stored PIN hash and no software counter (design D5, D6).
 */

#include "pin.h"
#include "pin_md.h"
#include "pin_token.h"
#include "ctap2.h"
#include "cbor.h"
#include "slots.h"

#include "tropic/tropic.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "sha2.h"
#include "hmac.h"
#include "aes/aes.h"
#include "ecdsa.h"
#include "nist256p1.h"
#include "memzero.h"

#include "stm32u5xx_hal.h"   /* HAL_GetTick: token timers */

/* ----- CBOR keys (request map) ----- */
#define CP_KEY_PIN_PROTOCOL   1u
#define CP_KEY_SUB_COMMAND    2u
#define CP_KEY_KEY_AGREEMENT  3u
#define CP_KEY_PIN_AUTH       4u
#define CP_KEY_NEW_PIN_ENC    5u
#define CP_KEY_PIN_HASH_ENC   6u
#define CP_KEY_PERMISSIONS    9u
#define CP_KEY_RP_ID         10u

/* ----- CBOR keys (response map) ----- */
#define CP_RESP_KEY_AGREEMENT 1u
#define CP_RESP_PIN_TOKEN     2u
#define CP_RESP_RETRIES       3u

/* ----- Sub-commands ----- */
#define CP_SUB_GET_RETRIES     0x01u
#define CP_SUB_GET_KEY_AGREE   0x02u
#define CP_SUB_SET_PIN         0x03u
#define CP_SUB_CHANGE_PIN      0x04u
#define CP_SUB_GET_PIN_TOKEN   0x05u
#define CP_SUB_GET_PIN_UV_TOKEN_PERMS 0x09u  /* CTAP2.1 getPinUvAuthTokenUsingPinWithPermissions */

/* ----- State (RAM-only) ----- */
static int     s_initted;
/* P-256 private key: 32 B big-endian scalar in [1, n-1]. */
static uint8_t s_eph_priv[32];
/* P-256 public key uncompressed: byte[0] = 0x04 || X[32] || Y[32]. */
static uint8_t s_eph_pub65[65];
/* The pinUvAuthToken and its state live in pin_token.c (Phase 9 M3). */
/* Consecutive wrong PINs THIS BOOT. Reset to 0 only on successful PIN
 * (which also resets retries to max). CTAP2 §5.5.4: at ≥3 consec fails,
 * authenticator MUST refuse further PIN ops until power-cycle. */
static uint8_t s_consec_fails;
/* Has the in-boot lockout fired? Once true, only power-cycle clears it. */
static int     s_auth_blocked;

/* ----- Helpers ----- */

/* Constant-time memcmp; returns 0 iff a == b. */
static int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff;
}

/* Generate a fresh ephemeral P-256 keypair. Discards previous keypair. */
static int regen_eph(void)
{
    /* Rejection-sample a P-256 private key in [1, n-1]. P-256 order
     * n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551.
     * Clearing the top bit of the high byte guarantees < 2^255 < n,
     * giving us ~half the range. Loop until non-zero. */
    for (int attempt = 0; attempt < 16; ++attempt) {
        if (tropic_random(s_eph_priv, 32) != 0) {
            return -1;
        }
        s_eph_priv[0] &= 0x7Fu;
        uint8_t any = 0;
        for (int i = 0; i < 32; ++i) any |= s_eph_priv[i];
        if (any != 0) {
            /* Compute public key. trezor_crypto returns 65-B uncompressed
             * form: 0x04 || X || Y. */
            if (ecdsa_get_public_key65(&nist256p1, s_eph_priv, s_eph_pub65) != 0) {
                continue;
            }
            return 0;
        }
    }
    return -1;
}

/* Compute shared_key = SHA-256(ECDH(eph_priv, platform_pub_xy).x).
 * platform_pub_xy is 64 B (X[32] || Y[32]). out_key is 32 B. */
static int compute_shared_key(const uint8_t platform_pub_xy[64],
                              uint8_t out_key[32])
{
    uint8_t peer65[65];
    peer65[0] = 0x04u;
    memcpy(&peer65[1], platform_pub_xy, 64);

    uint8_t shared65[65];
    if (ecdh_multiply(&nist256p1, s_eph_priv, peer65, shared65) != 0) {
        return -1;
    }

    /* SHA-256 of the X coordinate (bytes 1..32 of the 65-B uncompressed). */
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, &shared65[1], 32);
    sha256_Final(&ctx, out_key);

    memzero(shared65, sizeof shared65);
    return 0;
}

/* AES-256-CBC decrypt with IV=0. `len` must be multiple of 16. */
static int aes_cbc_dec_iv0(const uint8_t key[32], const uint8_t *in,
                           size_t len, uint8_t *out)
{
    aes_decrypt_ctx ctx;
    if (aes_decrypt_key256(key, &ctx) != EXIT_SUCCESS) return -1;
    uint8_t iv[16] = {0};
    if (aes_cbc_decrypt(in, out, (int) len, iv, &ctx) != EXIT_SUCCESS) return -1;
    memzero(&ctx, sizeof ctx);
    return 0;
}

/* AES-256-CBC encrypt with IV=0. `len` must be multiple of 16. */
static int aes_cbc_enc_iv0(const uint8_t key[32], const uint8_t *in,
                           size_t len, uint8_t *out)
{
    aes_encrypt_ctx ctx;
    if (aes_encrypt_key256(key, &ctx) != EXIT_SUCCESS) return -1;
    uint8_t iv[16] = {0};
    if (aes_cbc_encrypt(in, out, (int) len, iv, &ctx) != EXIT_SUCCESS) return -1;
    memzero(&ctx, sizeof ctx);
    return 0;
}

/* Compute LEFT(HMAC-SHA256(key, msg), 16) into out[16]. */
static void pin_auth_compute(const uint8_t key[32],
                             const uint8_t *msg, size_t msg_len,
                             uint8_t out[16])
{
    uint8_t full[32];
    hmac_sha256(key, 32, msg, (uint32_t) msg_len, full);
    memcpy(out, full, 16);
    memzero(full, sizeof full);
}

/* ----- CBOR helpers ----- */

/* Parse the COSE_Key for the platform's P-256 pubkey out of the
 * keyAgreement CBOR map. Returns X || Y in out[64]. */
static int parse_cose_p256_pubkey(cbor_reader_t *r, uint8_t out_xy[64])
{
    size_t n;
    if (cbor_reader_read_map_header(r, &n) < 0) return -1;

    int got_x = 0, got_y = 0;
    /* COSE_Key for P-256: keys 1 (kty), 3 (alg), -1 (crv), -2 (x), -3 (y).
     * We only need x and y; skip the rest. */
    for (size_t i = 0; i < n; ++i) {
        uint8_t mt; uint64_t key;
        if (cbor_reader_read_head(r, &mt, &key) < 0) return -1;
        /* mt 0 = positive int, mt 1 = negative int.
         * For negative ints, the encoded value v represents -1-v.
         * -2 means v=1 (mt=1). -3 means v=2 (mt=1). */
        if (mt == 1u && key == 1u) {
            /* COSE -2 (x). */
            const uint8_t *p; size_t L;
            if (cbor_reader_read_bytes(r, &p, &L) < 0 || L != 32u) return -1;
            memcpy(&out_xy[0], p, 32);
            got_x = 1;
        } else if (mt == 1u && key == 2u) {
            /* COSE -3 (y). */
            const uint8_t *p; size_t L;
            if (cbor_reader_read_bytes(r, &p, &L) < 0 || L != 32u) return -1;
            memcpy(&out_xy[32], p, 32);
            got_y = 1;
        } else {
            if (cbor_reader_skip(r) < 0) return -1;
        }
    }
    return (got_x && got_y) ? 0 : -1;
}

/* Build a P-256 COSE_Key for our ephemeral pubkey. Always 5 entries:
 *   1 (kty)   = 2          (EC2)
 *   3 (alg)   = -25        (ECDH-ES + HKDF-256)
 *  -1 (crv)   = 1          (P-256)
 *  -2 (x)     = X[32]
 *  -3 (y)     = Y[32]
 * Canonical CBOR map order: 0x01 < 0x03 < 0x20 < 0x21 < 0x22. */
static int build_cose_p256_pubkey(cbor_writer_t *w)
{
    cbor_write_map_header(w, 5);
    cbor_write_uint(w, 1);   cbor_write_uint(w, 2);         /* kty = EC2 */
    cbor_write_uint(w, 3);   cbor_write_negint(w, -25);     /* alg = ECDH-ES + HKDF-256 */
    cbor_write_negint(w, -1); cbor_write_uint(w, 1);        /* crv = P-256 */
    cbor_write_negint(w, -2); cbor_write_byte_string(w, &s_eph_pub65[1],  32);
    cbor_write_negint(w, -3); cbor_write_byte_string(w, &s_eph_pub65[33], 32);
    return cbor_writer_error(w) ? -1 : 0;
}

/* ----- Sub-command implementations ----- */

static int handle_get_retries(uint8_t *resp, size_t resp_max)
{
    uint8_t att = 0;
    uint32_t retries;
    switch (fido_pin_state(&att)) {
    case FPIN_NOT_SET: retries = FIDO_PIN_ROUNDS; break;   /* maxRetries */
    case FPIN_SET:     retries = att; break;
    case FPIN_BLOCKED: retries = 0; break;
    default:
        resp[0] = CTAP2_ERR_OTHER;                         /* never "full retries" */
        return 1;
    }

    if (resp_max < 1u) return -1;
    resp[0] = CTAP2_OK;

    cbor_writer_t w;
    cbor_writer_init(&w, &resp[1], resp_max - 1u);
    cbor_write_map_header(&w, 1);
    cbor_write_uint(&w, CP_RESP_RETRIES);
    cbor_write_uint(&w, retries);
    if (cbor_writer_error(&w)) {
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }
    return (int)(1u + cbor_writer_len(&w));
}

static int handle_get_key_agreement(uint8_t *resp, size_t resp_max)
{
    if (!s_initted) {
        if (pin_init() != 0) {
            resp[0] = CTAP2_ERR_OTHER;
            return 1;
        }
    }
    if (resp_max < 1u) return -1;
    resp[0] = CTAP2_OK;

    cbor_writer_t w;
    cbor_writer_init(&w, &resp[1], resp_max - 1u);
    cbor_write_map_header(&w, 1);
    cbor_write_uint(&w, CP_RESP_KEY_AGREEMENT);
    if (build_cose_p256_pubkey(&w) != 0) {
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }
    return (int)(1u + cbor_writer_len(&w));
}

/* Parameters of the ClientPIN sub-commands that carry a PIN.  The platform
 * key is kept and the shared key derived only after parsing, so no early
 * return has a secret to wipe. */
typedef struct {
    uint8_t        peer_xy[64];
    uint8_t        pin_auth[16];
    uint8_t        new_pin_enc[PIN_ENC_BUF_LEN];
    uint8_t        pin_hash_enc[16];
    int            got_ka, got_pa, got_npe, got_phe, got_perms, got_rp;
    uint64_t       perms;
    const uint8_t *rp_id;
    size_t         rp_id_len;
} pin_req_t;

static int read_fixed(cbor_reader_t *r, uint8_t *out, size_t len)
{
    const uint8_t *p; size_t L;
    if (cbor_reader_read_bytes(r, &p, &L) < 0 || L != len) return -1;
    memcpy(out, p, len);
    return 0;
}

static int parse_pin_req(cbor_reader_t *r, size_t n_keys, pin_req_t *t)
{
    memset(t, 0, sizeof *t);
    for (size_t i = 0; i < n_keys; ++i) {
        uint8_t mt; uint64_t key;
        if (cbor_reader_read_head(r, &mt, &key) < 0 || mt != 0u) {
            return CTAP2_ERR_INVALID_CBOR;
        }
        if (key == CP_KEY_KEY_AGREEMENT) {
            /* An unusable platform key = decapsulate error (CTAP §6.5.5.7). */
            if (parse_cose_p256_pubkey(r, t->peer_xy) != 0) {
                return CTAP1_ERR_INVALID_PARAMETER;
            }
            t->got_ka = 1;
        } else if (key == CP_KEY_PIN_AUTH) {
            if (read_fixed(r, t->pin_auth, sizeof t->pin_auth) != 0) return CTAP2_ERR_INVALID_CBOR;
            t->got_pa = 1;
        } else if (key == CP_KEY_NEW_PIN_ENC) {
            if (read_fixed(r, t->new_pin_enc, sizeof t->new_pin_enc) != 0) return CTAP2_ERR_INVALID_CBOR;
            t->got_npe = 1;
        } else if (key == CP_KEY_PIN_HASH_ENC) {
            if (read_fixed(r, t->pin_hash_enc, sizeof t->pin_hash_enc) != 0) return CTAP2_ERR_INVALID_CBOR;
            t->got_phe = 1;
        } else if (key == CP_KEY_PERMISSIONS) {
            if (cbor_reader_read_uint(r, &t->perms) < 0) {
                return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            t->got_perms = 1;
        } else if (key == CP_KEY_RP_ID) {
            if (cbor_reader_read_text(r, &t->rp_id, &t->rp_id_len) < 0) {
                return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            t->got_rp = 1;
        } else if (cbor_reader_skip(r) < 0) {
            return CTAP2_ERR_INVALID_CBOR;
        }
    }
    return 0;
}

/* shared_key = SHA-256(ECDH(eph, platform key).x).  0, or the CTAP status. */
static int shared_key_for(const pin_req_t *q, uint8_t key[32])
{
    if (!s_initted && pin_init() != 0) return CTAP2_ERR_OTHER;
    return compute_shared_key(q->peer_xy, key) == 0 ? 0 : CTAP1_ERR_INVALID_PARAMETER;
}

/* Decrypt newPinEnc and hash the PIN: 0, the policy status, or OTHER. */
static int new_pin_hash(const uint8_t key[32], const pin_req_t *q,
                        uint8_t hash[32], size_t *pin_len)
{
    uint8_t pin_padded[PIN_ENC_BUF_LEN];
    int rc = 0;
    if (aes_cbc_dec_iv0(key, q->new_pin_enc, PIN_ENC_BUF_LEN, pin_padded) != 0) {
        rc = CTAP2_ERR_OTHER;
    } else {
        size_t len = PIN_ENC_BUF_LEN;
        while (len > 0 && pin_padded[len - 1] == 0u) len--;
        sha256_Raw(pin_padded, (uint32_t) len, hash);
        *pin_len = len;
        if (len < PIN_MIN_BYTES || len > PIN_MAX_BYTES) rc = CTAP2_ERR_PIN_POLICY_VIOLATION;
    }
    memzero(pin_padded, sizeof pin_padded);
    return rc;
}

/* Wrong-PIN bookkeeping shared by the failure paths: the status follows
 * the binding as it is now (an unreadable one is OTHER, not BLOCKED). */
static uint8_t pin_mismatch_status(void)
{
    uint8_t att = 0;
    fido_pin_state_t st = fido_pin_state(&att);
    s_consec_fails++;
    if (s_consec_fails >= PIN_AUTH_BLOCKED_CONSEC) s_auth_blocked = 1;
    (void) regen_eph();
    if (st == FPIN_BLOCKED) return CTAP2_ERR_PIN_BLOCKED;
    if (st != FPIN_SET)     return CTAP2_ERR_OTHER;
    if (s_auth_blocked)     return CTAP2_ERR_PIN_AUTH_BLOCKED;
    return CTAP2_ERR_PIN_INVALID;
}

/* setPin (0x03), CTAP 2.1 §6.5.5.5: pinUvAuthParam = LEFT(HMAC(key,
 * newPinEnc), 16).  Only without a PIN (or an unreadable one: OTHER). */
static int set_pin_with_key(const uint8_t key[32], const pin_req_t *q)
{
    uint8_t expected[16], hash[32];
    size_t pin_len = 0;
    int rc;
    pin_auth_compute(key, q->new_pin_enc, PIN_ENC_BUF_LEN, expected);
    if (ct_memcmp(expected, q->pin_auth, 16) != 0) {
        rc = CTAP2_ERR_PIN_AUTH_INVALID;
    } else {
        rc = new_pin_hash(key, q, hash, &pin_len);
        /* The binding also sets the O1 guard and auto-enables Force-UV on
         * this first PIN (Phase 6 M2; toggleAlwaysUv turns it off).  Every
         * token dies before the binding is touched (Jan, step 3 HIGH). */
        if (rc == 0) {
            puat_reset();
            if (fido_pin_set(hash, (uint8_t) pin_len) != 0) rc = CTAP2_ERR_OTHER;
        }
    }
    if (rc == 0) {
        (void) regen_eph();          /* forward secrecy */
        puat_reset();
        s_consec_fails = 0;
        s_auth_blocked = 0;
    }
    memzero(expected, sizeof expected);
    memzero(hash, sizeof hash);
    return rc;
}

static int handle_set_pin(cbor_reader_t *r, size_t n_keys, uint8_t *resp)
{
    fido_pin_state_t st = fido_pin_state(NULL);
    if (st != FPIN_NOT_SET) {
        resp[0] = st == FPIN_ERROR ? CTAP2_ERR_OTHER : CTAP2_ERR_PIN_AUTH_INVALID;
        return 1;
    }
    pin_req_t q;
    uint8_t key[32];
    int rc = parse_pin_req(r, n_keys, &q);
    if (rc == 0 && (!q.got_ka || !q.got_pa || !q.got_npe)) rc = CTAP2_ERR_MISSING_PARAMETER;
    if (rc == 0) rc = shared_key_for(&q, key);
    if (rc == 0) {
        rc = set_pin_with_key(key, &q);
        memzero(key, sizeof key);
    }
    memzero(&q, sizeof q);
    resp[0] = (uint8_t) rc;          /* CTAP2_OK = 0: empty body */
    return 1;
}

/* changePin (0x04), CTAP 2.1 §6.5.5.6 (design D10): a wrong pinUvAuthParam
 * is answered before any attempt is spent — the MAC reveals nothing about
 * the PIN.  Then the old PIN (the attempt is spent either way, step 6) and
 * only then the new one: a new PIN that breaks the policy is reported after
 * a correct old PIN (step 10), via a plain verify. */
static int change_pin_with_key(const uint8_t key[32], const pin_req_t *q)
{
    uint8_t auth_input[PIN_ENC_BUF_LEN + 16], expected[16];
    uint8_t old_hash[PIN_HASH_LEN], new_hash[32];
    size_t pin_len = 0;
    int correct = 0, rc;
    memcpy(auth_input, q->new_pin_enc, PIN_ENC_BUF_LEN);
    memcpy(&auth_input[PIN_ENC_BUF_LEN], q->pin_hash_enc, 16);
    pin_auth_compute(key, auth_input, sizeof auth_input, expected);
    memset(new_hash, 0, sizeof new_hash);
    if (ct_memcmp(expected, q->pin_auth, 16) != 0) {
        rc = CTAP2_ERR_PIN_AUTH_INVALID;
    } else if (aes_cbc_dec_iv0(key, q->pin_hash_enc, 16, old_hash) != 0) {
        rc = CTAP2_ERR_OTHER;
    } else {
        int policy = new_pin_hash(key, q, new_hash, &pin_len);
        if (policy == CTAP2_ERR_OTHER) {
            rc = CTAP2_ERR_OTHER;
        } else {
            /* Every token dies before the binding is touched: an error
             * after the kernel's commit can mean the NEW PIN is live
             * (pin_md_kernel.h), so no old token may outlive the call
             * (Jan, step 3 HIGH; CTAP 2.1 §6.5.5.6 kills them on success). */
            puat_reset();
            int krc = policy == 0
                    ? fido_pin_change(old_hash, new_hash, (uint8_t) pin_len, &correct)
                    : fido_pin_verify(old_hash, &correct);
            if (krc == -2)        { (void) regen_eph(); rc = CTAP2_ERR_PIN_BLOCKED; }
            else if (krc != 0)    rc = CTAP2_ERR_OTHER;
            else if (!correct)    rc = pin_mismatch_status();
            else                  { s_consec_fails = 0; rc = policy; }
            if (rc == 0) (void) regen_eph();     /* forward secrecy */
        }
    }
    memzero(auth_input, sizeof auth_input);
    memzero(expected, sizeof expected);
    memzero(old_hash, sizeof old_hash);
    memzero(new_hash, sizeof new_hash);
    return rc;
}

static int handle_change_pin(cbor_reader_t *r, size_t n_keys, uint8_t *resp)
{
    switch (fido_pin_state(NULL)) {
    case FPIN_SET:     break;
    case FPIN_NOT_SET: resp[0] = CTAP2_ERR_PIN_NOT_SET; return 1;
    case FPIN_BLOCKED: resp[0] = CTAP2_ERR_PIN_BLOCKED; return 1;
    default:           resp[0] = CTAP2_ERR_OTHER;       return 1;
    }
    if (s_auth_blocked) {
        resp[0] = CTAP2_ERR_PIN_AUTH_BLOCKED; return 1;
    }
    pin_req_t q;
    uint8_t key[32];
    int rc = parse_pin_req(r, n_keys, &q);
    if (rc == 0 && (!q.got_ka || !q.got_pa || !q.got_npe || !q.got_phe)) {
        rc = CTAP2_ERR_MISSING_PARAMETER;
    }
    if (rc == 0) rc = shared_key_for(&q, key);
    if (rc == 0) {
        rc = change_pin_with_key(key, &q);
        memzero(key, sizeof key);
    }
    memzero(&q, sizeof q);
    resp[0] = (uint8_t) rc;
    return 1;
}

/* CTAP §6.5.5.7.1 / .2 parameter checks, in the spec's order. */
static int check_token_req(const pin_req_t *t, int with_perms, uint8_t *perms)
{
    if (!t->got_ka || !t->got_phe || (with_perms && !t->got_perms)) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (!with_perms) {
        /* Legacy getPinToken: no permissions or rpId; default mc + ga. */
        if (t->got_perms || t->got_rp) return CTAP1_ERR_INVALID_PARAMETER;
        *perms = (uint8_t)(PUAT_PERM_MC | PUAT_PERM_GA);
        return 0;
    }
    if (t->perms == 0u) return CTAP1_ERR_INVALID_PARAMETER;
    /* be: no bioEnroll; lbw: no largeBlobs.  cm, acfg, mc, ga are offered. */
    if (t->perms & (PUAT_PERM_BE | PUAT_PERM_LBW)) {
        return CTAP2_ERR_UNAUTHORIZED_PERMISSION;
    }
    *perms = (uint8_t)(t->perms & PUAT_PERMS_KNOWN);   /* undefined bits ignored */
    return 0;
}

/* Check the PIN behind pinHashEnc against the M&D binding.  Returns 0 if
 * correct, otherwise the CTAP2 status to send. */
static int verify_pin_hash_enc(const uint8_t shared_key[32],
                               const uint8_t pin_hash_enc[16])
{
    uint8_t submitted_hash[PIN_HASH_LEN];
    if (aes_cbc_dec_iv0(shared_key, pin_hash_enc, 16, submitted_hash) != 0) {
        return CTAP2_ERR_OTHER;
    }
    int correct = 0;
    int rc = fido_pin_verify(submitted_hash, &correct);
    memzero(submitted_hash, sizeof submitted_hash);
    if (rc == -2) {
        (void) regen_eph();
        return CTAP2_ERR_PIN_BLOCKED;
    }
    if (rc != 0) return CTAP2_ERR_OTHER;
    if (!correct) return pin_mismatch_status();
    s_consec_fails = 0;
    return 0;
}

/* Issue a new token: every older token dies first (resetPinUvAuthToken),
 * then the encrypted token goes into resp. */
static int issue_token(const uint8_t shared_key[32], uint8_t perms,
                       const pin_req_t *t, uint8_t *resp, size_t resp_max)
{
    puat_reset();
    uint8_t token[PUAT_TOKEN_LEN];
    if (tropic_random(token, sizeof token) != 0) {
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }
    uint8_t rp_hash[32];
    if (t->got_rp) sha256_Raw(t->rp_id, (uint32_t) t->rp_id_len, rp_hash);
    puat_begin(token, perms, t->got_rp ? rp_hash : NULL, HAL_GetTick());

    uint8_t token_enc[PUAT_TOKEN_LEN];
    int enc_rc = aes_cbc_enc_iv0(shared_key, token, sizeof token, token_enc);
    memzero(token, sizeof token);
    if (enc_rc != 0) {
        puat_reset();
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }

    resp[0] = CTAP2_OK;
    cbor_writer_t w;
    cbor_writer_init(&w, &resp[1], resp_max - 1u);
    cbor_write_map_header(&w, 1);
    cbor_write_uint(&w, CP_RESP_PIN_TOKEN);
    cbor_write_byte_string(&w, token_enc, PUAT_TOKEN_LEN);
    memzero(token_enc, sizeof token_enc);
    if (cbor_writer_error(&w)) {
        puat_reset();
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }
    return (int)(1u + cbor_writer_len(&w));
}

/* getPinToken (0x05, with_perms = 0) and
 * getPinUvAuthTokenUsingPinWithPermissions (0x09, with_perms = 1),
 * CTAP §6.5.5.7.1 / §6.5.5.7.2.  The ephemeral keypair is NOT rotated on
 * success: the platform may reuse its keyAgreement for the next call. */
static int handle_get_pin_token(cbor_reader_t *r, size_t n_keys,
                                uint8_t *resp, size_t resp_max, int with_perms)
{
    pin_req_t t;
    uint8_t perms = 0;
    int rc = parse_pin_req(r, n_keys, &t);
    if (rc == 0) rc = check_token_req(&t, with_perms, &perms);
    if (rc != 0) { resp[0] = (uint8_t) rc; return 1; }

    switch (fido_pin_state(NULL)) {
    case FPIN_SET:     break;
    case FPIN_NOT_SET: resp[0] = CTAP2_ERR_PIN_NOT_SET; return 1;
    case FPIN_BLOCKED: resp[0] = CTAP2_ERR_PIN_BLOCKED; return 1;
    default:           resp[0] = CTAP2_ERR_OTHER;       return 1;
    }
    if (s_auth_blocked) { resp[0] = CTAP2_ERR_PIN_AUTH_BLOCKED; return 1; }

    uint8_t shared_key[32];
    if (compute_shared_key(t.peer_xy, shared_key) != 0) {
        resp[0] = CTAP1_ERR_INVALID_PARAMETER; return 1;
    }
    rc = verify_pin_hash_enc(shared_key, t.pin_hash_enc);
    if (rc != 0) {
        memzero(shared_key, sizeof shared_key);
        resp[0] = (uint8_t) rc;
        return 1;
    }
    rc = issue_token(shared_key, perms, &t, resp, resp_max);
    memzero(shared_key, sizeof shared_key);
    return rc;
}

/* ----- Public surface ----- */

int pin_init(void)
{
    int rc = regen_eph();
    if (rc != 0) return rc;
    puat_reset();
    s_consec_fails    = 0;
    s_auth_blocked    = 0;
    s_initted = 1;
    return 0;
}

void pin_reset_ram(void)
{
    puat_reset();
    s_consec_fails = 0;
    s_auth_blocked = 0;
    (void) regen_eph();
}

int pin_is_set(void)
{
    /* An unreadable PIN state counts as "PIN set": every check that asks
     * then demands the stricter path (Phase 9 M3). */
    return fido_pin_state(NULL) != FPIN_NOT_SET;
}

int pin_token_is_valid(void)
{
    /* Timers applied; the lt-rpc setters also need a token not yet spent
     * (cpp-reviewer M3). */
    return puat_in_use(HAL_GetTick()) && puat_user_verified();
}

int pin_handle_cbor(const uint8_t *req, size_t req_len,
                    uint8_t *resp, size_t resp_max)
{
    if (!s_initted) {
        if (pin_init() != 0) {
            resp[0] = CTAP2_ERR_OTHER;
            return 1;
        }
    }

    cbor_reader_t r;
    cbor_reader_init(&r, req, req_len);

    size_t n_keys;
    if (cbor_reader_read_map_header(&r, &n_keys) < 0) {
        resp[0] = CTAP2_ERR_INVALID_CBOR;
        return 1;
    }

    /* First pass: extract pinProtocol + subCommand. Both MUST appear,
     * and we need to know the sub-command before parsing other fields
     * (different sub-commands have different required fields).
     * Spec mandates these fields appear with keys 1 and 2; in practice
     * they appear FIRST due to canonical ordering. We require it. */
    if (n_keys < 2u) {
        resp[0] = CTAP2_ERR_MISSING_PARAMETER;
        return 1;
    }

    uint8_t mt; uint64_t key;
    /* Key 1: pinProtocol */
    if (cbor_reader_read_head(&r, &mt, &key) < 0 || mt != 0u || key != CP_KEY_PIN_PROTOCOL) {
        resp[0] = CTAP2_ERR_MISSING_PARAMETER; return 1;
    }
    uint8_t pp_mt; uint64_t pp_v;
    if (cbor_reader_read_head(&r, &pp_mt, &pp_v) < 0 || pp_mt != 0u) {
        resp[0] = CTAP2_ERR_INVALID_CBOR; return 1;
    }
    if (pp_v != PIN_PROTOCOL_VERSION) {
        resp[0] = CTAP1_ERR_INVALID_PARAMETER; return 1;
    }

    /* Key 2: subCommand */
    if (cbor_reader_read_head(&r, &mt, &key) < 0 || mt != 0u || key != CP_KEY_SUB_COMMAND) {
        resp[0] = CTAP2_ERR_MISSING_PARAMETER; return 1;
    }
    uint8_t sc_mt; uint64_t sc_v;
    if (cbor_reader_read_head(&r, &sc_mt, &sc_v) < 0 || sc_mt != 0u) {
        resp[0] = CTAP2_ERR_INVALID_CBOR; return 1;
    }

    size_t rest = n_keys - 2u;

    if (sc_v > 0xFFu) {               /* no truncation onto a real sub-command */
        resp[0] = CTAP1_ERR_INVALID_PARAMETER;
        return 1;
    }
    switch ((uint8_t) sc_v) {
    case CP_SUB_GET_RETRIES:
        /* Skip remaining keys (spec allows but doesn't require them). */
        for (size_t i = 0; i < rest; ++i) {
            if (cbor_reader_read_head(&r, &mt, &key) < 0) { resp[0] = CTAP2_ERR_INVALID_CBOR; return 1; }
            if (cbor_reader_skip(&r) < 0) { resp[0] = CTAP2_ERR_INVALID_CBOR; return 1; }
        }
        return handle_get_retries(resp, resp_max);
    case CP_SUB_GET_KEY_AGREE:
        for (size_t i = 0; i < rest; ++i) {
            if (cbor_reader_read_head(&r, &mt, &key) < 0) { resp[0] = CTAP2_ERR_INVALID_CBOR; return 1; }
            if (cbor_reader_skip(&r) < 0) { resp[0] = CTAP2_ERR_INVALID_CBOR; return 1; }
        }
        return handle_get_key_agreement(resp, resp_max);
    case CP_SUB_SET_PIN:
        return handle_set_pin(&r, rest, resp);
    case CP_SUB_CHANGE_PIN:
        return handle_change_pin(&r, rest, resp);
    case CP_SUB_GET_PIN_TOKEN:
        return handle_get_pin_token(&r, rest, resp, resp_max, 0);
    case CP_SUB_GET_PIN_UV_TOKEN_PERMS:
        return handle_get_pin_token(&r, rest, resp, resp_max, 1);
    default:
        resp[0] = CTAP1_ERR_INVALID_PARAMETER;
        return 1;
    }
}
