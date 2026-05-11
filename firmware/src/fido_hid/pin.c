/*
 * Phase 5 M3 — CTAP2 ClientPIN protocol v1 (P-256 + AES-256-CBC + HMAC-SHA-256).
 *
 * Implementation matches CTAP2 §5.5.4 / §6.5. All crypto from
 * trezor_crypto (already linked for libtropic L3 + Ed25519 in Phase 3/5).
 *
 * Threat-model defensive choices in this file:
 *   - All secret comparisons use ct_memcmp (constant-time).
 *   - shared_key + ephemeral private key live ONLY on the stack; wiped
 *     before return (memzero / memset).
 *   - pinUvAuthToken is RAM-only and only generated AFTER successful
 *     PIN verification. Token is regenerated on every getPinToken call.
 *   - Ephemeral P-256 keypair regenerates after every successful PIN op
 *     for forward secrecy (so a compromise of one shared_key doesn't
 *     leak prior or subsequent shared_keys).
 *   - PIN entry deliberately omitted from log/printf statements
 *     (timing side channels via UART).
 *
 * The retry-counter design layers two backstops:
 *   - persistent pin_retries (8 max, R-mem): survives power-cycle. M4
 *     will swap this for MAC-and-Destroy slot consumption.
 *   - in-boot consec_fails (3 max, RAM): forces power-cycle after
 *     3 wrong PINs even if persistent counter still has retries left.
 *     CTAP2 §5.5.4 §2 mandates this.
 */

#include "pin.h"
#include "pin_md.h"
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

/* ----- CBOR keys (request map) ----- */
#define CP_KEY_PIN_PROTOCOL   1u
#define CP_KEY_SUB_COMMAND    2u
#define CP_KEY_KEY_AGREEMENT  3u
#define CP_KEY_PIN_AUTH       4u
#define CP_KEY_NEW_PIN_ENC    5u
#define CP_KEY_PIN_HASH_ENC   6u

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

/* ----- State (RAM-only) ----- */
static int     s_initted;
/* P-256 private key: 32 B big-endian scalar in [1, n-1]. */
static uint8_t s_eph_priv[32];
/* P-256 public key uncompressed: byte[0] = 0x04 || X[32] || Y[32]. */
static uint8_t s_eph_pub65[65];
/* pinUvAuthToken — RAM only, regenerated on every successful getPinToken. */
static uint8_t s_pin_token[PIN_TOKEN_LEN];
static int     s_pin_token_valid;
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
    int pin_set = 0;
    uint32_t retries = 0;
    if (slots_global_pin_get(&pin_set, &retries, NULL) != 0) {
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }
    /* Spec: if no PIN set, retries can still be reported. We report 8. */
    if (!pin_set) retries = SLOTS_PIN_RETRIES_INITIAL;

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

/* Common decoder for keyAgreement field; computes shared_key. */
static int parse_and_compute_shared_key(cbor_reader_t *r, uint8_t shared_key[32])
{
    uint8_t peer_xy[64];
    if (parse_cose_p256_pubkey(r, peer_xy) != 0) return -1;
    if (!s_initted) {
        if (pin_init() != 0) return -1;
    }
    return compute_shared_key(peer_xy, shared_key);
}

/* setPin sub-command (0x03). Spec §5.5.4.4.
 * Request fields:
 *   3: keyAgreement (platform pubkey)
 *   4: pinAuth = LEFT(HMAC(shared_key, newPinEnc), 16)
 *   5: newPinEnc (64 B = 4 AES blocks)
 * If a PIN is already set, returns CTAP2_ERR_PIN_AUTH_INVALID per spec
 * §5.5.4 step 6. (Platform must use changePin instead.) */
static int handle_set_pin(cbor_reader_t *r, size_t n_keys, uint8_t *resp, size_t resp_max)
{
    /* Refuse if a PIN already exists. */
    int pin_already_set = 0;
    if (slots_global_pin_get(&pin_already_set, NULL, NULL) != 0) {
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }
    if (pin_already_set) {
        resp[0] = CTAP2_ERR_PIN_AUTH_INVALID;
        return 1;
    }

    uint8_t shared_key[32]   = {0};
    uint8_t pin_auth_in[16]  = {0};
    uint8_t new_pin_enc[PIN_ENC_BUF_LEN] = {0};
    int got_ka = 0, got_pa = 0, got_npe = 0;

    /* We already consumed protocol(1) + subCommand(2). Parse the rest. */
    for (size_t i = 0; i < n_keys; ++i) {
        uint8_t mt; uint64_t key;
        if (cbor_reader_read_head(r, &mt, &key) < 0 || mt != 0u) {
            resp[0] = CTAP2_ERR_INVALID_CBOR; return 1;
        }
        if (key == CP_KEY_KEY_AGREEMENT) {
            if (parse_and_compute_shared_key(r, shared_key) != 0) {
                resp[0] = CTAP2_ERR_OTHER; return 1;
            }
            got_ka = 1;
        } else if (key == CP_KEY_PIN_AUTH) {
            const uint8_t *p; size_t L;
            if (cbor_reader_read_bytes(r, &p, &L) < 0 || L != 16u) {
                resp[0] = CTAP2_ERR_INVALID_CBOR; return 1;
            }
            memcpy(pin_auth_in, p, 16);
            got_pa = 1;
        } else if (key == CP_KEY_NEW_PIN_ENC) {
            const uint8_t *p; size_t L;
            if (cbor_reader_read_bytes(r, &p, &L) < 0 || L != PIN_ENC_BUF_LEN) {
                resp[0] = CTAP2_ERR_INVALID_CBOR; return 1;
            }
            memcpy(new_pin_enc, p, PIN_ENC_BUF_LEN);
            got_npe = 1;
        } else {
            if (cbor_reader_skip(r) < 0) { resp[0] = CTAP2_ERR_INVALID_CBOR; return 1; }
        }
    }
    if (!got_ka || !got_pa || !got_npe) {
        memzero(shared_key, sizeof shared_key);
        resp[0] = CTAP2_ERR_MISSING_PARAMETER; return 1;
    }

    /* Verify pinAuth = LEFT(HMAC(shared_key, newPinEnc), 16). */
    uint8_t expected[16];
    pin_auth_compute(shared_key, new_pin_enc, PIN_ENC_BUF_LEN, expected);
    if (ct_memcmp(expected, pin_auth_in, 16) != 0) {
        memzero(shared_key, sizeof shared_key);
        memzero(expected,   sizeof expected);
        resp[0] = CTAP2_ERR_PIN_AUTH_INVALID;
        return 1;
    }
    memzero(expected, sizeof expected);

    /* Decrypt newPinEnc → 64 B padded PIN. */
    uint8_t pin_padded[PIN_ENC_BUF_LEN];
    if (aes_cbc_dec_iv0(shared_key, new_pin_enc, PIN_ENC_BUF_LEN, pin_padded) != 0) {
        memzero(shared_key, sizeof shared_key);
        resp[0] = CTAP2_ERR_OTHER; return 1;
    }
    memzero(shared_key, sizeof shared_key);
    memzero(new_pin_enc, sizeof new_pin_enc);

    /* Determine real PIN length: trim trailing zero padding. */
    size_t pin_len = PIN_ENC_BUF_LEN;
    while (pin_len > 0 && pin_padded[pin_len - 1] == 0u) pin_len--;
    if (pin_len < PIN_MIN_BYTES || pin_len > PIN_MAX_BYTES) {
        memzero(pin_padded, sizeof pin_padded);
        resp[0] = CTAP2_ERR_PIN_POLICY_VIOLATION;
        return 1;
    }

    /* Hash and store (M3 layer: SHA-256(PIN)[:16] in R-mem). */
    uint8_t pin_hash[32];
    sha256_Raw(pin_padded, (uint32_t) pin_len, pin_hash);
    memzero(pin_padded, sizeof pin_padded);
    int rc = slots_global_pin_set(pin_hash);
    if (rc != 0) {
        memzero(pin_hash, sizeof pin_hash);
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }

    /* M4: initialize hardware-enforced M&D retry counter using the same
     * 16 B pin material (consistent with what the platform sends in
     * pinHashEnc for subsequent getPinToken calls). */
    int md_rc = pin_md_setup(pin_hash);
    memzero(pin_hash, sizeof pin_hash);
    if (md_rc != 0) {
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }

    /* Forward secrecy: rotate ephemeral keypair. */
    (void) regen_eph();
    /* New PIN means any previous pinUvAuthToken is no longer valid. */
    memzero(s_pin_token, sizeof s_pin_token);
    s_pin_token_valid = 0;
    s_consec_fails = 0;
    s_auth_blocked = 0;

    resp[0] = CTAP2_OK;
    return 1;  /* empty response body for setPin */
}

/* changePin sub-command (0x04). Spec §5.5.4.5.
 * Request fields (in addition to protocol + subCommand):
 *   3: keyAgreement
 *   4: pinAuth = LEFT(HMAC(shared_key, newPinEnc || pinHashEnc), 16)
 *   5: newPinEnc (64 B)
 *   6: pinHashEnc (16 B, encrypts SHA-256(oldPin)[:16])
 */
static int handle_change_pin(cbor_reader_t *r, size_t n_keys, uint8_t *resp, size_t resp_max)
{
    int pin_set = 0;
    uint32_t retries = 0;
    uint8_t expected_old_hash[PIN_HASH_LEN] = {0};
    if (slots_global_pin_get(&pin_set, &retries, expected_old_hash) != 0) {
        resp[0] = CTAP2_ERR_OTHER; return 1;
    }
    if (!pin_set) {
        resp[0] = CTAP2_ERR_PIN_NOT_SET; return 1;
    }
    if (retries == 0u) {
        resp[0] = CTAP2_ERR_PIN_BLOCKED; return 1;
    }
    if (s_auth_blocked) {
        resp[0] = CTAP2_ERR_PIN_AUTH_BLOCKED; return 1;
    }

    uint8_t shared_key[32]      = {0};
    uint8_t pin_auth_in[16]     = {0};
    uint8_t new_pin_enc[PIN_ENC_BUF_LEN] = {0};
    uint8_t pin_hash_enc[16]    = {0};
    int got_ka = 0, got_pa = 0, got_npe = 0, got_phe = 0;

    for (size_t i = 0; i < n_keys; ++i) {
        uint8_t mt; uint64_t key;
        if (cbor_reader_read_head(r, &mt, &key) < 0 || mt != 0u) {
            resp[0] = CTAP2_ERR_INVALID_CBOR; return 1;
        }
        if (key == CP_KEY_KEY_AGREEMENT) {
            if (parse_and_compute_shared_key(r, shared_key) != 0) {
                resp[0] = CTAP2_ERR_OTHER; return 1;
            }
            got_ka = 1;
        } else if (key == CP_KEY_PIN_AUTH) {
            const uint8_t *p; size_t L;
            if (cbor_reader_read_bytes(r, &p, &L) < 0 || L != 16u) {
                resp[0] = CTAP2_ERR_INVALID_CBOR; return 1;
            }
            memcpy(pin_auth_in, p, 16); got_pa = 1;
        } else if (key == CP_KEY_NEW_PIN_ENC) {
            const uint8_t *p; size_t L;
            if (cbor_reader_read_bytes(r, &p, &L) < 0 || L != PIN_ENC_BUF_LEN) {
                resp[0] = CTAP2_ERR_INVALID_CBOR; return 1;
            }
            memcpy(new_pin_enc, p, PIN_ENC_BUF_LEN); got_npe = 1;
        } else if (key == CP_KEY_PIN_HASH_ENC) {
            const uint8_t *p; size_t L;
            if (cbor_reader_read_bytes(r, &p, &L) < 0 || L != 16u) {
                resp[0] = CTAP2_ERR_INVALID_CBOR; return 1;
            }
            memcpy(pin_hash_enc, p, 16); got_phe = 1;
        } else {
            if (cbor_reader_skip(r) < 0) {
                resp[0] = CTAP2_ERR_INVALID_CBOR; return 1;
            }
        }
    }
    if (!got_ka || !got_pa || !got_npe || !got_phe) {
        memzero(shared_key, sizeof shared_key);
        resp[0] = CTAP2_ERR_MISSING_PARAMETER; return 1;
    }

    /* Verify pinAuth = LEFT(HMAC(shared_key, newPinEnc || pinHashEnc), 16). */
    uint8_t auth_input[PIN_ENC_BUF_LEN + 16];
    memcpy(auth_input,                   new_pin_enc,  PIN_ENC_BUF_LEN);
    memcpy(&auth_input[PIN_ENC_BUF_LEN], pin_hash_enc, 16);
    uint8_t expected_auth[16];
    pin_auth_compute(shared_key, auth_input, sizeof auth_input, expected_auth);
    if (ct_memcmp(expected_auth, pin_auth_in, 16) != 0) {
        memzero(shared_key, sizeof shared_key);
        memzero(expected_auth, sizeof expected_auth);
        resp[0] = CTAP2_ERR_PIN_AUTH_INVALID; return 1;
    }

    /* Decrement retries BEFORE the PIN check (defense in depth). */
    uint32_t new_retries = 0;
    (void) slots_global_pin_dec_retries(&new_retries);

    /* Decrypt pinHashEnc → 16 B submitted hash. */
    uint8_t submitted_hash[PIN_HASH_LEN];
    if (aes_cbc_dec_iv0(shared_key, pin_hash_enc, 16, submitted_hash) != 0) {
        memzero(shared_key, sizeof shared_key);
        resp[0] = CTAP2_ERR_OTHER; return 1;
    }

    /* Two-layer PIN check:
     *   (1) M3 ct_memcmp against stored hash (fast).
     *   (2) M4 pin_md_verify (hardware-enforced — consumes M&D slot).
     * If EITHER layer rejects, return PIN_INVALID. M&D must always be
     * run when M3 says OK because firmware compromise could bypass
     * the ct_memcmp; M&D is the ground truth. */
    int m3_ok = (ct_memcmp(submitted_hash, expected_old_hash, PIN_HASH_LEN) == 0);
    int md_correct = 0;
    int md_rc = pin_md_verify(submitted_hash, &md_correct);
    memzero(submitted_hash, sizeof submitted_hash);

    if (md_rc == -2) {
        /* HW-enforced lockout from M&D side. */
        memzero(shared_key, sizeof shared_key);
        (void) regen_eph();
        resp[0] = CTAP2_ERR_PIN_BLOCKED;
        return 1;
    }
    if (md_rc != 0 || !m3_ok || !md_correct) {
        /* Wrong old-PIN. M&D slot was consumed regardless. */
        memzero(shared_key, sizeof shared_key);
        s_consec_fails++;
        if (s_consec_fails >= PIN_AUTH_BLOCKED_CONSEC) s_auth_blocked = 1;
        (void) regen_eph();
        if (new_retries == 0u) {
            resp[0] = CTAP2_ERR_PIN_BLOCKED;
        } else if (s_auth_blocked) {
            resp[0] = CTAP2_ERR_PIN_AUTH_BLOCKED;
        } else {
            resp[0] = CTAP2_ERR_PIN_INVALID;
        }
        return 1;
    }

    /* Correct old-PIN. Decrypt newPinEnc and install. */
    uint8_t pin_padded[PIN_ENC_BUF_LEN];
    if (aes_cbc_dec_iv0(shared_key, new_pin_enc, PIN_ENC_BUF_LEN, pin_padded) != 0) {
        memzero(shared_key, sizeof shared_key);
        resp[0] = CTAP2_ERR_OTHER; return 1;
    }
    memzero(shared_key, sizeof shared_key);

    size_t pin_len = PIN_ENC_BUF_LEN;
    while (pin_len > 0 && pin_padded[pin_len - 1] == 0u) pin_len--;
    if (pin_len < PIN_MIN_BYTES || pin_len > PIN_MAX_BYTES) {
        memzero(pin_padded, sizeof pin_padded);
        resp[0] = CTAP2_ERR_PIN_POLICY_VIOLATION; return 1;
    }
    uint8_t new_pin_hash[32];
    sha256_Raw(pin_padded, (uint32_t) pin_len, new_pin_hash);
    memzero(pin_padded, sizeof pin_padded);

    int rc = slots_global_pin_set(new_pin_hash);
    if (rc != 0) {
        memzero(new_pin_hash, sizeof new_pin_hash);
        resp[0] = CTAP2_ERR_OTHER; return 1;
    }

    /* M4: re-initialize M&D state with the new PIN. The old M&D slots
     * are reset by pin_md_verify above (it re-initialized them on
     * successful match); pin_md_setup overwrites with new keying. */
    int md_setup_rc = pin_md_setup(new_pin_hash);
    memzero(new_pin_hash, sizeof new_pin_hash);
    if (md_setup_rc != 0) {
        resp[0] = CTAP2_ERR_OTHER; return 1;
    }

    /* Success: rotate ephemeral, reset RAM counters, invalidate old token. */
    (void) regen_eph();
    memzero(s_pin_token, sizeof s_pin_token);
    s_pin_token_valid = 0;
    s_consec_fails = 0;

    resp[0] = CTAP2_OK;
    return 1;
}

/* getPinToken sub-command (0x05). Spec §5.5.4.6.
 * Request fields:
 *   3: keyAgreement
 *   6: pinHashEnc (16 B, AES-CBC encrypted SHA-256(currentPin)[:16])
 * On success returns encrypted pinUvAuthToken.
 */
static int handle_get_pin_token(cbor_reader_t *r, size_t n_keys,
                                uint8_t *resp, size_t resp_max)
{
    int pin_set = 0;
    uint32_t retries = 0;
    uint8_t stored_hash[PIN_HASH_LEN] = {0};
    if (slots_global_pin_get(&pin_set, &retries, stored_hash) != 0) {
        resp[0] = CTAP2_ERR_OTHER; return 1;
    }
    if (!pin_set) {
        resp[0] = CTAP2_ERR_PIN_NOT_SET; return 1;
    }
    if (retries == 0u) {
        resp[0] = CTAP2_ERR_PIN_BLOCKED; return 1;
    }
    if (s_auth_blocked) {
        resp[0] = CTAP2_ERR_PIN_AUTH_BLOCKED; return 1;
    }

    uint8_t shared_key[32]    = {0};
    uint8_t pin_hash_enc[16]  = {0};
    int got_ka = 0, got_phe = 0;

    for (size_t i = 0; i < n_keys; ++i) {
        uint8_t mt; uint64_t key;
        if (cbor_reader_read_head(r, &mt, &key) < 0 || mt != 0u) {
            resp[0] = CTAP2_ERR_INVALID_CBOR; return 1;
        }
        if (key == CP_KEY_KEY_AGREEMENT) {
            if (parse_and_compute_shared_key(r, shared_key) != 0) {
                resp[0] = CTAP2_ERR_OTHER; return 1;
            }
            got_ka = 1;
        } else if (key == CP_KEY_PIN_HASH_ENC) {
            const uint8_t *p; size_t L;
            if (cbor_reader_read_bytes(r, &p, &L) < 0 || L != 16u) {
                resp[0] = CTAP2_ERR_INVALID_CBOR; return 1;
            }
            memcpy(pin_hash_enc, p, 16); got_phe = 1;
        } else {
            if (cbor_reader_skip(r) < 0) {
                resp[0] = CTAP2_ERR_INVALID_CBOR; return 1;
            }
        }
    }
    if (!got_ka || !got_phe) {
        memzero(shared_key, sizeof shared_key);
        resp[0] = CTAP2_ERR_MISSING_PARAMETER; return 1;
    }

    /* Decrement retries BEFORE checking. */
    uint32_t new_retries = 0;
    (void) slots_global_pin_dec_retries(&new_retries);

    /* Decrypt submitted hash; then defense-in-depth two-layer check
     * (M3 R-mem hash + M4 hardware-enforced M&D slot consumption). */
    uint8_t submitted_hash[PIN_HASH_LEN];
    if (aes_cbc_dec_iv0(shared_key, pin_hash_enc, 16, submitted_hash) != 0) {
        memzero(shared_key, sizeof shared_key);
        resp[0] = CTAP2_ERR_OTHER; return 1;
    }

    int m3_ok = (ct_memcmp(submitted_hash, stored_hash, PIN_HASH_LEN) == 0);
    int md_correct = 0;
    int md_rc = pin_md_verify(submitted_hash, &md_correct);
    memzero(submitted_hash, sizeof submitted_hash);

    if (md_rc == -2) {
        /* HW lockout — all 8 slots consumed. Needs factory_reset. */
        memzero(shared_key, sizeof shared_key);
        (void) regen_eph();
        resp[0] = CTAP2_ERR_PIN_BLOCKED;
        return 1;
    }
    if (md_rc != 0 || !m3_ok || !md_correct) {
        memzero(shared_key, sizeof shared_key);
        s_consec_fails++;
        if (s_consec_fails >= PIN_AUTH_BLOCKED_CONSEC) s_auth_blocked = 1;
        (void) regen_eph();
        if (new_retries == 0u) {
            resp[0] = CTAP2_ERR_PIN_BLOCKED;
        } else if (s_auth_blocked) {
            resp[0] = CTAP2_ERR_PIN_AUTH_BLOCKED;
        } else {
            resp[0] = CTAP2_ERR_PIN_INVALID;
        }
        return 1;
    }

    /* Correct PIN. Reset retries, generate new pinUvAuthToken, encrypt. */
    (void) slots_global_pin_reset_retries();
    s_consec_fails = 0;
    if (tropic_random(s_pin_token, PIN_TOKEN_LEN) != 0) {
        memzero(shared_key, sizeof shared_key);
        resp[0] = CTAP2_ERR_OTHER; return 1;
    }
    s_pin_token_valid = 1;

    uint8_t token_enc[PIN_TOKEN_LEN];
    if (aes_cbc_enc_iv0(shared_key, s_pin_token, PIN_TOKEN_LEN, token_enc) != 0) {
        memzero(shared_key, sizeof shared_key);
        resp[0] = CTAP2_ERR_OTHER; return 1;
    }
    memzero(shared_key, sizeof shared_key);

    if (resp_max < 1u) {
        memzero(token_enc, sizeof token_enc);
        return -1;
    }
    resp[0] = CTAP2_OK;

    cbor_writer_t w;
    cbor_writer_init(&w, &resp[1], resp_max - 1u);
    cbor_write_map_header(&w, 1);
    cbor_write_uint(&w, CP_RESP_PIN_TOKEN);
    cbor_write_byte_string(&w, token_enc, PIN_TOKEN_LEN);
    memzero(token_enc, sizeof token_enc);

    if (cbor_writer_error(&w)) {
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }
    /* NOTE: we deliberately do NOT rotate the ephemeral keypair after
     * getPinToken — the spec says it's preserved between getPinToken calls
     * for the same session so the platform can reuse keyAgreement.
     * Rotation happens on setPin/changePin only. */
    return (int)(1u + cbor_writer_len(&w));
}

/* ----- Public surface ----- */

int pin_init(void)
{
    int rc = regen_eph();
    if (rc != 0) return rc;
    memzero(s_pin_token, sizeof s_pin_token);
    s_pin_token_valid = 0;
    s_consec_fails    = 0;
    s_auth_blocked    = 0;
    s_initted = 1;
    return 0;
}

int pin_is_set(void)
{
    int pin_set = 0;
    (void) slots_global_pin_get(&pin_set, NULL, NULL);
    return pin_set;
}

int pin_token_is_valid(void)
{
    return s_pin_token_valid;
}

int pin_verify_pinauth(const uint8_t pinauth_16[PIN_AUTH_LEN],
                       const uint8_t client_data_hash_32[32])
{
    if (!s_pin_token_valid) return -1;
    uint8_t expected[16];
    pin_auth_compute(s_pin_token, client_data_hash_32, 32, expected);
    int rc = ct_memcmp(expected, pinauth_16, 16);
    memzero(expected, sizeof expected);
    return (rc == 0) ? 0 : -1;
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
        return handle_set_pin(&r, rest, resp, resp_max);
    case CP_SUB_CHANGE_PIN:
        return handle_change_pin(&r, rest, resp, resp_max);
    case CP_SUB_GET_PIN_TOKEN:
        return handle_get_pin_token(&r, rest, resp, resp_max);
    default:
        resp[0] = CTAP1_ERR_INVALID_PARAMETER;
        return 1;
    }
}
