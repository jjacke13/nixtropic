/*
 * Crypto stubs for libtropic — Phase 1 ONLY.
 *
 * libtropic's L3 secure-session implementation (libtropic_l3.c, lt_hkdf.c,
 * lt_l3_process.c) calls into a "crypto provider" via the headers
 * lt_aesgcm.h / lt_x25519.h / lt_sha256.h / lt_hmac_sha256.h /
 * lt_crypto_common.h. Real implementations are provided by an external
 * crypto library (mbedtls in the F439ZI example, trezor_crypto in
 * libtropic's vendor/ tree) that the application chooses.
 *
 * Phase 1 is L2-only (no L3 secure session — verified via P1.11), so we
 * never actually call any L3 path. But:
 *   - lt_init() calls lt_crypto_ctx_init() unconditionally
 *   - The L3 .c files reference the other crypto symbols
 *
 * Approach for Phase 1:
 *   - We DO NOT compile libtropic_l3.c, lt_l3_process.c, lt_hkdf.c
 *     (the L3-specific files). Their L3-only call sites simply don't
 *     exist in our binary.
 *   - We provide stubs for lt_crypto_ctx_init/deinit so lt_init succeeds.
 *   - We provide stubs for the other crypto fns so any inline calls
 *     from libtropic.c (e.g. inside lt_random_value_get, lt_session_start,
 *     etc.) link successfully. These functions ARE compiled into our
 *     binary but UNREACHABLE — `--gc-sections` strips them at link time
 *     unless we accidentally call them.
 *
 * Phase 5 will replace these stubs with a real crypto provider
 * (probably libtropic/vendor/trezor_crypto or mbedtls v4) when L3
 * secure session is needed for FIDO2 ClientPIN etc.
 *
 * SAFETY: Each stub returns LT_FAIL except lt_crypto_ctx_init/deinit.
 * If anything ever tries to actually use crypto via these stubs, the
 * caller will get LT_FAIL and bail out — no silent wrong behavior.
 */

#include <stddef.h>
#include <stdint.h>

#include "libtropic_common.h"

/* ---- Crypto context ---- */

lt_ret_t lt_crypto_ctx_init(void *ctx)
{
    /* Per the contract: "must not allocate anything, just initialize the
     * context structure to defined values." crypto_ctx is void* so we
     * have no struct to initialize. Returning LT_OK lets lt_init proceed. */
    (void) ctx;
    return LT_OK;
}

lt_ret_t lt_crypto_ctx_deinit(void *ctx)
{
    (void) ctx;
    return LT_OK;
}

/* ---- AES-GCM (unused in Phase 1) ---- */

lt_ret_t lt_aesgcm_encrypt_init(void *ctx, const uint8_t *key, const uint32_t key_len)
{
    (void) ctx; (void) key; (void) key_len;
    return LT_FAIL;
}

lt_ret_t lt_aesgcm_decrypt_init(void *ctx, const uint8_t *key, const uint32_t key_len)
{
    (void) ctx; (void) key; (void) key_len;
    return LT_FAIL;
}

lt_ret_t lt_aesgcm_encrypt(void *ctx, const uint8_t *iv, const uint32_t iv_len,
                           const uint8_t *add, const uint32_t add_len,
                           const uint8_t *plaintext, const uint32_t plaintext_len,
                           uint8_t *ciphertext, const uint32_t ciphertext_len)
{
    (void) ctx; (void) iv; (void) iv_len; (void) add; (void) add_len;
    (void) plaintext; (void) plaintext_len; (void) ciphertext; (void) ciphertext_len;
    return LT_FAIL;
}

lt_ret_t lt_aesgcm_decrypt(void *ctx, const uint8_t *iv, const uint32_t iv_len,
                           const uint8_t *add, const uint32_t add_len,
                           const uint8_t *ciphertext, const uint32_t ciphertext_len,
                           uint8_t *plaintext, const uint32_t plaintext_len)
{
    (void) ctx; (void) iv; (void) iv_len; (void) add; (void) add_len;
    (void) ciphertext; (void) ciphertext_len; (void) plaintext; (void) plaintext_len;
    return LT_FAIL;
}

lt_ret_t lt_aesgcm_encrypt_deinit(void *ctx) { (void) ctx; return LT_OK; }
lt_ret_t lt_aesgcm_decrypt_deinit(void *ctx) { (void) ctx; return LT_OK; }

/* ---- X25519 (unused in Phase 1) ---- */

lt_ret_t lt_X25519(const uint8_t *privkey, const uint8_t *pubkey, uint8_t *secret)
{
    (void) privkey; (void) pubkey; (void) secret;
    return LT_FAIL;
}

lt_ret_t lt_X25519_scalarmult(const uint8_t *sk, uint8_t *pk)
{
    (void) sk; (void) pk;
    return LT_FAIL;
}

/* ---- SHA-256 (unused in Phase 1) ---- */

lt_ret_t lt_sha256_init(void *ctx)   { (void) ctx; return LT_FAIL; }
lt_ret_t lt_sha256_start(void *ctx)  { (void) ctx; return LT_FAIL; }
lt_ret_t lt_sha256_update(void *ctx, const uint8_t *input, const size_t input_len)
{ (void) ctx; (void) input; (void) input_len; return LT_FAIL; }
lt_ret_t lt_sha256_finish(void *ctx, uint8_t *output)
{ (void) ctx; (void) output; return LT_FAIL; }
lt_ret_t lt_sha256_deinit(void *ctx) { (void) ctx; return LT_OK; }

/* ---- HMAC-SHA256 (unused in Phase 1) ---- */

lt_ret_t lt_hmac_sha256(const uint8_t *key, const uint32_t key_len,
                        const uint8_t *input, const uint32_t input_len, uint8_t *output)
{
    (void) key; (void) key_len; (void) input; (void) input_len; (void) output;
    return LT_FAIL;
}
