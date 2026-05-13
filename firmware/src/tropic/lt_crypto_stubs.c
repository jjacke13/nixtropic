/*
 * VESTIGIAL — Phase 1 placeholder, NOT compiled in the current build.
 *
 * Excluded from firmware/CMakeLists.txt: trezor_crypto's CAL provides
 * the real libtropic crypto callbacks (AES-GCM, X25519, SHA-256,
 * HMAC-SHA-256) since Phase 3 M4 — see firmware/CMakeLists.txt §
 * "trezor_crypto CAL".
 *
 * Kept in-tree as a historical reference for anyone reading Phase 1
 * commits (e.g. `git log -- firmware/src/tropic/lt_crypto_stubs.c`).
 * Slated for deletion in Phase 8 cleanup.
 *
 * Original purpose (Phase 1): libtropic's `lt_init` calls into a
 * crypto-provider context-init function unconditionally; we needed
 * something to satisfy the linker before trezor_crypto landed.  Each
 * stub returned LT_FAIL so any accidental L3 use would fail loudly.
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
