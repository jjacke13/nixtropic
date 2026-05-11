/*
 * Phase 5 M4 — MAC-and-Destroy PIN scheme implementation.
 *
 * Reference: libtropic/examples/model/mac_and_destroy/main.c (Tropic
 * Square canonical example). Adapted for our use:
 *   - SLOTS_MD_ROUNDS = 8 (CTAP2 retry limit, matches PIN_RETRIES_DEFAULT)
 *   - master_secret kept on-stack briefly; not stored, not exposed
 *   - additional_data unused (empty A in the algorithm — PIN only)
 *   - XOR for c_i = s ⊕ k_i (information-theoretically secure given
 *     unique 32 B HMAC-derived k_i per slot)
 *
 * Threat-model notes:
 *   - All intermediate keys (u, v, w, k_i, s) zeroed on exit (memzero).
 *   - master_secret never leaves the stack and is wiped before return.
 *   - The recovered s' on a verify is treated as opaque — we only check
 *     the tag, never use s' for anything else.
 *   - On wrong-PIN attempt, the slot is destroyed regardless of any
 *     firmware behavior — chip-enforced.
 */

#include "pin_md.h"
#include "slots.h"

#include "tropic/tropic.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "sha2.h"
#include "hmac.h"
#include "memzero.h"

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

/* XOR 32 bytes: out = a ⊕ b. */
static void xor32(const uint8_t *a, const uint8_t *b, uint8_t *out)
{
    for (size_t i = 0; i < 32u; ++i) {
        out[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

/* HMAC-SHA256 wrapper. Output is always 32 bytes. */
static void hmac_sha256_compute(const uint8_t *key, size_t key_len,
                                const uint8_t *msg, size_t msg_len,
                                uint8_t out[32])
{
    hmac_sha256(key, (uint32_t) key_len, msg, (uint32_t) msg_len, out);
}

/* ----- Public API ----- */

int pin_md_is_active(void)
{
    int active = 0;
    if (slots_global_md_get(&active, NULL, NULL, NULL) != 0) {
        return 0;
    }
    return active;
}

int pin_md_attempts_remaining(void)
{
    int active = 0;
    uint8_t next_slot = 0;
    if (slots_global_md_get(&active, &next_slot, NULL, NULL) != 0) {
        return 0;
    }
    if (!active) return (int) SLOTS_MD_ROUNDS;  /* no PIN set yet */
    if (next_slot >= SLOTS_MD_ROUNDS) return 0;
    return (int)(SLOTS_MD_ROUNDS - next_slot);
}

/* ===== setPin ===== */

int pin_md_setup(const uint8_t pin_material[PIN_MD_MATERIAL_LEN])
{
    if (!pin_material) return -1;

    /* Buffers for the scheme. Wiped before return. */
    uint8_t master_secret[PIN_MD_MASTER_SECRET_LEN] = {0};
    uint8_t tag[SLOTS_MD_TAG_LEN] = {0};            /* t = HMAC(s, [0x00]) */
    uint8_t u[32]   = {0};                           /* u = HMAC(s, [0x01]) */
    uint8_t v[32]   = {0};                           /* v = HMAC(0, PIN) */
    uint8_t w_i[32] = {0};                           /* per-slot M&D output */
    uint8_t k_i[32] = {0};                           /* per-slot encryption key */
    uint8_t ci_all[SLOTS_MD_CI_LEN] = {0};           /* all ciphertexts */
    uint8_t ignore[32];
    static const uint8_t zeros32[32] = {0};
    static const uint8_t kdf_input_00[1] = {0x00};
    static const uint8_t kdf_input_01[1] = {0x01};

    int rc = -2;

    /* Generate master_secret from TROPIC01 TRNG. */
    if (tropic_random(master_secret, PIN_MD_MASTER_SECRET_LEN) != 0) {
        goto cleanup;
    }

    /* t = HMAC(s, 0x00) */
    hmac_sha256_compute(master_secret, PIN_MD_MASTER_SECRET_LEN,
                        kdf_input_00, 1, tag);
    /* u = HMAC(s, 0x01) */
    hmac_sha256_compute(master_secret, PIN_MD_MASTER_SECRET_LEN,
                        kdf_input_01, 1, u);
    /* v = HMAC(0, pin_material) */
    hmac_sha256_compute(zeros32, 32, pin_material, PIN_MD_MATERIAL_LEN, v);

    /* Per-slot init+consume+reinit + ciphertext derivation. */
    for (uint8_t i = 0; i < SLOTS_MD_ROUNDS; ++i) {
        /* Step 1: init slot i with u — produces an internal slot key. */
        if (tropic_mac_and_destroy(i, u, ignore) != 0) {
            goto cleanup;
        }
        /* Step 2: consume slot i with v — returns w_i, slot destroyed. */
        if (tropic_mac_and_destroy(i, v, w_i) != 0) {
            goto cleanup;
        }
        /* Step 3: re-init slot i with u — ready for future verify. */
        if (tropic_mac_and_destroy(i, u, ignore) != 0) {
            goto cleanup;
        }
        /* k_i = HMAC(w_i, pin_material) */
        hmac_sha256_compute(w_i, 32, pin_material, PIN_MD_MATERIAL_LEN, k_i);
        /* c_i = master_secret XOR k_i (one-time pad property). */
        xor32(master_secret, k_i, &ci_all[i * SLOTS_MD_SLOT_SIZE]);
    }

    /* Persist {active=1, next_slot=0, tag, ci[]} to R-mem slot 0. */
    if (slots_global_md_set(1, 0, tag, ci_all) != 0) {
        goto cleanup;
    }
    rc = 0;

cleanup:
    memzero(master_secret, sizeof master_secret);
    memzero(tag,           sizeof tag);
    memzero(u,             sizeof u);
    memzero(v,             sizeof v);
    memzero(w_i,           sizeof w_i);
    memzero(k_i,           sizeof k_i);
    memzero(ci_all,        sizeof ci_all);
    /* `ignore` is non-secret (we wrote junk to it) but wipe anyway. */
    memzero(ignore,        sizeof ignore);
    return rc;
}

/* ===== verify PIN ===== */

int pin_md_verify(const uint8_t pin_material[PIN_MD_MATERIAL_LEN],
                  int *out_correct)
{
    if (!pin_material || !out_correct) return -1;
    *out_correct = 0;

    int active = 0;
    uint8_t next_slot = 0;
    uint8_t stored_tag[SLOTS_MD_TAG_LEN] = {0};
    uint8_t stored_ci[SLOTS_MD_CI_LEN] = {0};

    if (slots_global_md_get(&active, &next_slot, stored_tag, stored_ci) != 0) {
        return -1;
    }
    if (!active) {
        /* PIN not set at the M&D layer. Caller should not have called us. */
        return -1;
    }
    if (next_slot >= SLOTS_MD_ROUNDS) {
        /* All slots consumed. HW-enforced lockout. */
        return -2;
    }

    /* Commit attempt BEFORE crypto (power-loss safe — if we crash mid-
     * M&D, the slot is already counted as consumed). */
    uint8_t slot_idx = next_slot;
    if (slots_global_md_advance(NULL) != 0) {
        return -1;
    }

    uint8_t v[32]   = {0};
    uint8_t w_i[32] = {0};
    uint8_t k_i[32] = {0};
    uint8_t s_prime[PIN_MD_MASTER_SECRET_LEN] = {0};
    uint8_t t_prime[SLOTS_MD_TAG_LEN] = {0};
    static const uint8_t zeros32[32] = {0};
    static const uint8_t kdf_input_00[1] = {0x00};
    static const uint8_t kdf_input_01[1] = {0x01};

    int rc = -1;

    /* v' = HMAC(0, pin_material') */
    hmac_sha256_compute(zeros32, 32, pin_material, PIN_MD_MATERIAL_LEN, v);

    /* w_i' = M&D(slot_idx, v') — consumes slot. */
    if (tropic_mac_and_destroy(slot_idx, v, w_i) != 0) {
        goto cleanup;
    }

    /* k_i' = HMAC(w_i', pin_material') */
    hmac_sha256_compute(w_i, 32, pin_material, PIN_MD_MATERIAL_LEN, k_i);

    /* s' = c_i XOR k_i' */
    xor32(&stored_ci[slot_idx * SLOTS_MD_SLOT_SIZE], k_i, s_prime);

    /* t' = HMAC(s', 0x00) */
    hmac_sha256_compute(s_prime, PIN_MD_MASTER_SECRET_LEN,
                        kdf_input_00, 1, t_prime);

    if (ct_memcmp(t_prime, stored_tag, SLOTS_MD_TAG_LEN) == 0) {
        /* PIN correct. Re-initialize ALL 8 slots with new_u so that
         * slots consumed by prior wrong-PIN attempts (state K = f(v_wrong))
         * AND the one just consumed by this verify (K = f(v_correct))
         * are all restored to K = f(u_setup). Since s_recovered ==
         * s_original on a correct verify, new_u == u_setup. Re-initing
         * slots that were already in K = f(u_setup) state is idempotent
         * (one extra M&D call, same K). */
        uint8_t new_u[32] = {0};
        uint8_t ignore[32];
        int reinit_failed = 0;
        hmac_sha256_compute(s_prime, PIN_MD_MASTER_SECRET_LEN,
                            kdf_input_01, 1, new_u);
        for (uint8_t i = 0; i < SLOTS_MD_ROUNDS; ++i) {
            if (tropic_mac_and_destroy(i, new_u, ignore) != 0) {
                reinit_failed = 1;
                break;
            }
        }
        memzero(new_u, sizeof new_u);
        memzero(ignore, sizeof ignore);
        if (reinit_failed) {
            rc = -1;
            goto cleanup;
        }
        /* Reset {active=1, next_slot=0}; tag + ci unchanged. */
        if (slots_global_md_set(1, 0, stored_tag, stored_ci) != 0) {
            rc = -1;
            goto cleanup;
        }
        *out_correct = 1;
        rc = 0;
    } else {
        /* PIN wrong. Slot is consumed (already advanced); next attempt
         * uses next slot. *out_correct stays 0. */
        *out_correct = 0;
        rc = 0;
    }

cleanup:
    memzero(v,         sizeof v);
    memzero(w_i,       sizeof w_i);
    memzero(k_i,       sizeof k_i);
    memzero(s_prime,   sizeof s_prime);
    memzero(t_prime,   sizeof t_prime);
    memzero(stored_tag, sizeof stored_tag);
    memzero(stored_ci,  sizeof stored_ci);
    return rc;
}
