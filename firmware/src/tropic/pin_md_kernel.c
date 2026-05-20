/*
 * MAC-and-Destroy PIN kernel — implementation.
 *
 * Algorithm copied verbatim from the original FIDO `pin_md.c` (Phase
 * 5 M4); only the slot indices and the R-mem accessors are now
 * indirected through the `pin_md_layout_t` so other PINs (OpenPGP
 * PW1/PW3/RC in Phase 8 M4.B+) can re-use the same code.
 *
 * Threat-model contract reproduced from `pin_md.c`:
 *   - All intermediate keys (u, v, w, k_i, s) zero'd on exit.
 *   - master_secret never leaves the stack and is wiped before return.
 *   - The recovered s' on a verify is treated as opaque — we only
 *     check the tag, never use s' for anything else.
 *   - On wrong-PIN attempt, the slot is destroyed regardless of
 *     firmware behavior — chip-enforced.
 */

#include "pin_md_kernel.h"
#include "tropic/tropic.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "sha2.h"
#include "hmac.h"
#include "memzero.h"

/* ----- Helpers ----- */

static int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff;
}

static void xor32(const uint8_t *a, const uint8_t *b, uint8_t *out)
{
    for (size_t i = 0; i < 32u; ++i) {
        out[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

static void hmac_sha256_compute(const uint8_t *key, size_t key_len,
                                const uint8_t *msg, size_t msg_len,
                                uint8_t out[32])
{
    hmac_sha256(key, (uint32_t) key_len, msg, (uint32_t) msg_len, out);
}

static int valid_layout(const pin_md_layout_t *L)
{
    if (L == NULL) return 0;
    if (L->rounds == 0u || L->rounds > PIN_MD_KERNEL_ROUNDS_MAX) return 0;
    if (L->pin_material_len == 0u ||
        L->pin_material_len > PIN_MD_KERNEL_MATERIAL_MAX) return 0;
    if (L->state_get == NULL || L->state_set == NULL ||
        L->state_advance == NULL) return 0;
    return 1;
}

/* ----- Public API ----- */

int pin_md_kernel_is_active(const pin_md_layout_t *L)
{
    if (!valid_layout(L)) return 0;
    uint8_t active = 0;
    if (L->state_get(&active, NULL, NULL, NULL) != 0) {
        return 0;
    }
    return active ? 1 : 0;
}

int pin_md_kernel_attempts_remaining(const pin_md_layout_t *L)
{
    if (!valid_layout(L)) return 0;
    uint8_t active = 0;
    uint8_t next_slot = 0;
    if (L->state_get(&active, &next_slot, NULL, NULL) != 0) {
        return 0;
    }
    if (!active) return (int) L->rounds;
    if (next_slot >= L->rounds) return 0;
    return (int)(L->rounds - next_slot);
}

int pin_md_kernel_setup(const pin_md_layout_t *L,
                        const uint8_t *pin_material)
{
    if (!valid_layout(L) || pin_material == NULL) return -1;

    uint8_t master_secret[PIN_MD_KERNEL_MASTER_LEN] = {0};
    uint8_t tag[PIN_MD_KERNEL_TAG_LEN] = {0};
    uint8_t u[32]   = {0};
    uint8_t v[32]   = {0};
    uint8_t w_i[32] = {0};
    uint8_t k_i[32] = {0};
    uint8_t ci_all[PIN_MD_KERNEL_CI_LEN_MAX] = {0};
    uint8_t ignore[32];
    static const uint8_t zeros32[32] = {0};
    static const uint8_t kdf_input_00[1] = {0x00};
    static const uint8_t kdf_input_01[1] = {0x01};

    int rc = -2;

    if (tropic_random(master_secret, PIN_MD_KERNEL_MASTER_LEN) != 0) {
        goto cleanup;
    }

    /* t = HMAC(s, 0x00) */
    hmac_sha256_compute(master_secret, PIN_MD_KERNEL_MASTER_LEN,
                        kdf_input_00, 1, tag);
    /* u = HMAC(s, 0x01) */
    hmac_sha256_compute(master_secret, PIN_MD_KERNEL_MASTER_LEN,
                        kdf_input_01, 1, u);
    /* v = HMAC(0, pin_material) */
    hmac_sha256_compute(zeros32, 32, pin_material, L->pin_material_len, v);

    for (uint8_t i = 0; i < L->rounds; ++i) {
        uint8_t slot = (uint8_t)(L->md_slot_base + i);
        if (tropic_mac_and_destroy(slot, u, ignore) != 0) goto cleanup;
        if (tropic_mac_and_destroy(slot, v, w_i)    != 0) goto cleanup;
        if (tropic_mac_and_destroy(slot, u, ignore) != 0) goto cleanup;
        hmac_sha256_compute(w_i, 32, pin_material, L->pin_material_len, k_i);
        xor32(master_secret, k_i,
              &ci_all[(size_t) i * PIN_MD_KERNEL_SLOT_SIZE]);
    }

    if (L->state_set(1u, 0u, tag, ci_all) != 0) {
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
    memzero(ignore,        sizeof ignore);
    return rc;
}

int pin_md_kernel_verify(const pin_md_layout_t *L,
                         const uint8_t *pin_material,
                         int *out_correct)
{
    if (!valid_layout(L) || pin_material == NULL || out_correct == NULL) {
        return -1;
    }
    *out_correct = 0;

    uint8_t active = 0;
    uint8_t next_slot = 0;
    uint8_t stored_tag[PIN_MD_KERNEL_TAG_LEN] = {0};
    uint8_t stored_ci[PIN_MD_KERNEL_CI_LEN_MAX] = {0};

    if (L->state_get(&active, &next_slot, stored_tag, stored_ci) != 0) {
        return -1;
    }
    if (!active) {
        return -1;
    }
    if (next_slot >= L->rounds) {
        return -2;
    }

    /* Commit the advance BEFORE the destructive chip op (power-loss
     * safe — mid-op crash still counts the slot as consumed). */
    uint8_t slot_idx = next_slot;
    if (L->state_advance(NULL) != 0) {
        return -1;
    }

    uint8_t chip_slot = (uint8_t)(L->md_slot_base + slot_idx);

    uint8_t v[32]   = {0};
    uint8_t w_i[32] = {0};
    uint8_t k_i[32] = {0};
    uint8_t s_prime[PIN_MD_KERNEL_MASTER_LEN] = {0};
    uint8_t t_prime[PIN_MD_KERNEL_TAG_LEN] = {0};
    static const uint8_t zeros32[32] = {0};
    static const uint8_t kdf_input_00[1] = {0x00};
    static const uint8_t kdf_input_01[1] = {0x01};

    int rc = -1;

    hmac_sha256_compute(zeros32, 32, pin_material, L->pin_material_len, v);

    if (tropic_mac_and_destroy(chip_slot, v, w_i) != 0) {
        goto cleanup;
    }

    hmac_sha256_compute(w_i, 32, pin_material, L->pin_material_len, k_i);
    xor32(&stored_ci[(size_t) slot_idx * PIN_MD_KERNEL_SLOT_SIZE], k_i,
          s_prime);

    hmac_sha256_compute(s_prime, PIN_MD_KERNEL_MASTER_LEN,
                        kdf_input_00, 1, t_prime);

    if (ct_memcmp(t_prime, stored_tag, PIN_MD_KERNEL_TAG_LEN) == 0) {
        /* PIN correct.  Re-initialise ALL slots in the range so prior
         * wrong attempts (and the slot just consumed by this verify)
         * are all restored to K = f(u_setup). */
        uint8_t new_u[32] = {0};
        uint8_t ignore[32];
        int reinit_failed = 0;
        hmac_sha256_compute(s_prime, PIN_MD_KERNEL_MASTER_LEN,
                            kdf_input_01, 1, new_u);
        for (uint8_t i = 0; i < L->rounds; ++i) {
            if (tropic_mac_and_destroy((uint8_t)(L->md_slot_base + i),
                                       new_u, ignore) != 0) {
                reinit_failed = 1;
                break;
            }
        }
        memzero(new_u,  sizeof new_u);
        memzero(ignore, sizeof ignore);
        if (reinit_failed) {
            rc = -1;
            goto cleanup;
        }
        if (L->state_set(1u, 0u, stored_tag, stored_ci) != 0) {
            rc = -1;
            goto cleanup;
        }
        *out_correct = 1;
        rc = 0;
    } else {
        *out_correct = 0;
        rc = 0;
    }

cleanup:
    memzero(v,          sizeof v);
    memzero(w_i,        sizeof w_i);
    memzero(k_i,        sizeof k_i);
    memzero(s_prime,    sizeof s_prime);
    memzero(t_prime,    sizeof t_prime);
    memzero(stored_tag, sizeof stored_tag);
    memzero(stored_ci,  sizeof stored_ci);
    return rc;
}
