/*
 * Phase 5 M1 — TROPIC01 slot manager implementation. See slots.h.
 *
 * Wire encoding (big-endian for all multi-byte fields):
 *
 * Slot 0 (global state, 256 B):
 *   [0..3]   magic   "NX5K" (0x4E 0x58 0x35 0x4B)
 *   [4..5]   schema_version = 1
 *   [6..9]   bitmap (uint32_BE; bit i = slot i used)
 *   [10..255] reserved, zero-filled  (will hold PIN state in M3)
 *
 * Slot N+1 (per-credential, 256 B):
 *   [0..3]   magic   "NXCR" (0x4E 0x58 0x43 0x52)
 *   [4]      schema_version = 1
 *   [5]      alg (SLOTS_ALG_ED25519 = 8)
 *   [6]      flags
 *   [7]      reserved
 *   [8..39]  rp_id_hash (32 B)
 *   [40..55] cred_id_nonce (16 B)
 *   [56..255] reserved (will hold user_handle / rp_name / user_name in M3)
 */

#include "slots.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "tropic/tropic.h"

/* Wire layout offsets — kept as #defines, not magic numbers in code. */
#define GLOBAL_MAGIC_OFF          0
#define GLOBAL_MAGIC_LEN          4
#define GLOBAL_SCHEMA_OFF         4
#define GLOBAL_BITMAP_OFF         6
#define GLOBAL_BITMAP_LEN         4
/* PIN state (Phase 5 M3). Stored at offsets 10..30 in global R-mem slot. */
#define GLOBAL_PIN_SET_OFF       10
#define GLOBAL_PIN_HASH_OFF      11
#define GLOBAL_PIN_RETRIES_OFF   27
/* M&D state (Phase 5 M4). Stored at offsets 31..320 in global R-mem slot. */
#define GLOBAL_MD_ACTIVE_OFF     31
#define GLOBAL_MD_NEXT_SLOT_OFF  32
#define GLOBAL_MD_TAG_OFF        33   /* 32 B */
#define GLOBAL_MD_CI_OFF         65   /* 256 B */
#define GLOBAL_MD_END_OFF       (GLOBAL_MD_CI_OFF + SLOTS_MD_CI_LEN)  /* 321 */

#define CRED_MAGIC_OFF            0
#define CRED_MAGIC_LEN            4
#define CRED_SCHEMA_OFF           4
#define CRED_ALG_OFF              5
#define CRED_FLAGS_OFF            6
#define CRED_RP_HASH_OFF          8
#define CRED_NONCE_OFF            40

/* Magic byte values. */
static const uint8_t GLOBAL_MAGIC[GLOBAL_MAGIC_LEN] = { 'N', 'X', '5', 'K' };
static const uint8_t CRED_MAGIC[CRED_MAGIC_LEN]     = { 'N', 'X', 'C', 'R' };

/* schema_version 1 = M1/M3 (256 B layout, no M&D fields)
 * schema_version 2 = M4 (384 B layout, M&D state at offsets 31..320) */
#define SLOTS_SCHEMA_VERSION      2u
/* M4 grew global payload from 256 → 384 to fit M&D fields. */
#define SLOTS_GLOBAL_PAYLOAD_LEN  384u
#define SLOTS_CRED_PAYLOAD_LEN    SLOTS_RMEM_PER_CRED_SIZE

/* Cached state — populated in slots_init from R-mem slot 0. */
static uint32_t s_bitmap;
static int      s_initted;

/* ----- Helpers ----- */

static void be32_store(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t) v;
}

static uint32_t be32_load(const uint8_t *p)
{
    return ((uint32_t) p[0] << 24)
         | ((uint32_t) p[1] << 16)
         | ((uint32_t) p[2] <<  8)
         | ((uint32_t) p[3]);
}

/* Constant-time memcmp — return 0 iff equal. */
static int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff;
}

/* Cached PIN state — populated lazily from R-mem in slots_init / re-read
 * helpers. Mirrored to R-mem on every change. */
static uint8_t  s_pin_set;
static uint8_t  s_pin_hash[SLOTS_PIN_HASH_LEN];
static uint32_t s_pin_retries;
/* M4 M&D state. */
static uint8_t  s_md_active;
static uint8_t  s_md_next_slot;
static uint8_t  s_md_tag[SLOTS_MD_TAG_LEN];
static uint8_t  s_md_ci[SLOTS_MD_CI_LEN];

/* Write the global-state buffer back to R-mem slot 0. Always writes the
 * full 384 B (bumped from 256 in M4 for the M&D ci[] array) for layout
 * stability across firmware revisions. The buffer mirrors the cached
 * state in s_pin_* and s_md_*. */
static int write_global(uint32_t bitmap)
{
    uint8_t buf[SLOTS_GLOBAL_PAYLOAD_LEN];
    memset(buf, 0, sizeof buf);

    memcpy(&buf[GLOBAL_MAGIC_OFF], GLOBAL_MAGIC, GLOBAL_MAGIC_LEN);
    buf[GLOBAL_SCHEMA_OFF]     = 0;                              /* BE high */
    buf[GLOBAL_SCHEMA_OFF + 1] = (uint8_t) SLOTS_SCHEMA_VERSION;
    be32_store(&buf[GLOBAL_BITMAP_OFF], bitmap);

    /* PIN state (M3+). Default zeros if no PIN set; safe because zero is
     * "pin not set". */
    buf[GLOBAL_PIN_SET_OFF] = s_pin_set;
    memcpy(&buf[GLOBAL_PIN_HASH_OFF], s_pin_hash, SLOTS_PIN_HASH_LEN);
    be32_store(&buf[GLOBAL_PIN_RETRIES_OFF], s_pin_retries);

    /* M&D state (M4+). Default zeros if M&D not initialized. */
    buf[GLOBAL_MD_ACTIVE_OFF]     = s_md_active;
    buf[GLOBAL_MD_NEXT_SLOT_OFF]  = s_md_next_slot;
    memcpy(&buf[GLOBAL_MD_TAG_OFF], s_md_tag, SLOTS_MD_TAG_LEN);
    memcpy(&buf[GLOBAL_MD_CI_OFF],  s_md_ci,  SLOTS_MD_CI_LEN);

    /* Erase before write — R-mem slots are write-once until erased. */
    (void) tropic_rmem_erase(SLOTS_RMEM_GLOBAL_SLOT);
    return tropic_rmem_write(SLOTS_RMEM_GLOBAL_SLOT, buf, sizeof buf);
}

/* Read & validate the global-state slot. Returns 0 and populates
 * *out_bitmap on success; -1 if magic mismatch (caller should treat as
 * first boot); -2 on chip read error; -3 if schema is older than M4
 * (caller should factory_reset to migrate). */
static int read_global(uint32_t *out_bitmap)
{
    uint8_t  buf[SLOTS_GLOBAL_PAYLOAD_LEN];
    size_t   got = 0;

    int rc = tropic_rmem_read(SLOTS_RMEM_GLOBAL_SLOT, buf, sizeof buf, &got);
    if (rc != 0 || got < (GLOBAL_PIN_RETRIES_OFF + 4u)) {
        return -2;
    }
    if (memcmp(&buf[GLOBAL_MAGIC_OFF], GLOBAL_MAGIC, GLOBAL_MAGIC_LEN) != 0) {
        return -1;
    }

    /* Schema version check. M4 requires schema >= 2 (M&D fields at
     * offsets 31..320). Older schemas are migrated by factory_reset. */
    uint16_t schema = ((uint16_t) buf[GLOBAL_SCHEMA_OFF] << 8) |
                       (uint16_t) buf[GLOBAL_SCHEMA_OFF + 1];
    if (schema < 2u) {
        return -3;
    }

    *out_bitmap = be32_load(&buf[GLOBAL_BITMAP_OFF]);

    /* PIN state. */
    s_pin_set     = buf[GLOBAL_PIN_SET_OFF] & 0x01u;
    memcpy(s_pin_hash, &buf[GLOBAL_PIN_HASH_OFF], SLOTS_PIN_HASH_LEN);
    s_pin_retries = be32_load(&buf[GLOBAL_PIN_RETRIES_OFF]);

    /* M&D state (M4+). Only valid if schema >= 2 AND we read enough bytes. */
    if (got >= GLOBAL_MD_END_OFF) {
        s_md_active    = buf[GLOBAL_MD_ACTIVE_OFF] & 0x01u;
        s_md_next_slot = buf[GLOBAL_MD_NEXT_SLOT_OFF];
        memcpy(s_md_tag, &buf[GLOBAL_MD_TAG_OFF], SLOTS_MD_TAG_LEN);
        memcpy(s_md_ci,  &buf[GLOBAL_MD_CI_OFF],  SLOTS_MD_CI_LEN);
    } else {
        s_md_active = 0;
        s_md_next_slot = 0;
        memset(s_md_tag, 0, SLOTS_MD_TAG_LEN);
        memset(s_md_ci,  0, SLOTS_MD_CI_LEN);
    }

    return 0;
}

/* Write a fully-formed per-credential R-mem entry. */
static int write_cred(int slot_idx,
                      uint8_t alg,
                      uint8_t flags,
                      const uint8_t rp_id_hash[SLOTS_RP_ID_HASH_LEN],
                      const uint8_t cred_id_nonce[SLOTS_CRED_ID_NONCE_LEN])
{
    uint8_t buf[SLOTS_CRED_PAYLOAD_LEN];
    memset(buf, 0, sizeof buf);

    memcpy(&buf[CRED_MAGIC_OFF], CRED_MAGIC, CRED_MAGIC_LEN);
    buf[CRED_SCHEMA_OFF] = (uint8_t) SLOTS_SCHEMA_VERSION;
    buf[CRED_ALG_OFF]    = alg;
    buf[CRED_FLAGS_OFF]  = flags;
    memcpy(&buf[CRED_RP_HASH_OFF], rp_id_hash, SLOTS_RP_ID_HASH_LEN);
    memcpy(&buf[CRED_NONCE_OFF],   cred_id_nonce, SLOTS_CRED_ID_NONCE_LEN);

    uint16_t rs = SLOTS_RMEM_SLOT_FOR(slot_idx);
    (void) tropic_rmem_erase(rs);
    return tropic_rmem_write(rs, buf, sizeof buf);
}

/* Read & validate a per-credential R-mem entry. */
static int read_cred(int slot_idx, slot_meta_t *out)
{
    uint8_t buf[SLOTS_CRED_PAYLOAD_LEN];
    size_t  got = 0;

    int rc = tropic_rmem_read(SLOTS_RMEM_SLOT_FOR(slot_idx),
                              buf, sizeof buf, &got);
    if (rc != 0 || got < (CRED_NONCE_OFF + SLOTS_CRED_ID_NONCE_LEN)) {
        return -2;
    }
    if (memcmp(&buf[CRED_MAGIC_OFF], CRED_MAGIC, CRED_MAGIC_LEN) != 0) {
        return -1;
    }
    if (out != NULL) {
        out->alg   = buf[CRED_ALG_OFF];
        out->flags = buf[CRED_FLAGS_OFF];
        memcpy(out->rp_id_hash,    &buf[CRED_RP_HASH_OFF], SLOTS_RP_ID_HASH_LEN);
        memcpy(out->cred_id_nonce, &buf[CRED_NONCE_OFF],   SLOTS_CRED_ID_NONCE_LEN);
    }
    return 0;
}

/* Orphan-scrub: clear bitmap bits whose per-cred slot lacks valid magic. */
static void orphan_scrub(uint32_t *bitmap)
{
    uint32_t bm = *bitmap;
    for (int i = 0; i < (int) SLOTS_MAX; ++i) {
        if ((bm & (1u << i)) == 0u) {
            continue;
        }
        slot_meta_t tmp;
        if (read_cred(i, &tmp) != 0) {
            bm &= ~(1u << i);
        }
    }
    *bitmap = bm;
}

/* ----- Public API ----- */

int slots_init(void)
{
    if (s_initted) {
        return 0;
    }

    /* L3 session must be open for R-mem ops. */
    if (tropic_l3_session_ensure() != 0) {
        return -1;
    }

    uint32_t bitmap = 0;
    int rc = read_global(&bitmap);
    if (rc == -1) {
        /* First boot — magic mismatch (or never written). Write fresh. */
        if (write_global(0) != 0) {
            return -2;
        }
        bitmap = 0;
    } else if (rc == -2) {
        /* Chip read error — try fresh write once. If THAT fails, give up. */
        if (write_global(0) != 0) {
            return -3;
        }
        bitmap = 0;
    } else if (rc == -3) {
        /* Old schema (M1/M3 wrote schema=1). Migration: factory_reset to
         * fresh M4 layout. Existing PIN is lost — acceptable in Phase 5
         * dev (user re-sets via fido2-token -S). */
        if (write_global(0) != 0) {
            return -3;
        }
        bitmap = 0;
        s_pin_set = 0;
        memset(s_pin_hash, 0, sizeof s_pin_hash);
        s_pin_retries = 0;
        s_md_active = 0;
        s_md_next_slot = 0;
        memset(s_md_tag, 0, sizeof s_md_tag);
        memset(s_md_ci,  0, sizeof s_md_ci);
    } else {
        /* Existing state — orphan-scrub. */
        uint32_t scrubbed = bitmap;
        orphan_scrub(&scrubbed);
        if (scrubbed != bitmap) {
            /* Bitmap diverged from on-chip cred state; rewrite. */
            if (write_global(scrubbed) != 0) {
                return -4;
            }
            bitmap = scrubbed;
        }
    }

    s_bitmap = bitmap;
    s_initted = 1;
    return 0;
}

int slots_alloc(const uint8_t rp_id_hash[SLOTS_RP_ID_HASH_LEN],
                uint8_t alg,
                uint8_t out_cred_id[SLOTS_CRED_ID_LEN],
                int *out_slot_idx)
{
    if (rp_id_hash == NULL || out_cred_id == NULL || out_slot_idx == NULL) {
        return -1;
    }
    if (!s_initted) {
        int rc = slots_init();
        if (rc != 0) return -2;
    }

    /* Find first free slot. */
    int idx = -1;
    for (int i = 0; i < (int) SLOTS_MAX; ++i) {
        if ((s_bitmap & (1u << i)) == 0u) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        return -1;     /* full */
    }

    /* Generate 16 B nonce from TROPIC01 TRNG. */
    uint8_t nonce[SLOTS_CRED_ID_NONCE_LEN];
    if (tropic_random(nonce, sizeof nonce) != 0) {
        return -2;
    }

    /* Write per-credential metadata first; only then commit bitmap.
     * This makes a power-loss-mid-alloc safe: the bitmap bit stays 0,
     * so the orphan slot is invisible to lookup and will be overwritten
     * by the next alloc. */
    if (write_cred(idx, alg, SLOTS_FLAG_RESIDENT, rp_id_hash, nonce) != 0) {
        return -2;
    }

    uint32_t new_bitmap = s_bitmap | (1u << idx);
    if (write_global(new_bitmap) != 0) {
        /* R-mem cred written but bitmap not committed — leave it; the
         * orphan_scrub on next boot would NOT remove it because magic
         * is valid. Defensive: erase the orphan now. */
        (void) tropic_rmem_erase(SLOTS_RMEM_SLOT_FOR(idx));
        return -2;
    }
    s_bitmap = new_bitmap;

    /* Emit cred ID. */
    out_cred_id[0] = 0x01;
    out_cred_id[1] = (uint8_t) idx;
    memcpy(&out_cred_id[2], nonce, SLOTS_CRED_ID_NONCE_LEN);
    *out_slot_idx = idx;
    return 0;
}

int slots_lookup_by_credid(const uint8_t *cred_id, size_t cred_id_len,
                           int *out_slot_idx)
{
    if (cred_id == NULL || out_slot_idx == NULL) {
        return -1;
    }
    if (cred_id_len != SLOTS_CRED_ID_LEN) {
        return -1;
    }
    if (cred_id[0] != 0x01) {
        return -1;
    }
    uint8_t idx = cred_id[1];
    if (idx >= SLOTS_MAX) {
        return -1;
    }
    if (!s_initted) {
        if (slots_init() != 0) return -1;
    }
    if ((s_bitmap & (1u << idx)) == 0u) {
        return -1;
    }

    slot_meta_t meta;
    if (read_cred(idx, &meta) != 0) {
        return -1;
    }
    /* Constant-time nonce compare. */
    if (ct_memcmp(meta.cred_id_nonce, &cred_id[2], SLOTS_CRED_ID_NONCE_LEN) != 0) {
        return -1;
    }
    *out_slot_idx = (int) idx;
    return 0;
}

int slots_erase(int slot_idx)
{
    if (slot_idx < 0 || slot_idx >= (int) SLOTS_MAX) {
        return -1;
    }
    if (!s_initted) {
        if (slots_init() != 0) return -2;
    }

    /* Clear bit first, then erase R-mem. If power-loss between the two,
     * the next boot's orphan_scrub will reconcile. */
    uint32_t new_bitmap = s_bitmap & ~(1u << slot_idx);
    if (new_bitmap != s_bitmap) {
        if (write_global(new_bitmap) != 0) {
            return -2;
        }
        s_bitmap = new_bitmap;
    }
    /* Best-effort R-mem erase. Already-empty returns an error per
     * libtropic; tolerate. */
    (void) tropic_rmem_erase(SLOTS_RMEM_SLOT_FOR(slot_idx));
    return 0;
}

uint32_t slots_bitmap(void)
{
    if (!s_initted) {
        if (slots_init() != 0) return 0;
    }
    return s_bitmap;
}

int slots_count_used(void)
{
    uint32_t bm = slots_bitmap();
    int n = 0;
    while (bm) {
        n += (int)(bm & 1u);
        bm >>= 1;
    }
    return n;
}

int slots_read_meta(int slot_idx, slot_meta_t *out)
{
    if (slot_idx < 0 || slot_idx >= (int) SLOTS_MAX || out == NULL) {
        return -1;
    }
    if (!s_initted) {
        if (slots_init() != 0) return -2;
    }
    if ((s_bitmap & (1u << slot_idx)) == 0u) {
        return -1;
    }
    return read_cred(slot_idx, out);
}

int slots_factory_reset(void)
{
    if (tropic_l3_session_ensure() != 0) {
        return -1;
    }
    /* Erase all per-credential R-mem (1..32). */
    for (uint16_t i = 1u; i <= SLOTS_MAX; ++i) {
        (void) tropic_rmem_erase(i);
    }
    /* Reset cached PIN + M&D state to defaults BEFORE write_global so
     * the persisted layout reflects "no PIN, no M&D". */
    s_pin_set = 0;
    memset(s_pin_hash, 0, sizeof s_pin_hash);
    s_pin_retries = 0;
    s_md_active = 0;
    s_md_next_slot = 0;
    memset(s_md_tag, 0, sizeof s_md_tag);
    memset(s_md_ci,  0, sizeof s_md_ci);
    if (write_global(0) != 0) {
        s_bitmap = 0;
        s_initted = 0;
        return -1;
    }
    s_bitmap = 0;
    s_initted = 1;
    return 0;
}

/* ===== M&D accessors (Phase 5 M4) ===== */

int slots_global_md_get(int *out_active,
                        uint8_t *out_next_slot,
                        uint8_t out_tag[SLOTS_MD_TAG_LEN],
                        uint8_t out_ci[SLOTS_MD_CI_LEN])
{
    if (!s_initted) {
        if (slots_init() != 0) return -1;
    }
    if (out_active)    *out_active    = (int) s_md_active;
    if (out_next_slot) *out_next_slot = s_md_next_slot;
    if (out_tag)       memcpy(out_tag, s_md_tag, SLOTS_MD_TAG_LEN);
    if (out_ci)        memcpy(out_ci,  s_md_ci,  SLOTS_MD_CI_LEN);
    return 0;
}

int slots_global_md_set(int active,
                        uint8_t next_slot,
                        const uint8_t tag[SLOTS_MD_TAG_LEN],
                        const uint8_t ci[SLOTS_MD_CI_LEN])
{
    if (!s_initted) {
        if (slots_init() != 0) return -1;
    }
    s_md_active = active ? 1u : 0u;
    s_md_next_slot = next_slot;
    if (tag) memcpy(s_md_tag, tag, SLOTS_MD_TAG_LEN);
    else     memset(s_md_tag, 0,   SLOTS_MD_TAG_LEN);
    if (ci)  memcpy(s_md_ci,  ci,  SLOTS_MD_CI_LEN);
    else     memset(s_md_ci,  0,   SLOTS_MD_CI_LEN);
    return write_global(s_bitmap);
}

int slots_global_md_advance(uint8_t *out_new)
{
    if (!s_initted) {
        if (slots_init() != 0) return -1;
    }
    if (s_md_next_slot < SLOTS_MD_ROUNDS) {
        s_md_next_slot++;
    }
    if (out_new) *out_new = s_md_next_slot;
    return write_global(s_bitmap);
}

/* ===== PIN state accessors (Phase 5 M3) ===== */

int slots_global_pin_get(int *out_pin_set,
                         uint32_t *out_retries,
                         uint8_t out_pin_hash[SLOTS_PIN_HASH_LEN])
{
    if (!s_initted) {
        if (slots_init() != 0) return -1;
    }
    if (out_pin_set) *out_pin_set = (int) s_pin_set;
    if (out_retries) *out_retries = s_pin_retries;
    if (out_pin_hash) memcpy(out_pin_hash, s_pin_hash, SLOTS_PIN_HASH_LEN);
    return 0;
}

int slots_global_pin_set(const uint8_t pin_hash[SLOTS_PIN_HASH_LEN])
{
    if (!pin_hash) return -1;
    if (!s_initted) {
        if (slots_init() != 0) return -1;
    }
    s_pin_set = 1;
    memcpy(s_pin_hash, pin_hash, SLOTS_PIN_HASH_LEN);
    s_pin_retries = SLOTS_PIN_RETRIES_INITIAL;
    return write_global(s_bitmap);
}

int slots_global_pin_dec_retries(uint32_t *out_new)
{
    if (!s_initted) {
        if (slots_init() != 0) return -1;
    }
    if (s_pin_retries > 0u) {
        s_pin_retries--;
    }
    if (out_new) *out_new = s_pin_retries;
    return write_global(s_bitmap);
}

int slots_global_pin_reset_retries(void)
{
    if (!s_initted) {
        if (slots_init() != 0) return -1;
    }
    s_pin_retries = SLOTS_PIN_RETRIES_INITIAL;
    return write_global(s_bitmap);
}
