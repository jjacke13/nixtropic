/*
 * TROPIC01 slot manager implementation. See slots.h.
 *
 * O1 = FIDO global state, a rec_pair in R-mem slots 0 / 40 (Phase 9 M4,
 * docs/PHASE-9-M4-DESIGN.md §2, §4).  Payload (big-endian):
 *   [0..3]  bitmap (uint32; bit i = credential slot i allocated)
 *   [4]     force_uv (0 / 1)
 *   [5]     pin_bound (0 / 1): guard of the PIN binding O2 (§2.5)
 *
 * Slot N+1 (per-credential metadata, 256 B), written once per credential:
 *   [0..3]   magic   "NXCR" (0x4E 0x58 0x43 0x52)
 *   [4]      schema_version
 *   [5]      alg (SLOTS_ALG_ED25519 = 8, SLOTS_ALG_ES256 = 7)
 *   [6]      flags
 *   [7]      reserved
 *   [8..39]  rp_id_hash (32 B)
 *   [40..55] cred_id_nonce (16 B)
 *   [56]     user_handle_len, [57..120] user_handle, [121..124] created
 */

#include "slots.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "tropic/rec_pair.h"
#include "tropic/tropic.h"

#define O1_SLOT_A       SLOTS_RMEM_GLOBAL_SLOT   /* 0 */
#define O1_SLOT_B       40u
#define O1_OBJ          1u
#define O1_SCHEMA       1u
#define O1_LEN          6u

#define CRED_MAGIC_OFF            0
#define CRED_MAGIC_LEN            4
#define CRED_SCHEMA_OFF           4
#define CRED_ALG_OFF              5
#define CRED_FLAGS_OFF            6
#define CRED_RP_HASH_OFF          8
#define CRED_NONCE_OFF            40
/* Phase 6 M3 — user_handle in the previously-reserved area.  Old creds
 * (Phase 5) have zero-init here, decoding as user_handle_len = 0. */
#define CRED_USER_HANDLE_LEN_OFF 56
#define CRED_USER_HANDLE_OFF     57
/* Phase 9 M3 — creation sequence, BE, right after the 64 B user_handle
 * area (57..120).  Older writers zeroed the whole slot: reads as 0. */
#define CRED_CREATED_OFF        121
#define CRED_SCHEMA_VERSION       4u   /* unchanged since Phase 7 */
#define SLOTS_CRED_PAYLOAD_LEN    SLOTS_RMEM_PER_CRED_SIZE

static const uint8_t CRED_MAGIC[CRED_MAGIC_LEN] = { 'N', 'X', 'C', 'R' };

static rec_pair_t s_o1 = REC_PAIR(O1_SLOT_A, O1_SLOT_B, O1_OBJ, O1_SCHEMA);

/* RAM copy of O1, valid while slots_usable(). */
static int      s_initted;
static uint32_t s_bitmap;
static uint8_t  s_force_uv;
static uint8_t  s_pin_bound;

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

static void o1_encode(uint8_t out[O1_LEN], uint32_t bitmap, uint8_t uv, uint8_t bound)
{
    be32_store(out, bitmap);
    out[4] = uv;
    out[5] = bound;
}

/* Persist O1 in both copies, then (only then) take it into RAM.  A failure
 * leaves the pair uncertain: slots_usable() is 0 until the next boot. */
static int write_global(uint32_t bitmap, uint8_t uv, uint8_t bound)
{
    uint8_t buf[O1_LEN];
    if (!slots_usable()) return -1;
    o1_encode(buf, bitmap, uv, bound);
    if (rec_pair_write(&s_o1, buf, sizeof buf) != REC_OK) return -1;
    s_bitmap = bitmap;
    s_force_uv = uv;
    s_pin_bound = bound;
    return 0;
}

/* Write a fully-formed per-credential R-mem entry. */
static int write_cred(int slot_idx,
                      uint8_t alg,
                      uint8_t flags,
                      const uint8_t rp_id_hash[SLOTS_RP_ID_HASH_LEN],
                      const uint8_t cred_id_nonce[SLOTS_CRED_ID_NONCE_LEN],
                      const uint8_t *user_handle, size_t user_handle_len,
                      uint32_t created)
{
    uint8_t buf[SLOTS_CRED_PAYLOAD_LEN];
    memset(buf, 0, sizeof buf);

    memcpy(&buf[CRED_MAGIC_OFF], CRED_MAGIC, CRED_MAGIC_LEN);
    buf[CRED_SCHEMA_OFF] = CRED_SCHEMA_VERSION;
    buf[CRED_ALG_OFF]    = alg;
    buf[CRED_FLAGS_OFF]  = flags;
    memcpy(&buf[CRED_RP_HASH_OFF], rp_id_hash, SLOTS_RP_ID_HASH_LEN);
    memcpy(&buf[CRED_NONCE_OFF],   cred_id_nonce, SLOTS_CRED_ID_NONCE_LEN);

    /* Phase 6 M3 — optional user_handle (capped at SLOTS_USER_HANDLE_MAX). */
    if (user_handle != NULL && user_handle_len > 0u) {
        size_t cap = (user_handle_len > SLOTS_USER_HANDLE_MAX)
                        ? SLOTS_USER_HANDLE_MAX
                        : user_handle_len;
        buf[CRED_USER_HANDLE_LEN_OFF] = (uint8_t) cap;
        memcpy(&buf[CRED_USER_HANDLE_OFF], user_handle, cap);
    }
    buf[CRED_CREATED_OFF]      = (uint8_t)(created >> 24);
    buf[CRED_CREATED_OFF + 1]  = (uint8_t)(created >> 16);
    buf[CRED_CREATED_OFF + 2]  = (uint8_t)(created >> 8);
    buf[CRED_CREATED_OFF + 3]  = (uint8_t) created;

    uint16_t rs = SLOTS_RMEM_SLOT_FOR(slot_idx);
    if (tropic_rmem_erase(rs) != 0) {
        return -1;
    }
    return tropic_rmem_write(rs, buf, sizeof buf);
}

/* Read & validate a per-credential R-mem entry: 0, -1 bad magic, -2 chip
 * error or short read, -3 the slot reads empty. */
static int read_cred(int slot_idx, slot_meta_t *out)
{
    uint8_t buf[SLOTS_CRED_PAYLOAD_LEN];
    size_t  got = 0;

    int rc = tropic_rmem_read(SLOTS_RMEM_SLOT_FOR(slot_idx),
                              buf, sizeof buf, &got);
    if (rc == TROPIC_ERR_RMEM_SLOT_EMPTY || (rc == 0 && got == 0u)) {
        return -3;                       /* reads empty (as slots_wipe_meta counts it) */
    }
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

        /* Phase 6 M3 — user_handle if present and read length covers it.
         * Old (Phase 5) creds read 0 here, which is the sentinel "no
         * user info." */
        out->user_handle_len = 0;
        memset(out->user_handle, 0, sizeof out->user_handle);
        if (got > CRED_USER_HANDLE_LEN_OFF) {
            uint8_t len = buf[CRED_USER_HANDLE_LEN_OFF];
            if (len > 0u && len <= SLOTS_USER_HANDLE_MAX
                && got >= (size_t)(CRED_USER_HANDLE_OFF + len)) {
                out->user_handle_len = len;
                memcpy(out->user_handle,
                       &buf[CRED_USER_HANDLE_OFF], len);
            }
        }
        out->created = 0;
        if (got >= (size_t)(CRED_CREATED_OFF + 4)) {
            out->created = ((uint32_t) buf[CRED_CREATED_OFF] << 24)
                         | ((uint32_t) buf[CRED_CREATED_OFF + 1] << 16)
                         | ((uint32_t) buf[CRED_CREATED_OFF + 2] << 8)
                         |  (uint32_t) buf[CRED_CREATED_OFF + 3];
        }
    }
    return 0;
}

/* Orphan-scrub (design §4): a bit goes only when its metadata slot reads
 * empty.  A read error or bad content keeps it; such a credential then
 * fails to resolve, and its key is erased before the slot is reused. */
static void orphan_scrub(uint32_t *bitmap)
{
    uint32_t bm = *bitmap;
    for (int i = 0; i < (int) FIDO_SLOTS_MAX; ++i) {
        slot_meta_t tmp;
        if ((bm & (1u << i)) != 0u && read_cred(i, &tmp) == -3) {
            bm &= ~(1u << i);
        }
    }
    *bitmap = bm;
}

/* ----- Public API ----- */

int slots_init(void)
{
    uint8_t buf[O1_LEN];
    size_t n = 0;
    if (s_initted) {
        return s_o1.uncertain ? -1 : SLOTS_INIT_OK;
    }
    if (tropic_l3_session_ensure() != 0) {
        return -1;
    }
    rec_status_t st = rec_pair_read(&s_o1, buf, sizeof buf, &n, NULL);
    if (st == REC_ABSENT) {
        return SLOTS_INIT_ABSENT;
    }
    if (st != REC_OK || n != O1_LEN || buf[4] > 1u || buf[5] > 1u
        || (be32_load(buf) >> FIDO_SLOTS_MAX) != 0u) {
        return -2;                       /* damaged / unreadable: refuse */
    }
    s_bitmap = be32_load(buf);
    s_force_uv = buf[4];
    s_pin_bound = buf[5];
    s_initted = 1;

    uint32_t scrubbed = s_bitmap;
    orphan_scrub(&scrubbed);
    if (scrubbed != s_bitmap && write_global(scrubbed, s_force_uv, s_pin_bound) != 0) {
        s_initted = 0;
        return -3;
    }
    return SLOTS_INIT_OK;
}

int slots_init_fresh(void)
{
    uint8_t buf[O1_LEN];
    o1_encode(buf, 0u, 0u, 0u);
    s_initted = 0;
    s_o1.uncertain = false;   /* reset = the way out (design §6): checked erase + rewrite */
    if (rec_pair_init(&s_o1, buf, sizeof buf) != REC_OK) {
        return -1;
    }
    s_bitmap = 0;
    s_force_uv = 0;
    s_pin_bound = 0;
    s_initted = 1;
    return 0;
}

int slots_wipe_meta(void)
{
    uint8_t probe[8];
    for (int i = 0; i < (int) FIDO_SLOTS_MAX; ++i) {
        uint16_t rs = SLOTS_RMEM_SLOT_FOR(i);
        size_t got = 0;
        if (tropic_rmem_erase(rs) != 0) return -1;
        int rc = tropic_rmem_read(rs, probe, sizeof probe, &got);
        if (rc != TROPIC_ERR_RMEM_SLOT_EMPTY && !(rc == 0 && got == 0u)) return -1;
    }
    return 0;
}

int slots_alloc(const uint8_t rp_id_hash[SLOTS_RP_ID_HASH_LEN],
                uint8_t alg, uint8_t flags,
                const uint8_t *user_handle, size_t user_handle_len,
                uint32_t created, uint32_t replace_mask,
                uint8_t out_cred_id[SLOTS_CRED_ID_LEN],
                int *out_slot_idx)
{
    if (!slots_usable()) {
        return -2;
    }
    if (rp_id_hash == NULL || out_cred_id == NULL || out_slot_idx == NULL) {
        return -1;
    }
    if (user_handle_len > SLOTS_USER_HANDLE_MAX) {
        return -1;
    }
    /* Find first free slot.  Phase 7 M1: cap at FIDO_SLOTS_MAX (29);
     * slots 29/30/31 are reserved for OpenPGP sig/dec/aut keys.  At
     * full FIDO load this returns -1 (full) even though chip slots
     * 29..31 may be physically unused for OpenPGP — that's the
     * documented 29-credential cap (L6 in PHASE-7-PLAN.md §3). */
    int idx = -1;
    for (int i = 0; i < (int) FIDO_SLOTS_MAX; ++i) {
        if ((s_bitmap & (1u << i)) == 0u) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        return -1;     /* full (FIDO quota exhausted at 29 credentials) */
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
    if (write_cred(idx, alg, flags, rp_id_hash, nonce,
                   user_handle, user_handle_len, created) != 0) {
        return -2;
    }

    /* One bitmap write adds the new credential and drops the ones it
     * replaces (only allocated FIDO slots can be replaced). */
    uint32_t fido_mask  = (1u << FIDO_SLOTS_MAX) - 1u;
    uint32_t new_bitmap = (s_bitmap | (1u << idx)) & ~(replace_mask & fido_mask);
    if (write_global(new_bitmap, s_force_uv, s_pin_bound) != 0) {
        /* Maybe published, maybe not: keep the metadata (and the caller
         * keeps the key); the O1 pair is uncertain until the next boot. */
        return -3;
    }

    /* Emit cred ID. */
    out_cred_id[0] = 0x01;
    out_cred_id[1] = (uint8_t) idx;
    memcpy(&out_cred_id[2], nonce, SLOTS_CRED_ID_NONCE_LEN);
    *out_slot_idx = idx;
    return 0;
}

int slots_lookup_by_credid(const uint8_t *cred_id, size_t cred_id_len,
                           int *out_slot_idx, slot_meta_t *out_meta)
{
    if (!slots_usable()) {
        return -1;
    }
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
    if (idx >= FIDO_SLOTS_MAX) {      /* 29..31 are OpenPGP key slots */
        return -1;
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
    if (out_meta != NULL) {
        *out_meta = meta;
    }
    return 0;
}

int slots_erase(int slot_idx)
{
    if (slot_idx < 0 || slot_idx >= (int) FIDO_SLOTS_MAX) {
        return -1;
    }
    if (!slots_usable()) {
        return -2;
    }
    /* Clear bit first, then erase R-mem. If power-loss between the two,
     * the next boot's orphan_scrub will reconcile. */
    uint32_t new_bitmap = s_bitmap & ~(1u << slot_idx);
    if (new_bitmap != s_bitmap && write_global(new_bitmap, s_force_uv, s_pin_bound) != 0) {
        return -2;
    }
    /* The bitmap commit above already deleted the credential.  An erase
     * failure here leaves its metadata in R-mem until the slot is reused
     * (write_cred erases first): report it (Phase 9 M2).  The chip
     * answers OK for an already-empty slot. */
    if (tropic_rmem_erase(SLOTS_RMEM_SLOT_FOR(slot_idx)) != 0) {
        return -2;
    }
    return 0;
}

uint32_t slots_bitmap(void)
{
    return slots_usable() ? s_bitmap : 0u;
}

int slots_usable(void)
{
    return s_initted && !s_o1.uncertain;
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
    if (!slots_usable()) {
        return -2;
    }
    if (slot_idx < 0 || slot_idx >= (int) FIDO_SLOTS_MAX || out == NULL) {
        return -1;
    }
    if ((s_bitmap & (1u << slot_idx)) == 0u) {
        return -1;
    }
    int rc = read_cred(slot_idx, out);
    return rc == 0 ? 0 : (rc == -1 ? -1 : -2);
}

int slots_pin_bound(void)
{
    return slots_usable() ? (int) s_pin_bound : -1;
}

int slots_set_pin_bound(int bound, int force_uv_on)
{
    uint8_t uv = force_uv_on ? 1u : s_force_uv;
    return write_global(s_bitmap, uv, bound ? 1u : 0u);
}

/* ===== Force-UV accessors (Phase 6 M2) ===== */

int slots_force_uv_get(void)
{
    /* Unknown state reads as "on": the stricter policy (Phase 9 M3). */
    return slots_usable() ? (int) s_force_uv : 1;
}

int slots_force_uv_set(int value)
{
    return write_global(s_bitmap, value ? 1u : 0u, s_pin_bound);
}

void slots_make_cred_id(int slot_idx, const slot_meta_t *meta,
                        uint8_t out_cred_id[SLOTS_CRED_ID_LEN])
{
    out_cred_id[0] = 0x01u;
    out_cred_id[1] = (uint8_t) slot_idx;
    memcpy(&out_cred_id[2], meta->cred_id_nonce, SLOTS_CRED_ID_NONCE_LEN);
}

#ifdef NIXTROPIC_HOST_TEST
void slots_test_reboot(void)
{
    s_initted = 0;
    s_o1.uncertain = false;
}
#endif
