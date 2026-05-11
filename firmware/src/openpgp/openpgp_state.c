/*
 * Phase 7 M2 — OpenPGP applet state, persisted in R-mem slot 1.
 * See openpgp_state.h for the byte-level layout.
 *
 * For M2 the only callers are the read-only GET DATA paths; we read
 * R-mem on demand without caching.  M3 may add a write-through cache
 * once PUT DATA hits the hot path (signature counter increments,
 * cardholder edits etc).
 */

#include "openpgp_state.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "tropic/tropic.h"
#include "sha2.h"   /* trezor_crypto SHA-256 */

/* Magic identifies our PGP state from an arbitrary R-mem slot — slot 1
 * has no a-priori relationship to OpenPGP.  Bump if/when v1 layout
 * grows incompatible fields. */
static const uint8_t PGP_MAGIC[4]    = { 'P', 'G', '7', 'K' };
#define PGP_SCHEMA_VERSION  1u

/* pgp_state_present byte values (M3 — 3-state machine):
 *   0 = factory fresh (never bootstrapped) — next init auto-activates
 *   1 = Operational (PINs active, applet ready)
 *   2 = Terminated (TERMINATE DF sent — awaiting ACTIVATE FILE)
 */
#define PGP_STATE_FRESH        0u
#define PGP_STATE_OPERATIONAL  1u
#define PGP_STATE_TERMINATED   2u

/* Default OpenPGP card PINs per spec §4.3 — bootstrapped by activate().
 * User must change via `gpg --card-edit → passwd`. */
static const char PGP_DEFAULT_PW1[] = "123456";
static const char PGP_DEFAULT_PW3[] = "12345678";

/* Wire offsets (in R-mem slot 1 payload). */
#define OFF_MAGIC               0
#define OFF_MAGIC_LEN           4
#define OFF_SCHEMA              4
#define OFF_PGP_STATE_PRESENT   6
#define OFF_PW1_RETRIES         7
#define OFF_PW3_RETRIES         8
#define OFF_RC_RETRIES          9
#define OFF_FORCE_VERIFY       10
#define OFF_TOUCH_REQUIRED     11
#define OFF_RESERVED_UIF_LO    12  /* 2 B reserved (was per-slot UIF) */
#define OFF_NAME              14   /* 1 B len + 39 B data */
#define OFF_NAME_LEN          14
#define OFF_NAME_DATA         15
#define OFF_LANG              54   /* 2 B */
#define OFF_SEX               56   /* 1 B */
#define OFF_FPR_SIG           57   /* 20 B */
#define OFF_FPR_DEC           77   /* 20 B */
#define OFF_FPR_AUT           97   /* 20 B */
#define OFF_GENTIME_SIG      117   /* 4 B BE u32 */
#define OFF_GENTIME_DEC      121
#define OFF_GENTIME_AUT      125
#define OFF_SIG_COUNTER      129   /* 3 B BCD */
/* M3 — PIN hash storage.  v1 had these bytes reserved/zero, so old
 * state migrates cleanly (PIN hash region reads as zero → bootstrap
 * default PINs on first M3 boot). */
#define OFF_PW1_HASH         132   /* 16 B — SHA-256("123456")[:16] default */
#define OFF_PW3_HASH         148   /* 16 B — SHA-256("12345678")[:16] default */
#define OFF_RC_HASH          164   /* 16 B — all-zero if RC unset */

/* Read the full payload.  Returns 0 OK, -1 magic mismatch / unitialised,
 * -2 chip error. */
static int read_payload(uint8_t out[OPENPGP_RMEM_PRIMARY_SIZE])
{
    size_t got = 0;
    int rc = tropic_rmem_read(OPENPGP_RMEM_PRIMARY_SLOT, out,
                              OPENPGP_RMEM_PRIMARY_SIZE, &got);
    if (rc != 0 || got < (OFF_TOUCH_REQUIRED + 1u)) {
        return -2;
    }
    if (memcmp(&out[OFF_MAGIC], PGP_MAGIC, OFF_MAGIC_LEN) != 0) {
        return -1;
    }
    return 0;
}

/* Write a fully-formed payload back to R-mem slot 1.  Caller fills the
 * buffer; we erase + write. */
static int write_payload(const uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE])
{
    (void) tropic_rmem_erase(OPENPGP_RMEM_PRIMARY_SLOT);
    return tropic_rmem_write(OPENPGP_RMEM_PRIMARY_SLOT, buf,
                             OPENPGP_RMEM_PRIMARY_SIZE);
}

/* Write a fresh "Operational" state with defaults — PW1/PW3 default
 * PINs hashed, retry counters at max, sex 0x39, force_verify + touch
 * defaults on.  Used by both first-boot init and ACTIVATE FILE. */
static int write_activated_defaults(void)
{
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    memset(buf, 0, sizeof buf);

    memcpy(&buf[OFF_MAGIC], PGP_MAGIC, OFF_MAGIC_LEN);
    buf[OFF_SCHEMA]            = 0;
    buf[OFF_SCHEMA + 1]        = (uint8_t) PGP_SCHEMA_VERSION;
    buf[OFF_PGP_STATE_PRESENT] = PGP_STATE_OPERATIONAL;
    buf[OFF_PW1_RETRIES]       = OPENPGP_PW1_RETRIES_INITIAL;
    buf[OFF_PW3_RETRIES]       = OPENPGP_PW3_RETRIES_INITIAL;
    buf[OFF_RC_RETRIES]        = OPENPGP_RC_UNSET;
    buf[OFF_FORCE_VERIFY]      = 1;
    buf[OFF_TOUCH_REQUIRED]    = 1;
    buf[OFF_SEX]               = 0x39;  /* ISO 5218 "not applicable" */

    /* Hash default PINs into PW1 + PW3 slots.  SHA-256[:16] same
     * convention as Phase 5 pin.c. */
    uint8_t full[32];
    sha256_Raw((const uint8_t *) PGP_DEFAULT_PW1, (uint32_t) strlen(PGP_DEFAULT_PW1), full);
    memcpy(&buf[OFF_PW1_HASH], full, OPENPGP_PIN_HASH_LEN);
    sha256_Raw((const uint8_t *) PGP_DEFAULT_PW3, (uint32_t) strlen(PGP_DEFAULT_PW3), full);
    memcpy(&buf[OFF_PW3_HASH], full, OPENPGP_PIN_HASH_LEN);
    memset(full, 0, sizeof full);
    /* RC hash stays zero (RC unset). */

    return (write_payload(buf) == 0) ? 0 : -1;
}

int openpgp_state_init(void)
{
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];

    int rc = read_payload(buf);
    if (rc == -2) {
        return -1;  /* chip error */
    }

    if (rc == 0) {
        /* Existing PGP state — respect pgp_state_present.
         *   FRESH (0)        → bootstrap (M2 init wrote 0 too; legacy)
         *   OPERATIONAL (1)  → done, applet ready
         *   TERMINATED (2)   → respect; awaiting ACTIVATE FILE */
        uint8_t st = buf[OFF_PGP_STATE_PRESENT];
        if (st == PGP_STATE_OPERATIONAL || st == PGP_STATE_TERMINATED) {
            return 0;
        }
        /* PGP_STATE_FRESH (0) → fall through to bootstrap */
    }

    /* First-boot init OR upgrade-from-M2-state — write defaults. */
    return write_activated_defaults();
}

int openpgp_state_activate(void)
{
    return write_activated_defaults();
}

int openpgp_state_terminate(void)
{
    /* Wipe slot 1 — PIN hashes + cardholder + fingerprints + everything.
     * Magic + schema + pgp_state_present = TERMINATED stay. */
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    memset(buf, 0, sizeof buf);
    memcpy(&buf[OFF_MAGIC], PGP_MAGIC, OFF_MAGIC_LEN);
    buf[OFF_SCHEMA]            = 0;
    buf[OFF_SCHEMA + 1]        = (uint8_t) PGP_SCHEMA_VERSION;
    buf[OFF_PGP_STATE_PRESENT] = PGP_STATE_TERMINATED;
    buf[OFF_RC_RETRIES]        = OPENPGP_RC_UNSET;
    buf[OFF_SEX]               = 0x39;
    return (write_payload(buf) == 0) ? 0 : -1;
}

/* ---- Read accessors ---- */

uint8_t openpgp_state_force_verify_get(void)
{
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return 1;  /* default-safe */
    return (buf[OFF_FORCE_VERIFY] != 0u) ? 1u : 0u;
}

uint8_t openpgp_state_touch_required_get(void)
{
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return 1;  /* default-safe */
    return buf[OFF_TOUCH_REQUIRED];
}

uint8_t openpgp_state_pw1_retries_get(void)
{
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return OPENPGP_PW1_RETRIES_INITIAL;
    return buf[OFF_PW1_RETRIES];
}

uint8_t openpgp_state_pw3_retries_get(void)
{
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return OPENPGP_PW3_RETRIES_INITIAL;
    return buf[OFF_PW3_RETRIES];
}

uint8_t openpgp_state_rc_retries_get(void)
{
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return OPENPGP_RC_UNSET;
    return buf[OFF_RC_RETRIES];
}

int openpgp_state_fingerprint_get(int slot_idx, uint8_t out[OPENPGP_FPR_LEN])
{
    if (slot_idx < 0 || slot_idx > 2 || out == NULL) return -1;
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) {
        memset(out, 0, OPENPGP_FPR_LEN);
        return -2;
    }
    size_t off = (size_t) OFF_FPR_SIG + (size_t)(slot_idx * (int) OPENPGP_FPR_LEN);
    memcpy(out, &buf[off], OPENPGP_FPR_LEN);
    return 0;
}

int openpgp_state_gentime_get(int slot_idx, uint8_t out[OPENPGP_GENTIME_LEN])
{
    if (slot_idx < 0 || slot_idx > 2 || out == NULL) return -1;
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) {
        memset(out, 0, OPENPGP_GENTIME_LEN);
        return -2;
    }
    size_t off = (size_t) OFF_GENTIME_SIG + (size_t)(slot_idx * (int) OPENPGP_GENTIME_LEN);
    memcpy(out, &buf[off], OPENPGP_GENTIME_LEN);
    return 0;
}

int openpgp_state_sig_counter_get(uint8_t out[OPENPGP_SIG_COUNTER_LEN])
{
    if (out == NULL) return -1;
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) {
        memset(out, 0, OPENPGP_SIG_COUNTER_LEN);
        return -2;
    }
    memcpy(out, &buf[OFF_SIG_COUNTER], OPENPGP_SIG_COUNTER_LEN);
    return 0;
}

int openpgp_state_name_get(uint8_t out[OPENPGP_NAME_MAX], size_t *out_len)
{
    if (out == NULL || out_len == NULL) return -1;
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) {
        *out_len = 0;
        return -2;
    }
    uint8_t len = buf[OFF_NAME_LEN];
    if (len > OPENPGP_NAME_MAX) len = OPENPGP_NAME_MAX;
    memcpy(out, &buf[OFF_NAME_DATA], len);
    *out_len = len;
    return 0;
}

int openpgp_state_lang_get(uint8_t out[OPENPGP_LANG_LEN])
{
    if (out == NULL) return -1;
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) {
        memset(out, 0, OPENPGP_LANG_LEN);
        return -2;
    }
    memcpy(out, &buf[OFF_LANG], OPENPGP_LANG_LEN);
    return 0;
}

uint8_t openpgp_state_sex_get(void)
{
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return 0x39;  /* "not applicable" */
    uint8_t sex = buf[OFF_SEX];
    return (sex == 0u) ? 0x39u : sex;
}

/* ---- M3 PIN hash + retry accessors ---- */

static int pin_hash_offset(int which, size_t *out_off)
{
    switch (which) {
    case OPENPGP_PIN_PW1: *out_off = OFF_PW1_HASH; return 0;
    case OPENPGP_PIN_PW3: *out_off = OFF_PW3_HASH; return 0;
    case OPENPGP_PIN_RC:  *out_off = OFF_RC_HASH;  return 0;
    default: return -1;
    }
}

static int pin_retries_offset(int which, size_t *out_off)
{
    switch (which) {
    case OPENPGP_PIN_PW1: *out_off = OFF_PW1_RETRIES; return 0;
    case OPENPGP_PIN_PW3: *out_off = OFF_PW3_RETRIES; return 0;
    case OPENPGP_PIN_RC:  *out_off = OFF_RC_RETRIES;  return 0;
    default: return -1;
    }
}

int openpgp_state_pin_hash_get(int which, uint8_t out[OPENPGP_PIN_HASH_LEN])
{
    size_t off;
    if (pin_hash_offset(which, &off) != 0 || out == NULL) return -1;
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return -2;
    memcpy(out, &buf[off], OPENPGP_PIN_HASH_LEN);
    return 0;
}

int openpgp_state_pin_hash_set(int which,
                               const uint8_t hash[OPENPGP_PIN_HASH_LEN])
{
    size_t off;
    if (pin_hash_offset(which, &off) != 0 || hash == NULL) return -1;
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return -2;
    memcpy(&buf[off], hash, OPENPGP_PIN_HASH_LEN);
    return (write_payload(buf) == 0) ? 0 : -2;
}

int openpgp_state_pin_retries_set(int which, uint8_t v)
{
    size_t off;
    if (pin_retries_offset(which, &off) != 0) return -1;
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return -2;
    buf[off] = v;
    return (write_payload(buf) == 0) ? 0 : -2;
}

uint8_t openpgp_state_present_get(void)
{
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return PGP_STATE_FRESH;
    return buf[OFF_PGP_STATE_PRESENT];
}

int openpgp_state_present_set(uint8_t v)
{
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return -2;
    buf[OFF_PGP_STATE_PRESENT] = v;
    return (write_payload(buf) == 0) ? 0 : -2;
}

/* ---- M3 writable DO setters (PUT DATA) ---- */

int openpgp_state_name_set(const uint8_t *data, size_t len)
{
    if (len > OPENPGP_NAME_MAX) return -1;
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return -2;
    buf[OFF_NAME_LEN] = (uint8_t) len;
    if (len > 0u && data != NULL) {
        memcpy(&buf[OFF_NAME_DATA], data, len);
    }
    /* Zero the rest of the name buffer (cosmetic — stale bytes
     * shouldn't affect read_name_get since it honours the length byte,
     * but keeps R-mem dumps tidy). */
    if (len < OPENPGP_NAME_MAX) {
        memset(&buf[OFF_NAME_DATA + len], 0,
               (size_t)(OPENPGP_NAME_MAX - len));
    }
    return (write_payload(buf) == 0) ? 0 : -2;
}

int openpgp_state_lang_set(const uint8_t data[OPENPGP_LANG_LEN])
{
    if (data == NULL) return -1;
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return -2;
    memcpy(&buf[OFF_LANG], data, OPENPGP_LANG_LEN);
    return (write_payload(buf) == 0) ? 0 : -2;
}

int openpgp_state_sex_set(uint8_t v)
{
    /* Spec values: '1' (0x31) male, '2' (0x32) female, '9' (0x39) NA. */
    if (v != 0x31u && v != 0x32u && v != 0x39u) return -1;
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return -2;
    buf[OFF_SEX] = v;
    return (write_payload(buf) == 0) ? 0 : -2;
}

int openpgp_state_force_verify_set(uint8_t v)
{
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return -2;
    buf[OFF_FORCE_VERIFY] = (v != 0u) ? 1u : 0u;
    return (write_payload(buf) == 0) ? 0 : -2;
}

int openpgp_state_touch_required_set(uint8_t v)
{
    /* 0 = off, 1 = enabled, 2 = permanent.  Permanent should only be
     * set via vendor command (Phase 8 polish); applet PUT DATA path
     * accepts 0 / 1 only. */
    if (v > 2u) return -1;
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return -2;
    /* Refuse to UN-permanent (downgrade from 0x02) — only ACTIVATE FILE
     * can clear it. */
    if (buf[OFF_TOUCH_REQUIRED] == 2u && v != 2u) {
        return -3;  /* SW_CONDITIONS_NOT_SATISFIED at caller */
    }
    buf[OFF_TOUCH_REQUIRED] = v;
    return (write_payload(buf) == 0) ? 0 : -2;
}
