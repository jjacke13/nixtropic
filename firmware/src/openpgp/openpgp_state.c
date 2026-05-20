/*
 * Phase 7 M2 — OpenPGP applet state, persisted in R-mem slot 33 (was
 * slot 1 pre Phase 8 collision fix — see PRIMARY_SLOT comment in the
 * header).
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
 * has no a-priori relationship to OpenPGP.  Bumped 'PG7K' → 'PG7L'
 * at Phase 7 M3 HW debug (2026-05-12) to force re-init after the
 * 475-byte writes left slot 1 in an inconsistent state.  Bump again
 * if/when v1 layout grows incompatible fields. */
/* Bumped 'PG7L' → 'PG7M' at Phase 7 M5a flash 2026-05-12 — the prior
 * M4 state had a corrupted PW3 hash (or retry counter at 0) of unknown
 * cause; cleanest recovery is to force re-bootstrap via magic mismatch.
 * Any future state-shape change should bump this byte. */
/* Bumped 'PG7M' → 'PG7N' at M6 audit H2 fix 2026-05-12 — schema now
 * stores PIN lengths at offsets 212-214 so CHANGE REFERENCE DATA /
 * RESET RETRY COUNTER can split the APDU body at the canonical
 * boundary (OpenPGP card v3.4.1 §7.2.6) without an exhaustive search
 * that would consume the retry counter in a single APDU.  Existing
 * PG7M state is wiped: user re-enters default PINs after upgrade. */
/* Bumped 'PG7N' → 'PG7O' at Phase 8 cosmetic polish 2026-05-20 — DO
 * 5F2D Language preference now defaults to "en" instead of all-zero,
 * so `gpg --card-status` shows "Language: en" out of the box rather
 * than the raw `\xff\xff` / `\x00\x00` placeholder.  PG7N state is
 * wiped: PINs go back to defaults (123456 / 12345678). */
/* Bumped 'PG7O' → 'PG7P' at Phase 8 M4.0 (2026-05-20) — `force_verify`
 * default flipped 1 → 0 so `gpg` prompts for PW1 once per dongle
 * plug-in instead of for every PSO:CDS / PSO:DEC.  Daily-driver model
 * is now "PIN once, touch every op", matching Yubikey defaults.  PG7O
 * state is wiped: PINs go back to defaults (123456 / 12345678) and
 * user must re-run `gpg --card-edit > admin > generate`. */
/* Bumped 'PG7P' → 'PG7Q' at Phase 8 R-mem collision fix (2026-05-20) —
 * OpenPGP primary state moved from R-mem slot 1 to slot 33 to avoid
 * being overwritten by FIDO per-credential allocation (slot_idx=0
 * lands on R-mem slot 1).  Old slot-1 PG7P state is no longer read;
 * fresh PG7Q state initialises with defaults in slot 33.  User must
 * regenerate keys via `gpg --card-edit > admin > generate`.
 * FIDO credentials previously co-resident in slot 1 are also lost —
 * webauthn.io re-registration required. */
static const uint8_t PGP_MAGIC[4]    = { 'P', 'G', '7', 'Q' };
#define PGP_SCHEMA_VERSION  5u

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

/* Wire offsets (in R-mem primary payload). */
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
#define OFF_DEC_PRIV         180   /* 32 B — X25519 priv key, all-zero if no dec key yet */
/* M6 audit H2 fix — PIN length storage.  Schema v2 (PG7N) adds these
 * so CHANGE REF / RESET RC split the APDU body at the canonical
 * boundary instead of looping over plausible splits (which would
 * consume the retry counter on every wrong split in a single APDU). */
#define OFF_PW1_LEN          212   /* 1 B — actual byte length of current PW1 */
#define OFF_PW3_LEN          213   /* 1 B — actual byte length of current PW3 */
#define OFF_RC_LEN           214   /* 1 B — actual byte length of current RC, 0 if unset */

/* Read the full payload.
 *
 * Return codes (distinct for HW debug — Phase 7 M3 iteration
 * 2026-05-12):
 *   0   OK
 *  -1   magic mismatch (slot present but our magic missing)
 *  -3   chip read error (tropic_rmem_read returned non-zero)
 *  -4   short read (got fewer bytes than minimum-viable header) */
static int read_payload(uint8_t out[OPENPGP_RMEM_PRIMARY_SIZE])
{
    size_t got = 0;
    int rc = tropic_rmem_read(OPENPGP_RMEM_PRIMARY_SLOT, out,
                              OPENPGP_RMEM_PRIMARY_SIZE, &got);
    if (rc != 0) {
        return -3;
    }
    if (got < (OFF_TOUCH_REQUIRED + 1u)) {
        return -4;
    }
    if (memcmp(&out[OFF_MAGIC], PGP_MAGIC, OFF_MAGIC_LEN) != 0) {
        return -1;
    }
    return 0;
}

/* Write a fully-formed payload back to R-mem primary slot.  Caller fills the
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
    /* Phase 8 M4.0 — default force_verify = 0 so the user is prompted
     * for PW1 once per plug-in instead of for every PSO:CDS / PSO:DEC
     * / INTERNAL AUTHENTICATE.  Combined with the UIF gate (commit
     * 98486f4) the daily-driver model is "PIN once, touch every op",
     * matching Yubikey defaults.  Toggle at runtime via DO C4 PUT DATA
     * (gpg --card-edit > admin > forcesig) OR the lt-rpc
     * PGP_FORCE_VERIFY_SET vendor command (future CLI). */
    buf[OFF_FORCE_VERIFY]      = 0;
    buf[OFF_TOUCH_REQUIRED]    = 1;
    buf[OFF_SEX]               = 0x39;  /* ISO 5218 "not applicable" */
    /* DO 5F2D Language preference — default to "en" (ISO 639-1) so
     * gpg --card-status shows "Language: en" out of the box.  User
     * can override via card-edit > admin > lang <code>. */
    buf[OFF_LANG]              = 'e';
    buf[OFF_LANG + 1]          = 'n';

    /* Hash default PINs into PW1 + PW3 slots.  SHA-256[:16] same
     * convention as Phase 5 pin.c. */
    uint8_t full[32];
    size_t pw1_len = strlen(PGP_DEFAULT_PW1);
    size_t pw3_len = strlen(PGP_DEFAULT_PW3);
    sha256_Raw((const uint8_t *) PGP_DEFAULT_PW1, (uint32_t) pw1_len, full);
    memcpy(&buf[OFF_PW1_HASH], full, OPENPGP_PIN_HASH_LEN);
    sha256_Raw((const uint8_t *) PGP_DEFAULT_PW3, (uint32_t) pw3_len, full);
    memcpy(&buf[OFF_PW3_HASH], full, OPENPGP_PIN_HASH_LEN);
    memset(full, 0, sizeof full);
    /* RC hash stays zero (RC unset). */

    /* M6 audit H2 — record PIN lengths so CHANGE REF can split the
     * body at the canonical boundary on a single attempt. */
    buf[OFF_PW1_LEN] = (uint8_t) pw1_len;
    buf[OFF_PW3_LEN] = (uint8_t) pw3_len;
    buf[OFF_RC_LEN]  = 0u;  /* RC unset */

    return (write_payload(buf) == 0) ? 0 : -1;
}

int openpgp_state_init(void)
{
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];

    int rc = read_payload(buf);
    /* M6 audit M3 — only magic mismatch (-1) falls through to write
     * defaults.  Chip read errors (-3) or short reads (-4) must NOT
     * trigger a silent re-init: that would factory-wipe state on any
     * transient TROPIC01 communication glitch.  read_payload never
     * returns -2 (legacy dead branch removed). */
    if (rc == -3 || rc == -4) {
        return -1;  /* chip error — applet returns SW=6F00 on dispatch */
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

static int pin_len_offset(int which, size_t *out_off)
{
    switch (which) {
    case OPENPGP_PIN_PW1: *out_off = OFF_PW1_LEN; return 0;
    case OPENPGP_PIN_PW3: *out_off = OFF_PW3_LEN; return 0;
    case OPENPGP_PIN_RC:  *out_off = OFF_RC_LEN;  return 0;
    default: return -1;
    }
}

int openpgp_state_pin_hash_get(int which, uint8_t out[OPENPGP_PIN_HASH_LEN])
{
    size_t off;
    if (pin_hash_offset(which, &off) != 0 || out == NULL) return -1;
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    /* Propagate the distinct read_payload error code so the caller can
     * surface which failure mode tripped: -1 magic, -3 chip read, -4
     * short read.  pgp_pin.c translates each to its own SW value. */
    int rc = read_payload(buf);
    if (rc != 0) return rc;
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

int openpgp_state_pin_len_get(int which, uint8_t *out)
{
    if (out == NULL) return -1;
    size_t off;
    if (pin_len_offset(which, &off) != 0) return -1;
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return -2;
    *out = buf[off];
    return 0;
}

int openpgp_state_pin_len_set(int which, uint8_t v)
{
    size_t off;
    if (pin_len_offset(which, &off) != 0) return -1;
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

/* ---- M4 fingerprint / gentime / sig counter writers ---- */

static int slot_idx_to_fpr_offset(int slot_idx, size_t *out_off)
{
    switch (slot_idx) {
    case 0: *out_off = OFF_FPR_SIG; return 0;
    case 1: *out_off = OFF_FPR_DEC; return 0;
    case 2: *out_off = OFF_FPR_AUT; return 0;
    default: return -1;
    }
}

static int slot_idx_to_gentime_offset(int slot_idx, size_t *out_off)
{
    switch (slot_idx) {
    case 0: *out_off = OFF_GENTIME_SIG; return 0;
    case 1: *out_off = OFF_GENTIME_DEC; return 0;
    case 2: *out_off = OFF_GENTIME_AUT; return 0;
    default: return -1;
    }
}

int openpgp_state_fingerprint_set(int slot_idx,
                                   const uint8_t fpr[OPENPGP_FPR_LEN])
{
    size_t off;
    if (slot_idx_to_fpr_offset(slot_idx, &off) != 0 || fpr == NULL) return -1;
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return -2;
    memcpy(&buf[off], fpr, OPENPGP_FPR_LEN);
    return (write_payload(buf) == 0) ? 0 : -2;
}

int openpgp_state_gentime_set(int slot_idx,
                               const uint8_t gt[OPENPGP_GENTIME_LEN])
{
    size_t off;
    if (slot_idx_to_gentime_offset(slot_idx, &off) != 0 || gt == NULL) return -1;
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return -2;
    memcpy(&buf[off], gt, OPENPGP_GENTIME_LEN);
    return (write_payload(buf) == 0) ? 0 : -2;
}

int openpgp_state_dec_priv_get(uint8_t out[OPENPGP_DEC_PRIV_LEN])
{
    if (out == NULL) return -1;
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return -2;
    memcpy(out, &buf[OFF_DEC_PRIV], OPENPGP_DEC_PRIV_LEN);
    return 0;
}

int openpgp_state_dec_priv_set(const uint8_t key[OPENPGP_DEC_PRIV_LEN])
{
    if (key == NULL) return -1;
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return -2;
    memcpy(&buf[OFF_DEC_PRIV], key, OPENPGP_DEC_PRIV_LEN);
    return (write_payload(buf) == 0) ? 0 : -2;
}

int openpgp_state_sig_counter_increment(void)
{
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];
    if (read_payload(buf) != 0) return -2;
    /* DO 93 is 3 B BCD per OpenPGP spec §4.4.3.2 — the counter is a
     * binary integer encoded big-endian in 3 bytes (NOT actual BCD).
     * 24-bit range = up to ~16M signatures before wrap.  Wrap is
     * benign (no spec-defined effect; gpg just sees the counter
     * reset). */
    uint32_t ctr =
        ((uint32_t) buf[OFF_SIG_COUNTER + 0] << 16) |
        ((uint32_t) buf[OFF_SIG_COUNTER + 1] << 8)  |
        ((uint32_t) buf[OFF_SIG_COUNTER + 2]);
    ctr = (ctr + 1u) & 0x00FFFFFFu;
    buf[OFF_SIG_COUNTER + 0] = (uint8_t)((ctr >> 16) & 0xFFu);
    buf[OFF_SIG_COUNTER + 1] = (uint8_t)((ctr >>  8) & 0xFFu);
    buf[OFF_SIG_COUNTER + 2] = (uint8_t)( ctr        & 0xFFu);
    return (write_payload(buf) == 0) ? 0 : -2;
}
