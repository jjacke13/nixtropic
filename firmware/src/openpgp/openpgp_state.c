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

/* Magic identifies our PGP state from an arbitrary R-mem slot — slot 1
 * has no a-priori relationship to OpenPGP.  Bump if/when v1 layout
 * grows incompatible fields. */
static const uint8_t PGP_MAGIC[4]    = { 'P', 'G', '7', 'K' };
#define PGP_SCHEMA_VERSION  1u

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

int openpgp_state_init(void)
{
    uint8_t buf[OPENPGP_RMEM_PRIMARY_SIZE];

    int rc = read_payload(buf);
    if (rc == 0) {
        return 0;  /* already initialised */
    }
    if (rc == -2) {
        return -1;  /* chip error — don't paper over */
    }

    /* Magic mismatch — first-boot init.  Zero-fill, then stamp magic
     * + schema + defaults. */
    memset(buf, 0, sizeof buf);
    memcpy(&buf[OFF_MAGIC], PGP_MAGIC, OFF_MAGIC_LEN);
    buf[OFF_SCHEMA]               = 0;
    buf[OFF_SCHEMA + 1]           = (uint8_t) PGP_SCHEMA_VERSION;
    buf[OFF_PGP_STATE_PRESENT]    = 0;  /* not initialised by ACTIVATE FILE yet */
    buf[OFF_PW1_RETRIES]          = OPENPGP_PW1_RETRIES_INITIAL;
    buf[OFF_PW3_RETRIES]          = OPENPGP_PW3_RETRIES_INITIAL;
    buf[OFF_RC_RETRIES]           = OPENPGP_RC_UNSET;
    buf[OFF_FORCE_VERIFY]         = 1;  /* spec-recommended default */
    buf[OFF_TOUCH_REQUIRED]       = 1;  /* single global flag — default ON */
    /* Sex byte unset = ISO 5218 "9" (0x39, "not applicable"). */
    buf[OFF_SEX]                  = 0x39;

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
