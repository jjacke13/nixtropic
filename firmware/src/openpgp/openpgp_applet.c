/*
 * Phase 7 M2 — OpenPGP applet dispatcher.  See openpgp_applet.h.
 *
 * Hand-rolled BER-TLV emitter for composite DOs.  No malloc.  All
 * buffers are caller-supplied; we bounds-check every byte.
 */

#include "openpgp_applet.h"
#include "openpgp_aid.h"
#include "openpgp_state.h"
#include "ccid/ccid_proto.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ===== ISO 7816 INS bytes we recognise ===== */
#define INS_SELECT       0xA4
#define INS_GET_DATA     0xCA

/* ===== Algorithm-attribute byte sequences (DO C1/C2/C3) =====
 *
 * Per OpenPGP card v3.4.1 §4.4.3.7:
 *
 *   Ed25519 (sig, aut):
 *     algorithm_id = 0x16 (EdDSA)
 *     OID          = 2B 06 01 04 01 DA 47 0F 01  (1.3.6.1.4.1.11591.15.1)
 *     Total: 10 bytes
 *
 *   Cv25519 (dec):
 *     algorithm_id = 0x12 (ECDH)
 *     OID          = 2B 06 01 04 01 97 55 01 05 01  (1.3.6.1.4.1.3029.1.5.1)
 *     Total: 11 bytes
 *
 * Minimal form — no KDF/sym suffix; GnuPG accepts.  If a future GnuPG
 * version rejects ECDH attrs without KDF, append ` 03 01 08 07` (KDF
 * type 0x03 + cipher AES-128 + KDF hash SHA-256 + sym AES-128).
 */
static const uint8_t ALGO_ED25519[]  = {
    0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01
};
static const uint8_t ALGO_CV25519[]  = {
    0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01
};

/* ===== Extended capabilities (DO C0) per spec §4.4.3.6 =====
 *
 *   [0] = 0x70 — bit 6=KDF-DO present? 5=PSO:DEC present? 4=Algo Attrs
 *                writable.  Set: bit 6 (KDF DO support — we say yes
 *                but don't actually implement F9 in M2), bit 5 (PSO:DEC
 *                will be supported in M5), bit 4 (Algo Attrs writable
 *                in M3+).  Conservative for M2.
 *   [1] = 0x00 — Secure Messaging support (none — M5 may add)
 *   [2..3] = max length Get Challenge response (LE) = 0
 *   [4..5] = max length Card Holder Certificate = 0
 *   [6..7] = max special DO length = 0
 *   [8]    = Pin block 2 format support = 0
 *   [9]    = MSE command support = 0
 *
 * Total 10 bytes.  Conservative defaults; we expand in later milestones
 * if a host expects more.  GnuPG accepts this minimal form.
 */
static const uint8_t EXT_CAPS[] = {
    0x70,                          /* features bitmap */
    0x00,                          /* SM */
    0x00, 0x00,                    /* max Get Challenge resp */
    0x00, 0x00,                    /* max cert */
    0x00, 0x00,                    /* max special DO */
    0x00,                          /* PIN block 2 */
    0x00                           /* MSE */
};

/* ===== Historical bytes (DO 5F52) =====
 *
 * Minimal valid compressed-status form per ISO 7816-4 §8.1.1.3:
 *   00          — category indicator: "status indicator in compressed TLV form"
 *   31 84 73 80 — pre-issuing data (mfg + chip) — not strictly required
 *                 but some hosts log it; OmniKey-style placeholder
 *   90 00       — last 2 bytes: SW = 0x9000 marker for "valid card"
 *
 * Actually let's keep it tighter — 4 bytes:  00 73 80 90 00 5
 * Spec §8.1.1.3 says minimum compressed-status form ends with `90 00`.
 * Use:  00 73 80 90 00  (5 bytes)
 *   00      — category indicator
 *   73 80   — card service data + life-cycle: select by full DF, no SE
 *   90 00   — final 2 bytes = "card is OK"
 */
static const uint8_t HISTORICAL_BYTES[] = {
    0x00, 0x73, 0x80, 0x90, 0x00
};

/* ===== Helpers ===== */

static int emit_sw(uint16_t sw, uint8_t *out, size_t out_max, size_t *out_len)
{
    if (out_max < 2u) return -1;
    if (*out_len + 2u > out_max) {
        /* Truncate any partial response and emit just the SW. */
        *out_len = 0;
        if (out_max < 2u) return -1;
    }
    out[*out_len]      = (uint8_t)((sw >> 8) & 0xFFu);
    out[*out_len + 1u] = (uint8_t)( sw       & 0xFFu);
    *out_len += 2u;
    return 0;
}

/* BER-TLV: emit a 1- or 2-byte tag.  Returns bytes written or -1 if no room. */
static int emit_tag(uint8_t *out, size_t out_max, size_t *off, uint16_t tag)
{
    if (tag < 0x100u) {
        if (*off + 1u > out_max) return -1;
        out[*off] = (uint8_t)(tag & 0xFFu);
        *off += 1u;
        return 1;
    } else {
        if (*off + 2u > out_max) return -1;
        out[*off]      = (uint8_t)((tag >> 8) & 0xFFu);
        out[*off + 1u] = (uint8_t)( tag       & 0xFFu);
        *off += 2u;
        return 2;
    }
}

/* BER-TLV: emit a length (1, 2, or 3 byte form).  Lengths < 0x80 use
 * 1-byte form; <= 0xFF uses `81 LL`; up to 0xFFFF uses `82 LH LL`. */
static int emit_len(uint8_t *out, size_t out_max, size_t *off, size_t len)
{
    if (len < 0x80u) {
        if (*off + 1u > out_max) return -1;
        out[*off] = (uint8_t) len;
        *off += 1u;
        return 1;
    } else if (len <= 0xFFu) {
        if (*off + 2u > out_max) return -1;
        out[*off]      = 0x81u;
        out[*off + 1u] = (uint8_t) len;
        *off += 2u;
        return 2;
    } else {
        if (*off + 3u > out_max) return -1;
        out[*off]      = 0x82u;
        out[*off + 1u] = (uint8_t)((len >> 8) & 0xFFu);
        out[*off + 2u] = (uint8_t)( len       & 0xFFu);
        *off += 3u;
        return 3;
    }
}

/* Emit a complete TLV: tag + length + value. */
static int emit_tlv(uint8_t *out, size_t out_max, size_t *off,
                    uint16_t tag, const uint8_t *value, size_t value_len)
{
    if (emit_tag(out, out_max, off, tag) < 0) return -1;
    if (emit_len(out, out_max, off, value_len) < 0) return -1;
    if (*off + value_len > out_max) return -1;
    if (value_len > 0u && value != NULL) {
        memcpy(&out[*off], value, value_len);
    }
    *off += value_len;
    return 0;
}

/* ===== Composite DO builders ===== */

/* PW status (DO C4) — 7 bytes. */
static void build_pw_status(uint8_t out[7])
{
    out[0] = openpgp_state_force_verify_get();  /* PW1 force-verify */
    out[1] = 64u;                               /* PW1 max length */
    out[2] = 64u;                               /* RC max length */
    out[3] = 64u;                               /* PW3 max length */
    out[4] = openpgp_state_pw1_retries_get();
    uint8_t rc = openpgp_state_rc_retries_get();
    out[5] = (rc == OPENPGP_RC_UNSET) ? 0u : rc;
    out[6] = openpgp_state_pw3_retries_get();
}

/* Fingerprints (DO C5) — 60 B concatenated sig||dec||aut.  Returns
 * 0 OK, -1 on chip error (still writes zero buffer). */
static void build_fingerprints(uint8_t out[60])
{
    (void) openpgp_state_fingerprint_get(0, &out[0]);
    (void) openpgp_state_fingerprint_get(1, &out[20]);
    (void) openpgp_state_fingerprint_get(2, &out[40]);
}

/* Generation timestamps (DO CD) — 12 B concatenated. */
static void build_gentimes(uint8_t out[12])
{
    (void) openpgp_state_gentime_get(0, &out[0]);
    (void) openpgp_state_gentime_get(1, &out[4]);
    (void) openpgp_state_gentime_get(2, &out[8]);
}

/* Emit a constructed DO wrapper around the bytes a builder writes.
 * Pattern: emit tag, reserve worst-case 3-byte length, run builder,
 * then back-patch the length and shift content if a shorter length
 * encoding is sufficient.  Used for GET DATA on composite tags 65 /
 * 6E / 7A and for the nested 73 inside 6E. */
static int emit_constructed(uint8_t *out, size_t out_max, size_t *off,
                            uint16_t tag,
                            int (*builder)(uint8_t *, size_t, size_t *))
{
    if (emit_tag(out, out_max, off, tag) < 0) return -1;
    size_t len_off = *off;
    if (*off + 3u > out_max) return -1;
    *off += 3u;
    size_t content_start = *off;

    if (builder(out, out_max, off) < 0) return -1;

    size_t content_len = *off - content_start;
    if (content_len < 0x80u) {
        out[len_off] = (uint8_t) content_len;
        memmove(&out[len_off + 1u], &out[content_start], content_len);
        *off -= 2u;
    } else if (content_len <= 0xFFu) {
        out[len_off]      = 0x81u;
        out[len_off + 1u] = (uint8_t) content_len;
        memmove(&out[len_off + 2u], &out[content_start], content_len);
        *off -= 1u;
    } else {
        out[len_off]      = 0x82u;
        out[len_off + 1u] = (uint8_t)((content_len >> 8) & 0xFFu);
        out[len_off + 2u] = (uint8_t)( content_len       & 0xFFu);
    }
    return 0;
}

/* Cardholder Related Data (DO 65) — composite of 5B + 5F2D + 5F35. */
static int build_do_65(uint8_t *out, size_t out_max, size_t *off)
{
    uint8_t name[OPENPGP_NAME_MAX];
    size_t  name_len = 0;
    (void) openpgp_state_name_get(name, &name_len);
    uint8_t lang[OPENPGP_LANG_LEN];
    (void) openpgp_state_lang_get(lang);
    uint8_t sex = openpgp_state_sex_get();

    if (emit_tlv(out, out_max, off, 0x005B, name, name_len) < 0) return -1;
    if (emit_tlv(out, out_max, off, 0x5F2D, lang, sizeof lang) < 0) return -1;
    if (emit_tlv(out, out_max, off, 0x5F35, &sex, 1u) < 0) return -1;
    return 0;
}

/* Discretionary Data Objects (DO 73) — child of 6E.
 * Layout: C0 (ext caps) + C1+C2+C3 (algo attrs) + C4 (PW status)
 *       + C5 (fingerprints) + C6 (CA fingerprints, all zero) + CD (gen times) */
static int build_do_73(uint8_t *out, size_t out_max, size_t *off)
{
    if (emit_tlv(out, out_max, off, 0x00C0, EXT_CAPS, sizeof EXT_CAPS) < 0) return -1;
    if (emit_tlv(out, out_max, off, 0x00C1, ALGO_ED25519, sizeof ALGO_ED25519) < 0) return -1;
    if (emit_tlv(out, out_max, off, 0x00C2, ALGO_CV25519, sizeof ALGO_CV25519) < 0) return -1;
    if (emit_tlv(out, out_max, off, 0x00C3, ALGO_ED25519, sizeof ALGO_ED25519) < 0) return -1;

    uint8_t pw_status[7];
    build_pw_status(pw_status);
    if (emit_tlv(out, out_max, off, 0x00C4, pw_status, sizeof pw_status) < 0) return -1;

    uint8_t fprs[60];
    build_fingerprints(fprs);
    if (emit_tlv(out, out_max, off, 0x00C5, fprs, sizeof fprs) < 0) return -1;

    uint8_t ca_fprs[60] = {0};
    if (emit_tlv(out, out_max, off, 0x00C6, ca_fprs, sizeof ca_fprs) < 0) return -1;

    uint8_t gentimes[12];
    build_gentimes(gentimes);
    if (emit_tlv(out, out_max, off, 0x00CD, gentimes, sizeof gentimes) < 0) return -1;

    return 0;
}

/* Application Related Data (DO 6E) — composite of 4F + 5F52 + 73. */
static int build_do_6e(uint8_t *out, size_t out_max, size_t *off)
{
    if (emit_tlv(out, out_max, off, 0x004F, OPENPGP_AID, OPENPGP_AID_LEN) < 0) return -1;
    if (emit_tlv(out, out_max, off, 0x5F52, HISTORICAL_BYTES,
                 sizeof HISTORICAL_BYTES) < 0) return -1;
    /* DO 73 (Discretionary Data Objects) — nested constructed. */
    return emit_constructed(out, out_max, off, 0x0073, build_do_73);
}

/* Security Support Template (DO 7A) — child: 93 (sig counter). */
static int build_do_7a(uint8_t *out, size_t out_max, size_t *off)
{
    uint8_t sig_counter[OPENPGP_SIG_COUNTER_LEN];
    (void) openpgp_state_sig_counter_get(sig_counter);
    return emit_tlv(out, out_max, off, 0x0093, sig_counter, sizeof sig_counter);
}

/* ===== GET DATA handler ===== */

static int handle_get_data(uint16_t tag, uint8_t *out, size_t out_max, size_t *out_len)
{
    /* Initialise state on first GET DATA — handles fresh dongles
     * where the OpenPGP applet has never been touched. */
    (void) openpgp_state_init();

    size_t off = 0;

    switch (tag) {

    case 0x004F:  /* AID raw */
        if (off + OPENPGP_AID_LEN > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        memcpy(&out[off], OPENPGP_AID, OPENPGP_AID_LEN);
        off += OPENPGP_AID_LEN;
        break;

    case 0x005E:   /* Login data — M3 stores via PUT DATA */
    case 0x5F50:   /* URL — M3 */
        return emit_sw(SW_REF_DATA_NOT_FOUND, out, out_max, out_len);

    case 0x5F52: { /* Historical bytes */
        if (off + sizeof HISTORICAL_BYTES > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        memcpy(&out[off], HISTORICAL_BYTES, sizeof HISTORICAL_BYTES);
        off += sizeof HISTORICAL_BYTES;
        break;
    }

    case 0x0065: /* Cardholder Related Data (constructed) */
        if (emit_constructed(out, out_max, &off, 0x0065, build_do_65) < 0)
            return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        break;

    case 0x006E: /* Application Related Data (constructed) */
        if (emit_constructed(out, out_max, &off, 0x006E, build_do_6e) < 0)
            return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        break;

    case 0x007A: /* Security Support Template (constructed) */
        if (emit_constructed(out, out_max, &off, 0x007A, build_do_7a) < 0)
            return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        break;

    case 0x00C0:   /* Extended capabilities */
        if (off + sizeof EXT_CAPS > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        memcpy(&out[off], EXT_CAPS, sizeof EXT_CAPS);
        off += sizeof EXT_CAPS;
        break;

    case 0x00C1:   /* Algorithm attributes — sig (Ed25519) */
    case 0x00C3:   /* Algorithm attributes — aut (Ed25519) */
        if (off + sizeof ALGO_ED25519 > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        memcpy(&out[off], ALGO_ED25519, sizeof ALGO_ED25519);
        off += sizeof ALGO_ED25519;
        break;

    case 0x00C2:   /* Algorithm attributes — dec (Cv25519) */
        if (off + sizeof ALGO_CV25519 > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        memcpy(&out[off], ALGO_CV25519, sizeof ALGO_CV25519);
        off += sizeof ALGO_CV25519;
        break;

    case 0x00C4: { /* PW status */
        uint8_t pw_status[7];
        build_pw_status(pw_status);
        if (off + sizeof pw_status > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        memcpy(&out[off], pw_status, sizeof pw_status);
        off += sizeof pw_status;
        break;
    }

    case 0x00C5: { /* Fingerprints — 60 B */
        uint8_t fprs[60];
        build_fingerprints(fprs);
        if (off + 60u > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        memcpy(&out[off], fprs, 60u);
        off += 60u;
        break;
    }

    case 0x00C6: { /* CA fingerprints — 60 B all-zero */
        if (off + 60u > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        memset(&out[off], 0, 60u);
        off += 60u;
        break;
    }

    case 0x00C7:   /* Individual fingerprints */
    case 0x00C8:
    case 0x00C9: {
        int slot = (int)(tag - 0x00C7);
        uint8_t fpr[OPENPGP_FPR_LEN];
        (void) openpgp_state_fingerprint_get(slot, fpr);
        if (off + sizeof fpr > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        memcpy(&out[off], fpr, sizeof fpr);
        off += sizeof fpr;
        break;
    }

    case 0x00CD: { /* Generation timestamps — 12 B */
        uint8_t gentimes[12];
        build_gentimes(gentimes);
        if (off + 12u > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        memcpy(&out[off], gentimes, 12u);
        off += 12u;
        break;
    }

    case 0x00CE:   /* Individual generation timestamps */
    case 0x00CF:
    case 0x00D0: {
        int slot = (int)(tag - 0x00CE);
        uint8_t gt[OPENPGP_GENTIME_LEN];
        (void) openpgp_state_gentime_get(slot, gt);
        if (off + sizeof gt > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        memcpy(&out[off], gt, sizeof gt);
        off += sizeof gt;
        break;
    }

    case 0x0093: { /* Signature counter */
        uint8_t sig_counter[OPENPGP_SIG_COUNTER_LEN];
        (void) openpgp_state_sig_counter_get(sig_counter);
        if (off + sizeof sig_counter > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        memcpy(&out[off], sig_counter, sizeof sig_counter);
        off += sizeof sig_counter;
        break;
    }

    case 0x005B: { /* Cardholder name */
        uint8_t name[OPENPGP_NAME_MAX];
        size_t  name_len = 0;
        (void) openpgp_state_name_get(name, &name_len);
        if (off + name_len > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        memcpy(&out[off], name, name_len);
        off += name_len;
        break;
    }

    case 0x5F2D: { /* Language */
        uint8_t lang[OPENPGP_LANG_LEN];
        (void) openpgp_state_lang_get(lang);
        if (off + sizeof lang > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        memcpy(&out[off], lang, sizeof lang);
        off += sizeof lang;
        break;
    }

    case 0x5F35: { /* Sex */
        uint8_t sex = openpgp_state_sex_get();
        if (off + 1u > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        out[off++] = sex;
        break;
    }

    case 0x00D6:   /* UIF — sig (all alias the global flag in our impl) */
    case 0x00D7:   /* UIF — dec */
    case 0x00D8: { /* UIF — aut */
        uint8_t uif = openpgp_state_touch_required_get();
        /* UIF DO contents are 2 B: [UIF value, default 0x20 reserved] */
        if (off + 2u > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        out[off++] = uif;
        out[off++] = 0x20u;
        break;
    }

    default:
        return emit_sw(SW_REF_DATA_NOT_FOUND, out, out_max, out_len);
    }

    *out_len = off;
    return emit_sw(SW_OK, out, out_max, out_len);
}

/* ===== SELECT handler ===== */

static int handle_select(uint8_t p1, uint8_t p2,
                         const uint8_t *aid, size_t aid_len,
                         uint8_t *out, size_t out_max, size_t *out_len)
{
    /* P1=04 (select by DF name / AID), P2=00 (first or only occurrence)
     * are the only valid forms we accept. */
    if (p1 != 0x04u || p2 != 0x00u) {
        return emit_sw(SW_INCORRECT_P1P2, out, out_max, out_len);
    }

    /* Accept SELECT with the full AID OR with just the RID prefix (6
     * bytes).  Reject otherwise. */
    if (aid_len == OPENPGP_AID_LEN &&
        memcmp(aid, OPENPGP_AID, OPENPGP_AID_LEN) == 0) {
        /* Full AID match. */
    } else if (aid_len >= OPENPGP_AID_PREFIX_LEN &&
               memcmp(aid, OPENPGP_AID_PREFIX, OPENPGP_AID_PREFIX_LEN) == 0) {
        /* Partial match on RID prefix — accept. */
    } else {
        return emit_sw(SW_FILE_NOT_FOUND, out, out_max, out_len);
    }

    /* Best-effort state init on SELECT.  Failure not fatal (the
     * SELECT itself succeeds; later GET DATA may return default
     * values). */
    (void) openpgp_state_init();

    /* M2: no FCI template returned.  Just SW=9000. */
    *out_len = 0;
    return emit_sw(SW_OK, out, out_max, out_len);
}

/* ===== Entry point ===== */

int openpgp_applet_dispatch(const uint8_t *in, size_t in_len,
                             uint8_t *out, size_t out_max, size_t *out_len)
{
    if (out == NULL || out_len == NULL) return -1;
    *out_len = 0;

    if (in == NULL || in_len < 4u) {
        return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
    }

    uint8_t cla = in[0];
    uint8_t ins = in[1];
    uint8_t p1  = in[2];
    uint8_t p2  = in[3];

    if (cla != 0x00u && cla != 0x10u) {
        return emit_sw(SW_CLA_NOT_SUPPORTED, out, out_max, out_len);
    }

    /* Lc/data parse.  Short APDU: [4]=Lc, [5..]=data.  We don't yet
     * support extended-length here in M2 (no DO is that big).  Le is
     * ignored — we return as much as we have. */
    const uint8_t *body = NULL;
    size_t         body_len = 0;
    if (in_len > 4u) {
        size_t lc = in[4];
        if (in_len < 5u + lc) {
            /* Not enough bytes for declared body.  Could be case 2S
             * (`CLA INS P1 P2 Le`); treat as no body. */
            if (in_len == 5u) {
                body = NULL;
                body_len = 0;
            } else {
                return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
            }
        } else if (in_len >= 5u + lc) {
            body = &in[5];
            body_len = lc;
        }
    }

    switch (ins) {
    case INS_SELECT:
        return handle_select(p1, p2, body, body_len, out, out_max, out_len);

    case INS_GET_DATA: {
        uint16_t tag = (uint16_t)(((uint16_t) p1 << 8) | (uint16_t) p2);
        return handle_get_data(tag, out, out_max, out_len);
    }

    default:
        return emit_sw(SW_INS_NOT_SUPPORTED, out, out_max, out_len);
    }
}
