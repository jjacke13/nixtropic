/*
 * OpenPGP card applet — ISO 7816-4 APDU dispatcher implementing the
 * OpenPGP card v3.4.1 specification (FSFE / gnupg.org publication:
 * https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf).
 *
 * Routes via firmware/src/ccid/apdu_dispatch.c (single applet today;
 * the dispatcher is structured to accept a second applet, e.g. PIV in
 * Phase 7b).  Wire transport is USB CCID class 1.1 (firmware/src/usb/
 * usb_ccid.c).
 *
 * INS handlers implemented:
 *
 *   0xA4 SELECT                       §7.2.1   match on AID prefix
 *   0xCA GET DATA                     §7.2.6   DOs 4F/5E/65/6E/7A/C0-CD/5B/5F2D/5F35
 *   0xDA PUT DATA                     §7.2.8   writable DOs only (cardholder, fpr, lang…)
 *   0x20 VERIFY                       §7.2.2   PW1 / PW3 / RC
 *   0x24 CHANGE REFERENCE DATA        §7.2.3   single-attempt boundary (M6 H2 audit fix)
 *   0x2C RESET RETRY COUNTER          §7.2.4   via RC or via PW3
 *   0xE6 TERMINATE DF                 §7.2.16  erases chip ECC slots (M6 H1 audit fix)
 *   0x44 ACTIVATE FILE                §7.2.17  recovery from TERMINATE
 *   0x47 GENERATE ASYMMETRIC KEY PAIR §7.2.14  Ed25519 + X25519
 *   0x2A PSO                          §7.2.10  CDS (9E/9A sign), DEC (80/86 ECDH)
 *   0x88 INTERNAL AUTHENTICATE        §7.2.15  Ed25519 challenge-sign (SSH via gpg-agent)
 *
 * Hand-rolled BER-TLV emitter for composite DOs (no malloc); all
 * output buffers caller-supplied; bounds-checked every byte.  See
 * emit_tlv / emit_constructed.
 *
 * Spec status words + non-standard values defined at the top of the
 * file; spec-canonical 9000 / 6A88 / 6982 etc. used inline.
 */

#include "openpgp_applet.h"
#include "openpgp_aid.h"
#include "openpgp_state.h"
#include "pgp_lifecycle.h"
#include "pgp_pin.h"
#include "pgp_keys.h"
#include "ccid/ccid_proto.h"
#include "fido_hid/user_presence.h"   /* Phase 8 M3 — SW1 gate for UIF */
#include "memzero.h"   /* M6 audit M1 — zeroize ECDH shared secret on stack */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ===== Additional spec status words ===== */
#define SW_TERMINATED          0x6285
#define SW_PIN_BLOCKED_REMAIN0 0x63C0  /* + (remaining tries in lower nibble) */
#define SW_PIN_FAIL_RETRY_0    0x63C0  /* 0x63CN = wrong PIN, N tries remain */

/* ===== ISO 7816 INS bytes we recognise ===== */
#define INS_SELECT         0xA4
#define INS_GET_DATA       0xCA
#define INS_VERIFY         0x20
#define INS_CHANGE_REF     0x24
#define INS_RESET_RC       0x2C
#define INS_PUT_DATA       0xDA
#define INS_TERMINATE_DF   0xE6
#define INS_ACTIVATE_FILE  0x44
#define INS_GENERATE       0x47   /* GENERATE ASYMMETRIC KEY PAIR — M4 */
#define INS_PSO            0x2A   /* PERFORM SECURITY OPERATION — M4+M5 */
#define INS_INTERNAL_AUT   0x88   /* INTERNAL AUTHENTICATE — M5 (SSH) */

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

/* Attempts left, from the binding (an unreadable PIN or an unset RC: 0). */
static uint8_t pin_attempts(int which)
{
    uint8_t att = 0;
    (void) pgp_pin_status(which, &att, NULL);
    return att;
}

/* PW status (DO C4) — 7 bytes; byte 0 with its spec meaning (D9). */
static void build_pw_status(uint8_t out[7])
{
    out[0] = openpgp_state_c4_multi();
    out[1] = OPENPGP_PIN_MAX_LEN;               /* PW1 max length */
    out[2] = OPENPGP_PIN_MAX_LEN;               /* RC max length */
    out[3] = OPENPGP_PIN_MAX_LEN;               /* PW3 max length */
    out[4] = pin_attempts(OPENPGP_PIN_PW1);
    out[5] = pin_attempts(OPENPGP_PIN_RC);
    out[6] = pin_attempts(OPENPGP_PIN_PW3);
}

/* Fingerprints (DO C5) — 60 B concatenated sig||dec||aut.  Returns
 * 0 OK, -1 on chip error (still writes zero buffer). */
static void build_fingerprints(uint8_t out[60])
{
    openpgp_state_fingerprint(0, &out[0]);
    openpgp_state_fingerprint(1, &out[20]);
    openpgp_state_fingerprint(2, &out[40]);
}

/* Generation timestamps (DO CD) — 12 B concatenated. */
static void build_gentimes(uint8_t out[12])
{
    openpgp_state_gentime(0, &out[0]);
    openpgp_state_gentime(1, &out[4]);
    openpgp_state_gentime(2, &out[8]);
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
    size_t  name_len = openpgp_state_name(name);
    uint8_t lang[OPENPGP_LANG_LEN];
    openpgp_state_lang(lang);
    uint8_t sex = openpgp_state_sex();

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
    openpgp_state_sig_counter(sig_counter);
    return emit_tlv(out, out_max, off, 0x0093, sig_counter, sizeof sig_counter);
}

/* ===== GET DATA handler ===== */

static int handle_get_data(uint16_t tag, uint8_t *out, size_t out_max, size_t *out_len)
{
    size_t off = 0;

    switch (tag) {

    case 0x004F:  /* AID raw */
        if (off + OPENPGP_AID_LEN > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        memcpy(&out[off], OPENPGP_AID, OPENPGP_AID_LEN);
        off += OPENPGP_AID_LEN;
        break;

    case 0x005E:   /* Login data — empty body, not 6A88.  scdaemon's
                    do_learn_status chains do_getattr calls with `if
                    (!err)`; a 6A88 return on LOGIN-DATA propagates
                    GPG_ERR_NO_OBJ and aborts the rest of the chain
                    (KEY-FPR, KEY-TIME, CA-FPR, CHV-STATUS,
                    SIG-COUNTER), leaving gpg --card-status with
                    "[none]" for every key + "0 0 0" PINs. */
    case 0x5F50:   /* URL — same reasoning as 5E. */
        break;

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

    case 0x00C2:   /* Algorithm attributes — dec (real X25519/Cv25519 in M5) */
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
        openpgp_state_fingerprint(slot, fpr);
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
        openpgp_state_gentime(slot, gt);
        if (off + sizeof gt > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        memcpy(&out[off], gt, sizeof gt);
        off += sizeof gt;
        break;
    }

    case 0x0093: { /* Signature counter */
        uint8_t sig_counter[OPENPGP_SIG_COUNTER_LEN];
        openpgp_state_sig_counter(sig_counter);
        if (off + sizeof sig_counter > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        memcpy(&out[off], sig_counter, sizeof sig_counter);
        off += sizeof sig_counter;
        break;
    }

    case 0x005B: { /* Cardholder name */
        uint8_t name[OPENPGP_NAME_MAX];
        size_t  name_len = openpgp_state_name(name);
        if (off + name_len > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        memcpy(&out[off], name, name_len);
        off += name_len;
        break;
    }

    case 0x5F2D: { /* Language */
        uint8_t lang[OPENPGP_LANG_LEN];
        openpgp_state_lang(lang);
        if (off + sizeof lang > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        memcpy(&out[off], lang, sizeof lang);
        off += sizeof lang;
        break;
    }

    case 0x5F35: { /* Sex */
        uint8_t sex = openpgp_state_sex();
        if (off + 1u > out_max) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        out[off++] = sex;
        break;
    }

    case 0x00D6:   /* UIF — sig (all alias the global flag in our impl) */
    case 0x00D7:   /* UIF — dec */
    case 0x00D8: { /* UIF — aut */
        uint8_t uif = openpgp_state_uif();
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

/* ===== PIN handlers (Phase 9 M4, design §5) ===== */

/* Session access status (D9): PW1.81 (PSO:CDS), PW1.82 (PSO:DEC, INTERNAL
 * AUTHENTICATE), PW3 (admin).  RAM only; cleared by a card reset
 * (IccPowerOff/On, USB reset), a SELECT of another AID, TERMINATE,
 * ACTIVATE, and any change or reset of that PIN. */
#define AUTH_81  0x01u
#define AUTH_82  0x02u
#define AUTH_83  0x04u
static uint8_t s_auth;

void openpgp_applet_card_reset(void)
{
    s_auth = 0;
}

static uint8_t auth_flag(uint8_t p2)
{
    switch (p2) {
    case 0x81: return AUTH_81;
    case 0x82: return AUTH_82;
    case 0x83: return AUTH_83;
    default:   return 0u;
    }
}

static int pin_of(uint8_t flag)
{
    return flag == AUTH_83 ? OPENPGP_PIN_PW3 : OPENPGP_PIN_PW1;
}

static uint8_t flags_of(int which)
{
    return which == OPENPGP_PIN_PW1 ? (uint8_t) (AUTH_81 | AUTH_82)
         : which == OPENPGP_PIN_PW3 ? AUTH_83 : 0u;
}

static uint16_t retries_sw(int which)
{
    return (uint16_t) (0x63C0u | (pin_attempts(which) & 0x0Fu));
}

/* SW for a pgp_pin_* result; a wrong PIN answers 63CX, X = attempts left. */
static uint16_t pin_sw(int rc, int which)
{
    switch (rc) {
    case PGP_PIN_OK:      return SW_OK;
    case PGP_PIN_WRONG:   return retries_sw(which);
    case PGP_PIN_BLK:     return SW_AUTH_BLOCKED;
    case PGP_PIN_UNSET:   return SW_CONDITIONS_NOT_SATISFIED;
    case PGP_PIN_BAD_LEN: return SW_WRONG_LENGTH;
    default:              return SW_UNKNOWN_ERROR;
    }
}

static int handle_verify(uint8_t p1, uint8_t p2,
                          const uint8_t *body, size_t body_len,
                          uint8_t *out, size_t out_max, size_t *out_len)
{
    uint8_t flag = auth_flag(p2);
    if (flag == 0u || (p1 != 0x00u && p1 != 0xFFu)) {
        return emit_sw(SW_INCORRECT_P1P2, out, out_max, out_len);
    }
    int which = pin_of(flag);
    if (p1 == 0xFFu) {                  /* §7.2.2: reset this access status */
        if (body_len != 0u) return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        s_auth &= (uint8_t) ~flag;
        return emit_sw(SW_OK, out, out_max, out_len);
    }
    if (body_len == 0u) {               /* status: verified, or 63CX */
        uint16_t sw = (s_auth & flag) ? SW_OK : retries_sw(which);
        return emit_sw(sw, out, out_max, out_len);
    }
    int rc = pgp_pin_verify(which, body, body_len);
    if (rc == PGP_PIN_OK) {
        s_auth |= flag;                 /* this P2 only */
    } else {
        s_auth &= (uint8_t) ~flags_of(which);
    }
    return emit_sw(pin_sw(rc, which), out, out_max, out_len);
}

static int handle_change_ref(uint8_t p1, uint8_t p2,
                              const uint8_t *body, size_t body_len,
                              uint8_t *out, size_t out_max, size_t *out_len)
{
    uint8_t flag = auth_flag(p2);
    if (p1 != 0x00u || (flag != AUTH_81 && flag != AUTH_83)) {
        return emit_sw(SW_INCORRECT_P1P2, out, out_max, out_len);
    }
    int which = pin_of(flag);
    /* Body = old || new, split at the old PIN's length from its binding
     * (§7.2.3; committed with the PIN, D5): one attempt per APDU. */
    uint8_t old_len = 0;
    pgp_pin_state_t st = pgp_pin_status(which, NULL, &old_len);
    if (st == PGP_PIN_BLOCKED) return emit_sw(SW_AUTH_BLOCKED, out, out_max, out_len);
    if (st != PGP_PIN_ACTIVE) return emit_sw(SW_UNKNOWN_ERROR, out, out_max, out_len);
    if (body == NULL || body_len <= old_len) {
        return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
    }
    s_auth &= (uint8_t) ~flags_of(which);
    int rc = pgp_pin_change(which, body, old_len, body + old_len, body_len - old_len);
    return emit_sw(pin_sw(rc, which), out, out_max, out_len);
}

static int handle_reset_rc(uint8_t p1, uint8_t p2,
                            const uint8_t *body, size_t body_len,
                            uint8_t *out, size_t out_max, size_t *out_len)
{
    if (p2 != 0x81u || (p1 != 0x00u && p1 != 0x02u)) {
        return emit_sw(SW_INCORRECT_P1P2, out, out_max, out_len);
    }
    const uint8_t *pw1 = body;
    size_t pw1_len = body_len;
    if (p1 == 0x00u) {
        /* Body = RC || new PW1, split at the RC's length. */
        uint8_t rc_len = 0;
        pgp_pin_state_t st = pgp_pin_status(OPENPGP_PIN_RC, NULL, &rc_len);
        if (st == PGP_PIN_NOT_SET) {
            return emit_sw(SW_CONDITIONS_NOT_SATISFIED, out, out_max, out_len);
        }
        if (st == PGP_PIN_BLOCKED) return emit_sw(SW_AUTH_BLOCKED, out, out_max, out_len);
        if (st != PGP_PIN_ACTIVE) return emit_sw(SW_UNKNOWN_ERROR, out, out_max, out_len);
        if (body == NULL || body_len < (size_t) rc_len + OPENPGP_PW1_MIN_LEN
            || body_len - rc_len > OPENPGP_PIN_MAX_LEN) {
            return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);   /* no RC attempt */
        }
        int rc = pgp_pin_verify(OPENPGP_PIN_RC, body, rc_len);
        if (rc != PGP_PIN_OK) {
            return emit_sw(pin_sw(rc, OPENPGP_PIN_RC), out, out_max, out_len);
        }
        pw1 = body + rc_len;
        pw1_len = body_len - rc_len;
    } else if (!(s_auth & AUTH_83)) {
        return emit_sw(SW_SECURITY_NOT_SATISFIED, out, out_max, out_len);
    }
    /* A new PW1 with a fresh s: the "k changed" event M5 hooks into. */
    s_auth &= (uint8_t) ~flags_of(OPENPGP_PIN_PW1);
    int rc = pgp_pin_reset_pw1(pw1, pw1_len);
    return emit_sw(pin_sw(rc, OPENPGP_PIN_PW1), out, out_max, out_len);
}

static int handle_put_data(uint16_t tag,
                            const uint8_t *body, size_t body_len,
                            uint8_t *out, size_t out_max, size_t *out_len)
{
    /* All PUT DATA operations require PW3 verified — admin authority. */
    if (!(s_auth & AUTH_83)) {
        return emit_sw(SW_SECURITY_NOT_SATISFIED, out, out_max, out_len);
    }

    int rc;
    switch (tag) {
    case 0x005B:  /* Cardholder name */
        if (body_len > OPENPGP_NAME_MAX) {
            return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        }
        rc = openpgp_state_set_name(body, body_len);
        break;
    case 0x5F2D:  /* Language (ISO 639) */
        if (body_len != OPENPGP_LANG_LEN) {
            return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        }
        rc = openpgp_state_set_lang(body);
        break;
    case 0x5F35:  /* Sex (ISO 5218) */
        if (body_len != 1u) {
            return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        }
        if (body[0] != 0x31u && body[0] != 0x32u && body[0] != 0x39u) {
            return emit_sw(SW_INCORRECT_DATA, out, out_max, out_len);
        }
        rc = openpgp_state_set_sex(body[0]);
        break;
    case 0x00C4:  /* PW status — only byte 0 is writable (00 / 01) */
        if (body_len < 1u) {
            return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        }
        rc = openpgp_state_set_c4_multi(body[0] != 0u ? 1u : 0u);
        break;
    case 0x00D3:  /* Resetting Code (RC): empty body clears it */
        rc = pgp_pin_set_rc(body, body_len);
        return emit_sw(pin_sw(rc, OPENPGP_PIN_RC), out, out_max, out_len);
    case 0x00D6:  /* UIF sig — aliases global touch */
    case 0x00D7:  /* UIF dec */
    case 0x00D8:  /* UIF aut */
        if (body_len < 1u) {
            return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        }
        if (body[0] > 2u) {
            return emit_sw(SW_INCORRECT_DATA, out, out_max, out_len);
        }
        rc = openpgp_state_set_uif(body[0]);
        if (rc == -3) {
            return emit_sw(SW_CONDITIONS_NOT_SATISFIED, out, out_max, out_len);
        }
        break;

    /* Fingerprints + generation timestamps, written by gpg after a
     * GENERATE.  20 B fingerprint = SHA-1 over the public-key material
     * (RFC 4880); 4 B gentime = BE u32 seconds since the epoch. */
    case 0x00C7:   /* Fingerprint — sig */
    case 0x00C8:   /* Fingerprint — dec */
    case 0x00C9: { /* Fingerprint — aut */
        if (body_len != OPENPGP_FPR_LEN) {
            return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        }
        rc = openpgp_state_set_fingerprint((int)(tag - 0x00C7), body);
        break;
    }

    case 0x00CE:   /* Generation timestamp — sig */
    case 0x00CF:   /* Generation timestamp — dec */
    case 0x00D0: { /* Generation timestamp — aut */
        if (body_len != OPENPGP_GENTIME_LEN) {
            return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        }
        rc = openpgp_state_set_gentime((int)(tag - 0x00CE), body);
        break;
    }

    default:
        return emit_sw(SW_REF_DATA_NOT_FOUND, out, out_max, out_len);
    }

    return emit_sw((rc == 0) ? SW_OK : SW_UNKNOWN_ERROR, out, out_max, out_len);
}

/* ===== M4 — GENERATE ASYMMETRIC KEY PAIR (INS 0x47) ===== */

/* Build the 7F49-wrapped public key response into the response buffer.
 * Returns 0 OK, -1 if out_max too small. */
static int build_pubkey_response(uint8_t *out, size_t out_max, size_t *off,
                                  const uint8_t pubkey[PGP_KEYS_PUBKEY_LEN])
{
    /* Inner: 86 [len=20] [pubkey 32B] = 34 bytes */
    if (*off + 37u > out_max) return -1;

    out[(*off)++] = 0x7Fu;
    out[(*off)++] = 0x49u;
    out[(*off)++] = 0x22u;   /* length 34 of inner content */

    out[(*off)++] = 0x86u;
    out[(*off)++] = (uint8_t) PGP_KEYS_PUBKEY_LEN;  /* 32 */
    memcpy(&out[*off], pubkey, PGP_KEYS_PUBKEY_LEN);
    *off += PGP_KEYS_PUBKEY_LEN;
    return 0;
}

static int handle_generate(uint8_t p1, uint8_t p2,
                            const uint8_t *body, size_t body_len,
                            uint8_t *out, size_t out_max, size_t *out_len)
{
    if (p2 != 0x00u) {
        return emit_sw(SW_INCORRECT_P1P2, out, out_max, out_len);
    }
    /* P1: 0x80 = generate; 0x81 = read public key */
    int generate;
    switch (p1) {
    case 0x80u: generate = 1; break;
    case 0x81u: generate = 0; break;
    default:    return emit_sw(SW_INCORRECT_P1P2, out, out_max, out_len);
    }

    /* Body = control-reference template: CRT_TAG + 0x00 (empty value)
     * CRT_TAG = 0xB6 (sig), 0xB8 (dec), 0xA4 (aut). */
    if (body == NULL || body_len < 2u) {
        return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
    }
    uint8_t crt_tag = body[0];

    /* GENERATE (P1=80) requires PW3 verified.  READ (P1=81) does not
     * (per spec §7.2.14 — public keys are public). */
    if (generate && !(s_auth & AUTH_83)) {
        return emit_sw(SW_SECURITY_NOT_SATISFIED, out, out_max, out_len);
    }

    uint8_t pubkey[PGP_KEYS_PUBKEY_LEN];
    int rc;

    switch (crt_tag) {
    case 0xB6u:  /* Signature key */
        rc = generate ? pgp_keys_generate_sig(pubkey)
                      : pgp_keys_read_sig_pubkey(pubkey);
        break;

    case 0xB8u:  /* Decryption key (M5 stub: chip-side Ed25519) */
        rc = generate ? pgp_keys_generate_dec(pubkey)
                      : pgp_keys_read_dec_pubkey(pubkey);
        break;

    case 0xA4u:  /* Authentication key (M5: chip-side Ed25519, full) */
        rc = generate ? pgp_keys_generate_aut(pubkey)
                      : pgp_keys_read_aut_pubkey(pubkey);
        break;

    default:
        return emit_sw(SW_REF_DATA_NOT_FOUND, out, out_max, out_len);
    }

    if (rc == PGP_KEYS_NO_KEY) {
        /* READ on empty slot — return spec-defined "ref data not found" */
        return emit_sw(SW_REF_DATA_NOT_FOUND, out, out_max, out_len);
    }
    if (rc != PGP_KEYS_OK) {
        /* M6 audit M2 + L1 — collapse all chip failure paths to a
         * single SW_UNKNOWN_ERROR.  The earlier per-stage SW + 8-byte
         * R-config dump leaked chip-internal access-control state to
         * any unauthenticated READ PUBLIC KEY caller (P1=0x81 has no
         * PIN gate per spec §7.2.14), which is a reconnaissance oracle.
         * Chip FW 2.0.0 is stable; the diagnostic dump is no longer
         * needed.  pgp_keys_last_chip_rc/stage globals remain for
         * firmware-side debugging via UART. */
        return emit_sw(SW_UNKNOWN_ERROR, out, out_max, out_len);
    }

    size_t off = 0;
    if (build_pubkey_response(out, out_max, &off, pubkey) < 0) {
        return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
    }
    *out_len = off;
    return emit_sw(SW_OK, out, out_max, out_len);
}

/* ===== M4 — PERFORM SECURITY OPERATION : Compute Digital Signature ===== */

/* Parse the PSO:DEC body — gpg sends a constructed TLV per OpenPGP card
 * spec §7.2.10 ECDH input form:
 *
 *   A6 <len_A6>                              outer "Cipher DO"
 *     7F 49 <len_7F49>                       "Public Key DO"
 *       86 20                                "External Public Key" tag, 32 bytes
 *         <32 B peer ephemeral pubkey>
 *
 * Returns 0 OK with `*peer_out` pointing at the 32 B pubkey, or -1 on
 * malformed input.  Tolerates short or 1-byte-length encodings (BER). */
static int parse_pso_dec_body(const uint8_t *body, size_t body_len,
                               const uint8_t **peer_out)
{
    if (body == NULL || peer_out == NULL) return -1;
    if (body_len < 5u) return -1;

    /* Outer tag A6 + length */
    if (body[0] != 0xA6u) return -1;
    size_t off = 1;
    size_t a6_len;
    if (body[off] < 0x80u)       { a6_len = body[off]; off += 1; }
    else if (body[off] == 0x81u) { if (body_len < off + 2u) return -1; a6_len = body[off + 1u]; off += 2; }
    else if (body[off] == 0x82u) { if (body_len < off + 3u) return -1; a6_len = ((size_t) body[off + 1u] << 8) | body[off + 2u]; off += 3; }
    else return -1;
    if (off + a6_len > body_len) return -1;

    /* Inner tag 7F 49 + length */
    if (off + 2u > body_len) return -1;
    if (body[off] != 0x7Fu || body[off + 1u] != 0x49u) return -1;
    off += 2;
    size_t inner_len;
    if (body[off] < 0x80u)       { inner_len = body[off]; off += 1; }
    else if (body[off] == 0x81u) { if (body_len < off + 2u) return -1; inner_len = body[off + 1u]; off += 2; }
    else if (body[off] == 0x82u) { if (body_len < off + 3u) return -1; inner_len = ((size_t) body[off + 1u] << 8) | body[off + 2u]; off += 3; }
    else return -1;
    if (off + inner_len > body_len) return -1;

    /* Pubkey tag 86 [32] */
    if (off + 2u > body_len) return -1;
    if (body[off] != 0x86u) return -1;
    off += 1;
    if (body[off] != 0x20u) return -1;  /* length must be 32 for X25519 */
    off += 1;
    if (off + 32u > body_len) return -1;
    *peer_out = &body[off];
    return 0;
}

/* Phase 8 M3 — gate every chip-side crypto op on a fresh SW1 press
 * when the global `touch_required` flag (UIF DO D6/D7/D8, aliased to a
 * single byte in our impl) is non-zero.  Returns 0 if the gate passes
 * (either disabled or user pressed within timeout); -1 on timeout /
 * already-held / debouncer failure.  Spec OpenPGP card v3.4.1 §4.4.3.13
 * allows the card to refuse the op with SW=6982 ("security status not
 * satisfied") when the UIF check fails. */
#define OPENPGP_TOUCH_TIMEOUT_MS  15000u
static int require_touch_if_enabled(void)
{
    if (openpgp_state_uif() == 0u) {
        return 0;
    }
    if (user_presence_check(OPENPGP_TOUCH_TIMEOUT_MS) != UP_OK) {
        return -1;
    }
    return 0;
}

static int handle_pso(uint8_t p1, uint8_t p2,
                       const uint8_t *body, size_t body_len,
                       uint8_t *out, size_t out_max, size_t *out_len)
{
    /* PSO:DEC (P1=80, P2=86) — X25519 ECDH (M5).
     * PSO:CDS (P1=9E, P2=9A) — Ed25519 sign (M4). */

    /* PSO:DEC branch */
    if (p1 == 0x80u && p2 == 0x86u) {
        /* PW1.82 (decrypt / auth) must be verified this session (D9). */
        if (!(s_auth & AUTH_82)) {
            return emit_sw(SW_SECURITY_NOT_SATISFIED, out, out_max, out_len);
        }
        if (require_touch_if_enabled() != 0) {
            return emit_sw(SW_SECURITY_NOT_SATISFIED, out, out_max, out_len);
        }

        const uint8_t *peer = NULL;
        if (parse_pso_dec_body(body, body_len, &peer) != 0) {
            return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        }

        uint8_t shared[PGP_KEYS_PUBKEY_LEN];
        int rc = pgp_keys_ecdh_dec(peer, shared);
        if (rc == PGP_KEYS_NO_KEY) {
            return emit_sw(SW_REF_DATA_NOT_FOUND, out, out_max, out_len);
        }
        if (rc != PGP_KEYS_OK) {
            return emit_sw(SW_UNKNOWN_ERROR, out, out_max, out_len);
        }
        if (out_max < PGP_KEYS_PUBKEY_LEN + 2u) {
            memzero(shared, sizeof shared);
            return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        }
        memcpy(out, shared, PGP_KEYS_PUBKEY_LEN);
        /* M6 audit M1 — zeroize the ECDH shared secret on the stack
         * after it's been copied into the response buffer.  The shared
         * secret has the same sensitivity as the priv key (full ECDH
         * compromise once leaked) and pgp_keys.c already zeroes priv;
         * mirror that pattern at the applet layer for consistency. */
        memzero(shared, sizeof shared);
        *out_len = PGP_KEYS_PUBKEY_LEN;
        return emit_sw(SW_OK, out, out_max, out_len);
    }

    /* PSO:CDS branch (existing M4 path) */
    if (p1 != 0x9Eu || p2 != 0x9Au) {
        return emit_sw(SW_INCORRECT_P1P2, out, out_max, out_len);
    }

    /* PW1.81 must be verified this session.  With DO C4 byte 0 = 00 it
     * covers one signature: consumed once the access check passed (D9). */
    if (!(s_auth & AUTH_81)) {
        return emit_sw(SW_SECURITY_NOT_SATISFIED, out, out_max, out_len);
    }
    if (openpgp_state_c4_multi() == 0u) {
        s_auth &= (uint8_t) ~AUTH_81;
    }
    if (require_touch_if_enabled() != 0) {
        return emit_sw(SW_SECURITY_NOT_SATISFIED, out, out_max, out_len);
    }

    if (body == NULL || body_len == 0u) {
        return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
    }

    /* Count first (DO 93): the counter never shows fewer signatures than
     * the card made; a counter that cannot be written means no signature. */
    if (openpgp_state_sig_counter_increment() != 0) {
        return emit_sw(SW_UNKNOWN_ERROR, out, out_max, out_len);
    }
    uint8_t sig[PGP_KEYS_SIG_LEN];
    int rc = pgp_keys_sign_with_sig(body, body_len, sig);
    if (rc == PGP_KEYS_NO_KEY) {
        return emit_sw(SW_REF_DATA_NOT_FOUND, out, out_max, out_len);
    }
    if (rc != PGP_KEYS_OK) {
        return emit_sw(SW_UNKNOWN_ERROR, out, out_max, out_len);
    }

    if (out_max < PGP_KEYS_SIG_LEN + 2u) {
        return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
    }
    memcpy(out, sig, PGP_KEYS_SIG_LEN);
    *out_len = PGP_KEYS_SIG_LEN;
    return emit_sw(SW_OK, out, out_max, out_len);
}

static int handle_terminate_df(uint8_t p1, uint8_t p2,
                                uint8_t *out, size_t out_max, size_t *out_len)
{
    if (p1 != 0x00u || p2 != 0x00u) {
        return emit_sw(SW_INCORRECT_P1P2, out, out_max, out_len);
    }
    /* PW3 verified, or without PW3 when PW3 is blocked or the state cannot
     * be read (§7.2.16; no secure messaging here).  Only destroys. */
    pgp_pin_state_t pw3 = pgp_pin_status(OPENPGP_PIN_PW3, NULL, NULL);
    if (!(s_auth & AUTH_83) && openpgp_state_lifecycle() != PGP_LC_ERROR
        && pw3 != PGP_PIN_BLOCKED && pw3 != PGP_PIN_ERROR) {
        return emit_sw(SW_SECURITY_NOT_SATISFIED, out, out_max, out_len);
    }
    s_auth = 0;
    /* Keys, the DEC key (both O3 copies) and every PIN, checked, in that
     * order (D8); a failure stops it and TERMINATE can be sent again. */
    int rc = pgp_lifecycle_terminate();
    return emit_sw(rc == 0 ? SW_OK : SW_UNKNOWN_ERROR, out, out_max, out_len);
}

static int handle_activate_file(uint8_t p1, uint8_t p2,
                                 uint8_t *out, size_t out_max, size_t *out_len)
{
    if (p1 != 0x00u || p2 != 0x00u) {
        return emit_sw(SW_INCORRECT_P1P2, out, out_max, out_len);
    }
    /* No-op on an operational card (§7.2.17); factory PINs only over a
     * cleanly read TERMINATED state (D11). */
    if (openpgp_state_lifecycle() == PGP_LC_OPERATIONAL) {
        return emit_sw(SW_OK, out, out_max, out_len);
    }
    s_auth = 0;
    int rc = pgp_lifecycle_activate();
    uint16_t sw = rc == 0 ? SW_OK : rc == -1 ? SW_CONDITIONS_NOT_SATISFIED : SW_UNKNOWN_ERROR;
    return emit_sw(sw, out, out_max, out_len);
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
        s_auth = 0;                     /* another application: access status reset (D9) */
        return emit_sw(SW_FILE_NOT_FOUND, out, out_max, out_len);
    }

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

    /* The state is read once per power cycle (bootstrap on ABSENT); a boot
     * that failed is tried again with the next APDU — a transient chip
     * error must not push the user towards TERMINATE.  An uncertain pair
     * is not retried: it stays ERROR until reboot or TERMINATE. */
    if (!openpgp_state_loaded()) {
        (void) pgp_lifecycle_boot();
    }
    switch (openpgp_state_lifecycle()) {
    case PGP_LC_OPERATIONAL:
        break;
    case PGP_LC_TERMINATED:             /* awaiting ACTIVATE FILE */
        if (ins != INS_SELECT && ins != INS_ACTIVATE_FILE) {
            return emit_sw(SW_TERMINATED, out, out_max, out_len);
        }
        break;
    default:                            /* unreadable: only the way out (§5) */
        if (ins != INS_SELECT && ins != INS_TERMINATE_DF
            && !(ins == INS_VERIFY && p2 == 0x83u)) {
            return emit_sw(SW_UNKNOWN_ERROR, out, out_max, out_len);
        }
        break;
    }

    switch (ins) {
    case INS_SELECT:
        return handle_select(p1, p2, body, body_len, out, out_max, out_len);

    case INS_GET_DATA: {
        uint16_t tag = (uint16_t)(((uint16_t) p1 << 8) | (uint16_t) p2);
        return handle_get_data(tag, out, out_max, out_len);
    }

    case INS_VERIFY:
        return handle_verify(p1, p2, body, body_len, out, out_max, out_len);

    case INS_CHANGE_REF:
        return handle_change_ref(p1, p2, body, body_len, out, out_max, out_len);

    case INS_RESET_RC:
        return handle_reset_rc(p1, p2, body, body_len, out, out_max, out_len);

    case INS_PUT_DATA: {
        uint16_t tag = (uint16_t)(((uint16_t) p1 << 8) | (uint16_t) p2);
        return handle_put_data(tag, body, body_len, out, out_max, out_len);
    }

    case INS_TERMINATE_DF:
        return handle_terminate_df(p1, p2, out, out_max, out_len);

    case INS_ACTIVATE_FILE:
        return handle_activate_file(p1, p2, out, out_max, out_len);

    case INS_GENERATE:
        return handle_generate(p1, p2, body, body_len, out, out_max, out_len);

    case INS_PSO:
        return handle_pso(p1, p2, body, body_len, out, out_max, out_len);

    case INS_INTERNAL_AUT: {
        /* INTERNAL AUTHENTICATE: P1=P2=0, body = challenge to sign.
         * Returns Ed25519 signature using the aut-slot key.
         * Gated on PW1.82 (decrypt/auth PIN).  Phase 5 FIDO has the
         * same Ed25519 sign primitive — well-tested chip-side path. */
        if (p1 != 0x00u || p2 != 0x00u) {
            return emit_sw(SW_INCORRECT_P1P2, out, out_max, out_len);
        }
        if (!(s_auth & AUTH_82)) {
            return emit_sw(SW_SECURITY_NOT_SATISFIED, out, out_max, out_len);
        }
        if (require_touch_if_enabled() != 0) {
            return emit_sw(SW_SECURITY_NOT_SATISFIED, out, out_max, out_len);
        }
        if (body == NULL || body_len == 0u) {
            return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        }

        uint8_t sig[PGP_KEYS_SIG_LEN];
        int rc = pgp_keys_sign_with_aut(body, body_len, sig);
        if (rc == PGP_KEYS_NO_KEY) {
            return emit_sw(SW_REF_DATA_NOT_FOUND, out, out_max, out_len);
        }
        if (rc != PGP_KEYS_OK) {
            return emit_sw(SW_UNKNOWN_ERROR, out, out_max, out_len);
        }
        if (out_max < PGP_KEYS_SIG_LEN + 2u) {
            return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
        }
        memcpy(out, sig, PGP_KEYS_SIG_LEN);
        *out_len = PGP_KEYS_SIG_LEN;
        return emit_sw(SW_OK, out, out_max, out_len);
    }

    default:
        return emit_sw(SW_INS_NOT_SUPPORTED, out, out_max, out_len);
    }
}
