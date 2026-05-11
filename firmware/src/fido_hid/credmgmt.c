/*
 * authenticatorCredentialManagement (CTAP2 cmd 0x0A) — Phase 6 M3.
 * See credmgmt.h for design rationale.
 *
 * Iterator state machine:
 *
 *   ITER_NONE ──enumerateRPsBegin──> ITER_RPS
 *   ITER_RPS  ──enumerateRPsGetNextRP──> ITER_RPS (advance)
 *   ITER_RPS  ──any other cmd──> ITER_NONE
 *   ITER_NONE ──enumerateCredsBegin──> ITER_CREDS
 *   ITER_CREDS──enumerateCredsGetNext──> ITER_CREDS (advance)
 *   ITER_CREDS──any other cmd──> ITER_NONE
 *
 * Snapshotting at Begin: we walk the credstore ONCE at Begin time,
 * record the slot indices into a fixed buffer, then iterate the
 * recorded snapshot.  This keeps the iterator stable across concurrent
 * mutation attempts (which the H2 lock already refuses, but defense
 * in depth doesn't hurt).
 */

#include "credmgmt.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "ctap2.h"
#include "cbor.h"
#include "credstore.h"
#include "slots.h"
#include "pin.h"
#include "proto.h"

#define CREDMGMT_CMD_BYTE          0x0Au   /* matches CTAP2_CMD_CREDENTIAL_MGMT */
#define CREDMGMT_PIN_PROTO_V1      1u

/* Sub-command IDs (CTAP2.1 §6.8.2). */
#define SUB_GET_CREDS_METADATA            0x01u
#define SUB_ENUM_RPS_BEGIN                0x02u
#define SUB_ENUM_RPS_GET_NEXT             0x03u
#define SUB_ENUM_CREDS_BEGIN              0x04u
#define SUB_ENUM_CREDS_GET_NEXT           0x05u
#define SUB_DELETE_CREDENTIAL             0x06u
/* 0x07 updateUserInformation — Phase 8 polish */

/* Response CBOR keys (CTAP2.1 §6.8.3). */
#define RESP_KEY_EXIST_RES_CRED_COUNT     0x01u   /* getCredsMetadata */
#define RESP_KEY_MAX_POSSIBLE_REMAINING   0x02u
#define RESP_KEY_RP                       0x03u   /* enumerateRPs */
#define RESP_KEY_RP_ID_HASH               0x04u
#define RESP_KEY_TOTAL_RPS                0x05u
#define RESP_KEY_USER                     0x06u   /* enumerateCredentials */
#define RESP_KEY_CREDENTIAL_ID            0x07u
#define RESP_KEY_PUBLIC_KEY               0x08u
#define RESP_KEY_TOTAL_CREDENTIALS        0x09u

/* Iterator state. */
typedef enum {
    ITER_NONE  = 0,
    ITER_RPS,
    ITER_CREDS,
} iter_kind_t;

static iter_kind_t s_iter_kind;

/* RP iterator: snapshot of slot indices that are the FIRST occurrence
 * of each unique rpIdHash. */
static int8_t  s_iter_rp_slots[SLOTS_MAX];
static int     s_iter_rp_count;
static int     s_iter_rp_pos;

/* Cred iterator: snapshot of slot indices matching a queried rpIdHash. */
static uint8_t s_iter_cred_rp_hash[SLOTS_RP_ID_HASH_LEN];
static int8_t  s_iter_cred_slots[SLOTS_MAX];
static int     s_iter_cred_count;
static int     s_iter_cred_pos;

void credmgmt_reset_iterator(void)
{
    s_iter_kind = ITER_NONE;
    s_iter_rp_count = 0;
    s_iter_rp_pos = 0;
    s_iter_cred_count = 0;
    s_iter_cred_pos = 0;
    /* Don't memzero the slots arrays — they're indices, not secrets. */
}

/* ----- Helpers ----- */

/* Build a deduplicated list of RP indices from the current credstore.
 * "First occurrence" = the smallest slot index for each unique
 * rpIdHash.  out_slots receives those slot indices.  Returns the count
 * of unique RPs. */
static int build_rp_list(int8_t out_slots[SLOTS_MAX])
{
    int count = 0;
    uint32_t bitmap = slots_bitmap();
    for (int i = 0; i < (int) SLOTS_MAX; ++i) {
        if ((bitmap & (1u << i)) == 0u) {
            continue;
        }
        slot_meta_t meta;
        if (slots_read_meta(i, &meta) != 0) {
            continue;
        }
        /* Is this rp_id_hash already in out_slots[]? */
        int dup = 0;
        for (int j = 0; j < count; ++j) {
            slot_meta_t prev;
            if (slots_read_meta(out_slots[j], &prev) != 0) continue;
            if (memcmp(meta.rp_id_hash, prev.rp_id_hash,
                       SLOTS_RP_ID_HASH_LEN) == 0) {
                dup = 1;
                break;
            }
        }
        if (!dup) {
            out_slots[count++] = (int8_t) i;
        }
    }
    return count;
}

/* List all slots matching a given rpIdHash. */
static int build_cred_list_for_rp(const uint8_t rp_hash[SLOTS_RP_ID_HASH_LEN],
                                  int8_t out_slots[SLOTS_MAX])
{
    int count = 0;
    uint32_t bitmap = slots_bitmap();
    for (int i = 0; i < (int) SLOTS_MAX; ++i) {
        if ((bitmap & (1u << i)) == 0u) {
            continue;
        }
        slot_meta_t meta;
        if (slots_read_meta(i, &meta) != 0) {
            continue;
        }
        if (memcmp(meta.rp_id_hash, rp_hash, SLOTS_RP_ID_HASH_LEN) == 0) {
            out_slots[count++] = (int8_t) i;
        }
    }
    return count;
}

/* COSE_Key map for an Ed25519 public key (matches what MakeCredential
 * emits as attestedCredentialData.credPubKey).  46 bytes total. */
static int write_cose_ed25519(cbor_writer_t *w, const uint8_t pubkey[32])
{
    cbor_write_map_header(w, 4);
    cbor_write_uint(w, 1);   cbor_write_uint(w, 1);                   /* kty=OKP */
    cbor_write_uint(w, 3);   cbor_write_negint(w, -8);                /* alg=EdDSA */
    cbor_write_negint(w, -1); cbor_write_uint(w, 6);                  /* crv=Ed25519 */
    cbor_write_negint(w, -2); cbor_write_byte_string(w, pubkey, 32);  /* x */
    return cbor_writer_error(w) ? -1 : 0;
}

/* PublicKeyCredentialDescriptor for our 18 B credential ID. */
static void write_pkc_descriptor(cbor_writer_t *w,
                                 const uint8_t cred_id[SLOTS_CRED_ID_LEN])
{
    cbor_write_map_header(w, 2);
    cbor_write_text(w, "id");
    cbor_write_byte_string(w, cred_id, SLOTS_CRED_ID_LEN);
    cbor_write_text(w, "type");
    cbor_write_text(w, "public-key");
}

/* Reconstruct an 18 B credential ID from a slot index + the metadata's
 * nonce.  Mirrors slots.c's emit format. */
static void build_cred_id_for_slot(int slot_idx, const slot_meta_t *meta,
                                   uint8_t out_cred_id[SLOTS_CRED_ID_LEN])
{
    out_cred_id[0] = 0x01u;
    out_cred_id[1] = (uint8_t) slot_idx;
    memcpy(&out_cred_id[2], meta->cred_id_nonce, SLOTS_CRED_ID_NONCE_LEN);
}

/* PublicKeyCredentialUserEntity from a slot's user_handle.
 * Spec says `id` is required; we pass user_handle bytes verbatim.
 * If user_handle_len == 0 (Phase 5 cred, or omitted at MakeCred), we
 * fall back to using the credId bytes as a stand-in id — non-spec-
 * compliant strictly, but allows libfido2 to display the cred. */
static void write_user_entity(cbor_writer_t *w,
                              const slot_meta_t *meta,
                              const uint8_t cred_id[SLOTS_CRED_ID_LEN])
{
    cbor_write_map_header(w, 1);
    cbor_write_text(w, "id");
    if (meta->user_handle_len > 0u) {
        cbor_write_byte_string(w, meta->user_handle, meta->user_handle_len);
    } else {
        cbor_write_byte_string(w, cred_id, SLOTS_CRED_ID_LEN);
    }
}

/* ----- Sub-command handlers ----- */

static int do_get_creds_metadata(uint8_t *resp, size_t resp_max)
{
    int used = slots_count_used();
    int free_slots = (int) SLOTS_MAX - used;
    if (free_slots < 0) free_slots = 0;

    if (resp_max < 1u) return -1;
    resp[0] = CTAP2_OK;

    cbor_writer_t w;
    cbor_writer_init(&w, &resp[1], resp_max - 1u);
    cbor_write_map_header(&w, 2);
    cbor_write_uint(&w, RESP_KEY_EXIST_RES_CRED_COUNT);
    cbor_write_uint(&w, (uint64_t) used);
    cbor_write_uint(&w, RESP_KEY_MAX_POSSIBLE_REMAINING);
    cbor_write_uint(&w, (uint64_t) free_slots);
    if (cbor_writer_error(&w)) {
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }
    return (int)(1u + cbor_writer_len(&w));
}

/* Write a single RP entry response (used by both Begin and GetNextRP).
 *
 * PublicKeyCredentialRpEntity.id must be a TEXT string (DOMString) per
 * the WebAuthn spec — libfido2's `cbor_string_copy` requires it and
 * returns INVALID_CBOR if it gets a byte_string instead.  We don't
 * persist the original rp.id text (Phase 5 only stored the SHA-256
 * hash), so we emit the hex-encoded hash as a stand-in.  Phase 8
 * polish: add rp.id text storage and emit the real string. */
static int write_rp_entry(uint8_t *resp, size_t resp_max,
                          int slot_idx, int total_rps_or_zero)
{
    slot_meta_t meta;
    if (slots_read_meta(slot_idx, &meta) != 0) {
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }
    if (resp_max < 1u) return -1;
    resp[0] = CTAP2_OK;
    cbor_writer_t w;
    cbor_writer_init(&w, &resp[1], resp_max - 1u);

    /* Hex-encode rp_id_hash as a 64-char ASCII string. */
    static const char HEX[] = "0123456789abcdef";
    char hex[65];
    for (int i = 0; i < (int) SLOTS_RP_ID_HASH_LEN; ++i) {
        hex[i * 2]     = HEX[meta.rp_id_hash[i] >> 4];
        hex[i * 2 + 1] = HEX[meta.rp_id_hash[i] & 0x0fu];
    }
    hex[64] = '\0';

    cbor_write_map_header(&w, total_rps_or_zero ? 3 : 2);
    cbor_write_uint(&w, RESP_KEY_RP);
    cbor_write_map_header(&w, 1);
    cbor_write_text(&w, "id");
    cbor_write_text(&w, hex);
    cbor_write_uint(&w, RESP_KEY_RP_ID_HASH);
    cbor_write_byte_string(&w, meta.rp_id_hash, SLOTS_RP_ID_HASH_LEN);
    if (total_rps_or_zero) {
        cbor_write_uint(&w, RESP_KEY_TOTAL_RPS);
        cbor_write_uint(&w, (uint64_t) total_rps_or_zero);
    }

    if (cbor_writer_error(&w)) {
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }
    return (int)(1u + cbor_writer_len(&w));
}

static int do_enum_rps_begin(uint8_t *resp, size_t resp_max)
{
    s_iter_rp_count = build_rp_list(s_iter_rp_slots);
    s_iter_rp_pos = 0;
    s_iter_kind = ITER_RPS;

    if (s_iter_rp_count == 0) {
        resp[0] = CTAP2_ERR_NO_CREDENTIALS;
        return 1;
    }
    int rc = write_rp_entry(resp, resp_max,
                            s_iter_rp_slots[s_iter_rp_pos],
                            s_iter_rp_count);
    s_iter_rp_pos += 1;
    return rc;
}

static int do_enum_rps_next(uint8_t *resp, size_t resp_max)
{
    if (s_iter_kind != ITER_RPS) {
        resp[0] = CTAP2_ERR_NOT_ALLOWED;
        return 1;
    }
    if (s_iter_rp_pos >= s_iter_rp_count) {
        resp[0] = CTAP2_ERR_NOT_ALLOWED;
        return 1;
    }
    int rc = write_rp_entry(resp, resp_max,
                            s_iter_rp_slots[s_iter_rp_pos],
                            0 /* totalRPs only on Begin */);
    s_iter_rp_pos += 1;
    return rc;
}

/* Write a single credential entry response (Begin and GetNext share). */
static int write_cred_entry(uint8_t *resp, size_t resp_max,
                            int slot_idx, int total_or_zero)
{
    slot_meta_t meta;
    if (slots_read_meta(slot_idx, &meta) != 0) {
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }
    uint8_t pubkey[CREDSTORE_PUBKEY_LEN];
    if (credstore_get_pubkey(slot_idx, pubkey) != 0) {
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }

    uint8_t cred_id[SLOTS_CRED_ID_LEN];
    build_cred_id_for_slot(slot_idx, &meta, cred_id);

    if (resp_max < 1u) return -1;
    resp[0] = CTAP2_OK;
    cbor_writer_t w;
    cbor_writer_init(&w, &resp[1], resp_max - 1u);

    cbor_write_map_header(&w, total_or_zero ? 4 : 3);
    cbor_write_uint(&w, RESP_KEY_USER);
    write_user_entity(&w, &meta, cred_id);
    cbor_write_uint(&w, RESP_KEY_CREDENTIAL_ID);
    write_pkc_descriptor(&w, cred_id);
    cbor_write_uint(&w, RESP_KEY_PUBLIC_KEY);
    if (write_cose_ed25519(&w, pubkey) != 0) {
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }
    if (total_or_zero) {
        cbor_write_uint(&w, RESP_KEY_TOTAL_CREDENTIALS);
        cbor_write_uint(&w, (uint64_t) total_or_zero);
    }

    if (cbor_writer_error(&w)) {
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }
    return (int)(1u + cbor_writer_len(&w));
}

static int do_enum_creds_begin(const uint8_t *params, size_t params_len,
                               uint8_t *resp, size_t resp_max)
{
    /* params = { 1: rpIDHash (bytes, 32) } */
    cbor_reader_t r;
    cbor_reader_init(&r, params, params_len);
    size_t n_keys;
    if (cbor_reader_read_map_header(&r, &n_keys) < 0) {
        resp[0] = CTAP2_ERR_INVALID_CBOR;
        return 1;
    }
    uint8_t rp_hash[SLOTS_RP_ID_HASH_LEN];
    int got_rp_hash = 0;
    for (size_t i = 0; i < n_keys; ++i) {
        uint8_t mt; uint64_t key;
        if (cbor_reader_read_head(&r, &mt, &key) < 0 || mt != 0u) {
            resp[0] = CTAP2_ERR_INVALID_CBOR;
            return 1;
        }
        if (key == 1u) {
            const uint8_t *p; size_t L;
            if (cbor_reader_read_bytes(&r, &p, &L) < 0
                || L != SLOTS_RP_ID_HASH_LEN) {
                resp[0] = CTAP2_ERR_INVALID_CBOR;
                return 1;
            }
            memcpy(rp_hash, p, SLOTS_RP_ID_HASH_LEN);
            got_rp_hash = 1;
        } else {
            if (cbor_reader_skip(&r) < 0) {
                resp[0] = CTAP2_ERR_INVALID_CBOR;
                return 1;
            }
        }
    }
    if (!got_rp_hash) {
        resp[0] = CTAP2_ERR_MISSING_PARAMETER;
        return 1;
    }

    memcpy(s_iter_cred_rp_hash, rp_hash, SLOTS_RP_ID_HASH_LEN);
    s_iter_cred_count = build_cred_list_for_rp(rp_hash, s_iter_cred_slots);
    s_iter_cred_pos = 0;
    s_iter_kind = ITER_CREDS;

    if (s_iter_cred_count == 0) {
        resp[0] = CTAP2_ERR_NO_CREDENTIALS;
        return 1;
    }
    int rc = write_cred_entry(resp, resp_max,
                              s_iter_cred_slots[s_iter_cred_pos],
                              s_iter_cred_count);
    s_iter_cred_pos += 1;
    return rc;
}

static int do_enum_creds_next(uint8_t *resp, size_t resp_max)
{
    if (s_iter_kind != ITER_CREDS) {
        resp[0] = CTAP2_ERR_NOT_ALLOWED;
        return 1;
    }
    if (s_iter_cred_pos >= s_iter_cred_count) {
        resp[0] = CTAP2_ERR_NOT_ALLOWED;
        return 1;
    }
    int rc = write_cred_entry(resp, resp_max,
                              s_iter_cred_slots[s_iter_cred_pos],
                              0);
    s_iter_cred_pos += 1;
    return rc;
}

static int do_delete_credential(const uint8_t *params, size_t params_len,
                                uint8_t *resp, size_t resp_max)
{
    /* params = { 2: PublicKeyCredentialDescriptor }
     *   PKCD = { "id": bytes, "type": "public-key" } */
    cbor_reader_t r;
    cbor_reader_init(&r, params, params_len);
    size_t n_keys;
    if (cbor_reader_read_map_header(&r, &n_keys) < 0) {
        resp[0] = CTAP2_ERR_INVALID_CBOR;
        return 1;
    }
    const uint8_t *cred_id_p = NULL;
    size_t cred_id_len = 0;
    int got_id = 0;
    for (size_t i = 0; i < n_keys; ++i) {
        uint8_t mt; uint64_t key;
        if (cbor_reader_read_head(&r, &mt, &key) < 0 || mt != 0u) {
            resp[0] = CTAP2_ERR_INVALID_CBOR;
            return 1;
        }
        if (key == 2u) {
            /* PublicKeyCredentialDescriptor map */
            size_t mc;
            if (cbor_reader_read_map_header(&r, &mc) < 0) {
                resp[0] = CTAP2_ERR_INVALID_CBOR;
                return 1;
            }
            for (size_t j = 0; j < mc; ++j) {
                const uint8_t *kp; size_t kL;
                if (cbor_reader_read_text(&r, &kp, &kL) < 0) {
                    resp[0] = CTAP2_ERR_INVALID_CBOR;
                    return 1;
                }
                if (kL == 2u && memcmp(kp, "id", 2) == 0) {
                    if (cbor_reader_read_bytes(&r, &cred_id_p, &cred_id_len) < 0) {
                        resp[0] = CTAP2_ERR_INVALID_CBOR;
                        return 1;
                    }
                    got_id = 1;
                } else {
                    if (cbor_reader_skip(&r) < 0) {
                        resp[0] = CTAP2_ERR_INVALID_CBOR;
                        return 1;
                    }
                }
            }
        } else {
            if (cbor_reader_skip(&r) < 0) {
                resp[0] = CTAP2_ERR_INVALID_CBOR;
                return 1;
            }
        }
    }
    if (!got_id) {
        resp[0] = CTAP2_ERR_MISSING_PARAMETER;
        return 1;
    }

    credstore_handle_t handle = CREDSTORE_INVALID_HANDLE;
    if (credstore_lookup(cred_id_p, cred_id_len, &handle) != 0) {
        resp[0] = CTAP2_ERR_NO_CREDENTIALS;
        return 1;
    }
    if (credstore_erase_slot((int) handle) != 0) {
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }
    resp[0] = CTAP2_OK;
    return 1;
}

/* ----- Top-level CBOR dispatch ----- */

int credmgmt_handle_cbor(const uint8_t *req, size_t req_len,
                         uint8_t *resp, size_t resp_max)
{
    if (resp_max < 1u) return -1;

    /* Parse the outer request map.  Keys 1..4.
     * subCommandParams (key 2) is captured by raw-byte offsets so we
     * can HMAC over the exact wire-format bytes (H3 domain separation). */
    cbor_reader_t r;
    cbor_reader_init(&r, req, req_len);
    size_t n_keys;
    if (cbor_reader_read_map_header(&r, &n_keys) < 0) {
        resp[0] = CTAP2_ERR_INVALID_CBOR;
        return 1;
    }

    int sub = -1;
    const uint8_t *params_p = NULL;
    size_t params_len = 0;
    int pin_proto = 0;
    const uint8_t *pin_auth_p = NULL;
    size_t pin_auth_len = 0;

    for (size_t i = 0; i < n_keys; ++i) {
        uint8_t mt; uint64_t key;
        if (cbor_reader_read_head(&r, &mt, &key) < 0 || mt != 0u) {
            resp[0] = CTAP2_ERR_INVALID_CBOR;
            return 1;
        }
        if (key == 1u) {
            uint8_t m2; uint64_t v;
            if (cbor_reader_read_head(&r, &m2, &v) < 0 || m2 != 0u) {
                resp[0] = CTAP2_ERR_INVALID_CBOR;
                return 1;
            }
            sub = (int) v;
        } else if (key == 2u) {
            /* Capture raw bytes of subCommandParams for HMAC input. */
            size_t start = r.pos;
            if (cbor_reader_skip(&r) < 0) {
                resp[0] = CTAP2_ERR_INVALID_CBOR;
                return 1;
            }
            params_p   = &req[start];
            params_len = r.pos - start;
        } else if (key == 3u) {
            uint8_t m2; uint64_t v;
            if (cbor_reader_read_head(&r, &m2, &v) < 0 || m2 != 0u) {
                resp[0] = CTAP2_ERR_INVALID_CBOR;
                return 1;
            }
            pin_proto = (int) v;
        } else if (key == 4u) {
            if (cbor_reader_read_bytes(&r, &pin_auth_p, &pin_auth_len) < 0) {
                resp[0] = CTAP2_ERR_INVALID_CBOR;
                return 1;
            }
        } else {
            if (cbor_reader_skip(&r) < 0) {
                resp[0] = CTAP2_ERR_INVALID_CBOR;
                return 1;
            }
        }
    }

    if (sub < 0) {
        resp[0] = CTAP2_ERR_MISSING_PARAMETER;
        return 1;
    }

    /* PIN auth required for ALL credMgmt sub-commands per CTAP2.1 §6.8.
     * Iterator-continuation sub-commands (GetNextRP, GetNextCredential)
     * spec-allow either fresh pinAuth OR re-use of the prior Begin's
     * authentication context.  Pragmatically, libfido2 sends pinAuth on
     * EVERY sub-command including Get-Next, so we just verify it
     * every time. */
    if (pin_auth_p == NULL || pin_auth_len != 16u) {
        resp[0] = CTAP2_ERR_PIN_REQUIRED;
        return 1;
    }
    if (pin_proto != (int) CREDMGMT_PIN_PROTO_V1) {
        resp[0] = CTAP1_ERR_INVALID_PARAMETER;
        return 1;
    }
    /* pinUvAuthParam per CTAP2.1 §6.8.2 step 2:
     *   HMAC-SHA-256(pinUvAuthToken, subCommand || subCommandParams)[:16]
     *
     * Spec does NOT prepend the outer cmd byte 0x0a — sub-command alone
     * is the domain tag.  Cross-command replay defense (e.g. pinAuth
     * from MakeCred against credMgmt) comes from MakeCred's input being
     * a 32-byte clientDataHash vs. credMgmt's being subCmd || params —
     * different byte strings, different HMACs.
     *
     * (Earlier implementation prepended 0x0a per a cpp-reviewer
     * recommendation; that broke libfido2 compat which strictly follows
     * the spec.  Spec rules; recommendation was over-engineering.) */
    uint8_t auth_input[1 + 512];
    if (params_len > (sizeof auth_input - 1u)) {
        resp[0] = CTAP2_ERR_REQUEST_TOO_LARGE;
        return 1;
    }
    auth_input[0] = (uint8_t) sub;
    if (params_len > 0u && params_p != NULL) {
        memcpy(&auth_input[1], params_p, params_len);
    }
    if (pin_verify_pinauth_data(pin_auth_p, auth_input, 1u + params_len) != 0) {
        resp[0] = CTAP2_ERR_PIN_AUTH_INVALID;
        return 1;
    }

    /* Iterator-reset semantics: any sub-command other than the matching
     * GetNext resets the iterator state.  Strictly per CTAP2.1 §6.8. */
    if (sub != (int) SUB_ENUM_RPS_GET_NEXT && s_iter_kind == ITER_RPS) {
        credmgmt_reset_iterator();
    }
    if (sub != (int) SUB_ENUM_CREDS_GET_NEXT && s_iter_kind == ITER_CREDS) {
        credmgmt_reset_iterator();
    }

    switch ((unsigned) sub) {
    case SUB_GET_CREDS_METADATA:
        return do_get_creds_metadata(resp, resp_max);
    case SUB_ENUM_RPS_BEGIN:
        return do_enum_rps_begin(resp, resp_max);
    case SUB_ENUM_RPS_GET_NEXT:
        return do_enum_rps_next(resp, resp_max);
    case SUB_ENUM_CREDS_BEGIN:
        return do_enum_creds_begin(params_p, params_len, resp, resp_max);
    case SUB_ENUM_CREDS_GET_NEXT:
        return do_enum_creds_next(resp, resp_max);
    case SUB_DELETE_CREDENTIAL:
        return do_delete_credential(params_p, params_len, resp, resp_max);
    default:
        resp[0] = CTAP1_ERR_INVALID_COMMAND;
        return 1;
    }
}
