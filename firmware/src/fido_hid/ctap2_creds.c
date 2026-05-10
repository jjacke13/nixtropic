/*
 * CTAP2 MakeCredential (0x01) + GetAssertion (0x02) — stub backend.
 *
 * Authenticator-data layout (WebAuthn §6.5.1):
 *
 *   offset  size   field
 *   ------  ----   -----
 *      0    32     rpIdHash (SHA-256 of rpId)
 *     32     1     flags
 *                    bit 0 (UP)  user-presence — stubbed true
 *                    bit 2 (UV)  user-verified — we leave 0
 *                    bit 6 (AT)  attested-credential-data present
 *                                (MakeCredential only)
 *                    bit 7 (ED)  extensions present
 *     33     4     signCount (big-endian uint32)
 *     37   var     attestedCredentialData (if AT bit set)
 *                    {
 *                       aaguid       16 B
 *                       credIdLen     2 B BE
 *                       credId       credIdLen B
 *                       credPubKey   var (COSE_Key)
 *                    }
 *
 * Signature input = authData || clientDataHash.
 *
 * For MakeCredential we return a "packed" self-attestation:
 *   { 1: "packed", 2: authData, 3: { alg: -8, sig: <64 B> } }
 *
 * For GetAssertion we return:
 *   { 1: { id: <credId>, type: "public-key" },
 *     2: authData,
 *     3: <64 B sig> }
 */

#include "ctap2.h"
#include "credstore.h"
#include "cbor.h"
#include "proto.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* trezor_crypto SHA-256. */
#include "sha2.h"

/* AAGUID exported from ctap2.c. Duplicate definition here would shadow.
 * Borrow via extern. */
extern const uint8_t NIXTROPIC_AAGUID[16];

/* ----- Helpers ----- */

static void be32_store(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t) v;
}

/* COSE_Key for Ed25519 public key. CBOR map with integer keys in
 * canonical (length-then-byte) order:
 *
 *   1 → kty = 1   (OKP)
 *   3 → alg = -8  (EdDSA)
 *  -1 → crv = 6   (Ed25519)
 *  -2 → x          (32-byte public key)
 *
 * Encoded keys: 0x01, 0x03, 0x20, 0x21 — already in ascending byte
 * order, so writing them in the natural numeric order produces
 * canonical output. */
static int build_cose_ed25519(const uint8_t *pubkey, uint8_t *out, size_t out_max)
{
    cbor_writer_t w;
    cbor_writer_init(&w, out, out_max);
    cbor_write_map_header(&w, 4);
    cbor_write_uint(&w, 1);   cbor_write_uint(&w, 1);     /* kty: OKP */
    cbor_write_uint(&w, 3);   cbor_write_negint(&w, -8);  /* alg: EdDSA */
    cbor_write_negint(&w, -1); cbor_write_uint(&w, 6);    /* crv: Ed25519 */
    cbor_write_negint(&w, -2); cbor_write_byte_string(&w, pubkey, CREDSTORE_PUBKEY_LEN);
    if (cbor_writer_error(&w)) return -1;
    return (int) cbor_writer_len(&w);
}

/* ----- Request parsing ----- */

/* Minimal MakeCredential request parser. We extract only:
 *   key 1: clientDataHash (32 B)
 *   key 2: rp.id (text string)
 *   key 4: pubKeyCredParams must contain at least one supported alg
 *
 * Returns 0 on success, negative CTAP2 status on failure. */
static int parse_make_cred(const uint8_t *req, size_t req_len,
                           uint8_t *out_client_hash,
                           const uint8_t **out_rp_id, size_t *out_rp_id_len,
                           int *out_alg)
{
    int alg_found = 0;
    int alg_pref  = 0;        /* selected COSE alg id */
    int got_chash = 0;
    int got_rpid  = 0;

    cbor_reader_t r;
    cbor_reader_init(&r, req, req_len);

    size_t n_keys;
    if (cbor_reader_read_map_header(&r, &n_keys) < 0) {
        return -(int) CTAP2_ERR_INVALID_CBOR;
    }
    for (size_t i = 0; i < n_keys; ++i) {
        uint8_t  mt;
        uint64_t key;
        if (cbor_reader_read_head(&r, &mt, &key) < 0) {
            return -(int) CTAP2_ERR_INVALID_CBOR;
        }
        if (mt != 0u) {
            /* CTAP2 request map keys are unsigned ints. */
            return -(int) CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        if (key == 1u) {
            const uint8_t *p; size_t L;
            if (cbor_reader_read_bytes(&r, &p, &L) < 0) {
                return -(int) CTAP2_ERR_INVALID_CBOR;
            }
            if (L != 32u) return -(int) CTAP1_ERR_INVALID_LENGTH;
            memcpy(out_client_hash, p, 32);
            got_chash = 1;
        } else if (key == 2u) {
            /* rp = { "id": text, "name"?: text } */
            size_t mc;
            if (cbor_reader_read_map_header(&r, &mc) < 0) {
                return -(int) CTAP2_ERR_INVALID_CBOR;
            }
            for (size_t j = 0; j < mc; ++j) {
                const uint8_t *kp; size_t kL;
                if (cbor_reader_read_text(&r, &kp, &kL) < 0) {
                    return -(int) CTAP2_ERR_INVALID_CBOR;
                }
                if (kL == 2u && memcmp(kp, "id", 2) == 0) {
                    if (cbor_reader_read_text(&r, out_rp_id, out_rp_id_len) < 0) {
                        return -(int) CTAP2_ERR_INVALID_CBOR;
                    }
                    got_rpid = 1;
                } else {
                    if (cbor_reader_skip(&r) < 0) {
                        return -(int) CTAP2_ERR_INVALID_CBOR;
                    }
                }
            }
        } else if (key == 4u) {
            /* pubKeyCredParams = [ { "alg": int, "type": text }, ... ] */
            size_t ac;
            if (cbor_reader_read_array_header(&r, &ac) < 0) {
                return -(int) CTAP2_ERR_INVALID_CBOR;
            }
            for (size_t j = 0; j < ac; ++j) {
                size_t entries;
                if (cbor_reader_read_map_header(&r, &entries) < 0) {
                    return -(int) CTAP2_ERR_INVALID_CBOR;
                }
                int alg_here = 0;
                for (size_t k = 0; k < entries; ++k) {
                    const uint8_t *kp; size_t kL;
                    if (cbor_reader_read_text(&r, &kp, &kL) < 0) {
                        return -(int) CTAP2_ERR_INVALID_CBOR;
                    }
                    if (kL == 3u && memcmp(kp, "alg", 3) == 0) {
                        uint8_t  m;
                        uint64_t v;
                        if (cbor_reader_read_head(&r, &m, &v) < 0) {
                            return -(int) CTAP2_ERR_INVALID_CBOR;
                        }
                        if (m == 0u) alg_here = (int) v;          /* uint */
                        else if (m == 1u) alg_here = -1 - (int) v; /* negint */
                        else return -(int) CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                    } else {
                        if (cbor_reader_skip(&r) < 0) {
                            return -(int) CTAP2_ERR_INVALID_CBOR;
                        }
                    }
                }
                /* Pick the first supported alg in the host's preference order. */
                if (!alg_found && (alg_here == -8 || alg_here == -7)) {
                    alg_pref  = alg_here;
                    alg_found = 1;
                }
            }
        } else {
            if (cbor_reader_skip(&r) < 0) {
                return -(int) CTAP2_ERR_INVALID_CBOR;
            }
        }
    }

    if (!got_chash || !got_rpid) {
        return -(int) CTAP2_ERR_MISSING_PARAMETER;
    }
    if (!alg_found) {
        return -(int) CTAP2_ERR_UNSUPPORTED_ALGORITHM;
    }
    /* Phase 4 stub only signs with Ed25519 — refuse ES256 even if
     * advertised. Phase 5 may wire P-256 via TROPIC01 too. */
    if (alg_pref != -8) {
        return -(int) CTAP2_ERR_UNSUPPORTED_ALGORITHM;
    }
    *out_alg = alg_pref;
    return 0;
}

/* Minimal GetAssertion request parser. Extract:
 *   key 1: rpId (text)
 *   key 2: clientDataHash (32 B)
 *   key 3: allowList — optional, we ignore contents (stub accepts any)
 */
static int parse_get_assertion(const uint8_t *req, size_t req_len,
                               uint8_t *out_client_hash,
                               const uint8_t **out_rp_id, size_t *out_rp_id_len)
{
    int got_chash = 0;
    int got_rpid  = 0;

    cbor_reader_t r;
    cbor_reader_init(&r, req, req_len);

    size_t n_keys;
    if (cbor_reader_read_map_header(&r, &n_keys) < 0) {
        return -(int) CTAP2_ERR_INVALID_CBOR;
    }
    for (size_t i = 0; i < n_keys; ++i) {
        uint8_t mt; uint64_t key;
        if (cbor_reader_read_head(&r, &mt, &key) < 0 || mt != 0u) {
            return -(int) CTAP2_ERR_INVALID_CBOR;
        }
        if (key == 1u) {
            if (cbor_reader_read_text(&r, out_rp_id, out_rp_id_len) < 0) {
                return -(int) CTAP2_ERR_INVALID_CBOR;
            }
            got_rpid = 1;
        } else if (key == 2u) {
            const uint8_t *p; size_t L;
            if (cbor_reader_read_bytes(&r, &p, &L) < 0) {
                return -(int) CTAP2_ERR_INVALID_CBOR;
            }
            if (L != 32u) return -(int) CTAP1_ERR_INVALID_LENGTH;
            memcpy(out_client_hash, p, 32);
            got_chash = 1;
        } else {
            if (cbor_reader_skip(&r) < 0) {
                return -(int) CTAP2_ERR_INVALID_CBOR;
            }
        }
    }
    if (!got_chash || !got_rpid) {
        return -(int) CTAP2_ERR_MISSING_PARAMETER;
    }
    return 0;
}

/* ----- AuthData builder ----- */

#define FLAG_UP  0x01u
#define FLAG_AT  0x40u

static int build_authdata(const uint8_t *rp_id_hash, uint8_t flags,
                          uint32_t sign_count,
                          const uint8_t *cred_id, size_t cred_id_len,
                          const uint8_t *cose_pubkey, size_t cose_pubkey_len,
                          uint8_t *out, size_t out_max)
{
    /* base size = 32 + 1 + 4 = 37; with AT also +16 +2 +credIdLen +pkLen */
    size_t need = 37u;
    int have_at = (flags & FLAG_AT) != 0;
    if (have_at) {
        need += 16u + 2u + cred_id_len + cose_pubkey_len;
    }
    if (need > out_max) return -1;

    size_t off = 0;
    memcpy(&out[off], rp_id_hash, 32); off += 32u;
    out[off++] = flags;
    be32_store(&out[off], sign_count); off += 4u;

    if (have_at) {
        memcpy(&out[off], NIXTROPIC_AAGUID, 16); off += 16u;
        out[off++] = (uint8_t)(cred_id_len >> 8);
        out[off++] = (uint8_t) cred_id_len;
        memcpy(&out[off], cred_id, cred_id_len); off += cred_id_len;
        memcpy(&out[off], cose_pubkey, cose_pubkey_len); off += cose_pubkey_len;
    }

    return (int) off;
}

/* ----- Handlers ----- */

int ctap2_make_credential(const uint8_t *req, size_t req_len,
                          uint8_t *resp, size_t resp_max)
{
    uint8_t client_hash[32];
    const uint8_t *rp_id_p = NULL;
    size_t  rp_id_len = 0;
    int     alg = 0;

    int err = parse_make_cred(req, req_len, client_hash, &rp_id_p, &rp_id_len, &alg);
    if (err < 0) {
        resp[0] = (uint8_t)(-err);
        return 1;
    }

    /* rpIdHash = SHA-256(rpId) */
    uint8_t rp_id_hash[32];
    sha256_Raw(rp_id_p, (uint32_t) rp_id_len, rp_id_hash);

    /* COSE-encoded public key */
    uint8_t cose_pub[64];
    int cose_pub_len = build_cose_ed25519(credstore_pubkey(), cose_pub, sizeof cose_pub);
    if (cose_pub_len < 0) {
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }

    /* authData with AT bit set */
    uint8_t auth_data[256];
    int auth_data_len = build_authdata(rp_id_hash, FLAG_UP | FLAG_AT,
                                       credstore_next_signcount(),
                                       credstore_cred_id(), CREDSTORE_CRED_ID_LEN,
                                       cose_pub, (size_t) cose_pub_len,
                                       auth_data, sizeof auth_data);
    if (auth_data_len < 0) {
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }

    /* Signature over authData || clientDataHash */
    uint8_t sig_input[sizeof auth_data + 32];
    memcpy(sig_input, auth_data, (size_t) auth_data_len);
    memcpy(&sig_input[auth_data_len], client_hash, 32);
    uint8_t sig[CREDSTORE_SIG_LEN];
    credstore_sign(sig_input, (size_t) auth_data_len + 32u, sig);

    /* Build attestation response.
     * { 1: "packed", 2: authData, 3: { alg: -8, sig: sig } }
     * Status byte 0x00 first. */
    if (resp_max < 1u) return -1;
    resp[0] = CTAP2_OK;

    cbor_writer_t w;
    cbor_writer_init(&w, &resp[1], resp_max - 1u);
    cbor_write_map_header(&w, 3);

    cbor_write_uint(&w, 1);
    cbor_write_text(&w, "packed");

    cbor_write_uint(&w, 2);
    cbor_write_byte_string(&w, auth_data, (size_t) auth_data_len);

    cbor_write_uint(&w, 3);
    cbor_write_map_header(&w, 2);
    cbor_write_text(&w, "alg");
    cbor_write_negint(&w, -8);
    cbor_write_text(&w, "sig");
    cbor_write_byte_string(&w, sig, CREDSTORE_SIG_LEN);

    if (cbor_writer_error(&w)) {
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }
    return (int)(1u + cbor_writer_len(&w));
}

int ctap2_get_assertion(const uint8_t *req, size_t req_len,
                        uint8_t *resp, size_t resp_max)
{
    uint8_t client_hash[32];
    const uint8_t *rp_id_p = NULL;
    size_t  rp_id_len = 0;

    int err = parse_get_assertion(req, req_len, client_hash, &rp_id_p, &rp_id_len);
    if (err < 0) {
        resp[0] = (uint8_t)(-err);
        return 1;
    }

    uint8_t rp_id_hash[32];
    sha256_Raw(rp_id_p, (uint32_t) rp_id_len, rp_id_hash);

    /* authData WITHOUT attestedCredentialData (UP only) */
    uint8_t auth_data[64];
    int auth_data_len = build_authdata(rp_id_hash, FLAG_UP,
                                       credstore_next_signcount(),
                                       NULL, 0, NULL, 0,
                                       auth_data, sizeof auth_data);
    if (auth_data_len < 0) {
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }

    /* sigInput = authData || clientDataHash */
    uint8_t sig_input[sizeof auth_data + 32];
    memcpy(sig_input, auth_data, (size_t) auth_data_len);
    memcpy(&sig_input[auth_data_len], client_hash, 32);
    uint8_t sig[CREDSTORE_SIG_LEN];
    credstore_sign(sig_input, (size_t) auth_data_len + 32u, sig);

    /* Response:
     * { 1: { id: credId, type: "public-key" },
     *   2: authData,
     *   3: signature }
     */
    if (resp_max < 1u) return -1;
    resp[0] = CTAP2_OK;

    cbor_writer_t w;
    cbor_writer_init(&w, &resp[1], resp_max - 1u);
    cbor_write_map_header(&w, 3);

    cbor_write_uint(&w, 1);
    cbor_write_map_header(&w, 2);
    cbor_write_text(&w, "id");
    cbor_write_byte_string(&w, credstore_cred_id(), CREDSTORE_CRED_ID_LEN);
    cbor_write_text(&w, "type");
    cbor_write_text(&w, "public-key");

    cbor_write_uint(&w, 2);
    cbor_write_byte_string(&w, auth_data, (size_t) auth_data_len);

    cbor_write_uint(&w, 3);
    cbor_write_byte_string(&w, sig, CREDSTORE_SIG_LEN);

    if (cbor_writer_error(&w)) {
        resp[0] = CTAP2_ERR_OTHER;
        return 1;
    }
    return (int)(1u + cbor_writer_len(&w));
}
