/*
 * CTAP2 MakeCredential / GetAssertion request parsing (Phase 9 M3).
 *
 * Pure functions: no chip calls, no global state, so the host tests can
 * feed them valid and broken requests.  The dispatcher has already run
 * cbor_validate() on the whole map (depth, lengths); these parsers check
 * the CTAP structure: required members, member types, and the choice of
 * algorithm.  Pointers in the result point into the request buffer.
 *
 * Return value: 0 on success, otherwise the CTAP2 status byte to send.
 */

#ifndef NIXTROPIC_FIDO_HID_CTAP2_PARSE_H
#define NIXTROPIC_FIDO_HID_CTAP2_PARSE_H

#include <stddef.h>
#include <stdint.h>

#include "cbor.h"

#define CTAP2_OPT_ABSENT        (-1)
#define CTAP2_USER_ID_MAX       64u    /* WebAuthn user.id limit */
#define CTAP2_COSE_ALG_EDDSA    (-8)
#define CTAP2_COSE_ALG_ES256    (-7)

/* An allowList / excludeList: the raw bytes of the validated CBOR array of
 * PublicKeyCredentialDescriptor maps.  present = 0 when the key was absent. */
typedef struct {
    int            present;
    const uint8_t *ptr;
    size_t         len;
} ctap2_cred_list_t;

/* Options map: each entry is CTAP2_OPT_ABSENT, 0 or 1. */
typedef struct {
    int rk;
    int up;
    int uv;
} ctap2_options_t;

/* pinUvAuthParam (may be present with length 0, CTAP §6.1.2 step 1) and
 * pinUvAuthProtocol (CTAP2_OPT_ABSENT, or the value; anything above
 * 0xFFFF is reported as 0xFFFF, which no protocol uses). */
typedef struct {
    int            has_param;
    const uint8_t *param;
    size_t         param_len;
    int            protocol;
} ctap2_pin_uv_t;

typedef struct {
    uint8_t           client_hash[32];
    const uint8_t    *rp_id;
    size_t            rp_id_len;
    const uint8_t    *user_id;          /* NULL only if the request had none */
    size_t            user_id_len;
    int               alg;              /* chosen COSE algorithm */
    ctap2_cred_list_t exclude;
    int               want_cred_props;
    ctap2_options_t   opt;
    ctap2_pin_uv_t    pin_uv;
} ctap2_mc_req_t;

typedef struct {
    const uint8_t    *rp_id;
    size_t            rp_id_len;
    uint8_t           client_hash[32];
    ctap2_cred_list_t allow;
    ctap2_options_t   opt;
    ctap2_pin_uv_t    pin_uv;
} ctap2_ga_req_t;

int ctap2_parse_make_cred(const uint8_t *req, size_t len, ctap2_mc_req_t *out);
int ctap2_parse_get_assertion(const uint8_t *req, size_t len, ctap2_ga_req_t *out);

/* Walk the credential IDs of a list that the parser accepted.  Entries
 * whose type is not "public-key" are skipped (WebAuthn: ignore unknown
 * credential types).  Returns 1 and sets *id / *id_len for each entry,
 * 0 at the end. */
typedef struct {
    cbor_reader_t r;
    size_t        left;
} ctap2_cred_iter_t;

void ctap2_cred_iter_init(ctap2_cred_iter_t *it, const ctap2_cred_list_t *list);
int  ctap2_cred_iter_next(ctap2_cred_iter_t *it, const uint8_t **id, size_t *id_len);

#endif /* NIXTROPIC_FIDO_HID_CTAP2_PARSE_H */
