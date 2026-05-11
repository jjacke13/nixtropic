/*
 * authenticatorCredentialManagement (CTAP2 cmd 0x0A) — Phase 6 M3.
 *
 * Implements CTAP2.1 §6.8 sub-commands for enumeration and deletion of
 * resident credentials.  Wired into ctap2.c's CBOR dispatcher.
 *
 * Sub-commands implemented (CTAP2.1 §6.8.2):
 *   0x01  getCredsMetadata
 *   0x02  enumerateRPsBegin
 *   0x03  enumerateRPsGetNextRP
 *   0x04  enumerateCredentialsBegin
 *   0x05  enumerateCredentialsGetNextCredential
 *   0x06  deleteCredential
 *
 * Deferred:
 *   0x07  updateUserInformation — Phase 8 polish (needs full user
 *          name/displayName storage; M3 stores only user_handle).
 *
 * pinUvAuthParam construction — matches CTAP2.1 §6.8.2 step 2 AND
 * libfido2's `lib/credman.c` `prepare_hmac`:
 *   HMAC-SHA-256(pinUvAuthToken, subCommand || subCommandParams)[:16]
 * The sub-command byte alone is the domain tag.  No outer 0x0A prefix.
 *
 * (An earlier cpp-reviewer recommendation called for a 0x0A prefix per
 * one reading of CTAP2.1.  Empirically libfido2 does NOT include the
 * outer cmd byte — its `prepare_hmac` writes `hmac_data[0] = cmd`
 * where `cmd` IS the sub-command byte.  Cross-command replay defense
 * still holds: MakeCred's HMAC input is the 32-byte clientDataHash;
 * credMgmt's is `subCmd || params` which starts with a small integer.
 * Different byte sequences, different HMAC outputs.)
 *
 * Iterator state machine: any sub-command OTHER than the matching
 * GetNext* resets the iterator.  Strictly spec-conformant per
 * CTAP2.1 §6.8 (iterator expires on "any other authenticator operation").
 *
 * Concurrent-mutation defense (H2): deleteCredential calls
 * credstore_erase_slot which raises credstore_is_mutating().
 * MakeCred / GetAssertion in ctap2_creds.c check this flag and refuse
 * with NOT_ALLOWED while a delete is in flight.
 */

#ifndef NIXTROPIC_FIDO_HID_CREDMGMT_H
#define NIXTROPIC_FIDO_HID_CREDMGMT_H

#include <stdint.h>
#include <stddef.h>

/* Single entrypoint called from ctap2.c when cmd byte == 0x0A.
 *
 * @param  req      CBOR payload (sub-command byte at req[0]... no, that's
 *                  ctap2.c's responsibility; req here is the CBOR map after
 *                  the cmd byte was peeled off).  The map carries keys
 *                  {1: subCmd, 2: subCmdParams?, 3: pinProtocol?, 4: pinAuth?}.
 * @param  req_len  Length of req.
 * @param  resp     Response buffer; resp[0] is the CTAP2 status byte and
 *                  bytes after are the response CBOR (if any).
 * @param  resp_max Capacity of resp.
 * @return Length of the response (≥ 1, status byte always written).
 */
int credmgmt_handle_cbor(const uint8_t *req, size_t req_len,
                         uint8_t *resp, size_t resp_max);

/* Reset the iterator state.  Called by ctap2.c on any CTAP2 command other
 * than credMgmt-enumerate-next so the iterator can't span unrelated ops. */
void credmgmt_reset_iterator(void);

#endif /* NIXTROPIC_FIDO_HID_CREDMGMT_H */
