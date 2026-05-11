/*
 * CTAP2 ClientPIN protocol (CTAP2 §5.5.4 / §6.5) — pinProtocol version 1.
 *
 * Public surface:
 *   pin_init()                — bring up ephemeral P-256 keypair at boot
 *   pin_handle_cbor()         — handle CTAP2_CMD_CLIENT_PIN sub-commands
 *   pin_is_set()              — is a PIN currently configured (from R-mem)
 *   pin_token_is_valid()      — has the host successfully run getPinToken
 *                               this boot? (RAM token still exists)
 *   pin_verify_pinauth()      — check a 16 B pinAuth from MakeCred/GetAssertion
 *                               against (pinUvAuthToken, clientDataHash)
 *
 * Crypto layout for pinProtocol version 1:
 *   - Authenticator: ephemeral P-256 keypair, regenerated at boot AND
 *     after each successful setPin/changePin/getPinToken (forward
 *     secrecy for the shared key — limits damage if a per-op shared key
 *     leaks via side channel).
 *   - Shared key = SHA-256(ECDH(eph_priv, platform_pub).x)   (32 B)
 *   - Encryption: AES-256-CBC with IV=0, key=shared_key
 *   - MAC: pinAuth = LEFT(HMAC-SHA256(shared_key, msg), 16)
 *
 * pinUvAuthToken: 32 B random, generated on every successful getPinToken,
 * lives in RAM only. Wiped at boot and on factory reset. Used by the
 * platform to authenticate subsequent MakeCred/GetAssertion calls via
 *   pinAuth = LEFT(HMAC-SHA256(pinUvAuthToken, clientDataHash), 16)
 *
 * Retry logic (Phase 5 M3 — RAM-only retry counter sub-throttle):
 *   - R-mem-backed pin_retries: 8 max, decrements on every WRONG-PIN
 *     attempt (verified or auth-blocked), restored on correct PIN.
 *     Persists across power-cycles. M4 replaces this with TROPIC01
 *     MAC-and-Destroy slot consumption for hardware-enforced limit.
 *   - RAM-backed consec_fails_this_boot: 3 max, requires power-cycle
 *     to reset. CTAP2 §5.5.4 mandates this in-session limit.
 */

#ifndef NIXTROPIC_FIDO_HID_PIN_H
#define NIXTROPIC_FIDO_HID_PIN_H

#include <stdint.h>
#include <stddef.h>

#define PIN_PROTOCOL_VERSION   1u
#define PIN_HASH_LEN          16u
#define PIN_TOKEN_LEN         32u
#define PIN_AUTH_LEN          16u
#define PIN_MIN_BYTES          4u
#define PIN_MAX_BYTES         63u
#define PIN_ENC_BUF_LEN       64u   /* AES-CBC PIN ciphertext = 4 blocks */
#define PIN_AUTH_BLOCKED_CONSEC 3u  /* CTAP2 §5.5.4 in-boot limit */

/**
 * @brief Generate ephemeral P-256 keypair from TROPIC01 TRNG.
 *        Idempotent — additional calls force key rotation.
 *
 * @return 0 on success; negative on chip error.
 */
int pin_init(void);

/**
 * @brief Handle a CTAP2_CMD_CLIENT_PIN (0x06) sub-command.
 *        Called by the CTAP2 dispatcher in ctap2.c with the byte after
 *        the sub-command byte already stripped.
 *
 * @param req      CBOR-encoded parameter map
 * @param req_len  length of req
 * @param resp     output buffer; resp[0] is the CTAP2 status byte
 * @param resp_max size of resp
 * @return total bytes written to resp (>=1); negative on framing error
 */
int pin_handle_cbor(const uint8_t *req, size_t req_len,
                    uint8_t *resp, size_t resp_max);

/**
 * @brief Is a PIN currently set on this authenticator?
 *        Reads cached state from slots.c (which mirrors R-mem slot 0).
 */
int pin_is_set(void);

/**
 * @brief Has the platform performed a successful getPinToken this boot?
 *        Required before MakeCred/GetAssertion when pin_is_set().
 */
int pin_token_is_valid(void);

/**
 * @brief Verify a pinAuth tag from a MakeCred/GetAssertion request.
 *        Computes LEFT(HMAC-SHA256(pinUvAuthToken, client_data_hash), 16)
 *        and constant-time-compares against the supplied tag.
 *
 * @param pinauth_16          The 16 B tag from CBOR key 8 (MakeCred) / 6 (GetAssertion)
 * @param client_data_hash_32 The 32 B clientDataHash from CBOR key 1 (MakeCred) / 2 (GetAssertion)
 * @return 0 on match; -1 on mismatch / no token available
 */
int pin_verify_pinauth(const uint8_t pinauth_16[PIN_AUTH_LEN],
                       const uint8_t client_data_hash_32[32]);

#endif /* NIXTROPIC_FIDO_HID_PIN_H */
