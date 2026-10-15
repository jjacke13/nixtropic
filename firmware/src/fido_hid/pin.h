/*
 * CTAP2 ClientPIN protocol (CTAP2 §5.5.4 / §6.5) — pinProtocol version 1.
 *
 * Public surface:
 *   pin_init()                — bring up ephemeral P-256 keypair at boot
 *   pin_handle_cbor()         — handle CTAP2_CMD_CLIENT_PIN sub-commands
 *   pin_is_set()              — is a PIN currently configured (from R-mem)
 *   pin_reset_ram()           — forget token + in-boot PIN failure state
 *   pin_token_is_valid()      — is a pinUvAuthToken in use? (debug lt-rpc gate)
 *   Token checks for MakeCred / GetAssertion / credMgmt / config: pin_token.h
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
 * pinUvAuthToken: 32 B random, generated on every successful getPinToken
 * (0x05, permissions mc+ga) or getPinUvAuthTokenUsingPinWithPermissions
 * (0x09, CTAP2.1, Phase 9 M3).  RAM only; its state (permissions, RP ID,
 * timers) lives in pin_token.c.  Wiped at boot, on set/changePIN and on
 * factory reset.  The platform authenticates later commands with
 *   pinAuth = LEFT(HMAC-SHA256(pinUvAuthToken, message), 16)
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
 * @brief Forget the pinUvAuthToken, the in-boot PIN failure state, and
 *        rotate the key-agreement key.  authenticatorReset calls this
 *        (Phase 9 M3).
 */
void pin_reset_ram(void);

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
 * @brief Is a pinUvAuthToken in use (issued, not reset)?  Only the debug
 *        lt-rpc setters use this; CTAP commands check the token with
 *        pin_token.h (permissions, RP ID, timers).
 */
int pin_token_is_valid(void);

#endif /* NIXTROPIC_FIDO_HID_PIN_H */
