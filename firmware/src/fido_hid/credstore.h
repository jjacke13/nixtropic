/*
 * Phase 4 credential store — STUB only.
 *
 * A single fixed Ed25519 keypair, derived deterministically from a
 * compiled-in seed. Every credential the firmware returns reuses this
 * one keypair (and a deterministic 32-byte credential ID). The same
 * private key signs every assertion. This is FINE for Phase 4 because
 * the goal is protocol validation, not key isolation.
 *
 * Phase 5 will replace this module with a TROPIC01-backed implementation
 * that maps each (rpId, slot) to a TROPIC01 ECC slot and signs via
 * lt_ecc_eddsa_sign. The credstore.h API is intentionally minimal so
 * that swap is mechanical.
 *
 * WARNING: the seed and resulting private key are embedded in the
 * firmware binary. Anyone with a firmware image can forge signatures
 * against this device. Never use Phase 4 firmware for actual login.
 */

#ifndef NIXTROPIC_FIDO_HID_CREDSTORE_H
#define NIXTROPIC_FIDO_HID_CREDSTORE_H

#include <stdint.h>
#include <stddef.h>

#define CREDSTORE_PUBKEY_LEN     32u
#define CREDSTORE_SIG_LEN        64u
#define CREDSTORE_CRED_ID_LEN    32u

/**
 * @brief Initialize the stub credential store. Derives the Ed25519
 *        public key from the embedded seed; safe to call multiple times.
 */
void credstore_init(void);

/**
 * @brief Return the cached 32-byte Ed25519 public key.
 */
const uint8_t *credstore_pubkey(void);

/**
 * @brief Return the fixed 32-byte stub credential ID.
 */
const uint8_t *credstore_cred_id(void);

/**
 * @brief Ed25519 sign `msg` into `sig_out` (64 bytes).
 */
void credstore_sign(const uint8_t *msg, size_t msg_len, uint8_t *sig_out);

/**
 * @brief Read the *next* signature counter value without incrementing.
 *        Combined with credstore_commit_signcount() so the caller only
 *        advances state after the response has been successfully built.
 *        Phase 5 will persist the counter in TROPIC01 R-mem; advancing
 *        on failure desyncs the relying party so the two-step API is
 *        the production-shaped pattern. cpp-reviewer audit 2026-05-11
 *        finding M3.
 */
uint32_t credstore_peek_signcount(void);
void     credstore_commit_signcount(void);

#endif /* NIXTROPIC_FIDO_HID_CREDSTORE_H */
