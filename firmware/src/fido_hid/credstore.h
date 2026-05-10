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
 * @brief Read and atomically increment the global signature counter.
 *        Authenticator-data carries this as a big-endian uint32. The
 *        counter is volatile (RAM); rebooting resets to 0. That's fine
 *        for a stub but production must persist (Phase 5 stores in
 *        TROPIC01 R-mem).
 */
uint32_t credstore_next_signcount(void);

#endif /* NIXTROPIC_FIDO_HID_CREDSTORE_H */
