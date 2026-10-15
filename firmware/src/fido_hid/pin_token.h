/*
 * pinUvAuthToken state (CTAP 2.1 §6.5.2.1, §6.5.3.2) — Phase 9 M3.
 *
 * One token exists at a time.  It carries a permission set, an optional
 * permissions RP ID (stored as SHA-256 of the RP ID), a userVerified flag
 * and two timers: it must be used within PUAT_INITIAL_USE_MS of being
 * issued, and it dies PUAT_MAX_LIFE_MS after issue.  There is no cached
 * user presence: every operation that tests presence asks for a fresh
 * touch and then calls puat_consume(), which leaves the token without
 * permissions (CTAP §6.5.5.7: no lbw support, so nothing survives).
 *
 * Chip-free and clock-free: callers pass the current time in ms, so the
 * host tests drive the timers.  PIN/UV auth protocol 1 only:
 * pinUvAuthParam = LEFT(HMAC-SHA-256(token, message), 16).
 */

#ifndef NIXTROPIC_FIDO_HID_PIN_TOKEN_H
#define NIXTROPIC_FIDO_HID_PIN_TOKEN_H

#include <stddef.h>
#include <stdint.h>

#define PUAT_PERM_MC     0x01u
#define PUAT_PERM_GA     0x02u
#define PUAT_PERM_CM     0x04u
#define PUAT_PERM_BE     0x08u
#define PUAT_PERM_LBW    0x10u
#define PUAT_PERM_ACFG   0x20u
#define PUAT_PERMS_KNOWN 0x3Fu

#define PUAT_TOKEN_LEN        32u
#define PUAT_PARAM_LEN        16u
#define PUAT_RP_HASH_LEN      32u
#define PUAT_INITIAL_USE_MS   30000u     /* USB default, CTAP §6.5.2.1 */
#define PUAT_MAX_LIFE_MS      600000u    /* 10 minutes */

/* Forget the token and all its state (stopUsingPinUvAuthToken + wipe). */
void puat_reset(void);

/* Install a freshly generated token (resetPinUvAuthToken +
 * beginUsingPinUvAuthToken(userIsPresent=false)): userVerified = true,
 * the given permissions (unknown bits dropped), RP bound if rp_hash is not
 * NULL. */
void puat_begin(const uint8_t token[PUAT_TOKEN_LEN], uint8_t perms,
                const uint8_t *rp_hash, uint32_t now_ms);

/* Check pinUvAuthParam over msg.  Applies the timers first (an expired
 * token is reset and fails).  Returns 0 on a match — the token then
 * counts as used — and -1 otherwise. */
int puat_verify(const uint8_t *param, size_t param_len,
                const uint8_t *msg, size_t msg_len, uint32_t now_ms);

/* Is a token in use right now (timers applied)? */
int puat_in_use(uint32_t now_ms);

/* Changes with every new token and every reset.  A stateful command keeps
 * the value from its authenticated start and continues only while it is
 * unchanged and the token is still in use. */
uint32_t puat_generation(void);

/* Encrypt-side helper for ClientPIN: the raw token while one is in use. */
const uint8_t *puat_token(void);

int  puat_has_perm(uint8_t perm);
int  puat_user_verified(void);
int  puat_has_rp(void);
/* 1 if no permissions RP ID is bound, or it equals rp_hash. */
int  puat_rp_matches(const uint8_t rp_hash[PUAT_RP_HASH_LEN]);
/* Bind the permissions RP ID if none is bound yet. */
void puat_bind_rp(const uint8_t rp_hash[PUAT_RP_HASH_LEN]);
/* After an operation that tested user presence: clear userVerified and
 * every permission. */
void puat_consume(void);

#endif /* NIXTROPIC_FIDO_HID_PIN_TOKEN_H */
