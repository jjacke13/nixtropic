# TROPIC01 — Reference Notes

_Captured 2026-05-09 from the libtropic SDK headers and docs (github.com/tropicsquare/libtropic, tropicsquare.github.io/libtropic/latest)._

---

## What TROPIC01 actually gives you (concrete)

**Storage:**
- **32 ECC slots** (`TR01_ECC_SLOT_0..31`) — each holds either an **Ed25519** or **P-256** keypair, generated on-chip *or* imported
- **4 pairing key slots** (`SH0PUB..SH3PUB`) — X25519, gate access to the secure channel; `lt_pairing_key_invalidate` is one-way
- **128 MAC-and-Destroy slots** (`0..127`) — the rate-limiting primitive, 32-byte data in / 32-byte data out
- **512 R-memory user slots** (`TR01_R_MEM_DATA_SLOT_MAX = 511`) for arbitrary persistent bytes; min 1 byte/slot, max ~444 B/slot per datasheet (verify for production sizing). Permissions are per-quartile (slots 0-127, 128-255, 256-383, 384-511 each carry independent ACL bits)
- **16 monotonic counters** (`TR01_MCOUNTER_INDEX_0..15`), each up to `TR01_MCOUNTER_VALUE_MAX = 0xFFFFFFFE` (~4.29 billion), for anti-rollback / nonce ratcheting
- **R-config** (rewritable permissions) and **I-config** (one-way bit-flip permissions)

**Operations exposed via L3 secure channel** (X25519 KX → AES-256 AEAD, 12 B IV, 16 B tag, ~4 KiB max ciphertext):
- `lt_ecc_ecdsa_sign` (P-256, R||S 64 B), `lt_ecc_eddsa_sign` (Ed25519, msg ≤ 4096 B)
- `lt_random_value_get` (≤ 255 B/call) — TRNG
- `lt_mac_and_destroy(slot, data_out, data_in)` — single primitive
- `lt_mcounter_init / update / get`
- `lt_r_mem_data_*` (read/write/erase user data)
- `lt_pairing_key_*`, `lt_r_config_*`, `lt_i_config_*`

**Transports:** `hal/linux/spi`, `hal/linux/spi_native_cs`, `hal/posix`, `hal/esp-idf`, `hal/stm32`, `hal/arduino`, `hal/mock`. The **USB devkit (TS1302)** transport currently lives in `examples/linux/usb_devkit/` rather than `hal/linux/usb_*` — so the USB transport is example-resident, not a clean reusable HAL. Worth knowing.

**What it does NOT have** (important for design decisions):
- ❌ **secp256k1** → no direct Bitcoin / Lightning signing
- ❌ no on-chip RSA
- ❌ no exposed AES / ChaCha primitive (AES is *internal* to L3 only)
- ❌ no exposed hash or HMAC API (host does hashing)
- ❌ no exposed ECDH (X25519 is internal to handshake only)

So it's a **signing + small-storage + rate-limiter** chip, not a general crypto co-processor.

---

## Brainstorm — ranked by fit

### Tier 1 — actually useful daily, plays to existing strengths
1. **`tropic-ssh-agent`** — Ed25519 SSH agent socket where every signature goes to `lt_ecc_eddsa_sign`. Standard wire protocol, drop-in for `SSH_AUTH_SOCK`. Smallest viable end-to-end project (~few hundred lines C or Rust). Useful daily.
2. **Polished `nixtropic` flake foundation** — outputs: `libtropic` (lib), `lt-util` (CLI), `devShell`, NixOS module providing udev rules for the TS1302 dongle + permissions group + optional `tropic-ssh-agent` service. Unblocks every other idea.
3. **Hardware-backed CA / device identity issuer** — Ed25519 CA key in slot 0; CLI to issue short-lived certs for self-hosted services. Pairs with nixos-openclaw / nanobot / nixtcloud fleet (each device gets a TROPIC01-signed identity at provisioning).

### Tier 2 — interesting, more work
4. **MAC-and-Destroy password vault** — PIN-rate-limited password manager. Trezor-style UX: enter PIN → MAC-and-Destroy slot consumes one of N attempts → derive symmetric key → decrypt blob in R-mem. Educational write-up potential is huge; very few open implementations exist.
5. **PKCS#11 module backed by libtropic** — `libtropic-pkcs11.so` exposing slots/keys via standard PKCS#11. Once it works, *every* tool (nginx, openssl, ssh, gpg via scdaemon) gets hardware backing for free. Big effort but enormous leverage.
6. **GPG smartcard emulation** — implement enough of the OpenPGP card protocol to plug into `scdaemon`. EdDSA + P-256 is sufficient for modern keys.

### Tier 3 — speculative / requires more thought
7. **Software release signer** — Ed25519 sigs on git tags + monotonic counter so a rollback is detectable. Niche but cool with a public verifier.
8. **mimiclaw integration** — TROPIC01 could store API keys + sign LLM requests, but that's a *board redesign* (need raw chip + SPI on ESP32-S3, not the dongle). Park it.
9. **WireGuard provisioning helper** — TROPIC01 as the trusted enrollment authority (signs peer pubkeys at onboarding). Doesn't solve runtime crypto but eliminates the "trust the provisioning script" gap.

### Hard pass (given current chip)
- **Bitcoin / Lightning channel signer** — no secp256k1. Watch for future firmware additions.
- **age / rage hardware identity** — needs raw X25519 ECDH, not exposed.
- **TLS web server private key** — fine functionally (P-256 sign-per-handshake), but every connection roundtrips through USB → ~ms latency. Doable but slow for busy servers; OK for low-volume admin endpoints.

---

## My pick for what to build first

**Do (2) + (1) together as one project here:** lay down the `nixtropic` flake foundation properly, then build `tropic-ssh-agent` as the first consumer of it. That gives:
- A polished, reusable Nix packaging story
- A real working consumer to validate the API end-to-end
- A daily-driver tool that catches bugs which "hello world" never does
- A clean base to add CA / PKCS#11 / GPG-card later as additional flake outputs

---

## Primitives — quick reference

### Ed25519 vs X25519

Same underlying curve (**Curve25519**, prime 2^255 − 19, ~128-bit security), two different jobs:

- **X25519** — Diffie-Hellman *key exchange*. Combine your private key with someone's public key, both sides arrive at the same 32-byte shared secret. No signatures.
- **Ed25519** — *signature scheme* (EdDSA). Sign a message with a private key, anyone with the public key can verify. 64-byte signatures.

Internally they use different coordinate forms (Montgomery for X25519, twisted Edwards for Ed25519) — math is birationally equivalent, but key formats are NOT interchangeable. On TROPIC01: X25519 powers the *secure-channel handshake* under the hood; Ed25519 is what you use for actual signing in the 32 ECC slots.

### P-256

aka **secp256r1 / prime256v1 / NIST P-256**. A NIST/SECG-standardized curve, 256-bit prime field, Weierstrass form. Used everywhere "boring": TLS, FIDO2/WebAuthn, JWS, smartcards, gov PKI.

**Critical**: P-256 is **NOT** secp256k1 (the Bitcoin curve). Both are 256-bit, but the curve parameters differ — signatures don't transfer between them. That's why Bitcoin/Lightning is a hard pass.

### MAC-and-Destroy

A clever **brute-force-resistance primitive**, primarily for PIN/passphrase protection (Trezor pioneered this technique).

Mental model:
1. At setup, the chip stores a per-slot secret `S`. Slot is just numbered 0..127.
2. Call `lt_mac_and_destroy(slot, data_out)` — chip computes `MAC(S, data_out) → data_in`, returns it, and **physically overwrites S**. One-shot.
3. To gate access to encrypted data behind a PIN, wire it like: PIN guess → `data_out` → MAC reply combines into the actual decryption key. Wrong guess still consumes a slot.
4. After the slots run out, the encrypted blob is permanently unrecoverable.

Why it's strong: even desoldering and dumping the chip can't recover destroyed slots — they're zeroed in storage. With **128 slots** you can pick generous attempt budgets. Each `data_out` / `data_in` is 32 bytes.

### R-memory

"R" = **rewritable**. A flash region exposed as a slot-keyed key-value store — your app's tamper-resistant scratchpad.

Concrete: **512 slots** (`TR01_R_MEM_DATA_SLOT_MAX = 511`), variable size per slot (min 1 byte; max ~444 B per datasheet, total user partition ~few hundred KiB; verify for production sizing). `_write` / `_read` / `_erase` per slot. Permissions are per-quartile (slots 0-127, 128-255, 256-383, 384-511 each carry independent ACL bits).

Use it for: encrypted blobs, hashes, recovery seeds, app config that must survive power loss + tampering.

### Monotonic counters — exactly 16

**16** counters, indexed `TR01_MCOUNTER_INDEX_0..15`. Each counts up to `TR01_MCOUNTER_VALUE_MAX = 0xFFFFFFFE` (~4.29 billion).

Three operations: `init(value)` (set initial), `update()` (increment by 1, irreversibly), `get()` (read). You cannot rewind. Note the L3 result `mcounter done at 0` — once a counter hits zero (init high and decrement?), it's exhausted. Worth verifying behavior in practice.

Use cases: anti-rollback (refuse FW < counter), rate-limiting (N operations per chip lifetime), nonce ratcheting for protocols.

### R-config

**Rewritable configuration objects** = the chip's permission/policy table (ACL).

Each "config object" addresses one capability: e.g. "who can sign with ECC slot 5", "who can write R-mem slot quartile 2", "who can call MAC-and-Destroy". The "who" is one of the 4 pairing-key indices (`SH0PUB..SH3PUB`) — so you can have e.g. an "admin" pairing key with full rights and a "user" pairing key restricted to signing only.

⚠️ **Critical erratum** (`OI_TR01_ERR_2026010800`): writing R-config without erasing first puts the chip into permanent **Alarm Mode** = brick. Always: erase → write whole config.

### I-config

**Irreversible** version of the same config table, stored in OTP-style memory.

Bits flip **1 → 0 only** — once written, never reversible by anyone (not even with the master pairing key). Same operations as R-config but one-way.

Use case: production lockdown. Factory provisioning sets up keys + R-config, then writes I-config to permanently disable dangerous features ("no more pairing key writes", "no FW updates", "no debug log output"). After this point, the chip is locked into its operating policy for life.

Footnote: I-config is in *I-Memory*, which has a tighter operating temperature window (-20 °C to +85 °C) than the rest of the chip — relevant for outdoor/industrial deployments.
