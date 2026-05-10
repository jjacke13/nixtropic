# nixtropic — Project Document

> **Audience:** AI coding agents (Claude, Codex, etc.) working on this project across sessions.
> **Status:** Living document. Update as decisions and facts evolve.
> **Last updated:** 2026-05-11 (Phase 4 complete + decisions #7/#8/#9 amended to reflect retrospective)
> **Read order:** This document first. Reference `research/` files for technical depth as needed (don't preload them — fetch by section when relevant).

---

## 1. Project goal

Build custom open-source firmware for the **Tropic Square TS1302 USB devkit** (STM32U535 host MCU + TROPIC01 secure element) that turns the dongle into a **standards-compliant USB security key** exposing **FIDO2 (USB HID)** and **OpenPGP card (USB CCID)** interfaces, with TROPIC01 as the cryptographic backend.

End state: plug the dongle into any Linux/macOS/Windows machine, and it works as a Yubikey-class device for WebAuthn (browser login), GnuPG smartcard (SSH, signing, decrypt for QtPass), and PKCS#11 — without installing host-side drivers.

Distribution: Nix flake (`nixtropic`) packaging the firmware build, the host tooling, NixOS module with udev rules, and a `nixtropic` CLI for chip-level operations.

**Why this is novel:** verified open niche as of 2026-05-10. No existing project provides custom STM32U5/TS1302 firmware that exposes FIDO2 + CCID with TROPIC01 backing. STM32+FIDO2 ecosystem is mature (Nitrokey, SoloKey, Somu, LionKey) but none use TROPIC01 — they use ATECC608 or no SE. See `research/prior-art.md` for full search trail.

---

## 2. Locked decisions

| # | Decision | Rationale | Date |
|---|---|---|---|
| 1 | **Language: C** | libtropic is C; SoloKeys is C; ST drivers/CMSIS/TinyUSB primary API is C. Rust adds FFI overhead with no security upside (real crypto is on TROPIC01, not STM32). Mitigations: TrustZone-M, strict warnings, sanitizers in host tests, no malloc post-init. | 2026-05-10 |
| 2 | **Phase 7 USB class: OpenPGP card via CCID** (not PIV) | User uses GnuPG daily for QtPass + SSH. PIV deferred to optional Phase 7b. | 2026-05-10 |
| 3 | **Phase 5 user-presence: stub-true** | TS1302 has no button. Skip touch-to-confirm for FIDO2 MVP. Add via daughter board in Phase 6. Architecture: single `bool user_presence_check(uint32_t timeout_ms)` function gated by `CONFIG_USER_PRESENCE_REQUIRED` so Phase 6 is a localized change. | 2026-05-10 |
| 4 | **Execution: serial, no time pressure** | Each phase fully completes (with hardware-in-the-loop validation) before next begins. No parallel exploration. | 2026-05-10 |
| 5 | **Commitment: yes, dongle is project-dedicated** | User got TS1302 free. Phase 0 establishes recovery path; reflashing is reversible. | 2026-05-10 |
| 6 | **USB stack: TinyUSB (adapt U545 BSP for U535)** | U535 has no native TinyUSB BSP, but U545 (same FS controller, same PMA) port adapts trivially. Avoid ST USBX (proprietary leanings, heavier). | 2026-05-10 |
| 7 | **FIDO2 stack: hybrid — own CTAPHID + CBOR + dispatcher, SoloKeys-derived ClientPIN + credential storage + extensions** | Original (2026-05-10): "SoloKeys-derived port" for the full stack. Amended 2026-05-11 after Phase 4 retrospective: we wrote ~1100 LOC of our own for CTAPHID, CBOR, CTAP2 dispatcher, GetInfo, and MakeCred/GetAssertion stubs in Phase 4 — these are clean, small, audited, and SoloKeys' equivalents aren't materially better. BUT: Phase 5+ needs `ctap_pin.c` (PIN/UV protocol — DIY is dangerous, subtle security bugs), `storage.c` (resident-key + eviction with monotonic per-credential signCount), and `extensions/hmac-secret.c` (required by Bitwarden, age-plugin-fido2). Port THOSE from SoloKeys onto our own credstore + libtropic L3 backend. OpenSK (Rust) still rejected for language consistency. | 2026-05-10 / 2026-05-11 |
| 8 | **Software crypto library: trezor_crypto (reused from libtropic L3 CAL)** | Original (2026-05-10): "TinyCrypt + Monocypher". Amended 2026-05-11: Phase 3 M4 already wired trezor_crypto in for libtropic's L3 secure session (AES-256-GCM, SHA256, HMAC-SHA256, X25519, Ed25519 via ed25519-donna). All the algorithms FIDO2 needs are already linked. Reuse for Phase 5 ClientPIN (AES-CBC + HMAC + HKDF) saves ~25 KB of new vendor surface. TinyCrypt + Monocypher were never linked — decision was changed silently in Phase 3 by absorbing trezor_crypto's broader algorithm set; documenting here. | 2026-05-10 / 2026-05-11 |
| 9 | **Build: CMake + CMSIS + ST HAL** | Original (2026-05-10): "ST LL drivers". Amended 2026-05-11: Phase 1+ uses ST HAL (more Nix-friendly than expected; LL drivers would have required more glue for SPI/RNG init). HAL adds ~30 KB but well within budget. CMake + arm-none-eabi-gcc 14.3 unchanged. | 2026-05-10 / 2026-05-11 |
| 10 | **Pairing keys at build: default to PRODUCTION (`*_prod0`)** | User's specific TS1302 (validated 2026-05-10) ships **production** silicon `TR01-C2P-T101`, **silicon rev ACAB**, NOT engineering samples. Default the firmware build to `sh0priv_prod0`/`sh0pub_prod0`. Build flag `NIXTROPIC_ENG_KEYS` switches to `*_eng_sample` for development of other (older / engineering-sample) chips. | 2026-05-10 |
| 11 | **Document audience: AI agents primary** | This file is for AI agents. User reads conversationally, references this file when needed. | 2026-05-10 |

---

## 3. Architecture (the layer cake)

```
   ┌───────────────────────────────────────────────────────────┐
   │ USB host (browser, gpg, ssh, pcsc-lite, libfido2)         │ Standard host stack
   ├───────────────────────────────────────────────────────────┤   (no TROPIC01-specific code)
   │ USB wire (HID + CCID + CDC composite)                     │
   └───────────────────────────────────────────────────────────┘
                           │ USB FS (12 Mbps)
                           ▼
   ┌───────────────────────────────────────────────────────────┐
   │ STM32U535 — our custom firmware                           │
   │  ┌─────────────────────────────────────────────────────┐  │
   │  │ TinyUSB device stack (HID + CCID + CDC composite)   │  │ ← Configure, ship as-is
   │  │  - HID interface: FIDO2/CTAP2                       │  │
   │  │  - CCID interface: OpenPGP card APDUs               │  │
   │  │  - CDC-ACM interface: debug/legacy compat           │  │
   │  ├─────────────────────────────────────────────────────┤  │
   │  │ FIDO2 stack (SoloKeys-derived)                      │  │ ← Port + adapt
   │  │  - CTAP2 protocol state machine                     │  │
   │  │  - WebAuthn credential model                        │  │
   │  │  - ClientPIN (HKDF + AES-GCM, software)             │  │
   │  ├─────────────────────────────────────────────────────┤  │
   │  │ OpenPGP card stack                                  │  │ ← Port + adapt
   │  │  - APDU dispatch                                    │  │
   │  │  - Card lifecycle (PW1, PW3, RC)                    │  │
   │  ├─────────────────────────────────────────────────────┤  │
   │  │ ★ GLUE LAYER (project-original) ★                   │  │ ← Most of our work
   │  │  - "create credential" → ECC slot allocation        │  │
   │  │  - "sign challenge" → lt_ecc_eddsa_sign             │  │
   │  │  - "ClientPIN attempt" → lt_mac_and_destroy         │  │
   │  │  - "user presence" → user_presence_check()          │  │
   │  │  - Slot-allocation policy (eviction, indexing)      │  │
   │  │  - Persistent state (R-mem layout)                  │  │
   │  ├─────────────────────────────────────────────────────┤  │
   │  │ Software crypto: TinyCrypt + Monocypher             │  │ ← Use as-is (~25 KB)
   │  │  - AES-256-GCM, SHA-256, HMAC, P-256 ECDH           │  │
   │  ├─────────────────────────────────────────────────────┤  │
   │  │ libtropic (C SDK)                                   │  │ ← Use as-is
   │  │  - L3 secure channel (AES-256-GCM)                  │  │
   │  │  - L2 framing (252 B chunks)                        │  │
   │  │  - L1 transport (SPI shape)                         │  │
   │  ├─────────────────────────────────────────────────────┤  │
   │  │ libtropic HAL: hal/stm32/stm32u5xx                  │  │ ← Use as-is
   │  ├─────────────────────────────────────────────────────┤  │
   │  │ CMSIS + ST LL drivers (USB, SPI1, RNG, HASH)        │  │ ← Use as-is
   │  └─────────────────────────────────────────────────────┘  │
   │     │ Cortex-M33 + TrustZone-M                            │
   │     │ - Secure world: pairing-key handling, L3 session    │
   │     │ - Non-secure: USB, FIDO2, OpenPGP card              │
   └───────────────────────────────────────────────────────────┘
                           │ SPI1 (mode 0, MSB-first)
                           │ MOSI=PA7  MISO=PA6  SCK=PA5
                           │ CS=PA4    GPO=PB0   PWR=PA0
                           ▼
   ┌───────────────────────────────────────────────────────────┐
   │ TROPIC01                                                   │
   │  - 32 ECC slots (Ed25519/P-256), 64-byte signatures        │
   │  - 4 pairing key slots (X25519)                            │
   │  - 128 MAC-and-Destroy slots (32 B in/out)                 │
   │  - 512 R-mem slots (475 B/slot on FW ≥2.0.0)               │
   │  - 16 monotonic counters                                   │
   │  - TRNG, AES-256-GCM (L3 only), Cert store (4 certs)       │
   └───────────────────────────────────────────────────────────┘
```

---

## 4. Hardware essentials (commit to memory)

### TROPIC01 chip
- Modes: Start-up / Maintenance / Application / Alarm (`lt_tr01_mode_t`)
- 32 ECC slots, 4 pairing key slots, 128 MAC-and-Destroy slots, 512 R-mem slots, 16 monotonic counters, 4-cert store
- L3 channel: X25519 KX → AES-256-GCM (12 B IV with 32-bit LE counter at IV[0..3], 16 B tag, ≤4096 B ciphertext)
- This project's specific TS1302 dongle ships **production** silicon: long P/N **`TR01-C2P-T101`**, silicon rev **ACAB** (auto-managed FW banks), package QFN32 4×4 mm, Fab ID `0x001` (EPS Global / Brno), prov template v1.4. Validated via `nix run .#identify` on 2026-05-10. **Use `sh0priv_prod0` / `sh0pub_prod0` from libtropic's defaults.** Other TROPIC01 dongles in the wild may ship engineering-sample silicon (`TR01-B2S-*` part numbers); for those, set `NIXTROPIC_ENG_KEYS=1` at build to swap to `*_eng_sample` keys.
- Sleep mode current: 945 µA — irrelevant since dongle is bus-powered
- Full inventory: **`research/tropic01-inventory.md`**

### STM32U535 host MCU (TS1302)
- Cortex-M33 with TrustZone-M (security extension), max 160 MHz
- Likely 256 KB Flash, 64 KB SRAM (verify against stock firmware build)
- **Crypto accelerators present:** HASH (SHA-2), TRNG only
- **Crypto accelerators ABSENT** (unlike higher U5 SKUs): AES, PKA, SAES, MCE, OTFDEC, BHK
  - **Implication:** all symmetric crypto (AES-GCM for ClientPIN), HMAC-SHA256, P-256 ECDH must be **software** (TinyCrypt + Monocypher, ~25 KB)
  - Pairing-key isolation must rely solely on **TrustZone-M secure-world flash** (no BHK / SAES protected key store available)
- USB FS only (12 Mbps). Adequate for FIDO2/CCID. PA11=D−, PA12=D+, software 1.5 kΩ pull-up trick for re-enumeration
- Stock FW runs at 48 MHz Power Range 3; can push to 160 MHz Range 1 if needed
- Full inventory: **`research/stm32u535-inventory.md`**

### TS1302 board pinout (memorize)
| Function | STM32 pin | Notes |
|---|---|---|
| TROPIC01 SPI MOSI | PA7 | SPI1 |
| TROPIC01 SPI MISO | PA6 | SPI1 |
| TROPIC01 SPI SCK | PA5 | SPI1 |
| TROPIC01 SPI CS | PA4 | Soft CS, MSB-first, mode 0 |
| TROPIC01 GPO (IRQ) | PB0 | Ready signal from chip |
| TROPIC01 power switch | PA0 | Controls chip VCC |
| USB D− | PA11 | |
| USB D+ | PA12 | |
| BOOT0 / SW1 (DFU entry) | PH3 | Hold at reset → bootloader |
| Debug UART TX | (verify in schematic) | |
| Debug UART RX | (verify in schematic) | |
| LED(s) | (verify in schematic) | |

### DFU mode (memorize)
1. Hold SW1 (BOOT0=PH3) while plugging USB or pressing reset
2. Dongle enumerates as `0483:df11` (ST Microelectronics DFU)
3. Flash: `dfu-util -a 0 -s 0x08000000:leave -D firmware.bin`
4. Replug normally → custom firmware boots

---

## 5. Critical facts (do NOT forget)

These will hurt the project if violated. Re-read this section before any R-config or pairing-key change.

| Fact | Why it matters | Mitigation |
|---|---|---|
| **R-config write WITHOUT prior erase = brick** | Erratum `OI_TR01_ERR_2026010800` (2026-01-08). Triggers permanent Alarm Mode. **No recovery.** | ALWAYS `lt_r_config_erase` before `lt_r_config_write`. Validate against TVL simulator first. Never write R-config on a chip you don't own. |
| **Pairing keys are PUBLIC for development** | `libtropic_default_sh0_keys.c` ships keypairs publicly. Any adversary can establish a Secure Session with the chip. | For production deployments: generate new X25519 keypair → write pubkey to SH1 → invalidate SH0 → store new privkey in TrustZone secure-world flash. |
| **Production silicon vs engineering samples** | This project's TS1302 has `TR01-C2P-T101` production silicon (verified 2026-05-10). Default keys = `*_prod0`. Some TS1302 dongles in the wild are eng samples (`TR01-B2S-*`) — those need `*_eng_sample` keys instead. | Build flag `NIXTROPIC_ENG_KEYS=1` swaps key set. Default = production. Document in flash binary metadata (e.g., a `.section .firmware_meta` blob) which key set was compiled in, so future `nixtropic status` can report it. |
| **STM32U535 lacks BHK/SAES** | Cannot store secrets in HW-protected key memory. | TrustZone-M secure world is the only isolation mechanism. Configure SAU/IDAU strictly. |
| **R-mem slot size is FW-dependent** | 444 B/slot for App FW ≤1.0.1, 475 B/slot for ≥2.0.0 | Read App FW version at `lt_init`; size buffers conditionally. Do not assume 475. |
| **Default L3 ciphertext max = 4096 B** | Larger payloads need chunking | `TR01_L3_CMD_CIPHERTEXT_MAX_SIZE = 4112`, `TR01_L3_RES_CIPHERTEXT_MAX_SIZE = 4097` |
| **EdDSA msg max = 4096 B; ECDSA prehash required** | `lt_ecc_eddsa_sign` accepts msg up to 4096 B raw. ECDSA expects pre-hashed input. | For FIDO2 challenges (32 B), no chunking needed. For OpenPGP large signatures, host hashes first. |
| **Once you `lt_pairing_key_invalidate(slot)`, that slot is permanently dead** | Cannot un-invalidate | Never invalidate the only working pairing slot without confirming the replacement works first. |
| **I-config bits flip 1→0 only, irreversibly** | Lifetime lock-down | Never write I-config in development. Reserved for production lockdown step. |
| **TS1302 USB transport is example-resident, not a HAL** | Stock fw lives in `examples/linux/usb_devkit/` of libtropic, not `hal/` | Our custom firmware **replaces** the stock fw entirely; we don't extend a HAL |
| **`LT_CERT_KIND_XXXX = 1`** | Literal placeholder name in libtropic enum | Verify cert chain semantics in `ODN_TR01_app_003` before relying on cert kinds |
| **TROPIC01 TRNG NIST compliance UNVERIFIED** | Not stated in libtropic public source | Confirm via `ODN_TR01_app_008` before claiming SP 800-90B compliance in marketing/docs |
| **Stock fw doesn't enable RNG** | Adding libtropic on MCU requires `HAL_RNG_MODULE_ENABLED` in `stm32u5xx_hal_conf.h` | Enable explicitly. Don't assume RNG is wired up in our firmware. |

---

## 6. Phase plan

Each phase is **independently shippable**. Stop anywhere = useful artifact. Hardware-in-the-loop validation is mandatory at every phase boundary.

### Phase 0 — Reproducibility & recovery
**Goal:** Prove the toolchain works end-to-end. Round-trip stock firmware via Nix → DFU → chip identify.

**Deliverables:**
- `flake.nix` with `gcc-arm-embedded-13`, `dfu-util`, `openocd`, `picocom`, `cmake` pinned
- `nix/stock-firmware.nix` — derivation building `tropicsquare/tropic01-stm32u5-usb-devkit-fw` reproducibly
- `nix/dev-shell.nix` — devShell exposing the toolchain
- `nixos/tropic-udev.nix` — module with udev rules for app mode + DFU mode (`0483:df11`)
- `flake.nix` apps: `nix run .#flash-stock`, `nix run .#identify`
- `docs/RECOVERY.md` — DFU procedure + step-by-step recovery

**Test:** plug → `nix run .#identify` works → enter DFU → `nix run .#flash-stock` → replug → `nix run .#identify` returns identical chip ID.

**Stop-here value:** "Reproducible Nix-built stock firmware for TS1302" — already a contribution.

**Code: Nix only.** No C yet.

### Phase 1 — TROPIC01 round-trip on STM32 (no USB) — ✅ COMPLETE 2026-05-10 (commit `4b30bf0`)
**Goal:** Prove libtropic on STM32U535 talks to TROPIC01 via SPI on actual TS1302 hardware.

**Outcome:** USB CDC chosen instead of UART (Path Y), L2-only scope (Path A+C, no L3 secure session). 11/11 PASS via `nix run .#validate-phase1`. firmware.bin ≈ 35 KB. Chip ID byte-exact match to Phase 0 baseline.

**Deliverables:**
- `firmware/` directory with custom STM32 firmware
- Boot, blink LED
- Init libtropic via `hal/stm32/stm32u5xx`
- Call `lt_init`, `lt_get_info_chip_id`, `lt_random_value_get(32)`
- Print results over UART (hardware UART pin TBD from schematic)
- Host-side `picocom` reads UART, validates output

**Test:** chip ID matches what stock firmware reports (regression check via Phase 0). 32 bytes of TRNG come out, entropy looks plausible to host script. Cold-boot reset cycles work without lockout.

**Stop-here value:** First TS1302 firmware that exercises libtropic from the MCU side. Validates the highest-risk dependency.

**Risks:** SPI pin config wrong, TROPIC01 power-switch (PA0) handling missing, libtropic-stm32u5xx HAL doesn't quite match TS1302 pinout. Address by close reading of `research/stm32u535-inventory.md` SPI table and `libtropic/hal/stm32/stm32u5xx/`.

### Phase 2 — USB CDC-ACM passthrough (replicate stock) — ✅ COMPLETE 2026-05-10 (commits `c0edfb1` + `70eaa00`)
**Goal:** Add USB stack, replicate stock firmware behavior. Black-box equivalence with stock.

**Outcome:** Package renamed `firmware` → `open-firmware`. App `flash-firmware` → `flash-open`. New `validate-phase2` (5/5 PASS) + `flash-and-validate-phase2`. Open firmware is byte-faithful drop-in for stock TS1302; lt-util reads chip ID identically. lt-util's bundled libtropic v1.0.0 had an off-by-one bug (`count < 2 * tx_data_length`) patched in `flake.nix` postPatch — fixed in libtropic ≥ v3.x. firmware.bin ≈ 35 KB.

**Deliverables:**
- TinyUSB integrated, U545 BSP adapted for U535
- USB descriptor: CDC-ACM only (for now)
- Forward USB CDC bytes to TROPIC01 SPI, return responses (same wire protocol as stock)

**Test:** Stock `lt-util` and `libtropic-pkcs11` on Linux talk to our firmware identically to stock. Wireshark/usbmon dumps match (modulo timing).

**Stop-here value:** 100% Nix-built, drop-in replacement for stock TS1302 firmware. Reproducible, auditable.

### Phase 3 — Add HID interface (composite device) — ✅ COMPLETE 2026-05-10 (commits `675931e` + `13f5cfe` + `7a81a23` + M5 follow-ups)
**Goal:** Validate composite USB descriptors and HID-class enumeration.

**Outcome:** 5-test validation suite via `nix run .#validate-phase3` — PING (single + multi-packet), GET_RANDOM, CHIP_ID, ECC generate+sign+verify (Ed25519). TROPIC01 generates the keypair on chip, signs a 32 B challenge through the HID lt-rpc transport with libtropic's L3 secure session (X25519 KX → AES-256-GCM via trezor_crypto CAL), and python-cryptography verifies the signature host-side. CDC + Phase 2 lt-util chip-info still PASS in parallel. firmware.bin ≈ 145 KB / 256 KB; RAM 21 KB / 192 KB.

**Deliverables:**
- USB descriptor: CDC + HID composite (HID raw 64 B IN/OUT under vendor usage page 0xFF00)
- Custom HID-based "lt-rpc" protocol (CTAPHID-style framing, single fixed channel 0xCAFE0001)
- Host-side test client `tools/lt_rpc.py` (Python + hidapi + cryptography, ~250 LOC)

**Test:** Both `/dev/ttyACM*` AND `/dev/hidraw*` enumerate. `lt_ecc_eddsa_sign` round-trips over HID; signature verifies. CDC continues to work in parallel (Phase 2 regression 5/5 PASS).

**Stop-here value:** First TS1302 firmware exposing HID + first independently-verified open libtropic stack running L3 secure-session-backed Ed25519 sign end-to-end. Foundation for Phase 4 FIDO2 backend.

### Phase 4 — FIDO2 stack port (stub backend) — ✅ COMPLETE 2026-05-11 (commits `9f9c1a2` + `3b03d5b` + `b2abe82` + `bb3ba3a` + M5 follow-up)
**Goal:** FIDO2/CTAP2 protocol surface working with stub backend (no real crypto yet).

**Outcome:** Composite USB now has TWO HID interfaces — instance 0 = Phase 3 lt-rpc (vendor 0xFF00), instance 1 = FIDO2 (usage page 0xF1D0 with U2F usages). New `firmware/src/fido_hid/` module: CTAPHID framing with multi-CID allocation, hand-rolled CBOR encoder + decoder, CTAP2 dispatcher implementing `authenticatorGetInfo` (algorithms = Ed25519 + ES256), `authenticatorMakeCredential` and `authenticatorGetAssertion`. Stub backend uses a fixed Ed25519 keypair derived from a compiled-in seed (NOT secure — Phase 5 swaps to TROPIC01-backed ECC slots). 7/7 PASS via `nix run .#validate-phase4` — including host-side python-cryptography verifying real Ed25519 signatures over `authData || clientDataHash`. CDC + Phase 3 lt-rpc still pass in parallel. firmware.bin ≈ 162 KB / 256 KB; RAM 25 KB / 192 KB.

**Deliverables:**
- SoloKeys-style FIDO2 stub (derived patterns, not vendored code — ~1 200 LOC of original C across fido_hid/)
- HID interface advertises FIDO usage page (`0xF1D0`)
- `MakeCredential` returns "packed" self-attestation with a verifiable Ed25519 signature
- `GetAssertion` returns a verifiable Ed25519 assertion signature
- `tools/fido2_test.py` host client (CBOR codec, authData parser, COSE_Key reader, cryptography-based verification)

**Test:** 7/7 PASS in `nix run .#validate-phase4`. `MakeCredential` and `GetAssertion` signatures verify with python-cryptography Ed25519.

**Stop-here value:** First TS1302 firmware exposing FIDO2 (HID 0xF1D0) end-to-end with a verifiable signature flow. Protocol layer fully validated — Phase 5 only needs to swap the crypto backend.

### Phase 5 — Wire FIDO2 to TROPIC01 (THE MIC-DROP)
**Goal:** Real FIDO2 backed by real TROPIC01 keys. End-to-end working WebAuthn.

**Deliverables:**
- `MakeCredential` → fresh Ed25519 key in unused ECC slot → return public key + credentialId
- `GetAssertion` → look up credentialId → `lt_ecc_eddsa_sign` → return assertion
- Credential metadata (rpId hash, credentialId, slot index, counter) stored in R-mem
- Slot allocation/eviction policy
- ClientPIN: software AES-256-GCM (TinyCrypt) + HMAC-SHA256 (HASH peripheral + sw HMAC)

**Test:** Register on `webauthn.io` → log in successfully via real browser. Multiple sites, multiple credentials. Verify chip state matches expectations.

**Stop-here value:** Working open-source TROPIC01 FIDO2 dongle. World's first on TS1302.

### Phase 6 — Production-grade UX (button + PIN lockout)
**Goal:** Trustable as a daily-driver security key.

**Deliverables:**
- User-presence button: daughter board design (PCB + BOM in `hardware/`) OR repurpose existing GPIO
- `user_presence_check()` reads button + debounces
- ClientPIN attempts wired through `lt_mac_and_destroy` for HW-enforced rate limiting
- LED feedback (blink on incoming, solid on touch-confirm)

**Test:** N wrong PINs → MAC-and-Destroy slots count down → chip refuses → recovery (PIN reset). Touch required for every signature.

**Stop-here value:** Production-class security key.

### Phase 7 — CCID OpenPGP card
**Goal:** GnuPG / SSH (via gpg-agent) / QtPass work natively without host glue.

**Deliverables:**
- USB descriptor: CDC + HID-FIDO2 + CCID
- OpenPGP card APDU dispatcher
- Map sign/decrypt/auth slots to TROPIC01 ECC slots
- Card-state R-mem layout (URL, login data, fingerprints, KDF settings)

**Test:** `gpg --card-status` recognizes the device. `gpg --card-edit` walks menus. `git commit -S` succeeds. QtPass decrypts. SSH-via-gpg-agent works (`enable-ssh-support` in `~/.gnupg/gpg-agent.conf`).

**Stop-here value:** Yubikey-class for GPG/SSH/smartcard use cases.

### Phase 8 — Polish: Nix flake, NixOS module, CLI
**Goal:** Distribution-ready package.

**Deliverables:**
- `flake.nix` outputs: `firmware`, `firmware-stock` (recovery), `lt-util`, `libtropic-pkcs11`, `nixtropic` CLI, `devShell`
- `nixos/tropic.nix` module: udev rules, `tropic` group, optional service definitions
- `nixtropic` CLI (Rust, ~1-2k lines): `status`, `pair`, `update-firmware`, `config-show`, `factory-reset`
- DFU flash via `nix run .#flash`

**Test:** Fresh NixOS VM → install module → plug TS1302 → `nix run .#flash` → reboot → fully working FIDO2+OpenPGP-card dongle. Reproducible flake.lock.

**Stop-here value:** Whole project, end-to-end, reproducibly buildable.

### Future / optional
- **Phase 7b:** PIV (alongside or instead of OpenPGP card)
- **Phase 9:** GUI manager (Slint or Tauri) on top of `nixtropic` CLI
- **Phase 10:** Submission to nixpkgs
- **Phase 11:** Public release / blog post / show-and-tell

---

## 7. Test methodology (universal)

1. **Hardware-in-the-loop is mandatory.** Every phase boundary tests on the real TS1302. No "I tested in QEMU."
2. **Black-box checkpoints.** Define externally observable behavior; verify via host-side scripts. Firmware is SUT; laptop tools are test harness.
3. **Standard tools as test clients.** `fido2-token`, `pkcs11-tool`, `gpg`, `pcsc_scan`, `webauthn.io`. If those work, browsers will too. Do not write proprietary test clients except where standards don't cover (Phase 3).
4. **Recovery rehearsal.** Phase 0's recovery path is re-validated whenever we change anything risky. "What if I brick it?" must always have an answer.
5. **Demo gif/video at each phase boundary.** Forces "is this actually working from a user's view?" perspective. Feeds eventual show-off material.
6. **Host-side unit tests for crypto + glue logic.** Compile firmware crypto modules as a Linux library, run with ASan/UBSan/cppcheck/clang-tidy. Don't unit-test on the dongle.
7. **No integration test depends on the previous phase being instrumented.** Each phase ships with its own externally observable behavior.

---

## 8. Coding conventions (firmware C)

| Rule | Enforcement |
|---|---|
| `-Wall -Wextra -Werror -Wconversion -Wshadow -Wundef -Wcast-align -Wstrict-prototypes` | CMake CFLAGS |
| No dynamic allocation after init | `clang-tidy` rule + manual review |
| All buffers static, sized at compile time | Audit |
| Static analysis: `clang-tidy`, `cppcheck` | CI step |
| Sanitizers in host-side unit tests: ASan, UBSan, MSan | CMake test variant |
| No comments unless WHY is non-obvious | Code review |
| Functions <50 lines | Manual |
| Files <800 lines | Refactor when exceeded |
| Snake_case for functions and variables; UPPER_CASE for macros | Enforced |
| Headers minimal — only what callers need | Avoid leaking impls |
| Every protocol parser bounds-checks every byte | Review checklist |
| Secrets zeroized after use (`memset_s` or equivalent) | Audit |
| TrustZone secure-world functions documented with `__attribute__((cmse_nonsecure_entry))` | Compile-checked |

---

## 9. Build system structure (planned)

```
nixtropic/
├── flake.nix                  # Top-level Nix flake
├── flake.lock
├── PROJECT.md                 # This file
├── TROPIC01.md                # Earlier reference doc (kept for context)
├── README.md                  # Public-facing intro
├── nix/
│   ├── stock-firmware.nix     # Builds Tropic Square's stock fw
│   ├── firmware.nix           # Builds our custom fw
│   ├── nixtropic-cli.nix      # Builds the management CLI
│   ├── dev-shell.nix          # Toolchain devShell
│   └── apps.nix               # nix run targets (flash, identify, etc.)
├── nixos/
│   └── tropic.nix             # NixOS module (udev, group, services)
├── firmware/
│   ├── CMakeLists.txt
│   ├── src/
│   │   ├── main.c
│   │   ├── usb/               # TinyUSB integration + composite descriptor
│   │   ├── fido2/             # SoloKeys-derived stack
│   │   ├── openpgp/           # CCID OpenPGP card stack (Phase 7)
│   │   ├── glue/              # FIDO2/OpenPGP → TROPIC01 mapping (★ original work)
│   │   ├── crypto/            # TinyCrypt + Monocypher integration
│   │   ├── platform/          # CMSIS init, clock, USB IRQs, GPIO
│   │   └── secure_world/      # TrustZone secure-world: pairing-key handling
│   ├── third_party/
│   │   ├── libtropic/         # git submodule
│   │   ├── tinyusb/           # git submodule (with U545→U535 BSP adaptation patch)
│   │   ├── tinycrypt/         # git submodule
│   │   ├── monocypher/        # git submodule (or vendored — small)
│   │   └── solokeys/          # git submodule (or vendored subset)
│   ├── linker/
│   │   ├── stm32u535.ld       # Non-secure world
│   │   └── stm32u535_s.ld     # Secure world
│   └── tests/                 # Host-side unit tests (compile firmware crypto on Linux)
├── tools/
│   └── nixtropic/             # Rust CLI source (Phase 8)
├── hardware/
│   └── button-daughter/       # Phase 6 button board (KiCad)
├── docs/
│   ├── RECOVERY.md            # DFU recovery procedure
│   ├── DEPLOYMENT.md          # Production-key replacement, lockdown
│   └── ARCHITECTURE.md        # Detailed firmware architecture
└── research/
    ├── tropic01-inventory.md  # Subagent output, 811 lines
    ├── stm32u535-inventory.md # Subagent output, 623 lines
    └── prior-art.md           # Subagent output, 180 lines
```

---

## 10. References (load-on-demand, not preloaded)

When you need depth, fetch these. Don't preload — they're large.

| Document | Purpose | When to read |
|---|---|---|
| **`research/tropic01-inventory.md`** (811 lines) | Authoritative TROPIC01 reference: every constant, every API, every config object, every error code | Before any new libtropic-call code; before R-config or pairing-key changes |
| **`research/stm32u535-inventory.md`** (623 lines) | Authoritative STM32U535 + TS1302 reference: pinout, clocks, peripherals, security features, toolchain | Before Phase 0 toolchain config; before any GPIO/SPI/USB code |
| **`research/prior-art.md`** (180 lines) | Verification that this niche is open as of 2026-05-10 | Re-check periodically (every ~3 months) for late-arriving competition |
| **`TROPIC01.md`** (~150 lines) | Earlier conversational reference doc; primer-level | Skim for orientation; superseded by `research/tropic01-inventory.md` for facts |
| `https://github.com/tropicsquare/libtropic` | Official C SDK source | When implementing/extending HAL or chasing API semantics |
| `https://tropicsquare.github.io/libtropic/latest/` | Official docs site | Architecture, tutorials, FAQ |
| `https://github.com/tropicsquare/tropic01-stm32u5-usb-devkit-hw` | TS1302 schematics (KiCad) | Pinout disputes, hardware extensions |
| `https://github.com/tropicsquare/tropic01-stm32u5-usb-devkit-fw` | Stock firmware source | Phase 0 build target; Phase 2 protocol replication reference |
| `https://github.com/solokeys/solo` | SoloKeys FIDO2 firmware (port source for Phase 4) | Phase 4 |
| `https://github.com/hathach/tinyusb` | USB stack (U545 BSP source) | Phase 2 |
| `https://github.com/intel/tinycrypt` | Software crypto library | Phase 5 |
| `https://github.com/LoupVaillant/Monocypher` | Software crypto library (X25519/Ed25519/ChaCha20) | Phase 5 |
| `https://www.st.com/.../STM32U5_RM0456` | STM32U5 reference manual | Peripheral register details, TrustZone-M setup |
| `ODN_TR01_app_003` (Tropic Square App Note) | TROPIC01 PKI / cert kinds | Verify `LT_CERT_KIND_XXXX` semantics |
| `ODN_TR01_app_006` (App Note) | Configuration objects handling | Before any R-config write |
| `ODN_TR01_app_008` (App Note) | Security architecture | Verify TRNG NIST compliance, side-channel claims |

---

## 11. Operating instructions for AI agents (you, me, future)

1. **Always read this file on session start.** It's intended for context-window inclusion.
2. **Don't preload `research/*.md`.** Fetch by `Read` when needed; cite line numbers in commits/comments.
3. **Phase boundary discipline:** never start phase N+1 work on the repo until phase N is HW-in-the-loop validated. If user is excited and asks to "just start," gently push back and finish current phase first.
4. **Before writing any R-config / pairing-key / I-config code:** re-read §5 "Critical facts" and `research/tropic01-inventory.md` §4 (Configuration objects). The brick erratum is permanent.
5. **Before claiming a fact about TROPIC01 in committed code or docs:** verify against `research/tropic01-inventory.md`. If not there, fetch from libtropic source. If not there, fetch from official docs/App Note. If not there, note as `TODO(verify)`.
6. **Before claiming a fact about STM32U535:** verify against `research/stm32u535-inventory.md`. If pin/peripheral not listed there, fetch from the TS1302 schematic + datasheet directly.
7. **Status updates:** when completing a sub-step in current phase, append to a `STATUS.md` (create if doesn't exist) with date and what was validated. Future agents read this to know where the project actually is.
8. **Never auto-flash the user's dongle without explicit permission.** Even though Phase 0's recovery path exists, the user owns the hardware. Confirm before any `nix run .#flash*`.
9. **Never write production keys or invalidate the only working pairing slot without explicit user confirmation.** These are unrecoverable.
10. **If a research fact is questioned by the user and you're not sure:** spawn an Explore agent rather than guessing. Cheap correction is better than confident wrong.
11. **Update this PROJECT.md when:** a decision changes, a phase boundary completes, a new critical fact emerges, the architecture diagram changes, a new dependency is added. Increment "Last updated" date.

---

## 12. Glossary

| Term | Meaning |
|---|---|
| **TROPIC01** | The secure element chip we're integrating |
| **TS1302** | The USB devkit board (STM32U535 + TROPIC01 + USB-C) |
| **libtropic** | Official C SDK for TROPIC01 (host-side) |
| **L1 / L2 / L3** | TROPIC01's protocol layers: SPI transport / framing / encrypted secure session |
| **Pairing key** | X25519 keypair establishing the L3 secure channel. Public half on chip (SH0..3PUB), private half on host. |
| **STPUB** | Tropic Square's certified public key for the chip, baked at fab. Used for chip authentication. |
| **R-config / I-config** | The chip's permission/policy table. R = rewritable, I = irreversible (1→0 only). |
| **R-mem** | Rewritable user storage (512 slots × 444/475 B) |
| **MAC-and-Destroy** | One-shot per-slot MAC primitive for PIN-attempt rate limiting |
| **CTAP2** | FIDO Alliance protocol over USB HID for FIDO2 |
| **WebAuthn** | W3C browser API for FIDO2 authentication |
| **CCID** | USB Chip Card Interface Device class — smartcard reader protocol |
| **APDU** | Smartcard "Application Protocol Data Unit" — request/response unit over CCID |
| **OpenPGP card** | A standard APDU set for GnuPG-compatible smartcards |
| **PIV** | NIST FIPS-201 smartcard standard (US government, also used widely) |
| **TrustZone-M** | ARMv8-M security extension partitioning code/data into secure / non-secure worlds |
| **DFU** | Device Firmware Upgrade — USB-class for firmware flashing |
| **TinyUSB** | Open-source embedded USB device stack |
| **SoloKeys** | Open-source FIDO2 firmware (origin of our Phase 4 port) |
| **TinyCrypt / Monocypher** | Software crypto libraries we use for AES/SHA/ECDH on STM32 |

---

## 13. Open questions (resolve before they block)

| Question | Resolve by phase | Notes |
|---|---|---|
| Exact STM32U535 flash size on TS1302 (256 KB vs 512 KB)? | Phase 0 | Read from build output of stock firmware |
| Debug UART pin assignment on TS1302 | Phase 1 | Schematic check |
| `LT_CERT_KIND_XXXX` semantics | Phase 5 (when verifying full chain) | App Note `ODN_TR01_app_003` |
| TROPIC01 TRNG SP 800-90B compliance | Phase 8 (before public claims) | App Note `ODN_TR01_app_008` |
| Whether Tropic Square has a TS1302 firmware roadmap of their own | Re-verify quarterly | `research/prior-art.md` re-check |
| User-presence button hardware design (daughter board vs repurpose GPIO) | Phase 6 | Compare effort |
| Whether to also ship PIV (Phase 7b) | After Phase 7 ships | Decide based on uptake |

---

*End of PROJECT.md*
