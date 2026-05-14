# nixtropic — Project Document

> **Audience:** AI coding agents (Claude, Codex, etc.) and contributors
> working on this project across sessions.
> **Read order:** This document first.  Reference `research/*.md` files
> for technical depth as needed (don't preload them — fetch by section
> when relevant).  Open work items live in `docs/BACKLOG.md`.

---

## 1. Project goal

Build open-source firmware for the **Tropic Square TS1302 USB devkit**
(STM32U535 host MCU + TROPIC01 secure element) that turns the dongle
into a **standards-compliant USB security key** exposing **FIDO2 (USB
HID)** and **OpenPGP card (USB CCID)** interfaces, with TROPIC01 as the
cryptographic backend.

End state (current): plug the dongle into a Linux/NixOS machine, and it
works as a Yubikey-class device for WebAuthn (browser login), GnuPG
smartcard (`git commit -S`, `gpg --encrypt`/`--decrypt`), and SSH via
gpg-agent — without installing host-side drivers beyond the standard
`pcsc-lite` + `libfido2` stack.

Distribution: Nix flake (`nixtropic`) packaging the firmware build,
host tooling, NixOS module with udev rules, and `nix run` apps for
flashing + validation.

**Why this is novel:** verified open niche as of 2026-05-10.  No
existing project provides custom STM32U5 + TS1302 firmware that
exposes FIDO2 + CCID with TROPIC01 backing.  The STM32 + FIDO2
ecosystem is mature (Nitrokey, SoloKeys, Somu, LionKey) but none use
TROPIC01 — they use ATECC608 or no SE.  See `research/prior-art.md`
for the full search trail.

---

## 2. Locked decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | **Language: C** | libtropic is C; the FIDO/CTAP2 reference implementations are C; ST drivers/CMSIS/TinyUSB primary API is C.  Rust adds FFI overhead with no security upside since the real crypto is on TROPIC01, not the STM32. |
| 2 | **OpenPGP card via USB CCID** (not PIV) | User uses GnuPG daily for SSH + signing + encryption.  PIV deferred — see `docs/BACKLOG.md §4.4`. |
| 3 | **SW1 (PH3) doubles as user-presence button + BOOT0 strap** | TS1302 has one button (SW1) wired to PH3.  PH3 is sampled by silicon only at reset (BOOT0 strap); after reset it is a plain GPIO, free for runtime use as user-presence.  Caveat: holding SW1 while plugging USB lands in factory DFU bootloader (documented as a recovery affordance, see `docs/RECOVERY.md`). |
| 4 | **USB stack: TinyUSB (adapt U545 BSP for U535)** | U535 has no native TinyUSB BSP, but U545 (same FS controller, same PMA) adapts trivially.  Avoid ST USBX (proprietary leanings, heavier). |
| 5 | **FIDO2 stack: hand-rolled against CTAP2.1 spec** | Implementation against the canonical CTAP2.1 specification, using SoloKeys solo v1 and CanoKey as triangulation references when the spec is ambiguous.  No vendored FIDO code. |
| 6 | **OpenPGP card stack: hand-rolled against OpenPGP card v3.4.1 spec** | Same approach as FIDO2 — clean-room against the spec.  No Gnuk / CanoKey code referenced. |
| 7 | **Software crypto library: trezor_crypto (reused from libtropic L3 CAL)** | libtropic's L3 secure session already links trezor_crypto for AES-256-GCM, SHA-256, HMAC-SHA-256, X25519, Ed25519 (via ed25519-donna).  All the algorithms the host-side FIDO/OpenPGP code needs are already linked — no second crypto library. |
| 8 | **Build: CMake + CMSIS + ST HAL** | ST HAL is more Nix-friendly than ST LL (no missing glue for SPI/RNG init).  HAL adds ~30 KB but fits the budget.  CMake + arm-none-eabi-gcc 14.3. |
| 9 | **Pairing keys at build: PRODUCTION (`*_prod0`)** | The validated TS1302 dongle ships **production** silicon `TR01-C2P-T101`, rev ACAB — not engineering samples.  Build flag `NIXTROPIC_ENG_KEYS=1` switches to `*_eng_sample` for development against older / engineering-sample chips. |
| 10 | **Document audience: AI agents primary** | This file is structured for AI agents working on the project.  Users read conversationally and reference this file as needed. |
| 11 | **ECC-only (no RSA)** | Ed25519 (sig/aut) + Cv25519 / X25519 (dec).  TROPIC01 has zero RSA hardware.  Flash budget would not fit RSA on STM32U535's 256 KB ceiling.  GnuPG ECC smartcard is fully covered. |
| 12 | **Single firmware build** with both FIDO and OpenPGP card present | One firmware ships with both surfaces; the CCID interface is always present.  Users who only want FIDO can ignore the CCID interface (it enumerates but only responds to the OpenPGP AID SELECT). |
| 13 | **TROPIC01 ECC slot allocation** | Slots 0..28 for FIDO credentials (`FIDO_SLOTS_MAX=29`).  Slots 29 / 30 / 31 reserved for OpenPGP sig / dec / aut.  Slot 30 is currently unused since the OpenPGP dec key is X25519 host-side compute (Trezor Safe 7 pattern); kept reserved for future hardening (`docs/BACKLOG.md §1.2`).  M&D slots 0..7 for FIDO PIN; 8..16 reserved for OpenPGP PIN M&D (Phase-8 work). |

---

## 3. Architecture (the layer cake)

```
   ┌───────────────────────────────────────────────────────────┐
   │ Host stack — browser, gpg, ssh, pcsc-lite, libfido2       │
   ├───────────────────────────────────────────────────────────┤
   │ USB wire (CDC + HID×2 + CCID composite device)            │
   └───────────────────────────────────────────────────────────┘
                           │ USB FS (12 Mbps)
                           ▼
   ┌───────────────────────────────────────────────────────────┐
   │ STM32U535 — nixtropic open firmware                       │
   │  ┌─────────────────────────────────────────────────────┐  │
   │  │ TinyUSB device stack — composite device             │  │
   │  │  - IF 0/1  CDC-ACM (debug / printf console)         │  │
   │  │  - IF 2    HID #0   vendor 0xFF00 (lt-rpc)          │  │
   │  │  - IF 3    HID #1   FIDO 0xF1D0  (CTAPHID)          │  │
   │  │  - IF 4    CCID 0x0B (OpenPGP card)                 │  │
   │  ├─────────────────────────────────────────────────────┤  │
   │  │ FIDO2 / CTAP2 stack (firmware/src/fido_hid/)        │  │
   │  │  - CTAPHID framing (FIDO U2F HID 1.0)               │  │
   │  │  - CTAP2.1 dispatcher: GetInfo, MakeCredential,     │  │
   │  │    GetAssertion, ClientPIN (v1), Reset,             │  │
   │  │    CredentialManagement                             │  │
   │  │  - WebAuthn credential model                        │  │
   │  │  - SW1 user-presence + LED state machine            │  │
   │  ├─────────────────────────────────────────────────────┤  │
   │  │ OpenPGP card stack (firmware/src/openpgp/)          │  │
   │  │  - ISO 7816-4 APDU dispatch                         │  │
   │  │  - OpenPGP card v3.4.1 INS handlers                 │  │
   │  │  - PW1 / PW3 / RC handling                          │  │
   │  ├─────────────────────────────────────────────────────┤  │
   │  │ CCID transport (firmware/src/ccid/, usb_ccid.c)     │  │
   │  │  - USB CCID 1.1 + ISO 7816 T=1                      │  │
   │  ├─────────────────────────────────────────────────────┤  │
   │  │ TROPIC01 glue (firmware/src/tropic/)                │  │
   │  │  - Power-up + lt_init                               │  │
   │  │  - Slot manager (R-mem + ECC slot allocation)       │  │
   │  │  - MAC-and-Destroy PIN counter                      │  │
   │  ├─────────────────────────────────────────────────────┤  │
   │  │ Software crypto: trezor_crypto (vendored via         │  │
   │  │ libtropic)                                          │  │
   │  │  - AES-256-CBC + GCM, SHA-256, HMAC-SHA-256         │  │
   │  │  - Ed25519 (ed25519-donna), X25519, P-256 (NIST)    │  │
   │  ├─────────────────────────────────────────────────────┤  │
   │  │ libtropic (vendored via Nix flake input)            │  │
   │  │  - L3 secure channel (X25519 Noise IK → AES-GCM)    │  │
   │  │  - L2 framing (252 B chunks)                        │  │
   │  │  - L1 transport (SPI shape)                         │  │
   │  ├─────────────────────────────────────────────────────┤  │
   │  │ libtropic HAL port: hal/stm32/stm32u5xx             │  │
   │  ├─────────────────────────────────────────────────────┤  │
   │  │ CMSIS + ST HAL (RCC, GPIO, SPI, RNG, PWR)           │  │
   │  └─────────────────────────────────────────────────────┘  │
   │     Cortex-M33 + TrustZone-M                              │
   └───────────────────────────────────────────────────────────┘
                           │ SPI1 (mode 0, MSB-first)
                           │ MOSI=PA7  MISO=PA6  SCK=PA5
                           │ CS=PA4    GPO=PB0   PWR=PA0
                           ▼
   ┌───────────────────────────────────────────────────────────┐
   │ TROPIC01                                                  │
   │  - 32 ECC slots (Ed25519 / P-256, 64-byte signatures)     │
   │  - 4 pairing key slots (X25519)                           │
   │  - 128 MAC-and-Destroy slots (32 B in / 32 B out)         │
   │  - 512 R-mem slots (256 B/slot default)                   │
   │  - 16 monotonic counters                                  │
   │  - TRNG, AES-256-GCM (L3 only), Cert store (4 certs)      │
   └───────────────────────────────────────────────────────────┘
```

---

## 4. Hardware essentials (commit to memory)

### TROPIC01 chip

- Modes: Start-up / Maintenance / Application / Alarm (`lt_tr01_mode_t`)
- 32 ECC slots, 4 pairing key slots, 128 MAC-and-Destroy slots, 512
  R-mem slots, 16 monotonic counters, 4-cert store
- L3 channel: X25519 KX → AES-256-GCM (12 B IV with 32-bit LE counter
  at IV[0..3], 16 B tag, ≤4096 B ciphertext)
- Validated TS1302 silicon: **`TR01-C2P-T101`** (production), rev
  **ACAB** (auto-managed FW banks), QFN32 4×4 mm, Fab ID `0x001`
  (EPS Global / Brno).  Use `sh0priv_prod0` / `sh0pub_prod0` keys.
- Older TS1302 in the wild may ship engineering samples
  (`TR01-B2S-*`); for those, set `NIXTROPIC_ENG_KEYS=1`.
- Full inventory: **`research/tropic01-inventory.md`**

### STM32U535 host MCU (TS1302)

- Cortex-M33 with TrustZone-M, max 160 MHz
- 256 KB Flash, 96 KB SRAM
- Crypto accelerators **present**: HASH (SHA-2), TRNG
- Crypto accelerators **absent**: AES, PKA, SAES, MCE, OTFDEC, BHK
  (only on higher U5 SKUs).  All symmetric crypto, HMAC, ECDH must be
  software.
- USB FS only (12 Mbps).  Adequate for FIDO2/CCID.  PA11=D−, PA12=D+,
  software 1.5 kΩ pull-up trick for re-enumeration.
- Open firmware runs at 48 MHz Power Range 3 (matches stock).
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
| BOOT0 / SW1 (user-presence) | PH3 | Sampled at reset for BOOT0; runtime input thereafter |
| LED | PA9 | Active-high, 1 user LED |

### DFU mode (memorize)

1. Hold SW1 (BOOT0=PH3) while plugging USB or pressing reset
2. Dongle enumerates as `0483:df11` (ST DFU class)
3. Flash: `dfu-util -a 0 -s 0x08000000:leave -D firmware.bin`
4. Replug → new firmware boots

---

## 5. Critical facts (do NOT forget)

These will hurt the project if violated.  Re-read this section before
any R-config or pairing-key change.

| Fact | Why it matters | Mitigation |
|---|---|---|
| **R-config write WITHOUT prior erase = brick** | Erratum `OI_TR01_ERR_2026010800`.  Triggers permanent Alarm Mode.  **No recovery.** | ALWAYS `lt_r_config_erase` before `lt_r_config_write`.  Validate against TVL simulator first.  Never write R-config on a chip you don't own. |
| **Pairing keys are PUBLIC for development** | `libtropic_default_sh0_keys.c` ships keypairs publicly.  Any adversary can establish a Secure Session with the chip. | For production deployments: generate new X25519 keypair → write pubkey to SH1 → invalidate SH0 → store new privkey in TrustZone secure-world flash. |
| **Production vs engineering-sample silicon** | This project's TS1302 has `TR01-C2P-T101` production silicon (verified 2026-05-10).  Default keys = `*_prod0`.  Eng-sample chips need `*_eng_sample` keys instead. | Build flag `NIXTROPIC_ENG_KEYS=1` swaps the key set. |
| **STM32U535 lacks BHK/SAES** | Cannot store secrets in HW-protected key memory. | TrustZone-M secure world is the only isolation mechanism. |
| **R-mem slot size is config-dependent** | Default per-slot configuration is **256 B**.  The chip's inventory document mentions 475 B max — that's max capacity, not default. | Use 256 B for new R-mem schemas.  Phase-7 M3 hit this gotcha — see commit history. |
| **Default L3 ciphertext max = 4096 B** | Larger payloads need chunking | `TR01_L3_CMD_CIPHERTEXT_MAX_SIZE = 4112`, `TR01_L3_RES_CIPHERTEXT_MAX_SIZE = 4097` |
| **EdDSA msg max = 4096 B; ECDSA prehash required** | `lt_ecc_eddsa_sign` accepts msg up to 4096 B raw.  ECDSA expects pre-hashed input. | For FIDO2 challenges (32 B), no chunking needed. |
| **Once `lt_pairing_key_invalidate(slot)`, slot is permanently dead** | Cannot un-invalidate | Never invalidate the only working pairing slot without confirming the replacement works first. |
| **I-config bits flip 1→0 only, irreversibly** | Lifetime lock-down | Never write I-config in development. |
| **`HAL_GPIO_Init` is required even after RCC clock-enable** | Enabling the GPIO bank's RCC clock alone leaves pins in silicon-default analog mode — reads return 0 regardless of wire voltage. | EVERY runtime GPIO needs BOTH bank-clock-enabled AND a `HAL_GPIO_Init` call with explicit Mode/Pull. |
| **STM32U5 PWR clock gate is mandatory** | `__HAL_RCC_PWR_CLK_ENABLE()` must run BEFORE any HAL_PWR call.  Without it, `HAL_PWREx_ControlVoltageScaling` silently times out. | `platform/clock.c` already does this at Step 0. |
| **TROPIC01 TRNG SP 800-90B compliance UNVERIFIED** | Not stated in libtropic public source | Verify via `ODN_TR01_app_008` before any public production claims. |

---

## 6. Test methodology

1. **Hardware-in-the-loop is mandatory.**  Every change is validated on
   the real TS1302.  No "I tested in QEMU."
2. **Black-box checkpoints.**  Define externally observable behavior;
   verify via host-side scripts.  Firmware is SUT; host tools are the
   test harness.
3. **Standard tools as test clients.**  `fido2-token`, `pkcs11-tool`,
   `gpg`, `pcsc_scan`, `webauthn.io`.  If those work, browsers will
   too.  Avoid proprietary test clients.
4. **Recovery rehearsal.**  The DFU recovery path is re-validated
   whenever risky firmware lands.
5. **Host-side static analysis.**  Run `nix run .#lint` (cppcheck) over
   the original firmware code before any commit touching it.
6. **`nix run .#validate`** runs the canonical FIDO + OpenPGP card
   validation suite (`tools/validate.sh` → `validate-fido.sh` +
   `validate-openpgp.sh`).  Single command, plug-and-play.

---

## 7. Coding conventions (firmware C)

| Rule | Enforcement |
|---|---|
| `-Wall -Wextra -Werror -Wconversion -Wshadow -Wundef -Wcast-align -Wstrict-prototypes` | CMake CFLAGS |
| No dynamic allocation after init | Manual review |
| All buffers static, sized at compile time | Audit |
| Static analysis: `cppcheck` via `nix run .#lint` | Pre-commit check |
| No comments unless WHY is non-obvious — exception: file headers (per the comment pass that lives in firmware/src/ today) | Code review |
| Functions <50 lines | Manual |
| Files <800 lines | Refactor when exceeded |
| Snake_case for functions and variables; UPPER_CASE for macros | Enforced |
| Headers minimal — only what callers need | Avoid leaking impls |
| Every protocol parser bounds-checks every byte | Review checklist |
| Secrets zeroized after use (`memzero`) | Audit |

---

## 8. Build system structure

```
nixtropic/
├── flake.nix                 # Top-level Nix flake
├── flake.lock
├── PROJECT.md                # This file
├── README.md                 # User-facing intro + daily-driver setup
├── TROPIC01.md               # Conversational primer on the chip
├── nix/
│   ├── stock-firmware.nix    # Builds Tropic Square's stock fw
│   ├── firmware.nix          # Builds our open firmware
│   ├── fw-update-chip.nix    # Builds the chip-firmware updater
│   ├── dev-shell.nix         # Toolchain devShell
│   └── apps.nix              # nix run targets
├── nixos/
│   └── tropic.nix            # NixOS module (udev, pcsc-lite, libccid patch)
├── firmware/
│   ├── CMakeLists.txt
│   ├── cmake/                # arm-none-eabi toolchain file
│   ├── linker/               # stm32u535.ld
│   ├── src/
│   │   ├── main.c
│   │   ├── usb/              # TinyUSB integration + composite descriptor + CCID
│   │   ├── fido_hid/         # CTAPHID + CTAP2 + ClientPIN + credstore
│   │   ├── openpgp/          # OpenPGP card applet + PIN handling + key ops
│   │   ├── ccid/             # ISO 7816 APDU dispatcher + CCID protocol
│   │   ├── hid_rpc/          # vendor lt-rpc framing
│   │   ├── cdc_protocol/     # transparent SPI bridge mode (stock-compatible)
│   │   ├── tropic/           # libtropic glue
│   │   └── platform/         # STM32U5 HAL wrappers, board pinout, clock, GPIO, LED
│   └── third_party_overlay/  # U545→U535 BSP adaptation for TinyUSB
├── tools/
│   ├── validate.sh           # full FIDO + OpenPGP validation wrapper
│   ├── validate-fido.sh      # FIDO2 surface checks
│   ├── validate-openpgp.sh   # OpenPGP card APDU checks
│   ├── fido2_test.py         # development-time deep FIDO test helper
│   ├── lt_rpc.py             # lt-rpc client for vendor HID commands
│   └── fw-update-chip-main.c # TROPIC01 chip-firmware updater source
├── docs/
│   ├── BACKLOG.md            # Open work items
│   ├── RECOVERY.md           # DFU recovery procedure
│   ├── WEBAUTHN-NOTES.md     # Browser quirks + AAGUID policy
│   └── history/              # Per-phase design docs (archived)
└── research/
    ├── tropic01-inventory.md # Chip facts ground-truth
    ├── stm32u535-inventory.md# MCU facts ground-truth
    └── prior-art.md          # Niche-open verification
```

---

## 9. References (load-on-demand, not preloaded)

| Document | Purpose | When to read |
|---|---|---|
| **`research/tropic01-inventory.md`** | Authoritative TROPIC01 reference: constants, APIs, config objects, error codes | Before any new libtropic-call code; before R-config or pairing-key changes |
| **`research/stm32u535-inventory.md`** | Authoritative STM32U535 + TS1302 reference: pinout, clocks, peripherals, security features | Before any new GPIO/SPI/USB code |
| **`research/prior-art.md`** | Niche-open verification (2026-05-10) | Re-check periodically for late-arriving competition |
| **`TROPIC01.md`** | Conversational primer; superseded by `research/tropic01-inventory.md` for facts | Skim for orientation |
| `docs/BACKLOG.md` | Open work items | When planning the next batch of work |
| `docs/history/` | Per-phase design docs | When you need the historical rationale behind a decision |
| `https://github.com/tropicsquare/libtropic` | Official C SDK source | Implementing/extending HAL or chasing API semantics |
| `https://github.com/tropicsquare/tropic01-stm32u5-usb-devkit-fw` | Stock firmware source | Recovery / SPI passthrough reference |
| `https://github.com/solokeys/solo` | SoloKeys v1 — secondary reference for CTAP2 control flow | Spec triangulation |
| `https://github.com/canokeys/canokey-core` | CanoKey — active C FIDO2 + OpenPGP firmware (Apache 2.0); not vendored, used as a reference | Spec triangulation |
| `https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf` | OpenPGP card v3.4.1 spec | Any OpenPGP applet work |
| FIDO Alliance CTAP 2.1 PS 2021-06-15 | CTAP2 spec | Any FIDO2 stack work |
| `https://github.com/hathach/tinyusb` | TinyUSB upstream | USB stack debugging |
| ST RM0456 | STM32U5 reference manual | Peripheral register details, TrustZone-M setup |
| App Note `ODN_TR01_app_008` | TROPIC01 security architecture | Verify TRNG NIST compliance, side-channel claims |

---

## 10. Operating instructions for AI agents

1. **Always read this file at session start.**  It's intended for
   context-window inclusion.
2. **Don't preload `research/*.md`.**  Fetch by `Read` when needed;
   cite line numbers in commits/comments.
3. **Before writing any R-config / pairing-key / I-config code:**
   re-read §5 "Critical facts" and `research/tropic01-inventory.md`
   §4 (Configuration objects).  The brick erratum is permanent.
4. **Before claiming a fact about TROPIC01:** verify against
   `research/tropic01-inventory.md`.  If not there, libtropic source.
   If not there, official docs / App Note.  If not there, note as
   `TODO(verify)`.
5. **Before claiming a fact about STM32U535:** verify against
   `research/stm32u535-inventory.md`.  If pin/peripheral not listed
   there, fetch from the TS1302 schematic + datasheet directly.
6. **Never auto-flash the user's dongle without explicit permission.**
   Even though DFU recovery exists, the user owns the hardware.
   Confirm before any `nix run .#flash-*`.
7. **Never write production keys or invalidate the only working
   pairing slot without explicit user confirmation.**  Unrecoverable.
8. **If a fact is questioned and you're not sure:** spawn an Explore
   agent rather than guessing.  Cheap correction beats confident wrong.
9. **Update this PROJECT.md when:** a decision changes, a new critical
   fact emerges, the architecture diagram changes, a new dependency is
   added.

---

## 11. Glossary

| Term | Meaning |
|---|---|
| **TROPIC01** | The secure element chip |
| **TS1302** | The USB devkit board (STM32U535 + TROPIC01 + USB-C) |
| **libtropic** | Official C SDK for TROPIC01 |
| **L1 / L2 / L3** | TROPIC01's protocol layers: SPI transport / framing / encrypted secure session |
| **Pairing key** | X25519 keypair establishing the L3 secure channel.  Public half on chip (SH0..3PUB), private half on host. |
| **STPUB** | Tropic Square's certified public key for the chip, baked at fab.  Used for chip authentication. |
| **R-config / I-config** | Chip's permission/policy table.  R = rewritable, I = irreversible (1→0 only). |
| **R-mem** | Rewritable user storage (512 slots × 256 B default) |
| **MAC-and-Destroy** | One-shot per-slot MAC primitive for PIN-attempt rate limiting |
| **CTAP2** | FIDO Alliance protocol over USB HID for FIDO2 |
| **WebAuthn** | W3C browser API for FIDO2 authentication |
| **CCID** | USB Chip Card Interface Device class — smartcard reader protocol |
| **APDU** | Smartcard "Application Protocol Data Unit" — request/response unit over CCID |
| **OpenPGP card** | A standard APDU set for GnuPG-compatible smartcards |
| **TrustZone-M** | ARMv8-M security extension partitioning code/data into secure / non-secure worlds |
| **DFU** | Device Firmware Upgrade — USB class for firmware flashing |
| **TinyUSB** | Open-source embedded USB device stack |
| **trezor_crypto** | Software crypto library (Trezor firmware) — Ed25519/X25519/SHA/HMAC/AES |
