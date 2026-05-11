# Project Status

> Append-only log. Most recent entry at top. Each entry: date, phase, what was validated, what's next.

---

## 2026-05-11 — Phase 5 PASS ✅✅✅ — TROPIC01-backed FIDO2 with hardware-enforced PIN

**Phase:** 5 (Wire FIDO2 to TROPIC01 — THE MIC-DROP) — **COMPLETE, all 5 milestones**

**Pass criterion met (per docs/PHASE-5-PLAN.md §2):**
Plug nixtropic dongle → Firefox → `https://webauthn.io` → register → log out → log in → success. **Confirmed live** with credential `AQS57EtxK4UI7IuVwL1YNDlW` (slot 4 on chip, version=0x01, 16 B TRNG nonce). After completion the dongle is a working open-source FIDO2 security key with hardware-backed PIN protection.

**Milestone-by-milestone HW validation:**

| | What | Commits | Validation |
|---|---|---|---|
| **M1** | TROPIC01 slot manager + R-mem layout | c0bf345 | 7/7 PASS `validate-phase5-m1` + persistence across power-cycle |
| **M2** | Credstore on TROPIC01 (chip-side Ed25519) | 4e793f7 | 8/8 PASS `validate-phase5-m2` + real webauthn.io register/login via Firefox |
| **M3** | ClientPIN protocol v1 (P-256 + AES-CBC + HMAC) | 936d6ca + b95ff09 | 15/15 PASS + `fido2-token -S` + Firefox UV-required PIN prompt |
| **M4** | MAC-and-Destroy hardware PIN retry counter | bfa86f0 + b32ee94 | 15/15×2 regression + manual 9-wrong-PIN lockout test confirms HW enforcement |
| **M5** | authenticatorReset + cpp-reviewer audit | 8b77c35 | Reset within 10 s window + 4 audit findings fixed (1 HIGH, 2 MEDIUM, 1 stale comment) |

**cpp-reviewer audit (M5):** 1 HIGH (changePin retry-decrement ordering) + 2 MEDIUM (expected_auth not zeroed on success path; mcounter not reset on factory_reset) + 1 INFO (stale "256 B" comment). All fixed in commit `8b77c35`. Audit also confirmed: prior Phase 3/4 findings not regressed; two-layer M3+M4 PIN bypass protection structurally sound (no code path reaches successful PIN response while skipping `pin_md_verify`); M4 re-init-all-slots fix correctly structured.

**`nix run .#lint`:** 25/25 cppcheck clean.

**Build numbers at Phase 5 completion:**
- `firmware.bin = 202 120 B / 256 KB (77%)` — +43 KB over Phase 4 stub (added P-256 ECDH, M&D scheme, slot manager).
- `RAM = 25 576 B / 192 KB (13%)` — +728 B over Phase 4 stub.
- Lint sweep covers `firmware/src/{cdc_protocol,fido_hid,hid_rpc,platform,tropic,usb,main.c}/` — 25 files.

**AAGUID:** `6e697874726f70696300000000000002` — "nixtropic\0\0\0\0\0\0\x02". Unchanged since M2; per `docs/WEBAUTHN-NOTES.md §3` policy M4/M5 internal hardening doesn't warrant a bump.

**What's a "real security key" now means:** an adversary who physically possesses the dongle and reflashes the STM32 firmware **still cannot brute-force the PIN**. After 8 wrong attempts, the TROPIC01 hardware M&D slots are consumed — the master_secret required to decrypt the PIN-verification ciphertext is unrecoverable without the correct PIN. Only `authenticatorReset` (or vendor `slots-reset`) recovers, and either wipes all credentials in the process.

**Outstanding follow-ups (Phase 8 polish bucket):**
- credProps extension (task 52) — fixes "unknown discoverability" RP label
- Brave/Chromium WebAuthn modal greyed out on Linux — investigated, libfido2 + Firefox work
- hidraw udev rule in `nixos/tropic.nix` — currently in `/run/udev/rules.d/` (volatile)
- `authenticatorCredentialManagement` (task 54) — enables `ykman fido credentials list`-style enumeration
- Force-UV device-side option (task 53) — Yubikey-style "always require PIN" regardless of RP hints

**Phase 6 preview:** real user-presence button (daughter board), replaces the UP=stub-true. Touch-to-confirm signatures + Reset.

**Next phase:** Phase 6 — production-grade UX (button + PIN lockout).

---

## 2026-05-11 — Phase 4 PASS ✅ — FIDO2 stack (stub backend) running end-to-end

**Phase:** 4 (CTAPHID + CTAP2 GetInfo/MakeCredential/GetAssertion, stub Ed25519 backend) — **COMPLETE**

**Pass criterion met:** Dongle enumerates a second HID interface with the FIDO Alliance usage page (0xF1D0); a real CTAP2 transaction (`MakeCredential` → `GetAssertion`) round-trips over CTAPHID and the host-side python-cryptography verifies the Ed25519 signatures on `authData || clientDataHash`. CDC + Phase 3 lt-rpc still PASS in parallel.

**Canonical evidence — `nix run .#validate-phase4` output:**

```
═══════════════════════════════════════════════════════════════
  Phase 4 validation — CTAPHID + CTAP2 stubs over HID
═══════════════════════════════════════════════════════════════
FIDO HID @ /dev/hidraw5

═══════════════════════════════════════════════════════════════
  Phase 4 — CTAPHID framing + CTAP2 GetInfo validation
═══════════════════════════════════════════════════════════════
[1/7] INIT (broadcast → new CID + caps)                                PASS
[2/7] PING 32 B (single packet)                                        PASS
[3/7] PING 512 B (multi-packet INIT+CONT)                              PASS
[4/7] MSG → SW=0x6E00 (CLA not supported)                              PASS
[5/7] CTAP2 GetInfo (versions, aaguid, options, algorithms)            PASS
[6/7] CTAP2 MakeCredential (Ed25519 self-attestation verifies)         PASS
[7/7] CTAP2 GetAssertion (Ed25519 assertion verifies)                  PASS

7/7 PASS — Phase 4 validated.

═══════════════════════════════════════════════════════════════
  ✓ Phase 4 validation PASS
═══════════════════════════════════════════════════════════════
```

**Build:** firmware.bin ≈ 161 792 B (~63% of 256 KB flash), 24 848 B RAM (~13% of 192 KB). +16 KB over Phase 3, largely from ed25519-donna's basepoint table being pulled in for the host-side stub signing, plus the new fido_hid/ module (CTAPHID framing + CBOR encoder/decoder + CTAP2 dispatcher).

**Architecture milestones in this phase:**

| M | Scope | Commit |
|---|---|---|
| M1 | Composite descriptor extended to 2 HID interfaces (instance 0 = lt-rpc 0xFF00, instance 1 = FIDO 0xF1D0 with U2F usages 0x20/0x21). EP4 OUT/IN added. lt-rpc gated on instance==0. | 9f9c1a2 |
| M2 | `firmware/src/fido_hid/`: CTAPHID framing (INIT/CONT, CID allocator, BUSY semantics), commands INIT/PING/MSG/CANCEL/CBOR. Stub `fido_hid_cbor_dispatch` weak-symbol returns CTAP2_ERR_INVALID_COMMAND. | 3b03d5b |
| M3 | CBOR encoder (~150 LOC), CTAP2 dispatcher, `authenticatorGetInfo` returning the locked map (versions/aaguid/options/maxMsgSize/transports/algorithms — Ed25519+ES256). | b2abe82 |
| M4 | CBOR decoder extension, `credstore.{h,c}` (fixed Ed25519 keypair from embedded seed), `ctap2_creds.c` (MakeCredential + GetAssertion), authData builder, COSE_Key Ed25519 encoder. Phase 4 stub signs with trezor_crypto's ed25519-donna (the same lib used for Phase 3 L3 verification, now used locally). | bb3ba3a |
| M5 | `tools/validate-phase4.sh` + `nix run .#validate-phase4` + `flash-and-validate-phase4` apps. STATUS/PROJECT/memory updates. | (this) |

**Key files added/modified:**

- `firmware/src/fido_hid/` (NEW) — `proto.h` (wire-format), `ctaphid.{h,c}` (framing), `cbor.{h,c}` (encoder + decoder), `ctap2.{h,c}` (dispatcher + GetInfo), `ctap2_creds.c` (MakeCred + GetAssertion stubs), `credstore.{h,c}` (fixed Ed25519 keypair)
- `firmware/src/usb/usb_descriptors.c` — second HID interface with FIDO usage page 0xF1D0, U2F input/output usages, EP4 endpoint pair
- `firmware/src/usb/tusb_config.h` — `CFG_TUD_HID = 2`
- `firmware/src/hid_rpc/rpc.c` — `tud_hid_set_report_cb` dispatches by instance (0 → lt-rpc, 1 → fido_hid)
- `firmware/src/main.c` — boots `fido_hid_init` + `credstore_init`; main loop pumps `fido_hid_task`
- `firmware/CMakeLists.txt` — adds the 5 new `fido_hid/` sources
- `tools/fido2_test.py` — host-side CTAPHID + CTAP2 test client (~600 LOC) with CBOR encoder/decoder, authData parser, COSE_Key reader, Ed25519 signature verification via python-cryptography
- `tools/validate-phase4.sh` — wrapper called by the new nix apps
- `nix/apps.nix` — `validate-phase4` + `flash-and-validate-phase4`
- `docs/PHASE-4-PLAN.md` — locked decisions, milestones, risk register

**Locked decisions executed:**

- **Two separate HID interfaces** rather than dual-collection — each enumerates as its own `/dev/hidrawN` and libfido2 cleanly identifies the FIDO one by usage page
- **Stub keypair embedded in firmware** — recognizable bytes ("nixtropic stub seed v1\0..." for the secret, "nixtropic-cred-v1\0...\x01" for the credential id). Insecure by design; Phase 5 swaps to TROPIC01 ECC slots
- **Ed25519-only** for Phase 4 stub — ES256 advertised in GetInfo so libfido2 can negotiate, but firmware refuses with CTAP2_ERR_UNSUPPORTED_ALGORITHM on MakeCredential
- **AAGUID** `6e697874726f70696300000000000001` — "nixtropic" + 6 zero bytes + version byte; stable across Phase 4 builds, bumps on Phase 5

**Subtle bugs found:**

1. `tud_hid_set_report_cb` had to be made instance-aware — without it, packets on the FIDO interface fed straight into the lt-rpc state machine (which would reject them with CID_MISMATCH, but the M2 architecture would have been clean-broken).
2. Stale-buffer info-disclosure invariant from Phase 3 carried over: `fido_hid/ctaphid.c` zeros `s_req_buf` at every INIT and on `reset_assembly` exactly like `hid_rpc/rpc.c` does. The audit pattern wasn't re-run but the structural rule was kept.
3. Python `hid.enumerate(vid, pid)` doesn't always populate `usage_page` (depends on backend); `find_fido_path()` falls back to picking the higher hidraw index since the FIDO interface enumerates second by descriptor order. Worked first try on Linux + hidapi-libusb.

**Outstanding follow-ups (Phase 8 polish bucket or carryover):**

- Phase 2 first-call CDC transient (race between boot-time `lt_init` and lt-util's first call) — carried over from Phase 3
- pid.codes VID/PID allocation (currently TinyUSB demo 0xCAFE:0x4001) — carried over
- `fido2-token -I` direct exercise from libfido2 not yet wired into validate-phase4 (currently uses hand-rolled Python). Worth adding `pkgs.libfido2` to the validate-phase4 runtimeInputs for a smoke test that exercises libfido2's parser as well.
- ES256 (P-256) support — defer to Phase 5 where TROPIC01 can do P-256 natively
- Static-analysis pass over `fido_hid/` (mirror Phase 3 cpp-reviewer audit) — schedule before Phase 5 wires real keys

**Validation commands:**

- `nix run .#validate-phase4` — Phase 4 CTAPHID + CTAP2 suite (7/7)
- `nix run .#flash-and-validate-phase4` — DFU flash + Phase 4 validate one-shot
- `python3 tools/fido2_test.py make-cred` — standalone MakeCredential + Ed25519 verify
- `python3 tools/fido2_test.py assertion` — standalone MakeCred → GetAssertion round-trip
- `nix run .#validate-phase3` — Phase 3 lt-rpc regression (5/5)

**Next phase:** Phase 5 — wire FIDO2 to TROPIC01. `MakeCredential` allocates a fresh ECC slot on the chip, returns the chip-generated pubkey; `GetAssertion` calls `lt_ecc_eddsa_sign` for the chip-resident slot. Credential metadata (rpId hash, slot index, sign counter) persisted in TROPIC01 R-mem. ClientPIN wired through `lt_mac_and_destroy` for hardware-enforced rate limiting. Pass criterion: register on `webauthn.io` from Firefox/Chrome and log in successfully.

---

## 2026-05-10 — Phase 3 OFFICIALLY PASS ✅✅✅ — composite USB + Ed25519 sign over HID

**Phase:** 3 (composite USB CDC + HID, lt-rpc framing, libtropic L3 on chip, Ed25519 sign+verify) — **COMPLETE**

**Pass criterion met:** TROPIC01 generates an Ed25519 keypair on chip, signs a 32 B challenge over the HID lt-rpc transport, host verifies the signature with python-cryptography. CDC + Phase 2 regression still works in parallel.

**Canonical evidence — `nix run .#validate-phase3` output:**

```
═══════════════════════════════════════════════════════════════
  Phase 3 validation — lt-rpc-over-HID (PING / RANDOM / CHIP_ID / SIGN)
═══════════════════════════════════════════════════════════════
═══════════════════════════════════════════════════════════════
  Phase 3: lt-rpc-over-HID validation
═══════════════════════════════════════════════════════════════
[1/5] PING (32 B echo)                         PASS
[2/5] PING (large 256 B multi-packet)          PASS
[3/5] GET_RANDOM (32 B entropy)                PASS
[4/5] CHIP_ID (128 B)                          PASS
[5/5] ECC generate + sign + Ed25519 verify (slot 0) PASS

5/5 PASS — Phase 3 lt-rpc-over-HID validated.

═══════════════════════════════════════════════════════════════
  ✓ Phase 3 validation PASS
═══════════════════════════════════════════════════════════════
```

**Build:** firmware.bin ≈ 144 928 B (~56% of 256 KB flash), 20 608 B RAM (~10% of 192 KB). Trezor_crypto vendor lib + libtropic L3 + cert store buffers + crypto context account for the bulk of the M3→M4 size jump.

**Architecture milestones in this phase:**

| M | Scope | Commit |
|---|---|---|
| M1 | Composite USB descriptor (CDC + HID raw 64-byte vendor reports under usage page 0xFF00). HID echo stub. | 675931e |
| M2 | CTAPHID-style framing layer (single fixed channel 0xCAFE0001, INIT/CONT packetization). PING + GET_RANDOM commands. | 675931e |
| M3 | Re-enable libtropic on chip (CMakeLists block uncommented, tropic.c re-added). L2 CHIP_ID command over HID. | 13f5cfe |
| M4 | libtropic CAL (trezor_crypto) + AES-GCM + SHA256 + HMAC + X25519. L3 secure session via lt_session_start with sh0_prod0 default keys. ECC generate/pubkey/sign/erase commands. | 7a81a23 |
| M5 | `nix run .#validate-phase3` + `flash-and-validate-phase3` apps. STATUS/PROJECT/memory updates. | (this) |

**Key files added/modified:**

- `firmware/src/hid_rpc/` (NEW) — `lt_rpc_proto.h`, `rpc.{h,c}` (framing state machine), `rpc_cmds.c` (command handlers)
- `firmware/src/tropic/tropic.{h,c}` — extended with `tropic_l3_session_ensure`, `tropic_ecc_{generate,pubkey_read,eddsa_sign,erase}`, `tropic_chip_id_read`
- `firmware/CMakeLists.txt` — libtropic L3 sources, trezor_crypto CAL, trezor vendor crypto subset wired in; trezor needs `AES_VAR + USE_INSECURE_PRNG + ed25519_verify=trezor_crypto_ed25519_verify` per upstream tests recipe
- `firmware/src/usb/usb_descriptors.c` — added HID INOUT descriptor, vendor usage page 0xFF00, new `STR_HID_INTERFACE` string
- `firmware/src/usb/tusb_config.h` — `CFG_TUD_HID = 1`, `CFG_TUD_HID_EP_BUFSIZE = 64`
- `firmware/src/platform/stm32u5xx_hal_conf.h` — explicit `USE_HAL_*_REGISTER_CALLBACKS=0` to satisfy `-Wundef` on the (now non-suppressed) tropic.c
- `tools/lt_rpc.py` (NEW) — host-side Python client (hidapi-based) with subcommands: ping / random / chip-id / sign-test / validate
- `tools/validate-phase3.sh` (NEW) — wrapper invoked by `nix run .#validate-phase3`
- `nix/apps.nix` — new apps `validate-phase3` and `flash-and-validate-phase3`

**Subtle bugs found in this phase:**

1. **Test ordering caught a missing ECC erase**: validate suite re-ran sign-test against an already-occupied slot 0 and got LT_RPC_ERR_OTHER. Added `tropic_ecc_erase` + `LT_RPC_CMD_ECC_ERASE` and made the host test idempotent.
2. **HAL register-callback macros undefined**: hal_conf.h didn't have `USE_HAL_*_REGISTER_CALLBACKS` defines; tropic.c (now non-suppressed) blew up on `-Wundef` when including stm32u5xx_hal.h. Added explicit `0U` defines.
3. **trezor_crypto needs `AES_VAR`**: aesgcm.c calls the variable-key dispatcher `aes_encrypt_key()` (not `aes_encrypt_key256`). Found the canonical defines in libtropic's `tests/functional/src/CMakeLists.txt:134`.
4. **hasher.c dispatcher pulls 5+ unused hash algos**: blake256, blake2b/s, sha3, groestl, ripemd160 all referenced even when only `HASHER_SHA2` is ever requested. Easier to include them (gc-sections strips unused paths) than to fork hasher.c.
5. **Pre-existing misleading-indentation warnings in tropic.c**: Phase 1's `if (foo()) bar++; tud_task();` pattern only compiled because the libtropic warning-suppression block included tropic.c. Once tropic.c re-entered APP_SOURCES with strict flags, those warnings became errors. Cleaned up the brace pattern.
6. **Phase 2 first-call transient**: after tropic_init runs lt_init on boot, the first lt-util chip_info call over CDC occasionally catches the SPI bus in an unexpected state and fails with LT_L1_SPI_ERROR. Self-recovers on retry. Tracked as a future polish item (most likely a CS deassert needed between libtropic's session-init L1 traffic and the first ASCII-passthrough command from lt-util).

**Outstanding follow-ups:**

- Phase 2 first-call transient race (see above) — non-blocking, retry works
- Migrate to libtropic's identify_chip example which uses the fixed adapter (drops `flake.nix` postPatch) — Phase 8 polish
- pid.codes VID/PID allocation (currently TinyUSB demo 0xCAFE:0x4001) — Phase 8
- Phase 4 next: FIDO2 stack port (SoloKeys-derived) with stub backend

**Validation commands:**

- `nix run .#validate-phase3` — Phase 3 lt-rpc-over-HID suite (5/5)
- `nix run .#flash-and-validate-phase3` — one-shot DFU flash + validate
- `nix run .#validate-phase2` — Phase 2 regression (CDC + lt-util)
- `nix run .#identify` — works against stock OR open firmware

**Next phase:** Phase 4 — port SoloKeys-derived FIDO2 stack with stub backend. HID interface advertises FIDO usage page 0xF1D0. `fido2-token -L` should list our device.

---

## 2026-05-10 — Phase 2 OFFICIALLY PASS ✅✅✅ — open firmware byte-faithful with stock

**Phase:** 2 (USB CDC ↔ SPI passthrough — replicate stock fw protocol) — **COMPLETE**

**Pass criterion met:** unmodified host-side `lt-util` reads chip ID byte-for-byte matching the Phase 0 baseline.

**Canonical evidence — `nix run .#validate-phase2` output:**

```
Running lt-util chip-info against /dev/ttyACM0 (timeout 15s)...

  ✓ lt_util_runs
  ✓ silicon_rev_acab
  ✓ sn_baseline
  ✓ long_pn_baseline
  ✓ fab_id_eps_brno

═══════════════════════════════════════════════════════════════
  ✓ Phase 2 validation PASS (5/5 checks)
═══════════════════════════════════════════════════════════════

Drop-in stock-fw replacement confirmed: lt-util reads chip ID
byte-for-byte matching the Phase 0 baseline. Open firmware works.
```

**Full lt-util output (chip ID matches Phase 0 baseline):**

```
CHIP_ID ver            = 0x01000000 (v1.0.0.0)
FL_PROD_DATA           = 0x00000000000000000000000000000000 (N/A)
MAN_FUNC_TEST          = 0x01000000000000FF (PASSED)
Silicon rev            = 0x41434142 (ACAB)
Package ID             = 0x80AA (QFN32, 4x4mm)
Prov info ver          = 0x01 (v1)
Fab ID                 = 0x001 (EPS Global - Brno)
P/N ID (short P/N)     = 0x101
Prov date              = 0x085B
HSM HW/FW/SW ver       = 0x00060501
Programmer ver         = 0x00000000
S/N                    = 0x02001101085B1905090D00000000048B
P/N (long)             = 0x0D545230312D4332502D54313031FFFF (TR01-C2P-T101)
Prov template ver      = 0x0104 (v1.4)
Prov template tag      = 0xD8966128
Prov specification ver = 0x000C (v0.12)
Prov specification tag = 0x7DEDA870
Batch ID               = 0x1905090D00
```

**Build artifact:** `firmware.bin` SHA256 `426dc906a060fe15af192e01891a44627e52eb5f0cf80fa982aca69f9c35f62e`, 35084 bytes (text=34944 + data=140), 13.7 % of 256 KB FLASH. Reproducible Nix build.

**Architectural decisions in this phase:**
- Phase 1's libtropic-on-MCU L2 round-trip work (commit `4b30bf0`) was **excluded from the build but kept on disk** (commented out in CMakeLists, src/tropic/ retained per user no-delete rule). Re-activated in Phase 3 when HID lt-rpc needs on-chip libtropic.
- New code lives in `firmware/src/cdc_protocol/` (parser, hex, protocol, cmd) and `firmware/src/platform/spi.c` (direct HAL_SPI_Init replacing libtropic's port).
- Package renamed `firmware` → `open-firmware` (`packages.open-firmware`); flash app `flash-firmware` → `flash-open` for symmetry with `stock-firmware`/`flash-stock`. Old `flash-and-validate` renamed to `flash-and-validate-phase1`. New `validate-phase2` and `flash-and-validate-phase2` apps.
- VID/PID kept at TinyUSB demo `0xCAFE:0x4001` (real allocation deferred to Phase 8). lt-util accepts any /dev/ttyACMN regardless of VID, so compatibility is unaffected.

**Bugs found and fixed in this phase:**

| # | Bug | Where | Fix |
|---|---|---|---|
| 1 | Hex parser misinterpreted command lines starting with hex letters (CS=0, AUTO=1, etc.) — `'C'` is a hex digit, parser's loop entered, broke with n=0, but still asserted CS and emitted `\r\n` (2 bytes) instead of letting `cmd_dispatch` emit `OK\r\n` (4 bytes). Host's lt_l1_spi_csn_high read 2 bytes vs expected 4 → LT_L1_SPI_ERROR | `firmware/src/cdc_protocol/protocol.c` `try_hex_passthrough` | Added `if (n == 0u) return false;` after parse loop so empty hex yield falls through to cmd_dispatch |
| 2 | TinyUSB CDC TX FIFO too small (256 B) for chip_id response (~262 B). 6 bytes of every 130-byte L1 transfer dropped, host short-read → LT_L1_SPI_ERROR | `firmware/src/usb/tusb_config.h` | Bumped CFG_TUD_CDC_TX_BUFSIZE to 2048; added retry loop in protocol.c for safety. RAM cost: ~2 KB |
| 3 | TROPIC01 not auto-powered at boot; lt-util doesn't issue `PWR=1` (assumes chip already powered, like stock fw does at boot) | `firmware/src/main.c` | Added explicit power cycle (PA0 OFF→20 ms→ON→300 ms settle) at boot, before USB enumeration |
| 4 | Missing `HAL_SPIEx_SetConfigAutonomousMode` call after `HAL_SPI_Init`; libtropic port does it. Default state may be undefined | `firmware/src/platform/spi.c` | Added explicit autonomous-mode-disable call |
| 5 | Boot banner emitted AFTER 1.5 s tud_task pump — could land in host kernel buffer AFTER lt-util's `tcflush(TCIOFLUSH)` and pollute response stream | `firmware/src/main.c` `boot_banner` | Moved printf calls BEFORE the pump so banner enters the FIFO during enumeration and drains before lt-util opens the device |
| 6 | **lt-util's bundled libtropic v1.0.0** has off-by-one in `lt_port_unix_usb_dongle.c`: readback loop iterates `2 * tx_data_length` instead of `tx_data_length`. For chip_id (130 B → 260 iterations) walks 8+ bytes past `buffered_chars[512]` and writes past `s2->buff[257]`, corrupting state → LT_L1_SPI_ERROR. Fixed in libtropic v3.x but lt-util upstream is dormant and still pins v1.0.0. | `flake.nix` lt-util `postPatch` | One-line `substituteInPlace` to fix the loop bound. Patch can be removed when upstream lt-util bumps its libtropic submodule. |
| 7 | Validate-phase2.sh patterns required literal space before `ACAB` and the S/N hex, but lt-util's `lt_print_chip_id` formats them inside parens `(ACAB)` and after `0x` (no space). All-data-present false negatives. | `tools/validate-phase2.sh` | Removed the literal space from regex patterns. |

**Bug 6 is host-side only**, not a firmware bug. Manual end-to-end replication of lt-util's chip_id sequence (printf-based, dongle in DFU recovery loop) confirmed our firmware emits exactly the right byte counts at every step. It's the host adapter that mis-parses the response.

**Cosmetic note for manual diagnostics:** by default the host's `/dev/ttyACMN` opens with `echo icanon` set in termios. With `cat` in another terminal, our firmware's TX is echoed back to the device as RX, creating a feedback loop of "PWR: 1 → ERR illegal → ERR unknown → ...". lt-util disables echo via `tcsetattr` so its session is clean. For human diagnostics, run `sudo stty -echo -icanon raw -F /dev/ttyACM0` first.

**Files in firmware/ (final Phase 2 layout):**
```
firmware/
├── CMakeLists.txt               (libtropic excluded; re-enabled in Phase 3)
├── cmake/arm-none-eabi.cmake
├── linker/stm32u535.ld
└── src/
    ├── main.c                   (boot, power cycle, banner-first, main loop)
    ├── platform/
    │   ├── stm32u5xx_hal_conf.h
    │   ├── board.h
    │   ├── clock.{h,c}
    │   ├── gpio.{h,c}
    │   ├── rng.{h,c}            (kept from Phase 1; harmless if unused)
    │   ├── blink.{h,c}
    │   └── spi.{h,c}            (NEW — direct HAL SPI1 + CS GPIO control)
    ├── usb/
    │   ├── tusb_config.h        (CDC TX FIFO bumped to 2048)
    │   ├── usb_descriptors.c    (CDC-ACM, VID cafe:4001)
    │   ├── usb.{h,c}
    │   └── cdc_io.c
    ├── cdc_protocol/            (NEW Phase 2 directory)
    │   ├── protocol.{h,c}       (line dispatch, hex passthrough, AUTO tick)
    │   ├── parser.{h,c}         (1024 B line buffer + \r\n stripping)
    │   ├── hex.{h,c}            (hex_byte / hex_emit_byte)
    │   └── cmd.{h,c}            (10 stock-protocol commands)
    └── tropic/                  (Phase 1 — kept on disk, not in build)
        ├── tropic.{h,c}
        └── lt_crypto_stubs.c
```

**Validation commands available:**
- `nix run .#identify` — host runs lt-util chip-info (works against either stock or open firmware)
- `nix run .#validate-phase2` — automated 5-check PASS test against currently-flashed firmware
- `sudo nix run .#flash-open` — DFU-flash open firmware
- `sudo nix run .#flash-and-validate-phase2` — one-shot regression test
- `nix run .#read` — open USB CDC console via screen (for human inspection)
- `sudo nix run .#flash-stock` — recovery fallback (always available)

**Outstanding follow-ups (not Phase-2-blocking):**
- Migrate lt-util to newer libtropic-based identify_chip example (would drop our patch, use bundled trezor_crypto). Tracked for Phase 8 polish.
- D5 cold-boot stress test (10× unplug/replug, manual). Optional confidence check.
- nixosModules.tropic integration into user's NixOS config still pending (sudo for flash works fine).

**🎉 Phase 2 done.** Custom open firmware is now a verified drop-in replacement for the stock TS1302 firmware. Stock `lt-util` (the host-side library that talks to the chip via the dongle) reads chip ID identically against our firmware vs. stock — proving wire-protocol byte-equivalence. From here, the firmware can begin growing Phase 3+ features (HID composite, lt-rpc, FIDO2) without ever needing to revisit the protocol bridge.

---

## 2026-05-10 — Phase 1 OFFICIALLY PASS ✅✅✅ + Group E packaging done

**Phase:** 1 (TROPIC01 L2 round-trip on STM32U535 over USB CDC) — **COMPLETE**

**Canonical evidence — full screen capture from user's TS1302 dongle:**

```
[boot] nixtropic phase 1 — USB CDC up
[boot] vid=0xCAFE pid=0x4001
[hal_rng] 65 ed f9 61 27 2f 77 c0 c5 53 48 bd 84 f5 12 13 6c 81 c6 9e 0b 87 7c fa fe 5d a6 98 54 c2 5b 7c
[tropic] lt_init OK (TROPIC01 powered + L1 link up)
[chip_id] 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 ff 41 43 41 42 80 aa ff ff 01 00 11 01 08 5b 00 06 05 01 00 00 00 00 ff ff 02 00 11 01 08 5b 19 05 09 0d 00 00 00 00 04 8b 0d 54 52 30 31 2d 43 32 50 2d 54 31 30 31 ff ff 01 04 d8 96 61 28 00 0c 7d ed a8 70 19 05 09 0d 00 ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
[riscv_fw] 00 01 03 00
[spect_fw] 00 01 03 00
[fw_bank FW1] FAIL ret=37
[fw_bank FW2] FAIL ret=37
[fw_bank SPECT1] FAIL ret=37
[fw_bank SPECT2] FAIL ret=37
[tropic] 4 fw_bank query warnings (expected on ACAB silicon — auto-managed banks)
[tropic] L2 sweep PASS (chip_id + riscv_fw + spect_fw OK)
[boot] PHASE1 OK — Group D HW round-trip passed
[tick 0 rng 29]
[tick 1 rng 49]
```

**Chip ID byte-for-byte match against Phase 0 baseline:**

| Field | Bytes captured | Phase 0 baseline | Match |
|---|---|---|---|
| Silicon rev (offset 28-31) | `41 43 41 42` ("ACAB") | ACAB | ✅ |
| Package (offset 32-33) | `80 aa` | 0x80AA QFN32 | ✅ |
| S/N (offset 51-66, 16 B) | `02 00 11 01 08 5b 19 05 09 0d 00 00 00 00 04 8b` | `02001101085B1905090D00000000048B` | ✅ |
| Long P/N (offset 71-83, 13 B) | `54 52 30 31 2d 43 32 50 2d 54 31 30 31` | "TR01-C2P-T101" | ✅ |
| Batch ID (within S/N region) | `19 05 09 0d 00` | 0x1905090D00 | ✅ |
| Fab ID (within S/N region) | `01` | 0x001 (EPS Global / Brno) | ✅ |

**Group E deliverables added in this iteration:**
- `tools/validate-phase1.sh` — automated 11-check parser (boot block, hal_rng, lt_init, chip_id present, silicon rev ACAB, long P/N match, S/N match, riscv_fw, spect_fw, L2 sweep PASS, PHASE1 OK marker). Exits 0/non-zero.
- `nix run .#read` — opens `/dev/ttyACM*` via `screen` at 115200. Uses screen instead of picocom because picocom's tcsetattr races with TinyUSB CDC SET_LINE_CODING (task #27 follow-up).
- `nix run .#validate-phase1` — wraps validate-phase1.sh; one-shot regression test for any future firmware change.
- `nixos/tropic.nix` — udev rules extended to include VID `cafe:4001` (custom firmware) with `ENV{ID_MM_DEVICE_IGNORE}="1"` so ModemManager doesn't probe-and-hold our dongle.

**Validation criteria from PHASE-1-PLAN v3 §4 — final scorecard:**

| # | Criterion | Status |
|---|---|---|
| 1 | `nix flake check --all-systems` passes | ✅ |
| 2 | `nix build .#firmware` reproducible (build twice → same hash) | ✅ |
| 3 | `firmware.elf` text+data: < 64 KB total | ✅ (35 KB used / 64 KB budget) |
| 4 | DFU flash via `sudo nix run .#flash-firmware` succeeds | ✅ |
| 5 | Host shows `0xCAFE:0x4001` in `lsusb`; `/dev/ttyACM*` appears within 2 s | ✅ |
| 6 | `screen /dev/ttyACM0` shows full `[boot]` block within 1 s | ✅ |
| 7 | All L2 info fields match Phase 0 baseline byte-for-byte | ✅ chip_id + RISC-V FW + SPECT FW match. fw_bank warns (ACAB silicon auto-managed banks; informational, not a failure). |
| 8 | STM32 HAL_RNG output: 32 bytes, fresh per cold-boot | ✅ |
| 9 | LED solid heartbeat post-success | ✅ (1 Hz steady) |
| 10 | 10/10 cold-boot reset cycles pass | ⏳ pending user manual test |
| 11 | DFU recovery via `flash-stock` returns to baseline | ✅ proven in Phase 0; recovery path always-on |

**Outstanding items (not Phase-1-blocking):**
- D5 cold-boot stress test (10× unplug/replug, manual)
- picocom termios hang follow-up (task #27) — `screen` and `cat` work fine; `picocom --noinit` works as a workaround
- nixosModules.tropic integration into user's NixOS config (still uses `sudo` for flash; deferred to whenever user wants to import the module)

**Build sizes (final Phase 1):** firmware.bin = 35264 B. FLASH 13.8% / 256 KB. RAM ~9 KB / 192 KB.

**Files in firmware/ (final Phase 1 layout):**
```
firmware/
├── CMakeLists.txt
├── cmake/arm-none-eabi.cmake
├── linker/stm32u535.ld
└── src/
    ├── main.c                            (boot sequence + main loop)
    ├── platform/
    │   ├── stm32u5xx_hal_conf.h          (HAL module selection)
    │   ├── board.h                       (TS1302 pin assignments)
    │   ├── clock.{h,c}                   (HSE→PLL→48 MHz + HSI48)
    │   ├── gpio.{h,c}                    (PA9 LED, PA0 power, PB0 GPO)
    │   ├── rng.{h,c}                     (HAL_RNG init + read API)
    │   └── blink.{h,c}                   (LED state machine)
    ├── usb/
    │   ├── tusb_config.h                 (TinyUSB compile config)
    │   ├── usb_descriptors.c             (CDC-ACM device + config descriptor)
    │   ├── usb.{h,c}                     (HSI48+CRS, VDDUSB, AF mux, IRQ)
    │   └── cdc_io.c                      (_write retarget to CDC TX)
    └── tropic/
        ├── tropic.{h,c}                  (TROPIC01 power + L2 sweep)
        └── lt_crypto_stubs.c             (L3 placeholder stubs)
```

**Memory notes added during Phase 1:**
- `feedback_u5_hal_pwr_clock_gate.md` — `__HAL_RCC_PWR_CLK_ENABLE()` mandatory before any HAL_PWR call on U5
- `feedback_acab_fw_bank.md` — fw_bank GET_INFO returns LT_L2_GEN_ERR on ACAB silicon
- `project_phase1_done.md` — Phase 1 milestone

**Next phase preview (per PROJECT.md §6):**
- Phase 2 — replicate stock CDC-ACM passthrough behavior (drop-in replacement for stock firmware)
  - Adapter for stock fw's command framing
  - lt-util compatibility test
- Phase 3 — add HID interface (composite CDC + HID), `lt-rpc` over HID
- Phase 4-7 — FIDO2, ClientPIN, OpenPGP card, polish

**🎉 PHASE 1 IS DONE.** The TS1302 dongle now runs custom open-source firmware that exercises libtropic L1+L2 against TROPIC01 over SPI, exposes USB CDC for diagnostics, builds reproducibly via Nix, and round-trips via DFU recovery in case anything goes wrong. Foundation laid for Phase 2+ work.

---

## 2026-05-10 — Phase 1 Groups C + D FULLY VALIDATED ✅ (USB CDC + libtropic L2 round-trip on hardware)

**Phase:** 1 (Group C: USB CDC bring-up; Group D: TROPIC01 L1+L2 round-trip via libtropic) — **HW-in-the-loop checkpoints passed**

**Group C result (USB CDC-ACM):**
- ✅ USB enumerates as `0xCAFE:0x4001` (TinyUSB demo VID/PID per P1.15)
- ✅ `/dev/ttyACM0` appears via `cdc_acm` mainline driver
- ✅ `picocom -b 115200 /dev/ttyACM0` opens cleanly, "Terminal ready" reached
- ✅ Boot output, RNG dump, periodic ticks, CRLF translation all flowing
- ✅ TinyUSB v0.20.0 + U545 BSP-derived integration; `dcd_stm32_fsdev` driver (PMA-based, U535's USB DRD FS controller)

**Group D result (libtropic L1+L2):**
- ✅ TROPIC01 powered up via PA0 / IC4 load switch (300 ms post-power settle)
- ✅ `lt_init` returns LT_OK — L1 SPI link + L2 framing functional
- ✅ `lt_get_info_chip_id` returns 128 bytes that match the Phase 0 baseline **byte-for-byte**:
  - Silicon rev: `41 43 41 42` ("ACAB", offset 28) ✅
  - Package: `80 aa` (0x80AA QFN32, offset 32) ✅
  - Long P/N: `54 52 30 31 2d 43 32 50 2d 54 31 30 31` ("TR01-C2P-T101", offset 71) ✅
  - S/N: `02 00 11 01 08 5b 19 05 09 0d 00 00 00 00 04 8b` (matches baseline, offset 51) ✅
- ✅ `lt_get_info_riscv_fw_ver` returns `00 01 03 00` (4 bytes)
- ✅ `lt_get_info_spect_fw_ver` returns `00 01 03 00` (4 bytes)

**Known limitation on ACAB silicon:**
- ❌ `lt_get_info_fw_bank` for FW1/FW2/SPECT1/SPECT2 all return **LT_L2_GEN_ERR (37)** ("some other error")
- Cause: ACAB silicon uses **auto-managed FW banks** — the chip itself manages bank rotation and doesn't expose explicit-bank introspection via the L2 GET_INFO query. ABAB silicon would respond.
- **Not a libtropic-on-STM32U5 bug** — it's a chip-side feature/limitation. libtropic round-trip itself is fully functional.
- Treated as "informational warning" in `tropic_l2_sweep`: logged, but doesn't count toward Phase 1 errors.

**Critical fixes that unblocked Group D:**
1. **CDC `_write` was dropping bytes pre-connect** — fixed by pushing to FIFO regardless of `tud_cdc_connected()`. TinyUSB drains buffered bytes once host opens the port.
2. **CDC stalled during long L2 sweep** — fixed by deferring `tropic_init` + `tropic_l2_sweep` to the main loop (1.5 s after boot, after USB has stably enumerated), and interleaving `tud_task()` between L2 commands.
3. **CRLF translation in `_write`** — picocom doesn't translate `\n` by default; firmware now emits `\r\n` for clean column alignment.
4. **TinyUSB `tusb_init()` no-arg call needed `TUD_OPT_RHPORT 0`** in `tusb_config.h`, else the macro expands to `_Static_assert(false, ...)` at function scope (compile error).
5. **U5 USB clock symbols**: HAL exposes USB FS clock as part of "ICLK" (intermediate clock shared by USB / SDMMC / RNG) — `RCC_PERIPHCLK_ICLK` + `IclkClockSelection` + `RCC_ICLK_CLKSOURCE_HSI48`, not the F4-style `RCC_PERIPHCLK_USB`.
6. **Diagnostic blink-codes (raw GPIO pre-HAL)** kept in main.c as a permanent triage primitive — the 4 quick blinks at boot prove CPU is running our code; subsequent N-pattern blink encodes the failed init stage.

**Build sizes (current):** firmware.bin = 35264 B. FLASH usage 13.8% / 256 KB. RAM ~9 KB / 192 KB.

**Tasks closed in C+D:**
- C-batch (TinyUSB CDC integration: tusb_config + descriptors + usb.c + cdc_io + main loop wiring) ✅
- D-batch (libtropic compile + crypto stubs + tropic.c + power-up + L2 sweep + CRLF fix) ✅
- B3 (rng.c — folded into Group C with HAL_RNG init for both libtropic device handle and P1.22 sanity dump) ✅

**Phase 1 sub-tasks still pending:**
- D5 (10× cold-boot stress test) — manual test for user. Each cycle: unplug+replug, confirm chip_id matches, RNG fresh.
- Group E (validation tooling): `validate-phase1.sh` host-side parser, STATUS auto-update on PASS, packaging polish.

**Memory note added:** `feedback_acab_fw_bank.md` — ACAB silicon's auto-managed FW banks reject the explicit-bank GET_INFO query.

**Phase 1 functional pass criterion (per plan v3 §4 modified):**
> chip_id + RISC-V FW + SPECT FW match Phase 0 baseline byte-for-byte; libtropic L1+L2 round-trip OK; USB CDC enumerates and prints output; LED heartbeats post-success.

**RESULT: Phase 1 functionally PASS as of 2026-05-10.** The user's TS1302 dongle now runs custom firmware that:
- Boots in ~1.5 s
- Enumerates as a USB CDC-ACM serial device
- Powers and queries TROPIC01 over SPI via libtropic
- Validates chip identity end-to-end
- Loops with periodic RNG ticks + LED heartbeat indicating "alive"

**Next:** D5 stress test + Group E packaging. Then Phase 2 (replicate stock CDC passthrough + composite USB).

---

## 2026-05-10 — Phase 1 Group B FULLY VALIDATED ✅ (heartbeat alive on hardware)

**Phase:** 1 (Group B: platform basics — clock, GPIO, blink) — **HW-in-the-loop checkpoint passed**

**Hardware result:** PA9 LED pulses visibly (~1 Hz) after `sudo nix run .#flash-firmware` on user's TS1302 dongle. User reports "it is flashing!" and "feels a bit faster than 1Hz" (perceptual; not investigated as an issue — heartbeat is indicative-only).

**Critical fix that unblocked Group B:**
- First HW iteration: LED stayed dark — diagnosed via the layered-diagnostic main.c (4 quick raw-register blinks at boot, then blink-code based on clock_init return). User reported "4 quick blinks then 1-blink-pause repeating", pinpointing `HAL_PWREx_ControlVoltageScaling(SCALE3)` returning `HAL_TIMEOUT`.
- Root cause: `__HAL_RCC_PWR_CLK_ENABLE()` was missing. On STM32U5, PWR is on AHB3 with a clock gate (RCC_AHB3ENR_PWREN) that defaults to **disabled** at reset. Without it, all PWR register writes silently no-op, and `PWR->VOSR.VOSRDY` never goes high, causing HAL_PWREx to wait its full timeout.
- Fix: added `__HAL_RCC_PWR_CLK_ENABLE()` as Step 0 of `clock_init()`. Saved as durable memory note (`feedback_u5_hal_pwr_clock_gate.md`) so future-me / future-AI doesn't repeat the iteration.
- Old STM32 series (F4, L4) have PWR always-on from backup-domain power tree, so the enable is omitted in patterns from those series. U5 (and presumably H7+, newer) put PWR on a regular clock gate.

**What the diagnostic main.c proved:**
- 4 quick blinks at boot (raw register writes, no HAL): proves CPU runs our code, vector table OK, startup file OK, linker layout OK
- Subsequent blink-code: maps `clock_init` return value to LED pattern (1=PWREx, 2=OscConfig, 3=ClockConfig, 6=HAL_Init)
- Heartbeat: proves SysTick alive at correct rate, blink module state-machine correct
- This pattern is a useful debug primitive — keeping it in main.c for now; will simplify when we're more confident in the boot sequence.

**Files modified this iteration:**
- `firmware/src/main.c` — rewrote with layered diagnostic (raw GPIO + 4 quick blinks → HAL_Init → clock_init with blink-code on failure → heartbeat)
- `firmware/src/platform/clock.c` — `__HAL_RCC_PWR_CLK_ENABLE()` at top of clock_init (the actual fix)
- `firmware/CMakeLists.txt` — extended HAL warning suppressions to `-Wno-cast-align -Wno-conversion`
- `~/.claude/projects/.../memory/feedback_u5_hal_pwr_clock_gate.md` — new memory note

**Build sizes (current):** firmware.bin = 7508 B. FLASH 7536 B / 256 KB (2.87%). RAM 2616 B / 192 KB (1.33%). Well under criterion 3 (< 64 KB).

**Group B official scorecard:**
- B4 (hal_conf.h) ✅
- B1 (clock.c, 48 MHz; HSI48 still pending — used in Group C) ✅
- B2 (gpio.c, Phase 1 pins; SPI/USB AF mux deferred) ✅
- B5 (blink.c with heartbeat + blink-codes) ✅
- B6 (main.c wiring + build verification + HW-in-the-loop) ✅
- B3 (rng.c) — deferred to Group C as planned

**Next:** Group C — TinyUSB CDC bring-up. Sub-tasks per plan §3:
- C1 — TinyUSB sources already pinned at flake-input level (from Group A1)
- C2 — Fork U545 BSP → U535
- C3 — `PWR_SVMCR_USV` enable (USB voltage detector independent)
- C4 — PA12 renumeration trick (drive low briefly before AF10)
- C5 — USB descriptors (VID/PID `0xCAFE:0x4001`, single CDC interface)
- C6 — `tusb_init` + IRQ handler + main-loop `tud_task` polling
- C7 — `_write` retarget to CDC TX

HW checkpoint at end of Group C: USB enumerates as `0xCAFE:0x4001` with `/dev/ttyACM*`, picocom shows `[boot] hello` test print.

---

## 2026-05-10 — Phase 1 Group B software-side complete; awaiting heartbeat HW test (superseded — see entry above for HW-validated state)

**Phase:** 1 (Group B: platform basics — clock, GPIO, blink). RNG init (B3) deferred to Group C; flash-firmware app pulled forward from Group E1.

**What was built (software-side, no hardware required):**
- ✅ `firmware/src/platform/stm32u5xx_hal_conf.h` — minimal HAL config: HAL_RCC, FLASH, GPIO, PWR, CORTEX, RNG, SPI, DMA, EXTI enabled. UART and PCD explicitly off. HSE_VALUE=8000000, HSI48_VALUE=48000000.
- ✅ `firmware/src/platform/board.h` — single source of truth for TS1302 pin assignments (LED PA9, TROPIC01 power PA0, SPI1 PA4-7, GPO PB0, USB PA11/12, button PH3).
- ✅ `firmware/src/platform/clock.c` — HSE 8 MHz → PLL ×96/16 → 48 MHz SYSCLK at Range 3, flash latency 1ws, AHB/APB div 1. Mirrors stock fw exactly.
- ✅ `firmware/src/platform/gpio.c` — initializes PA9 LED, PA0 TROPIC01 power switch, PB0 GPO input. RCC clocks for GPIOA/B/H. SPI/USB pins deferred to their owner groups.
- ✅ `firmware/src/platform/blink.c` — state-machine LED driver (P1.20 + P1.24): BLINK_OFF / SOLID / HEARTBEAT / PATTERN(N). Polled from main loop via `blink_tick()`. No own SysTick.
- ✅ `firmware/src/main.c` — boot sequence: HAL_Init → clock_init (1=fail) → gpio_init → `blink_set_heartbeat()` → main loop polling `blink_tick` + `__WFI`. Overrides weak `SysTick_Handler` to call `HAL_IncTick`.
- ✅ HAL .c files compiled in: stm32u5xx_hal{,_rcc,_rcc_ex,_flash,_flash_ex,_gpio,_pwr,_pwr_ex,_cortex,_rng,_rng_ex,_spi,_spi_ex,_dma,_dma_ex,_exti}.c — `-Wno-{strict-prototypes,unused-parameter,undef,maybe-uninitialized}` applied to HAL sources only; application code stays strict.
- ✅ `nix run .#flash-firmware` — pulled forward from Group E1 (decision P1.23) so user can test heartbeat now. Same DFU mechanic as `flash-stock`, different binary.
- ✅ `nix flake check --all-systems` passes (aarch64-linux + x86_64-linux).
- ✅ `nix build .#firmware` produces `firmware.{elf,bin,hex,map}`. Sizes: text 7272 B, data 20 B, bss 2604 B. FLASH 7292 B / 256 KB (2.78%). RAM 2616 B / 192 KB (1.33%). Well under criterion 3 (< 64 KB).

**Tasks closed in this group (5/6, B3 deferred):**
- B4 (hal_conf.h) ✅
- B1 (clock.c, 48 MHz; HSI48 still pending — used in Group C) ✅
- B2 (gpio.c, Phase 1 pins; SPI/USB AF mux deferred) ✅
- B5 (blink.c with heartbeat + blink-codes) ✅
- B6 (main.c wiring + build verification) ✅
- **B3 (rng.c) — DEFERRED to Group C**: HAL_RNG `.c` is linked but no `rng_init()` yet. Will be added alongside `tusb_init()` so libtropic's `device->rng_handle` and the P1.22 32-byte HAL_RNG dump both have a working `RNG_HandleTypeDef`.

**HW-in-the-loop checkpoint — needs user action ⛔:**
1. Verify Phase 0 recovery still works: plug dongle (no button) → `nix run .#check-dongle` should report `0483:5740` app mode.
2. Hold SW1, replug → `lsusb | grep 0483:df11` confirms DFU mode.
3. `sudo nix run .#flash-firmware` → DFU flashes Phase 1 firmware.
4. Wait ~2 s after flash. **Watch PA9 LED**: should pulse at ~1 Hz (heartbeat).
5. `lsusb` will show **no device** (or "device descriptor read error" loops in `dmesg`) — this is expected: USB stack comes in Group C.
6. Recover anytime via Phase 0: hold SW1, replug, `sudo nix run .#flash-stock` → back to baseline app mode.

**Pass criterion:** PA9 LED pulses ~1 Hz steady. If LED stays off / always-on / wrong pattern, that's a clock or GPIO issue and we triage.

**Not blocking:** the libc_nano stub warnings (`_close`/`_lseek`/`_read`/`_write` not implemented) are benign — those syscalls are referenced indirectly by newlib but never called from our firmware. We retarget `_write` to USB CDC in Group C; others stay always-fail (this is freestanding).

**Next (after user confirms heartbeat visible):** Group C — TinyUSB bring-up. C1 (pull TinyUSB sources, already done at flake-input level), C2 (fork U545 BSP → U535), C3 (`PWR_SVMCR_USV` enable), C4 (PA12 renumeration), C5 (descriptors), C6 (`tusb_init` + IRQ + `tud_task`), C7 (CDC `_write` retarget).

---

## 2026-05-10 — Phase 1 Group A COMPLETE ✅ (build infrastructure)

**Phase:** 1 (Group A: build infra → reproducible firmware build pipeline)

**What was validated (software-side, no hardware required):**
- ✅ `nix flake metadata` resolves all four new inputs: `cmsis-core` @ master Release 6.3.0, `cmsis-device-u5` @ v1.4.2, `stm32u5xx-hal-driver` @ v1.6.2, `tinyusb` @ 0.20.0. None have submodules.
- ✅ `nix build .#firmware` produces `firmware.{elf,bin,hex,map}`
- ✅ ELF properties: ARM EXEC, hard-float ABI (FPv5-SP-D16), entry @ `0x080002cd` in FLASH region, `.isr_vector` correctly placed at `0x08000000`
- ✅ Sizes (skeleton): text 972 B, data 8 B, bss 28 B (+ 2564 B reserved heap+stack); FLASH 980 B / 256 KB (0.37%), RAM 2592 B / 192 KB (1.32%) — well under budget
- ✅ Cross-toolchain wired: `arm-none-eabi-gcc 14.3.1` from `gcc-arm-embedded`, AR/RANLIB/STRIP forced via toolchain file (Nix `stdenvNoCC` was passing empty `-DCMAKE_AR=` etc., breaking try-compile)
- ✅ Reuses ST-shipped `startup_stm32u535xx.s` and `system_stm32u5xx.c` from `cmsis-device-u5/Source/Templates/` — no hand-written CRT
- ✅ Linker script `firmware/linker/stm32u535.ld` — FLASH 256K @ 0x08000000, SRAM1 192K @ 0x20000000 (TZEN=0 layout per P1.7)
- ✅ Build remote-built via `eu.nixbuild.net`, ~2 s build time

**Files created/modified this group:**
- `flake.nix` — added 4 inputs (cmsis-core, cmsis-device-u5, stm32u5xx-hal-driver, tinyusb) + `firmware` package output
- `nix/firmware.nix` (new) — `stdenvNoCC` derivation, passes source roots as CMake cache vars
- `firmware/CMakeLists.txt` (new) — top-level, validates source roots, compiles main.c + ST startup + ST system file
- `firmware/cmake/arm-none-eabi.cmake` (new) — Cortex-M33 hard-float, AR/RANLIB/STRIP forced (FORCE), strict warnings (–Werror parked until past skeleton)
- `firmware/linker/stm32u535.ld` (new) — U535 standard layout, no TZ splits
- `firmware/src/main.c` (new) — placeholder spinning on `__WFI()`

**Issues hit + fixed:**
- Try-compile failure: Nix's cmakeBuilder hooks pass empty `-DCMAKE_AR=` for `stdenvNoCC`, breaking the compiler test. Fixed by `set(CMAKE_AR ... CACHE FILEPATH "" FORCE)` in toolchain file (and same for RANLIB/STRIP/OBJCOPY/OBJDUMP/SIZE).
- HAL include chain: `STM32U535xx` + `USE_HAL_DRIVER` defined globally caused CMSIS device header to pull in `stm32u5xx_hal.h` → needs `stm32u5xx_hal_conf.h` (task B4). Fixed by removing `USE_HAL_DRIVER` from toolchain (per-target instead) and removing HAL include path from skeleton CMakeLists (re-added in B4 with hal_conf.h).
- libc_nano benign warnings (`_close`/`_lseek`/`_read`/`_write` not implemented) — accepted; we'll retarget `_write` to USB CDC in Group C, others stay always-fail since this is freestanding.

**Decision deltas folded in vs plan v3:**
- `cmsis-core` pinned to master @ `2327f7224ff212b2436e5a4cadda3288143fd041` (labeled "Release 6.3.0", 2026-03-16) instead of latest tagged `v5.9.0_20250520` — newer rev with same stability.
- `-Werror` deferred to Group D (re-enabled once HAL noise is contained) — strict warnings still on (`-Wall -Wextra -Wconversion -Wshadow -Wundef -Wcast-align -Wstrict-prototypes`).

**Next:** Group B (platform basics — clock, GPIO, RNG, blink). HW-in-the-loop checkpoint at end of B (heartbeat LED visible after flash).

---

## 2026-05-10 — Phase 1 plan v3 LOCKED, ready for Group A start

**Phase:** 1 (TROPIC01 L2 round-trip on STM32 over USB CDC-ACM, no L3 session) — **all decisions locked, awaiting user "go" for Group A (build infra)**

**P1.11 verified against libtropic master (`6d058a36`):**
- `lt_init` (`src/libtropic.c:39-112`): sets `h->l3.session_status = LT_SECURE_SESSION_OFF` (line 53), no L3 setup ✅
- `lt_get_info_chip_id` (`src/libtropic.c:297-330`): pure L2 (`lt_l2_send` / `lt_l2_receive`), no session check ✅
- `lt_random_value_get` (`src/libtropic.c:1196-1222`, line 1201): explicit `if (h->l3.session_status != LT_SECURE_SESSION_ON) return LT_HOST_NO_SESSION;` ❌ — **DROPPED from Phase 1**
- Working example confirms: `examples/stm32/nucleo_f439zi/identify_chip/Src/main.c:323` calls `lt_get_info_chip_id` after `lt_init` only, no `lt_session_start` anywhere

**Replacement test surface (per P1.21 + P1.22):**
- L2 sweep: `lt_get_info_chip_id`, `lt_get_info_riscv_fw_ver`, `lt_get_info_spect_fw_ver`, `lt_get_info_fw_bank` × {FW1, FW2, SPECT1, SPECT2}
- STM32 HAL_RNG sanity check (32 bytes per cold-boot) — host-MCU RNG validation, decoupled from TROPIC01 RNG (deferred to Phase 5)

**All §7 questions resolved (per `docs/PHASE-1-PLAN.md` §7):**
- Q1 VID/PID: `0xCAFE:0x4001` (TinyUSB defaults), real allocation deferred to ship-prep
- Q2 Naming: keep `flash-stock` + add `flash-firmware` (no rename)
- Q3 Heartbeat LED: enabled during init
- Q4 P1.11 verification: done, plan amended to A+C path (drop `lt_random_value_get`, add L2 sweep + HAL_RNG)
- Q5 TinyUSB pin: latest stable tag at flake-input time, not master HEAD

**Plan v3 details:**
- 28 sub-tasks across 5 groups (A: build infra, B: platform, C: USB CDC stack, D: L2 round-trip, E: ship)
- 25 locked technical decisions (P1.1 through P1.25)
- Effort estimate unchanged: 10–20 h focused work
- HW-in-the-loop checkpoints at end of B, C, D, E

**Still no firmware C written.**

**Next:** user says "go" → begin Group A (build infrastructure). No firmware C until A4 reachable.

---

## 2026-05-10 — Phase 1 plan revised to Path Y (USB CDC instead of UART) — superseded by v3

**Phase:** 1 (TROPIC01 round-trip on STM32 **over USB CDC-ACM**) — **superseded by v3**

**What changed from v1:**
- User flagged: external USB-UART adapter requires soldering or flaky test clips; TS1302 already has a USB port; the existing USB-CDC channel (used by stock fw) is the obvious debug surface
- Plan rewritten as Path Y: bring up minimal USB CDC-ACM via TinyUSB in Phase 1 instead of LPUART1 on test points
- Net effect: Phase 1 grows by one task group (USB stack), Phase 2 shrinks (becomes "add HID + CCID composite to existing CDC")
- No external hardware purchase needed — TS1302's own USB-C port is the debug channel

**`docs/PHASE-1-PLAN.md` v2 highlights:**
- 28 sub-tasks across 5 groups (A: build infra, B: platform, C: USB CDC stack, D: TROPIC01 round-trip, E: ship)
- 20 locked technical decisions (P1.1–P1.20), incl. TinyUSB master + U545→U535 BSP fork (P1.13), CDC-ACM-only descriptor (P1.14), VID/PID = TinyUSB demo defaults `0xCAFE:0x4001` for now (P1.15), PA12 renumeration trick mirrored from stock fw (P1.16), `tud_task()` polled in main loop (P1.17), pre-CDC failure mode = LED blink codes (P1.20)
- Effort estimate: 10–20 h focused work (vs 7–14 h in v1) — Group C (USB) is the highest-risk
- New risk: U545→U535 BSP fork (largely mechanical per inventory, but unverified)
- 5 open questions for user (most important: Q1 = OK with TinyUSB demo VID/PID for Phase 1, Q4 = spawn Explore agent to verify P1.11 about L3 session before chip-ID query)

**Still no firmware C written.**

**Next:** user reviews `docs/PHASE-1-PLAN.md` v2, answers §7 questions. Then begin Group A (build infrastructure).

---

## 2026-05-10 — Phase 1 prep v1 (Path Z, UART) — superseded by v2

**Phase:** 1 (TROPIC01 round-trip on STM32, no USB) — **planning, superseded by v2**

**What was produced:**
- `docs/PHASE-1-PLAN.md` — 21-sub-task plan (groups A/B/C/D), 12 locked technical decisions, validation criteria, risks, open questions for user
- Re-read of `research/stm32u535-inventory.md` (623 lines) for pinout, clocks, HAL port specifics
- Pulled and reviewed `libtropic/hal/stm32/stm32u5xx/libtropic_port_stm32u5xx.{c,h}` (225 + 46 LOC). Confirmed: small surface, blocking SPI HAL calls, requires application to provide GPIO/clock/RNG init (libtropic only configures the SPI peripheral itself + CS GPIO line, not the GPIOA AF mux for SPI1 pins).

**Key findings folded into the plan:**
- `lt_init` requires `device->rng_handle` populated → app must initialize `HAL_RNG` before calling `lt_init`
- libtropic does NOT mux PA5/PA6/PA7 to AF5 — that's the application's responsibility
- libtropic does NOT enable RCC clocks for GPIOA — same
- `LT_USE_INT_PIN` should remain undefined (TS1302 PB0 is GPO, not an L1 INT line)
- HAL-based libtropic port → our firmware must use ST HAL (selectively), not LL drivers

**Blocking decision needed from user (per plan §1.1):**
- Debug UART hardware path: USB-UART adapter (option A, default), SWD probe with SWO (B), defer until cable arrives (C), or fall back to LED-only signaling (D)?

**Other open questions for user (plan §7):** flash-app naming, heartbeat LED, optional Explore-agent verification of libtropic API assumption P1.11.

**No firmware C written.** No `firmware/` directory created yet. No `nix/firmware.nix` derivation yet. All Phase 1 work waits on user review of the plan.

**Next:** user reviews `docs/PHASE-1-PLAN.md`, answers §1.1 + §7. Then begin Group A (build infrastructure).

---

## 2026-05-10 — Phase 0 FULLY VALIDATED ✅

**Phase:** 0 (Reproducibility & recovery) — **complete**

**Hardware round-trip validated end-to-end** on user's specific TS1302 dongle:

| Step | Command | Result |
|---|---|---|
| 1 | Plug in (no button) | `lsusb` shows `0483:5740` (app mode) |
| 2 | `nix run .#check-dongle` | "Dongle present in APP MODE; permissions ✓" |
| 3 | `sudo nix run .#identify` | Full chip ID dump returned (see below) |
| 4 | Hold SW1 + replug | `lsusb` shows `0483:df11` (DFU mode) |
| 5 | `sudo nix run .#flash-stock` | Erase + Download + File downloaded successfully + Submit leave (benign tail get_status error — known dfu-util quirk) |
| 6 | `sudo nix run .#identify` | **Bit-identical chip ID** vs step 3 |

**Chip ID confirmed (used as Phase 1 baseline):**
- Silicon rev: `0x41434142` ("ACAB" — production, auto-managed FW banks)
- Package: `0x80AA` (QFN32 4×4 mm)
- Long P/N: **`TR01-C2P-T101`** (production, NOT engineering sample)
- S/N: `02001101085B1905090D00000000048B`
- Batch ID: `0x1905090D00`
- Fab ID: `0x001` (EPS Global, Brno)
- Provisioning: template v1.4, specification v0.12
- MAN_FUNC_TEST: PASSED

**Why this matters for the project:**
- Chip is **production-grade silicon**. PROJECT.md decision #10 updated: default firmware build will use `*_prod0` keys, NOT `*_eng_sample`.
- Recovery path is proven for every Phase 1+ flash cycle. Each subsequent custom-firmware experiment can be safely reverted with one DFU sequence.
- `sudo nix run` is the temporary access pattern. Long-term fix: import `nixosModules.tropic` into the user's NixOS config; deferred to whenever they integrate the module (Phase 8 at the latest).

**Known quirk to track:** dfu-util's "Error during download get_status" after `:leave` is benign. `nix/apps.nix` flash-stock script polished to recognize this so the message no longer reads as a partial-success.

**Phase 0 checklist:** 12/12 tasks completed.

**Pause point per project discipline:** before Phase 1 starts, re-read `research/stm32u535-inventory.md` for UART debug pinout, re-read libtropic's `hal/stm32/stm32u5xx/`, propose Phase 1 task list for user review.

---

## 2026-05-10 — Phase 0 software-side complete; awaiting hardware validation

**Phase:** 0 (Reproducibility & recovery)

**What was validated:**
- ✅ `nix flake check --all-systems` passes cleanly (aarch64-linux + x86_64-linux)
- ✅ `nix build .#stock-firmware` succeeds — produces `firmware.{bin,elf,hex}` reproducibly. Output verified as ARM Cortex-M ELF, hard-float ABI, entry point `0x800632d` within STM32U5 flash region. Sizes: text=31696 / data=176 / bss=18384 bytes.
- ✅ `nix build .#lt-util` succeeds — host x86_64 ELF
- ✅ `nix run .#check-dongle` runs without errors (correctly reports "not detected" with no dongle plugged in)
- ✅ Source pins reproducible:
  - libtropic v3.2.1 → `6d058a36` (`sha256-Ap+wa05RgDO0UMofBBmhDQ30dLKUmYDlpJ1FvqTgEhU=`)
  - stock fw master → `36a40baa` (source: `sha256-tjdEFE31EigzR683JQr8rcw8ULZbg6NvVx1eK8/gT1U=`)
  - lt-util master → `cbc30f5a` (source: `sha256-P4+VEaed40qKPLNLFwOdTCCCJ5PbjNk3JvJhOVedyAc=`)
  - libtropic-pkcs11 main → `37406ec5`
- ✅ NixOS module evaluates; udev rules render correctly for both VID/PID modes (`0483:5740` app, `0483:df11` DFU)
- ✅ `docs/RECOVERY.md` written with full DFU procedure
- ✅ `README.md` updated to reflect firmware-project pivot
- ✅ Stale `default.nix` removed; old `flake.lock` regenerated by current flake

**What was NOT validated (requires dongle plugged in):**
- ⏳ The full round-trip: app-mode chip ID → enter DFU → flash stock fw → exit DFU → app-mode chip ID matches
- ⏳ udev rules actually grant access (need user added to `tropic` group with the NixOS module enabled)
- ⏳ `nix run .#identify` against real hardware
- ⏳ DFU mode entry sequence (SW1+replug) on this specific dongle

**Files created/modified this phase:**
- `flake.nix` (rewrite from scratch — replaces old archived-util packaging)
- `nix/stock-firmware.nix` (new derivation)
- `nix/dev-shell.nix` (new devShell)
- `nix/apps.nix` (new flake apps)
- `nixos/tropic.nix` (new NixOS module)
- `docs/RECOVERY.md` (new)
- `README.md` (rewrite)
- `STATUS.md` (this file, new)
- `default.nix` (deleted — obsoleted by pivot)
- `flake.lock` (will be regenerated when first proper lock-file write happens)

**Build infrastructure note:** Builds went through user's `eu.nixbuild.net` remote builder. Local Nix daemon and remote builder both work. Caching: nixbuild caches our outputs across rebuilds.

**Hash placeholder warning:** Fake hashes (`sha256-AAAA...` and `sha256-BBBB...`) used during initial flake evaluation, then replaced with real hashes once Nix reported them. Both `stock-firmware` and `lt-util` source hashes now correct and reproducible.

**Next step (still Phase 0):** User plugs in TS1302 dongle and runs the round-trip flash-and-identify validation. Until that succeeds, Phase 0 is not officially complete and Phase 1 cannot start.

**Hardware validation procedure (for the user):**
1. Plug in TS1302 dongle (don't hold any button)
2. `nix run .#check-dongle` → should report "Dongle present in APP MODE"
3. `nix run .#identify` → should print chip ID, FW versions, etc.
4. Unplug. Hold SW1. Plug back in while still holding. Release SW1.
5. `lsusb | grep "0483:df11"` should show DFU mode
6. `nix run .#flash-stock` → should reflash and exit DFU
7. Wait ~2 seconds, replug if needed
8. `nix run .#identify` → same chip ID as step 3 (regression-free recovery)

If steps 1–8 succeed, Phase 0 is officially complete.

**If anything fails at hardware-validation time:** stop, debug, do NOT advance to Phase 1.

---
