# Phase 3 — Composite USB (CDC + HID) + lt-rpc-over-HID

> **Status:** Plan, 2026-05-10. Executes after Phase 2 (commits `c0edfb1` + `70eaa00` + `e04da71`).
> **Goal (per PROJECT.md §6):** Validate composite USB descriptors and HID-class enumeration. End state: OS sees `/dev/ttyACM*` AND `/dev/hidraw*`; `lt_ecc_eddsa_sign` round-trips over HID; signature verifies.

---

## Scope summary

Phase 3 adds three things on top of Phase 2:

1. **A second USB interface (HID raw, 64-byte reports)** alongside the existing CDC-ACM.
2. **A custom binary RPC protocol over HID** ("lt-rpc") — CTAPHID-style framing so we can re-use it for FIDO2 in Phase 4.
3. **libtropic on-chip activation** + L3 secure session (X25519 KX → AES-GCM via trezor_crypto CAL) + ECC operations.

What stays the same:
- Phase 2 CDC ASCII protocol is **unchanged**. lt-util continues to work against /dev/ttyACMN.
- Phase 1 `firmware/src/tropic/` work re-enters the build (was kept on disk, commented out in Phase 2).

---

## Milestones (commit boundaries)

Each milestone is a **separate commit** with HW-in-the-loop validation before the next begins.

### M1 — Composite descriptor (CDC + raw HID echo)

Risk surface: USB enumeration. Keep changes minimal and isolated.

- `tusb_config.h`: `CFG_TUD_HID = 1`, `CFG_TUD_HID_EP_BUFSIZE = 64`.
- `usb_descriptors.c`: extend the config descriptor to CDC + HID composite (IAD for CDC pair, single HID interface). Add HID report descriptor for **vendor-defined 64-byte IN/OUT** (no usage page; raw bytes).
- New file `firmware/src/hid_rpc/echo.c`: minimal `tud_hid_report_complete_cb` / `tud_hid_set_report_cb` that echoes received OUT reports back as IN reports. Just enough to validate enumeration.
- Update product string to `"nixtropic Phase 3"`.

**HW validation criteria:**
- `lsusb` shows VID:PID `cafe:4001` still. Config descriptor decodes cleanly (1 device, 3 interfaces total: CDC-comm, CDC-data, HID).
- `/dev/ttyACM*` AND `/dev/hidraw*` both appear after enumeration.
- Phase 2 regression: `nix run .#validate-phase2` still 5/5 PASS.
- Manual HID echo test: Python `hidapi` 64-byte write → readback matches.

### M2 — lt-rpc framing + PING + GET_RANDOM

Risk surface: framing bugs. Defer libtropic-on-chip to next milestone.

**Wire format (CTAPHID-derived, single channel):**

```
HID report = 64 bytes. No report ID.

INIT packet (first or only):
  byte 0..3   CID      0xCAFE0001 (fixed; multi-channel arrives with FIDO2 in Phase 4)
  byte 4      CMD      0x80 | cmd_id  (top bit set marks "INIT")
  byte 5..6   BCNT     total payload length across all packets (big-endian uint16)
  byte 7..63  DATA     up to 57 bytes of payload

CONT packet (continuation, if BCNT > 57):
  byte 0..3   CID      0xCAFE0001
  byte 4      SEQ      0..0x7F (top bit clear); SEQ=0 is the FIRST continuation
  byte 5..63  DATA     up to 59 bytes of payload

Response packets use the same shape (device → host IN).
```

**Commands (M2 subset):**

| ID   | Name           | Request payload | Response payload |
|------|----------------|-----------------|------------------|
| 0x01 | LT_RPC_PING    | arbitrary bytes (≤ 256 B)         | echo of request payload |
| 0x02 | LT_RPC_GET_RANDOM | 1 byte: N (1..32)              | N bytes of HW RNG (STM32 TRNG, no chip needed) |
| 0x3F | LT_RPC_ERROR   | n/a                                | 1 byte: error code (response only) |

**Firmware:**
- New `firmware/src/hid_rpc/rpc.{h,c}` — framing state machine + dispatch.
- New `firmware/src/hid_rpc/rpc_cmds.c` — PING + GET_RANDOM handlers.
- `main.c` adds `hid_rpc_init()` after `cdc_protocol_init()`.

**Host tool:**
- `tools/lt_rpc.py` — small Python (~150 LOC) using `hid` package. Functions: `ping(data)`, `get_random(n)`. Auto-detects device by VID:PID; falls back to `/dev/hidraw0`.

**HW validation:**
- `python tools/lt_rpc.py ping --bytes 32` round-trips.
- `python tools/lt_rpc.py random --n 32` returns 32 distinct-looking bytes.
- CDC still works in parallel.

### M3 — re-enable libtropic on chip + CHIP_ID over lt-rpc

Risk surface: re-introducing libtropic build into the firmware after Phase 2 stripped it. Should be uncomment-only.

- Uncomment libtropic block in `firmware/CMakeLists.txt`:
  - `LIBTROPIC_SOURCES`, foreach EXISTS check
  - `src/tropic/tropic.c` and `src/tropic/lt_crypto_stubs.c` re-added to `APP_SOURCES`
  - `${LIBTROPIC_SOURCES}` re-added to `APP_SOURCES`
  - `ACAB` and `LT_LOG_ENABLE_ERROR=1` re-enabled
  - libtropic include dirs re-added
  - libtropic warning-suppression `foreach` block re-enabled
- Refactor `firmware/src/tropic/tropic.c`:
  - Phase 1's `tropic_l2_sweep()` printed to UART. Phase 3 needs structured returns. Add `int tropic_chip_id_read(uint8_t out[128])` that wraps `lt_get_info_chip_id` and copies into caller's buffer. Keep `tropic_init()` as is.
- New RPC command:

| ID   | Name             | Request | Response |
|------|------------------|---------|----------|
| 0x03 | LT_RPC_CHIP_ID   | none    | 128 B chip_id |

- Python: `tools/lt_rpc.py chip_id` returns bytes, prints hex. Compare to Phase 0 baseline.

**HW validation:**
- `lt_rpc.py chip_id` returns byte-exact Phase 0 baseline.
- CDC + Phase 2 lt-util chip-info still PASS (regression).

### M4 — L3 secure session + ECC sign over lt-rpc

Risk surface: the biggest in Phase 3. New crypto vendor lib (~30 trezor_crypto files), ~20 KB of additional firmware code, X25519 + AES-GCM + SHA256 + HMAC operating in lockstep with the chip's matching crypto.

- Add libtropic CAL (`cal/trezor_crypto/`) to CMakeLists. Add vendor `trezor_crypto/aes/*.c`, `trezor_crypto/chacha20poly1305/*` (not needed but bundled), trim to the subset actually called:
  - `aes/aes_modes.c`, `aes/aescrypt.c`, `aes/aeskey.c`, `aes/aestab.c`, `aes/gf128mul.c`, `aes/aesgcm.c` for AES-GCM
  - `sha2.c`, `hmac.c` for SHA-256 + HMAC-SHA256
  - `ed25519-donna/curve25519-donna-32bit.c`, `ed25519-donna/ed25519-donna-impl-base.c` etc. for X25519
- Remove our Phase 1 stub file from build (`lt_crypto_stubs.c` no longer in APP_SOURCES — the CAL provides the real impls).
- `tropic_init()` adds a `lt_session_start(h, sh0pub_prod0, SH0, sh0priv_prod0)` call after `lt_init`.
- New RPC commands:

| ID   | Name                | Request                          | Response |
|------|---------------------|----------------------------------|----------|
| 0x04 | LT_RPC_ECC_GENERATE | 1 B slot + 1 B curve (0=Ed25519, 1=P256) | none (or pubkey 32 B if available without further L3 round-trip — verify in libtropic) |
| 0x05 | LT_RPC_ECC_SIGN     | 1 B slot + 32 B msg              | 64 B signature |
| 0x06 | LT_RPC_ECC_PUBKEY   | 1 B slot                         | 32 B pubkey |

- Python: `tools/lt_rpc.py sign-test` does generate → sign → verify locally using `cryptography` or `pynacl` Ed25519 verify. End-to-end pass = signature verifies.

**HW validation:**
- `lt_rpc.py sign-test` generates a key in slot 0, signs a random 32-byte challenge, verifies signature using host-side Ed25519. PASS.
- CDC + Phase 2 lt-util + Phase 3 chip_id still PASS (no regression).

### M5 — Polish: validate-phase3 app + STATUS/PROJECT/memory + commit

- `nix run .#validate-phase3` — runs `tools/lt_rpc.py` test suite (PING + RANDOM + CHIP_ID + SIGN) against the connected device.
- `nix run .#flash-and-validate-phase3` — DFU flash + settle + validate-phase3.
- `STATUS.md` Phase 3 entry with PASS log.
- `PROJECT.md` §6 Phase 3 marked ✅ COMPLETE with commit hash.
- Memory file `project_phase3_done.md` + index in `MEMORY.md`.
- Local commit (no push).

---

## Locked decisions (M1-M5)

| # | Decision | Why |
|---|---|---|
| 1 | **CTAPHID framing** (not custom) | Phase 4 (FIDO2) needs CTAPHID anyway. Build it now, reuse with channel multiplexing later. |
| 2 | **Single fixed channel `0xCAFE0001`** | M3 has one logical client. Real channel-init (CTAPHID_INIT 0x86) deferred to Phase 4. |
| 3 | **HID report descriptor: raw vendor-defined, no usage page** | Keeps Linux from auto-grabbing the device for HID-keyboard/mouse subsystems. `/dev/hidraw*` exposes raw 64-byte transfers. |
| 4 | **trezor_crypto CAL** for L3 (vs mbedtls) | Already in libtropic's `cal/trezor_crypto/`. No external dep churn. mbedtls v4 needs PSA Crypto API plumbing — overkill for our 25 KB software-crypto budget. |
| 5 | **Default sh0 pairing keys** (sh0pub_prod0 / sh0priv_prod0) | User's chip is ACAB production silicon (`TR01-C2P-T101`). PROJECT.md §5 confirms. |
| 6 | **No backward-compat shim for stub crypto** | When M4 lands, `lt_crypto_stubs.c` is dropped from build outright. CAL replaces it. |
| 7 | **Python (not Rust) host client** | 150 LOC, single file, no toolchain dep beyond `python3 -m pip install hidapi cryptography`. |
| 8 | **No multi-packet timeout** in M2 | Single-threaded host, sequential PING/RANDOM. Add CTAPHID's KEEPALIVE only when needed in Phase 4. |
| 9 | **No PIN protection in M4** | M4 just proves L3 + sign works. ClientPIN gating arrives in Phase 6. |
| 10 | **Slot 0 only for M4 ECC** | Single fixed slot; slot allocation policy = Phase 5. |
| 11 | **HW validation between every milestone**, not just at end | Per memory `feedback_phase_serial.md`. User flashes; I prepare clean diffs. |
| 12 | **No flash without explicit user permission** | PROJECT.md §11.8. Each M ends with "ready to flash" prompt. |

---

## File layout (post-M5)

```
firmware/src/
├── main.c                       (modified: hid_rpc_init in stage 8)
├── platform/                    (unchanged from Phase 2)
├── usb/
│   ├── tusb_config.h            (modified: HID enable + buf size)
│   ├── usb.c                    (unchanged)
│   ├── usb_descriptors.c        (modified: composite CDC+HID descriptor)
│   └── cdc_io.c                 (unchanged)
├── cdc_protocol/                (UNCHANGED — Phase 2 ASCII protocol preserved)
│   ├── parser.{h,c}, hex.{h,c}, protocol.{h,c}, cmd.{h,c}
├── tropic/                      (Phase 1 work, re-activated in M3)
│   ├── tropic.{h,c}             (refactor: add structured tropic_chip_id_read)
│   └── lt_crypto_stubs.c        (REMOVED in M4 — trezor_crypto CAL replaces)
└── hid_rpc/                     (NEW)
    ├── rpc.{h,c}                (framing state machine, dispatch)
    ├── rpc_cmds.c               (PING, GET_RANDOM, CHIP_ID, ECC_*)
    └── lt_rpc_proto.h           (wire-format constants shared with Python)

tools/
└── lt_rpc.py                    (NEW; ~250 LOC: framing + commands + sign-test)
```

---

## Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Composite descriptor breaks CDC enumeration on Linux | Medium | M1's HW validation is exactly this. If it breaks, the only Phase 2 file changed is `usb_descriptors.c` — diff is small and reversible. |
| `dcd_stm32_fsdev` EP allocation conflicts (we'll have 5 EPs: CTRL + CDC notif/in/out + HID in/out) | Low-Medium | STM32U535 PMA has plenty of room (1 KB PMA). EP numbers we'll pick: CDC notif=EP1, CDC data=EP2, HID=EP3. |
| trezor_crypto compile errors (large vendor lib, never built for STM32U5 in this repo) | Medium-High | Build M4 in isolation first. If size budget blows out, swap to subset (just aes+sha+x25519, no ed25519-donna). |
| libtropic L3 session_start hangs / fails on this chip | Medium | This was Phase 5's biggest unknown moved earlier. If it fails, diagnose via CDC log + lt_session_start return code. Fall back: just CHIP_ID over HID and defer sign to Phase 5. |
| Pairing key mismatch (eng vs prod) | Low | Memory + PROJECT.md confirm prod0 keys. ACAB silicon verified. |
| Flash size overflow (256 KB STM32U535 limit) | Low | Phase 2 firmware.bin = 35 KB. Headroom = 221 KB. Estimate: composite +1 KB, hid_rpc +3 KB, libtropic +8 KB, trezor_crypto subset +20 KB = ~67 KB. Within budget. |

---

## What "Phase 3 done" looks like

```
$ nix run .#validate-phase3
═══════════════════════════════════════════════════════════════
  Phase 3: lt-rpc-over-HID validation
═══════════════════════════════════════════════════════════════
[1/5] PING (32 B echo) ............ PASS
[2/5] GET_RANDOM (32 B entropy) ... PASS
[3/5] CHIP_ID (128 B baseline) .... PASS
[4/5] ECC generate (slot 0, Ed25519) PASS
[5/5] ECC sign + Ed25519 verify ... PASS

5/5 PASS — Phase 3 lt-rpc-over-HID validated.
CDC interface (Phase 2) still functional in parallel.
```

Plus: `nix run .#validate-phase2` still 5/5 (Phase 2 regression).

---

*End of PHASE-3-PLAN.md*
