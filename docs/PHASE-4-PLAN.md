# Phase 4 Plan — FIDO2 stack port (stub backend)

> **Phase 4 goal (PROJECT.md §6):** SoloKeys-derived FIDO2 stack ported to STM32U535. HID interface advertises FIDO usage page (`0xF1D0`). `MakeCredential` / `GetAssertion` return cryptographically dummy responses. `fido2-token -L` lists the device. `fido2-token -I` returns plausible info. `libfido2` `MakeCredential` succeeds with stub.

## Locked decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | **Two separate HID interfaces** (lt-rpc on 0xFF00 + FIDO on 0xF1D0) | Cleaner than dual-collection. Different report descriptors, distinct `/dev/hidraw*`. STM32U535 has spare endpoints. |
| 2 | **Don't vendor SoloKeys' fido2/ wholesale** | SoloKeys' code is ~5k LOC including real crypto, attestation cert handling, ClientPIN. For Phase 4 stub we write ~500 LOC ourselves matching CTAP2 spec — derived patterns, not vendored code. Phase 5 may pull in selected SoloKeys logic for credential management. |
| 3 | **CBOR: hand-rolled encoder, tinycbor parser** | Encoder is a few hundred lines of obvious code; vendoring tinycbor (~3 files, ~2 KB) only saves work on the parser side. Decision: hand-roll both for now since CTAP2 inputs are small (≤1 KB) and well-bounded. Revisit if parser complexity grows. |
| 4 | **Stub signatures: real Ed25519 over a fixed keypair** | We already link trezor_crypto Ed25519 from Phase 3. A fixed-key signature passes any verifier the host runs against the public key we return in attestation. More honest than fixed bytes. |
| 5 | **No ClientPIN in Phase 4** | ClientPIN is Phase 5 (TROPIC01-backed via MAC-and-Destroy). Stub responds with `clientPin: false` in GetInfo. |
| 6 | **AAGUID: a fixed 16 B nixtropic-specific value** | Generated once, baked in. Per FIDO spec, must be unique per authenticator model. Use `0x6e69 7874 726f 7069 6300 0000 0000 0001` ("nixtropic" + version). |
| 7 | **No reset / discoverable-credential storage** | Stub doesn't persist anything. MakeCredential returns a stateless credential ID containing the encoded private key (not safe — but stub-explicit). Phase 5 stores in TROPIC01 R-mem. |
| 8 | **Re-use Phase 3 framing patterns but separate module** | `fido_hid/` module owns CTAPHID INIT/PING/MSG/CBOR + multi-channel CID. Don't entangle with `hid_rpc/` (lt-rpc). Patterns shared (BE16/BE32 helpers); state and tables separate. |

## Wire format (CTAPHID, FIDO interface)

64-byte HID reports under usage page `0xF1D0` (FIDO Alliance), usages `0x20` (data in) / `0x21` (data out).

**INIT packet:** identical layout to Phase 3 lt-rpc since lt-rpc was already CTAPHID-derived.
```
byte  0..3   CID       big-endian uint32, host-allocated
byte  4      CMD       0x80 | cmd_id  (top bit set = INIT)
byte  5..6   BCNT      big-endian uint16, total payload length
byte  7..63  DATA      up to 57 bytes
```

**CONT packet:**
```
byte  0..3   CID
byte  4      SEQ       0..0x7F (top bit clear)
byte  5..63  DATA      up to 59 bytes
```

**Channel IDs:**
- `0xFFFFFFFF` is the broadcast CID; only valid as destination of `CTAPHID_INIT`
- Server allocates fresh CIDs starting at `0x00000001`, monotonic
- INIT reply always echoes the 8-byte nonce in payload, plus new CID + version + caps

**Commands implemented in M2..M4:**
| Code | Name | Purpose |
|---|---|---|
| `0x86` | `CTAPHID_INIT` | Channel allocation, capabilities echo |
| `0x81` | `CTAPHID_PING` | Echo payload (used by `fido2-token -L` ping check) |
| `0x83` | `CTAPHID_MSG` | U2F APDU passthrough — return 0x6E00 (CLA not supported) |
| `0x10` | `CTAPHID_CBOR` | CTAP2 commands (sub-cmd in payload[0]) |
| `0x11` | `CTAPHID_CANCEL` | Abort current transaction |
| `0xBF` | `CTAPHID_ERROR` | Server-emitted error response |

**CTAP2 sub-commands inside `CTAPHID_CBOR`:**
| Code | Name | Phase |
|---|---|---|
| `0x01` | `authenticatorMakeCredential` | M4 (stub) |
| `0x02` | `authenticatorGetAssertion` | M4 (stub) |
| `0x04` | `authenticatorGetInfo` | M3 |
| `0x07` | `authenticatorReset` | not implemented (return CTAP2_ERR_OPERATION_DENIED) |

## Milestones

### M1 — Composite descriptor with second HID interface
- `tusb_config.h`: `CFG_TUD_HID = 2`
- `usb_descriptors.c`: two HID report descriptors (existing lt-rpc 0xFF00 + new FIDO 0xF1D0), two `TUD_HID_INOUT_DESCRIPTOR` instances (interfaces 2 + 3), new EP pair (`0x04 OUT` / `0x84 IN`)
- `hid_rpc/rpc.c`: gate `tud_hid_set_report_cb` on `instance == 0`
- M1 stub: a no-op `fido_hid_set_report_cb` for instance 1

**HW checkpoint:** `lsusb -v` shows two HID interfaces; `ls /dev/hidraw*` shows two devices for the dongle; `nix run .#validate-phase3` still 5/5 PASS (lt-rpc unaffected).

### M2 — CTAPHID INIT/PING + multi-channel CID allocator
- `firmware/src/fido_hid/ctaphid.{h,c}` — framing layer (assemble INIT+CONT, fragment response) split by CID
- `firmware/src/fido_hid/proto.h` — wire-format constants
- CID allocator: monotonic counter starting at 1, no recycling for now (cap at 32 channels)
- Implement `CTAPHID_INIT` (echo nonce, return new CID, version 2.0.0, capabilities = 0x05 = WINK | CBOR — but actually 0x04 = CBOR only since we don't support U2F; revisit), `CTAPHID_PING`, `CTAPHID_CANCEL`
- `CTAPHID_MSG` returns 0x6E00 status (CLA not supported)

**HW checkpoint:** `fido2-token -L` lists the device. A bespoke Python harness round-trips PING.

### M3 — CTAP2 GetInfo
- Minimal CBOR encoder (`fido_hid/cbor.{h,c}`) — int, bytes, string, array, map writers
- `fido_hid/ctap2.c` — `authenticatorGetInfo` returning the locked plan (versions, aaguid, options, transports)
- Hardcoded AAGUID per decision #6

**HW checkpoint:** `fido2-token -I /dev/hidrawN` returns our info.

### M4 — MakeCredential + GetAssertion stubs
- CBOR parser additions (just enough to extract clientDataHash, rpId, user info, pubKeyCredParams)
- `authenticatorMakeCredential`: build well-formed authenticatorData + COSE pubkey + Ed25519 self-attestation signature (using a fixed Ed25519 keypair in firmware, NOT TROPIC01)
- `authenticatorGetAssertion`: build well-formed authenticatorData + Ed25519 signature over (rpIdHash || authData || clientDataHash) using the same fixed keypair
- Credential ID = encoded slot index (currently always 0) + small magic; matched on assertion

**HW checkpoint:** `fido2-token -M -i creds.txt` MakeCredential succeeds; `libfido2`'s assertion API verifies the signature.

### M5 — validation app + docs + commit
- `tools/validate-phase4.sh`: combines `fido2-token -L`, `-I`, `-M`, `-G` checks
- `nix run .#validate-phase4` app
- `STATUS.md`: Phase 4 entry with M1..M5 commit table
- `PROJECT.md` §6: mark ✅
- Memory updates (`project_phase4_done.md`, MEMORY.md index)
- Each milestone committed separately for bisect-friendliness

## Risks

| Risk | Mitigation |
|---|---|
| TinyUSB multi-HID-instance config wrong | Validated by lt-rpc-still-works regression at M1 |
| libfido2 strict about CBOR canonical form | Hand-rolled encoder writes deterministic key order; verify with libfido2 source if M3 rejected |
| `fido2-token -L` enumeration order quirks | Linux libfido2 enumerates `/dev/hidraw*` matching FIDO usage page automatically; no extra setup |
| Linux requires udev rule for non-root hidraw access | Phase 0 udev module already covers our VID/PID broadly; add narrower hidraw rule if needed |
| Buffer overflow in CBOR decoding stub responses | M4 input bounds-check at every byte (review checklist) — same audit pattern as Phase 3 |
| Endpoint exhaustion on USB FS | U5 USB FS has 8 EP slots. Currently using 4 (CTRL + CDC notif + CDC data + HID lt-rpc). Adding HID FIDO uses 5. Plenty. |

## File layout (planned)

```
firmware/src/
├── fido_hid/                NEW
│   ├── proto.h              wire-format + status codes
│   ├── ctaphid.h            framing API
│   ├── ctaphid.c            INIT/PING/MSG/CBOR routing + CID allocator
│   ├── ctap2.h              CTAP2 dispatcher API
│   ├── ctap2.c              GetInfo + MakeCredential + GetAssertion stubs
│   ├── cbor.h               CBOR encoder/parser
│   └── cbor.c
├── hid_rpc/                 (existing — instance 0 only after M1)
└── usb/
    └── usb_descriptors.c    refactored for 2 HID instances

tools/
├── validate-phase4.sh       NEW
└── fido2_test.py            NEW — Python+fido2 library, used by validate
```
