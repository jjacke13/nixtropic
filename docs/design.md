# Design

## Principles

1. **Keys stay in the secure element where the chip allows it.** Signing keys are
   generated and used inside TROPIC01 key slots. Where the chip offers no operation
   (X25519 decryption), the key is computed on the STM32 and stored sealed, and the
   documentation says so.
2. **The chip enforces PIN limits.** Retry limits come from TROPIC01's
   MAC-and-Destroy function, not from a counter in the firmware: a guess consumes chip
   state that only the correct PIN restores.
3. **Fail closed.** An empty read never proves a fresh device. A write counts only
   after it reads back. An object whose state is uncertain refuses to serve until the
   next boot decides.
4. **Never replay a chip command.** After an ambiguous error the command may have run
   on the chip; the firmware reports the error and re-opens the session instead of
   retrying.
5. **Small release surface.** The release build exposes FIDO2 and the OpenPGP card,
   nothing else. Debug interfaces are compiled out, and a build check proves it.
6. **Say only what is true.** GetInfo announces `FIDO_2_0` because the CTAP 2.1
   features required for `FIDO_2_1` are not all there. The docs list what is missing.
7. **Written against the specifications.** CTAP 2.1, WebAuthn and OpenPGP card 3.4.1
   are implemented from the specs; other projects serve only as cross-checks.
8. **Reproducible.** Every input is pinned; `nix build` produces the same firmware
   from the same commit.
9. **No irreversible chip operations in normal code.** The firmware never writes the
   chip's configuration, pairing keys or I-config, and never updates the chip
   firmware.
10. **Tests with outside references.** Expected values come from specifications,
    independent implementations and real clients (gpg, libfido2, browsers), not from
    the code under test. See [testing](testing.md).

## PINs: MAC-and-Destroy

TROPIC01 has 128 MAC-and-Destroy (M&D) slots. An M&D call sends 32 bytes to a slot
and returns 32 bytes computed by the chip from the input and the slot's hidden state;
the call also **replaces** that state with a new one derived from the input. The chip
does not know what a PIN is: the protocol built on top decides whether a PIN was
right. nixtropic implements the scheme of Tropic Square's PIN verification application
note (ODN_TR01_app_002), with HMAC-SHA256 as the KDF.

Notation, exactly as implemented (`firmware/src/tropic/pin_md_kernel.c`):

| Symbol | Value |
|---|---|
| `m` | PIN material: OpenPGP `SHA-256(PIN)` (32 B); FIDO the CTAP `pinHash`, `LEFT(SHA-256(PIN), 16)` (16 B) |
| `s` | 32-byte secret from the TROPIC01 TRNG; a PIN change keeps it, a reset makes a new one |
| `t, u, k` | `HMAC-SHA256(s, 0x00)`, `(s, 0x01)`, `(s, 0x02)`: one-byte labels |
| `v` | `HMAC-SHA256(32 zero bytes, m)` |
| `c_i` | `s ⊕ HMAC-SHA256(w_i, m)`, stored per slot together with `t` |

```mermaid
sequenceDiagram
  participant F as Firmware (STM32)
  participant C as TROPIC01
  Note over F: setup: fresh s, derive t, u, k
  loop each slot i of the PIN's range
    F->>C: M&D(slot i, u)
    F->>C: M&D(slot i, v)
    C-->>F: w_i
    F->>C: M&D(slot i, u)
    Note over F: c_i = s ⊕ HMAC(w_i, m)
  end
  Note over F: commit record {c_i, t, next = 0}
  Note over F: verify(m'): commit next+1 first (the attempt is reserved)
  F->>C: M&D(slot next, v' = HMAC(0³², m'))
  C-->>F: w'
  Note over F: s' = c_next ⊕ HMAC(w', m'); correct iff HMAC(s', 0x00) = t
  alt correct
    Note over F: u' = HMAC(s', 0x01)
    F->>C: M&D(slot j, u') for every slot j (re-arm)
    Note over F: commit next = 0; k = HMAC(s', 0x02) available
  else wrong
    Note over F: slot "next" was re-keyed by v' and no longer yields s
  end
```

Properties:

- A wrong guess changes the slot's state; only `u`, which needs `s`, which needs the
  right PIN, restores it. The number of guesses that can be evaluated is bounded by
  intact slots, whatever the firmware's record says.
- Nothing stored lets anyone test a PIN offline: no PIN hash is kept, and the check
  value `t` is useful only together with the chip’s slots.
- `k = HMAC(s, 2)` exists only after a correct PIN. M5 derives the key that seals the
  OpenPGP decryption key from it ([security](security.md#the-openpgp-decryption-key)).
- A PIN change keeps `s` (same `k`); a reset creates a fresh `s`.
- Ranges A/B let a PIN change commit in one step: the new binding is written to the
  unused range and committed before the old range is retired, so an interruption leaves
  either the old or the new PIN working (except the last-try case in the
  [security model](security.md#persistent-state-under-faults)). A change that reports an
  error may already have committed; the next boot finishes the retirement.

## Decisions

The numbered decisions from the project's history; code comments refer to the
numbers.

| # | Decision | Rationale |
|---|---|---|
| 1 | **C** | libtropic, the ST HAL and TinyUSB are C. The sensitive crypto runs on TROPIC01. |
| 2 | **OpenPGP card over USB CCID, not PIV** | gpg covers signing, decryption and SSH. PIV is on the [backlog](backlog.md). |
| 3 | **SW1 is the user-presence button and the BOOT0 strap** | The board has one button. BOOT0 is sampled only at reset; afterwards PH3 is a normal input. Holding SW1 while plugging in enters DFU. |
| 4 | **TinyUSB**, with the STM32U545 board support adapted to the U535 | Same USB full-speed controller. |
| 5 | **FIDO2 written against CTAP 2.1** | SoloKeys and CanoKey only as cross-checks; no vendored FIDO code. |
| 6 | **OpenPGP card written against the 3.4.1 specification** | Same approach; no Gnuk or CanoKey code. |
| 7 | **trezor-crypto as the software crypto library** | libtropic already links it for its session; one library for SHA-256, HMAC, AES-GCM, X25519, Ed25519, P-256. |
| 8 | **CMake + CMSIS + ST HAL; nixpkgs' Arm toolchain** | Arm GNU 15.2 since nixos-26.05; the dev shell uses the same compiler. |
| 9 | **libtropic's production pairing key `sh0_prod0`** | The dongle has production silicon `TR01-C2P-T101`. This key is public development material ([security](security.md)). An engineering-sample switch described in early docs was never implemented. |
| 10 | *(superseded)* Documentation for AI agents first | Since v0.3.0 the docs are written for people; agent instructions live outside the published docs. |
| 11 | **ECC only, no RSA** | TROPIC01 has no RSA, and software RSA does not fit the flash budget. |
| 12 | **One release firmware with both FIDO2 and OpenPGP** | The CCID interface is always present; FIDO-only users can ignore it. |
| 13 | **Fixed slot allocation** | ECC 0–28 FIDO, 29/31 OpenPGP signature/authentication, 30 reserved. Full map in [architecture](architecture.md#persistent-state). |
| 14 | **WebAuthn attestation format `none`** | The AAGUID is self-assigned, so self-attestation proves nothing, and some servers cannot verify Ed25519 attestation. |
| 15 | **TROPIC01 laser fault-injection advisory acknowledged; no mitigation shipped** | Advisory `ODR_TR01_SA_2026012900` affects this part. Its mitigations (restricting maintenance mode, a controlled update procedure) need chip configuration writes, which v0.3.0 does not do. See [security](security.md#physical-attacks-on-the-chip). |
| 16 | **Release / debug build split** | Release: FIDO2 + CCID only. Debug adds the log console and lt-rpc. The stock-compatible SPI passthrough was removed: the chip accepts a new request while chip-select stays low, so no filter could keep maintenance commands out. |
| 17 | **Chip errors drop the session; commands are never replayed** | Only results the chip returned inside the session keep it. Anything else aborts it and the next call re-handshakes. An ambiguous M&D call counts as an attempt. |
| 18 | **USB callbacks never run requests; one request at a time** | TinyUSB re-arms an endpoint only after its callback returns, and a touch wait pumps the USB stack. Requests run from the main loop; during a touch wait others are answered busy or held. |
| 19 | **FIDO2 surface = FIDO_2_0 + the CTAP 2.1 parts implemented** | EdDSA and ES256; options `rk`, `credMgmt`, `authnrCfg`, `pinUvAuthToken`, `alwaysUv`, `makeCredUvNotRqd`. Permission tokens bound to an RP; a credential signs only for its RP; the signature counter is reserved before signing. |
| 20 | **Persistent state in mirrored record pairs; the M&D binding is the only PIN state** | Tolerates one interrupted write or one damaged slot. No software PIN check, no PIN hash, no retry mirror. |
| 21 | **USB starts after the boot stages; CCID listens again right after processing** | A host that talks to a device that cannot answer yet gives up on it. |
| 22 | **The OpenPGP decryption key is stored sealed under a key derived from PW1** | TROPIC01 has no X25519 for user keys. AES-256-GCM under KEK = HMAC(k, label); a PW1 change keeps it, a PW1 reset destroys it. |

The full reasoning, reviews and test evidence behind decisions 15–22 are in the
[Phase 9 design documents](https://github.com/jjacke13/nixtropic/tree/main/docs/history).
