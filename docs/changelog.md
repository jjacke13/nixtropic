# Changelog

## v0.3.1 — October 2026

FIDO2 on Windows with a PIN. A bug-fix release on top of v0.3.0.

### Upgrading from v0.3.0

Flash over v0.3.0; nothing else to do. The storage layout is unchanged, so FIDO2
credentials, the FIDO2 PIN and the OpenPGP keys stay. (From v0.2, follow the v0.3.0
steps below.)

### Fixes

- **CTAPHID KEEPALIVE.** While a FIDO2 request runs, the dongle now sends KEEPALIVE on
  the request's channel: PROCESSING between chip operations, UPNEEDED while it waits
  for SW1 ([CTAP 2.2 §11.2.9.1.7](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#usb-hid-keepalive)).
  Windows no longer abandons the PIN token (2.6 s) or a PIN change (6.6 s):
  registration, login, PIN change in Settings, a slow touch and Cancel all work
  ([Windows](windows.md)). The longest gap is about 250 ms, in the PIN operations;
  see [testing](testing.md#keepalive-timing).
- **Channel resync during a request.** A CTAPHID INIT on the busy channel now abandons
  the running request as CTAP requires (§11.2.9.1.3); its answer is dropped and the
  INIT is answered.
- **CANCEL before the touch wait.** A CANCEL that arrives while a request is still
  working, before it waits for SW1, now ends the wait at once with
  `CTAP2_ERR_KEEPALIVE_CANCEL`; before, it was lost.
- One-packet replies (INIT, errors) are queued when the IN endpoint is busy instead of
  dropped.
- Debug build: the lt-rpc interface answers BUSY while a FIDO2 request runs, so it
  never enters the chip library in the middle of one.

### Documentation

- [Windows](windows.md): v0.3.1 results, the alwaysUv-after-reset note.
- [References](references.md#protocols): which specification each USB interface
  follows, with links: CTAP 2.2 for the HID transport, CTAP 2.1 for the commands,
  OpenPGP card 3.4.1, CCID 1.1, ISO/IEC 7816-4.

### Sizes

Release `firmware.bin` 223 364 B, debug 229 776 B.

## v0.3.0 — October 2026

Phase 9: hardening. A development release, like v0.2; see [status](status.md) for what
it is and is not.

### Upgrading

!!! danger "Your keys and credentials do not survive this upgrade"
    The persistent storage layout changed and is not migrated. Prepare first: a second
    FIDO2 authenticator or recovery codes for every site, and a plan for your OpenPGP
    keys (their private parts cannot be exported). See
    [flashing](flashing.md).

After flashing v0.3.0 over v0.2 or an earlier v0.3 build:

1. **FIDO2 reset.** Until then FIDO answers only GetInfo and Reset. Replug, then within
   10 seconds run `fido2-token -R /dev/hidrawN` and press SW1.
2. **OpenPGP reset.** Until then the card reads as damaged (`gpg --card-status` fails;
   GET DATA answers `6F00`) and accepts only SELECT, VERIFY of the Admin PIN, and
   TERMINATE. Reset it with the standard TERMINATE DF + ACTIVATE FILE commands.
   These erase the selected card, so first find the nixtropic reader's number:

    ```bash
    opensc-tool -l          # note the number N of the "nixtropic" reader
    ```

    Card from **v0.2**:

    ```bash
    opensc-tool -r N -s 00A4040006D27600012401 -s 00E60000 -s 00440000
    ```

    Card from an **earlier v0.3 build**: verify your current Admin PIN first (VERIFY
    `00 20 00 83`, then the PIN's length in bytes and the PIN as hex). The PIN appears
    briefly in the process list.

    ```bash
    read -rs PW3
    LC=$(printf '%02X' "$(printf '%s' "$PW3" | wc -c)")
    HEX=$(printf '%s' "$PW3" | od -An -tx1 | tr -d ' \n')
    opensc-tool -r N -s 00A4040006D27600012401 -s "00200083${LC}${HEX}" -s 00E60000 -s 00440000
    unset PW3 HEX
    ```

    gpg's `factory-reset` sends the same commands but was not tested against the old
    layouts.

3. Set new PINs and generate new keys: [card setup](card-setup.md).

### Security

- **Release / debug split (M1).** The release build exposes only FIDO2 HID and the
  OpenPGP CCID interface. The USB serial SPI passthrough and the lt-rpc vendor
  interface are gone from it; the passthrough is gone from both builds.
- **Chip calls (M2).** Real results for erase operations; an error the chip did not
  return inside the session (transport, framing, unknown result) drops the session, and
  no command is ever replayed; the P-256 blinding uses the STM32 TRNG.
- **FIDO2 (M3).** Requests validated before parsing; credentials bound to their RP;
  real discoverable credentials; the signature counter reserved before signing;
  permission tokens (ClientPIN `0x09`); `authenticatorConfig` (`toggleAlwaysUv`);
  GetInfo reports only what exists (`FIDO_2_0`). ES256 credentials next to EdDSA (M3b).
- **PINs and state (M4).** Settings and PINs stored as mirrored record pairs; one power
  cut, lost reply or damaged slot never grants access or rolls back an acknowledged
  change (availability limits in the [security model](security.md#persistent-state-under-faults)). All PINs are
  MAC-and-Destroy bindings: no PIN hash anywhere, no software fallback. OpenPGP PW1 for
  signing (81) and for decryption/authentication (82) are separate; verification ends
  on card reset, another application, or a PIN change; DO C4 has its specified
  meaning.
- **Decryption key (M5).** The OpenPGP X25519 key is stored sealed with AES-256-GCM
  under a key derived from the PW1 binding.

### Changes in behaviour

- Resetting PW1 with the Reset Code or the Admin PIN **destroys the decryption key**; a
  PW1 change keeps it.
- Generating the decryption key needs a verified PW1 in addition to the Admin PIN
  (`6982` otherwise). gpg verifies PW1 first and works unchanged.
- USB starts only after the chip and FIDO state are ready, so the dongle appears on the
  bus a little later than v0.2.
- An OpenPGP PIN verification takes about 1.4 s (mirrored record writes).
- `alwaysUv` is set with `fido2-token -S -u` / `-D -u`, not a vendor command.

### Documentation

- New documentation site built from `docs/`: flashing (with and without Nix), Linux
  setup, card setup, architecture, hardware, design, security model, testing.
- Earlier documents corrected (secure-session protocol, data slot sizes, counters,
  MAC-and-Destroy, alarm mode, chip configuration procedure, STM32 facts); see
  [hardware](hardware.md#corrections-to-earlier-documentation).
- `PROJECT.md`, `STATUS.md`, `TROPIC01.md`, `research/` and the phase plans moved to
  `docs/history/` as a frozen record. `docs/UBUNTU.md` became
  [flashing](flashing.md) and [Linux setup](linux-setup.md); `docs/RECOVERY.md`,
  `docs/WEBAUTHN-NOTES.md` and `docs/BACKLOG.md` became lowercase pages.

### Known issues

- **FIDO2 on Windows with a PIN set fails.** The dongle sends no CTAPHID KEEPALIVE while
  it works, and Windows abandons a silent request after a few seconds; the PIN token
  (about 2.6 s) and a PIN change (about 6.6 s) take longer since the crash-safe PIN
  storage. Registration then loops, and a PIN change reports an error although it
  completed. The OpenPGP card works on Windows. Fixed in v0.3.1. Linux clients
  are not affected.

### Sizes

Release `firmware.bin` 223 188 B (85 % of flash), debug 229 072 B.

## v0.2 — 24 May 2026

Phase 8: OpenPGP PIN counters on MAC-and-Destroy, credProps, hidraw udev rule,
OpenPGP touch policy, attestation format `none` for RP compatibility (Proton), Windows
check.

## v0.1 — 14 May 2026

First daily-driver release: FIDO2 / WebAuthn with PIN and touch, OpenPGP card with
Ed25519 signing, X25519 decryption and SSH, reproducible Nix builds.
