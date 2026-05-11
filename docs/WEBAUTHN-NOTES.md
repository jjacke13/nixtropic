# nixtropic + WebAuthn — Field-by-Field Reference

> **Purpose:** Decode what relying parties (webauthn.io, real RPs) show about
> credentials registered against nixtropic. So we don't have to re-derive
> the same explanations every time someone asks.
> **Last updated:** 2026-05-11 (Phase 5 M2 mic-drop)

---

## 1. The credential ID format

nixtropic credentialIds are **18 bytes** with this layout:

```
byte    field
 [0]    version = 0x01
 [1]    slot index on TROPIC01 (0..31)
 [2..17] 16-byte random nonce from TROPIC01 TRNG
```

RPs see base64url-encoded form (e.g. `AQS57EtxK4UI7IuVwL1YNDlW`). To decode by hand:

```
base64url decode → first byte must be 0x01
                   second byte = slot index (also visible in firmware logs)
                   remaining 16 bytes = nonce (compared constant-time
                                              against R-mem on lookup)
```

Forgeability: a 128-bit nonce makes credId forgery infeasible (2^128 brute
force). The slot byte being adversary-visible is fine — knowing "credentials
exist in slots 0..N" leaks no secrets.

### Real-world examples

| credId (b64url) | Hex bytes 0..1 | Slot |
|---|---|---|
| `AQS57EtxK4UI7IuVwL1YNDlW` | `01 04` | 4 |
| `AQNld7LNhFz234m_-xEtvWSM` | `01 03` | 3 |

Use `base64 -d <<< ... | xxd` (or `python3 -c "import base64; print(base64.urlsafe_b64decode('...'+'==').hex())"`) to decode.

---

## 2. What webauthn.io's "Credentials for ..." panel shows

After registration, webauthn.io's session-stored credential entry shows:

### Description: `device-bound credential of unknown discoverability`

Two distinct concepts:

- **device-bound** = the credential is pinned to this specific TROPIC01 chip.
  Opposite is *synced passkey* (Apple iCloud Keychain, Google Password Manager
  replicating the private key across the user's devices). Ours is the more
  secure, less convenient kind — physical possession is required.

- **unknown discoverability** = webauthn.io can't determine whether this is a
  *discoverable* (a.k.a. *resident*) credential. Two contributing reasons:
  1. We advertise `rk: true` in `authenticatorGetInfo` — we DO support
     resident keys (credentials live in TROPIC01 R-mem, persistent).
  2. **We don't implement the `credProps` extension yet.** That's the
     mechanism RPs use to ask the authenticator "did you actually store
     this credential resident?" during MakeCredential. Without it, the
     RP guesses → "unknown".

  Reality: ours IS resident — slot N's metadata lives in R-mem slot N+1.
  See **§5 below** for the credProps follow-up plan.

### Transports: `["usb"]`

Straight from our `authenticatorGetInfo` response (CTAP2 key 9). Used by RPs
to hint UI: "Please insert your USB security key" vs "Tap your phone".

### Provider Information: `Name: (Unavailable)`

webauthn.io looks up the AAGUID against the **FIDO Alliance Metadata Service
(MDS)** at https://fidoalliance.org/metadata/ to get the manufacturer name
(e.g. "YubiKey 5C NFC"). Two reasons it shows "(Unavailable)":

1. webauthn.io's default `attestation: "none"` causes the browser to zero
   the AAGUID before forwarding (see next field).
2. Even with real AAGUID forwarded: we haven't registered nixtropic with the
   FIDO MDS (would require $25k/yr certification — not happening for an
   open-source firmware project). So an MDS lookup against our self-allocated
   AAGUID returns no match.

### AAGUID: `00000000-0000-0000-0000-000000000000`

**Our firmware sends `6e697874726f70696300000000000003`.** The user agent
(Firefox/Chrome/Brave) replaces it with 16 zero bytes before forwarding to
the RP. This is W3C-mandated behavior per WebAuthn §13.4.4:

> If the relying party did not request attestation, the user agent MUST
> replace authData.attestedCredentialData.aaguid with 16 zero bytes before
> delivering the assertion to the relying party.

To make webauthn.io display our real AAGUID:
1. On webauthn.io's **Advanced Settings**, set `Attestation` → **Direct**
2. Re-register
3. AAGUID field will now show `6e697874-726f-7069-6300-000000000003` (or `…-000000000002` if a Phase 5-vintage credential)
4. `Name: (Unavailable)` will still be (Unavailable) because of the MDS
   non-registration above

---

## 3. The nixtropic AAGUID — what it is, what it represents

```
6e 69 78 74 72 6f 70 69 63 00 00 00 00 00 00 0X
└─ "nixtropic" ────────────┘ └─ pad ─┘ └ version
```

- Bytes 0-8: ASCII `"nixtropic"` (recognizable in dumps; intentional)
- Bytes 9-14: zero padding
- Byte 15: version (currently `0x02`)

### Version history + bump policy

The trailing byte distinguishes **behaviorally-different** firmware versions
of the SAME hardware. Bump when relying parties would care about the difference:

| Version | Released | Trigger |
|---|---|---|
| 0x01 | Phase 4 (2026-05-11) | First nixtropic AAGUID. Stub firmware with embedded fixed Ed25519 keypair. *Never shipped publicly.* |
| 0x02 | Phase 5 M2..M5 (2026-05-11) | TROPIC01-backed per-credential keys + ClientPIN protocol v1 + MAC-and-Destroy retry counter + authenticatorReset (10 s window). Phase 5 closed. |
| 0x03 | Phase 6 (2026-05-11) | **Current.** Real SW1 user-presence button (PH3, debounced, sign-canary return) + LED state machine + Force-UV auto-enabled on first setPIN + `alwaysUv` advertised + authenticatorCredentialManagement (CTAP2 cmd 0x0A: getCredsMetadata, enumerateRPs Begin/Next, enumerateCredentials Begin/Next, deleteCredential) + Reset-with-SW1 gating (when state exists). R-mem schema bumped v2→v3 with magic `"NX5K"`→`"NX6K"`. Existing 0x02 credentials will NOT roam to 0x03 firmware — same trade-off Yubikey makes across firmware versions. |
| 0x04 | TBD: when behavior changes again | Phase 7 OpenPGP card via CCID would warrant a bump (the device gains a new wire-visible interface even though FIDO behavior is unchanged). credProtect / per-credential-UV-policy support (Phase 8) is borderline. |
| 0xFF | reserved for "unstable / development" | Do NOT use for ship builds. |

### Bumping rules (in order)

1. **Don't bump for backwards-compatible firmware fixes.** If a Phase 5 patch
   release fixes a CBOR parsing bug without changing the FIDO surface, AAGUID
   stays.
2. **Bump for any change a relying party can observe**:
   - New algorithms advertised in `authenticatorGetInfo` key 10
   - Changes in `options` map (rk, up, plat, clientPin, uv)
   - Changes in supported CTAP2 commands
   - Backwards-INCOMPATIBLE protocol changes (very rare)
3. **Document the bump in PROJECT.md §6** at the same time as the code change.
4. **Update `firmware/src/fido_hid/ctap2.c`'s `NIXTROPIC_AAGUID` constant**.
5. **Update this table** with the new version row.

### Is the AAGUID stable from now on?

Yes for the SAME firmware-feature-set:
- Same AAGUID across all bug-fix releases of Phase 5 M2.
- Same AAGUID after a Phase 5 M3 release IF the only change is internal (e.g.,
  ClientPIN's RAM counter without the MD limiter).
- Different AAGUID once M5 ships with full Reset + PIN-gated MakeCred (call
  that 0x03 or 0x04 — decide at ship time).

The AAGUID is **never** reused across hardware models. If we ever ship a
nixtropic-v2 device (e.g. on a different SoC), it gets a new AAGUID.

### Why not register with FIDO Alliance for an "official" AAGUID?

The FIDO Alliance MDS lookup gives the warm-fuzzy "Made by ACME Corp" label
to RPs. Costs ~$25k/yr in membership fees + certification. For an
open-source firmware project not selling product, the math doesn't work.

Tradeoff:
- (+) `MDS lookup → "nixtropic firmware (open source)"` would be cool
- (-) Cost prohibitive
- (-) Cert process incompatible with "anyone can rebuild from source"

Our path: self-allocated AAGUID, documented in this repo. Anyone reading the
authenticator's bytes sees `"nixtropic"` ASCII. RPs that care can look us up
manually. RPs that don't care — most consumer RPs — accept any device that
produces valid signatures.

---

## 4. Other webauthn.io / RP fields you might see

### "Credentials are stored for 24 hours"

webauthn.io's own policy — they GC test credentials after 24 h. **Our chip
still has the keypair persistently**; webauthn.io just stops accepting
authentication attempts because they delete their copy of the public key.

To "delete" a credential from our chip side: run `slots-erase <slot>` via
lt-rpc (debug command), or wait for `authenticatorReset` in Phase 5 M5.

### "signCount"

Increases monotonically across all authentications **from this device**
(shared counter, not per-credential). Backed by TROPIC01 hardware monotonic
counter 0. WebAuthn §6.1.1 allows shared counters explicitly. At 1 sig/sec
continuous, counter exhausts in ~136 years.

### authData byte layout

For reference when debugging:

```
[0..31]    rpIdHash (SHA-256 of rp.id)
[32]       flags:
             bit 0 (UP)  user-presence — always 1 on our device
             bit 2 (UV)  user-verified — 0 for now (M3+ will set when PIN OK)
             bit 6 (AT)  attested-credential-data present (MakeCred only)
             bit 7 (ED)  extensions present (when we add credProps etc.)
[33..36]   signCount (uint32_BE)
[37..]     attestedCredentialData (if AT bit set):
             [37..52]   AAGUID (16 B)
             [53..54]   credIdLen (uint16_BE)
             [55..]     credId (18 B for us)
             [+18..]    COSE_Key (46 B for Ed25519)
```

---

## 5. credProps extension — TODO follow-up

WebAuthn level 2 introduced the `credProps` extension which lets the
authenticator report whether the credential is resident/discoverable. Adding
it would change webauthn.io's display from "unknown discoverability" to
"discoverable credential".

**Implementation:** ~30 LOC in `ctap2_creds.c`:
1. In MakeCredential request parsing, watch for extensions map (CBOR key 6).
2. If the platform sent `{"credProps": true}` in extensions, echo it in
   authData with `rk: true` (we always store resident in M2+).
3. Flip the `ED` flag in authData flags byte to indicate extensions present.

**Why not in M2:** scope discipline — M2 was "swap credstore to TROPIC01".
credProps doesn't fix any threat or unlock new functionality, just changes
the RP's UX text. Tracked as follow-up.

**Schedule:** earliest Phase 5 M3 (already touching ctap2_creds.c for PIN-
gating). Could also defer to Phase 8 polish. Either is fine — not blocking.

---

## 6. Debugging an RP issue

When a relying party fails to register/authenticate, the diagnostic ladder:

1. **Is the device enumerated at all?** `lsusb | grep cafe:4001`
2. **Does libfido2 see it?** `fido2-token -L` (run as user, no sudo)
3. **Does GetInfo work?** `fido2-token -I /dev/hidrawN` — expect:
   - `aaguid: 6e697874726f70696300000000000003`
   - `options: rk, up, noplat, noclientPin`
   - `algorithms: eddsa, es256`
4. **Does MakeCred work as user?** `fido2-cred -M -i input.txt /dev/hidrawN eddsa`
   (see `docs/WEBAUTHN-NOTES.md` git history for the input.txt format)
5. **Does the browser see hidraw?** Check `chrome://device-log` /
   `about:webauthn`. Most likely issue: ACL on `/dev/hidrawN` not granting
   user access — see §7.
6. **Does the page request something we can't do?** Open browser dev tools
   → Network → look for the `navigator.credentials.create()` arguments.
   `userVerification: required` will fail us in M2 (no PIN). Set to
   `discouraged` on the test page.

---

## 7. Linux udev permission gotcha

The `nixos/tropic.nix` module covers `SUBSYSTEM="tty"` (CDC) and
`SUBSYSTEM="usb"` (top-level) for cafe:4001 but DOES NOT explicitly cover
`SUBSYSTEM="hidraw"`. Systemd's built-in hwdb auto-tags the FIDO HID
interface as `security-device` (because of the FIDO usage page 0xF1D0 in
the report descriptor), and logind grants ACL based on that tag. This
covers the common case, but if a browser ever can't access /dev/hidrawN,
the diagnostic is:

```
ls -la /dev/hidrawN
# Expect crw-rw----+ with ACL granting user access. If you see crw-------:

udevadm info /dev/hidrawN | grep TAGS
# Expect TAGS=:uaccess:seat:systemd:security-device:
# If security-device is missing, the FIDO HID descriptor isn't being
# recognized by udev's auto-rules; manually add a rule.
```

Temporary fix (volatile, until reboot):

```bash
sudo tee /run/udev/rules.d/99-nixtropic-hidraw.rules <<'EOF'
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="cafe", ATTRS{idProduct}=="4001", \
  TAG+="uaccess", MODE="0660"
EOF
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=hidraw
```

Permanent fix (Phase 8 polish): add the rule to `nixos/tropic.nix`.

---

## 8. Browser-specific notes

### Firefox / Linux — **works**

Default WebAuthn UI. Just works. Some RPs default to settings we can't meet
(`userVerification: required`); on those, relax via the RP's advanced
settings to `discouraged`.

### Brave / Chromium / Linux — **WebAuthn modal greys out our device**

`libfido2` and direct hidraw access from user space work fine. Brave's
internal WebAuthn UI (the OS-level credential picker) doesn't activate the
"Use your security key" option for our device. Investigation deferred to
Phase 8 polish. Workaround: use Firefox.

Suspected cause: Chrome/Chromium-based browsers' Linux FIDO HID detection
path differs from libfido2's — possibly checks systemd hwdb tags or a
hardcoded VID/PID list. Untested as of 2026-05-11.

### Safari / macOS — untested.
### Chrome / Windows — untested.

---

*End of WEBAUTHN-NOTES.md*
