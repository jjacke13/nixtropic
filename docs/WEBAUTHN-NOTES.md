# WebAuthn reference

What relying parties see when you register a credential with nixtropic.
Decoders for the AAGUID, credential ID format, signCount, authData
layout, plus the host-side gotchas that surface in browser UIs.

## AAGUID

```
6e 69 78 74 72 6f 70 69 63 00 00 00 00 00 00 03
└─── "nixtropic" ───────┘ └─ pad ─┘ └─ version
```

Self-allocated.  Not FIDO MDS-registered ($25k/yr not viable for an
open-source project).  Trailing byte = capability-set version (currently
`0x03`).

Why most RPs show `Provider: (Unavailable)`: they look up the AAGUID
against the FIDO Alliance Metadata Service, which doesn't know us.

### Bump policy

Bump the trailing byte when a relying party can observe a behaviour
change:

- algorithms advertised in `authenticatorGetInfo` change
- `options` map flags change (`rk`, `up`, `uv`, `clientPin`, `alwaysUv`)
- new CTAP2 commands supported
- backwards-incompatible protocol changes

Don't bump for internal fixes that aren't RP-visible.  Adding the OpenPGP
card surface didn't bump it (FIDO behaviour unchanged).

When you bump, update `firmware/src/fido_hid/ctap2.c`'s
`NIXTROPIC_AAGUID` constant in the same change.

## Credential ID format

18 bytes:

```
byte    field
 [0]    version = 0x01
 [1]    ECC slot index (0..28)     — slots 29..31 are reserved for OpenPGP
 [2..17] 16 B nonce (TROPIC01 TRNG)
```

RPs see it base64url-encoded.  Decode manually with:

```bash
python3 -c "import base64,sys; print(base64.urlsafe_b64decode(sys.argv[1]+'==').hex())" "$CRED_ID"
```

Forgeability: 128-bit nonce → 2^128 brute force.  Slot byte is
adversary-visible but leaks no secrets.

## What webauthn.io shows

| Field | Value | Why |
|---|---|---|
| Description | `device-bound credential of unknown discoverability` | We're device-bound (real chip, no sync).  "unknown" because we don't implement the `credProps` extension yet — see `docs/BACKLOG.md §2.1`. |
| Transports | `["usb"]` | From `authenticatorGetInfo` key 9. |
| Provider | `(Unavailable)` | Not in FIDO MDS — see above. |
| AAGUID | all-zeros UNLESS `Attestation: Direct` set | Per W3C WebAuthn §13.4.4 the user-agent zeroes the AAGUID when attestation is `none` (webauthn.io's default). |

### Make webauthn.io show the real AAGUID

1. Advanced Settings → Attestation → **Direct**
2. Re-register
3. AAGUID shows `6e697874-726f-7069-6300-000000000003`

## authData byte layout

For debugging:

```
[0..31]  rpIdHash (SHA-256 of rp.id)
[32]     flags
            bit 0 (UP) user-presence (always 1)
            bit 2 (UV) user-verified (1 when PIN OK)
            bit 6 (AT) attestedCredentialData present
            bit 7 (ED) extensions present
[33..36] signCount (uint32 BE)
[37..]   attestedCredentialData (AT set):
            [37..52]   AAGUID (16 B)
            [53..54]   credIdLen (uint16 BE) = 18
            [55..72]   credId (18 B)
            [73..118]  COSE_Key (46 B for Ed25519)
```

`signCount` is backed by TROPIC01 hardware monotonic counter 0 (single
shared counter, not per-credential — WebAuthn §6.1.1 allows this).
Exhausts after ~136 years at 1 sig/sec continuous.

## GetInfo response

`fido2-token -I /dev/hidrawN` should report:

- `aaguid: 6e697874726f70696300000000000003`
- `options: rk, up, plat=false, alwaysUv, credMgmt, clientPin, credentialMgmtPreview` — `alwaysUv` is dynamic (true once a PIN is set)
- `algorithms: eddsa, es256`
- `pin protocols: 1`

## Browser compatibility

| Browser / OS | Works? | Notes |
|---|---|---|
| Firefox / Linux | ✅ | Default WebAuthn UI.  Just works. |
| Chrome / Linux | ⚠ | Greyed out in WebAuthn modal — tracked in `docs/BACKLOG.md §2.2`.  Suspected Chromium-side FIDO HID detection mismatch. |
| Brave / Linux | ⚠ | Same as Chrome (Chromium-based). |
| Safari / macOS | ? | Untested. |
| Chrome / Windows | ? | Untested. |

## Linux udev gotcha

`nixos/tropic.nix` covers `tty` + `usb` subsystems for `cafe:4001` but
not `hidraw` explicitly.  systemd's built-in hwdb auto-tags FIDO HID
interfaces as `security-device` (because of usage page 0xF1D0 in the
report descriptor), and logind grants user ACL based on that tag — so
the common case works without an explicit rule.

If a browser ever can't access `/dev/hidrawN`:

```bash
ls -la /dev/hidrawN
# Want:  crw-rw----+    (ACL grants your user)

udevadm info /dev/hidrawN | grep TAGS
# Want:  TAGS=:uaccess:seat:systemd:security-device:
```

If `security-device` is missing, drop a temporary udev rule:

```bash
sudo tee /run/udev/rules.d/99-nixtropic-hidraw.rules <<'EOF'
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="cafe", ATTRS{idProduct}=="4001", \
  TAG+="uaccess", MODE="0660"
EOF
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=hidraw
```

Permanent fix tracked in `docs/BACKLOG.md §2.3`.

## RP debugging ladder

When an RP fails to register or authenticate, work down this list:

1. **Enumerated?** `lsusb | grep cafe:4001`
2. **libfido2 sees it?** `fido2-token -L`
3. **GetInfo works?** `fido2-token -I /dev/hidrawN` — fields above
4. **Browser request shape?** Dev-tools → Network → look at the
   `navigator.credentials.create()` args.  Some RPs default to
   `userVerification: required`; if you haven't set a PIN, set it to
   `discouraged` (RP-side setting) or set a PIN on the device first.
5. **Browser-side logs:** `chrome://device-log` for Chromium-based,
   Firefox `about:webauthn` for Firefox.
