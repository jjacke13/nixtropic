# Card setup

The settings a user changes on the dongle: PINs, touch policy, key generation and
resets. Everything here uses standard tools (`gpg`, `fido2-token`) and the standard
FIDO2 and OpenPGP card commands. None of it touches the TROPIC01 configuration, its
pairing keys, its firmware or the STM32's protection settings.

Set up the host first: [Linux setup](linux-setup.md).

## Factory defaults

| | Setting | Default |
|---|---|---|
| OpenPGP | User PIN (PW1) | `123456` — 6 to 64 bytes |
| | Admin PIN (PW3) | `12345678` — 8 to 64 bytes |
| | Reset Code | not set — 8 to 64 bytes |
| | Tries per PIN | 3 |
| | Keys | none |
| | Touch (UIF) | on for every key operation |
| | Signature PIN | not forced: PW1 stays verified until unplug |
| FIDO2 | PIN | not set — 4 to 63 bytes |
| | Tries | 8 in total, at most 3 wrong per plug-in |
| | `alwaysUv` | off |
| | Credentials | none |

!!! warning "Change the default OpenPGP PINs first"
    Anyone who knows the defaults can use a card that still has them.

## OpenPGP card

All commands run inside `gpg --card-edit`, after `admin`.

### PINs

```text
gpg/card> admin
gpg/card> passwd
1 - change PIN            # PW1, used for signing, decryption and SSH
2 - unblock PIN           # new PW1, authorised by the Admin PIN
3 - change Admin PIN      # PW3
4 - set the Reset Code
```

Do 3, then 1. Set a Reset Code (4) if you want to unblock PW1 without the Admin PIN:
the separate `unblock` command at the `gpg/card>` prompt (no `admin` needed) sets a new
PW1 with the Reset Code. PIN lengths count bytes, so a non-ASCII character counts more
than once.

The PIN retry limit is enforced by the TROPIC01 chip's MAC-and-Destroy function, not
by a counter in the firmware: each attempt consumes chip state that only the correct
PIN restores. Three wrong PW1 entries block PW1; three wrong PW3 entries block PW3.

!!! danger "Unblocking PW1 destroys the decryption key"
    The decryption key is stored encrypted under a key derived from PW1 (see
    [security model](security.md)). **Changing** PW1 keeps it. **Unblocking** or
    resetting PW1 (with the Reset Code or the Admin PIN) cannot recover it, so the
    card erases it: mail encrypted to that key can no longer be decrypted on this card.
    Signing and authentication keys are kept. Generate a new encryption key
    afterwards. This differs from a YubiKey, where the Admin PIN only resets the
    counter.

### Cardholder data

```text
gpg/card> name      # cardholder name
gpg/card> lang      # language preference
gpg/card> salutation
```

The URL and login data objects are not supported.

### Signature PIN (`forcesig`)

```text
gpg/card> forcesig
```

Toggles between "PIN once per plug-in" (default) and "PIN for every signature".
Decryption and SSH authentication always use the PW1 verification of the current
plug-in.

### Touch policy (`uif`)

```text
gpg/card> uif 1 on          # 1 = signature, 2 = decryption, 3 = authentication
gpg/card> uif 1 off
gpg/card> uif 1 permanent
```

The card has **one** touch flag for all three keys: setting it through any key sets
it for all. When on, every signature, decryption and SSH authentication waits up to
15 s for a press of SW1 (the LED blinks). `permanent` cannot be switched off again;
only a factory reset clears it.

Needs v0.3.2 or later: older firmware did not announce the button, and gpg refused
`uif` as not supported.

### Generate keys

```text
gpg/card> generate
Make off-card backup of encryption key? (Y/n) n
```

gpg asks for PW1, then the Admin PIN. Answer **n** to the backup question: the card
generates the keys itself and offers no backup. The algorithms are fixed:

| Key | Algorithm | Where it lives |
|---|---|---|
| Signature | Ed25519 | TROPIC01 key slot, never leaves the chip |
| Decryption | Curve25519 (X25519) | generated on the STM32, stored sealed under PW1 |
| Authentication | Ed25519 | TROPIC01 key slot, never leaves the chip |

Importing keys made elsewhere (`keytocard`) is not supported; see the
[roadmap](roadmap.md).

### Factory reset

```text
gpg/card> factory-reset
```

Erases all keys, PINs and cardholder data and restores the defaults. It needs no PIN:
gpg first blocks PW1 and the Admin PIN with wrong attempts, then terminates and
re-activates the card. This is the way back when the Admin PIN is forgotten.

## FIDO2

Find the device path first:

```bash
fido2-token -L
# /dev/hidraw5: vendor=0xcafe, product=0x4001 (nixtropic nixtropic)
```

| Task | Command |
|---|---|
| Set a PIN | `fido2-token -S /dev/hidrawN` |
| Change the PIN | `fido2-token -C /dev/hidrawN` |
| `alwaysUv` on / off | `fido2-token -S -u /dev/hidrawN` / `fido2-token -D -u /dev/hidrawN` |
| Show device info | `fido2-token -I /dev/hidrawN` |
| List discoverable credentials | `fido2-token -L -r /dev/hidrawN` |
| Delete a credential | `fido2-token -D -i <credential-id> /dev/hidrawN` |

Setting the first PIN also switches `alwaysUv` on, so every login then asks for the
PIN. Switch it off with `fido2-token -D -u` if you want sites to decide. Every
registration and login waits for a press of SW1.

After 8 wrong PINs in total the PIN is blocked and only a reset helps. After 3 wrong
PINs in one plug-in, unplug and replug to continue.

### FIDO reset

A reset erases every FIDO credential and the PIN. It works only within **10 seconds
of plugging in**, and it always asks for a press of SW1:

```bash
fido2-token -R /dev/hidrawN      # replug first, then run within 10 s; press SW1 when the LED blinks
```

The window and the press stop software on the computer from wiping the dongle at an
arbitrary moment. They do not stop someone who holds the dongle: replugging opens the
window again.

## What the card does not do

| Not supported | Why |
|---|---|
| RSA keys | TROPIC01 has no RSA; ECC only |
| Key import (`keytocard`) | not implemented yet |
| Per-key touch policy, cached touch | one global flag today ([backlog](backlog.md)) |
| KDF-DO, URL and login DOs, private DOs | not implemented |
| FIDO `hmac-secret`, `credProtect`, PIN protocol 2 | not implemented; GetInfo reports `FIDO_2_0` honestly |
| FIDO attestation | `none` format; the AAGUID is self-assigned ([WebAuthn notes](webauthn.md)) |
