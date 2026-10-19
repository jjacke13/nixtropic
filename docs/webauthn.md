# WebAuthn notes

What a relying party (a website) sees when you register nixtropic, and how to read it.

## AAGUID

```text
6e 69 78 74 72 6f 70 69 63 00 00 00 00 00 00 04
└──────── "nixtropic" ───────┘ └── zero ──┘ └ version
```

Self-assigned: registering with the FIDO Alliance Metadata Service is not affordable
for a hobby open-source project. Sites that look the AAGUID up show the provider as
unknown or unavailable. The last byte is the capability version, `0x04` since v0.3.0.

**When it changes:** whenever a site can observe a difference — algorithms or options
in GetInfo, supported commands, protocol behaviour. Internal fixes and the OpenPGP
card do not change it. The constant is `NIXTROPIC_AAGUID` in
`firmware/src/fido_hid/ctap2.c`.

## Attestation

Format `none`. A self-signed attestation would prove nothing with a self-assigned
AAGUID, and some servers fail to verify Ed25519 attestation signatures. With
`none`, browsers usually zero the AAGUID too; request **direct** attestation (for
example on webauthn.io: Advanced Settings → Attestation → Direct) to see it.

## Credential ID

18 bytes:

```text
[0]      version = 0x01
[1]      ECC key slot (0..28)
[2..17]  16-byte random nonce from the TROPIC01 TRNG
```

The nonce is stored with the credential: a forged ID would have to guess 128 bits.
The slot number is visible and reveals nothing secret. Every credential, discoverable
or not, occupies a chip slot, so the dongle holds at most 29.

## Algorithms

| COSE | Algorithm | Key on the chip |
|---|---|---|
| -8 | EdDSA (Ed25519) | 32-byte public key |
| -7 | ES256 (P-256) | 64-byte public key; the STM32 hashes `authData ‖ clientDataHash`, the chip signs the digest |

The authenticator takes the first of the two in the order the site lists them. RS256
is not supported (no RSA on the chip).

## authData layout

```text
[0..31]   rpIdHash (SHA-256 of the RP ID)
[32]      flags: bit 0 UP, bit 2 UV, bit 6 AT, bit 7 ED
[33..36]  signCount (uint32, big-endian)
[37..]    attestedCredentialData, when AT is set:
            [37..52]  AAGUID
            [53..54]  credential ID length = 18
            [55..72]  credential ID
            [73..]    COSE public key
```

**signCount** comes from TROPIC01 monotonic counter 0, shared by all credentials
(WebAuthn allows this). The chip's counter counts down; the firmware reports
`MAX − value`, reserving the value before it signs. The 32-bit range alone would
last about 136 years at one signature per second; in practice the chip’s write
endurance, not the range, is the limit (the datasheet gives 100 000 reprogram cycles as a
typical figure).

## GetInfo

`fido2-token -I /dev/hidrawN` reports:

- versions `FIDO_2_0`
- AAGUID `6e697874726f70696300000000000004`
- options `rk`, `up`, `plat=false`, `clientPin`, `credMgmt`, `authnrCfg`,
  `pinUvAuthToken`, `alwaysUv`, `makeCredUvNotRqd` (the last two change with the
  `alwaysUv` setting)
- algorithms `eddsa`, `es256`
- PIN protocol 1

GetInfo lists no extensions; MakeCredential still answers the `credProps` extension
(whether the credential was stored as discoverable) when a site asks for it.

## Browsers

| Browser / OS | Result |
|---|---|
| Firefox / Linux | works |
| Brave / Linux | works |
| Chrome / Linux | expected to work (same engine as Brave), not verified separately |
| Windows 11 browsers | works from v0.3.1 (Brave, webauthn.io, PIN set); v0.3.0 failed when a PIN was set because Windows abandoned the silent PIN steps ([Windows](windows.md)) |
| Safari / macOS | untested |

Troubleshooting steps: [Linux setup](linux-setup.md#fido2-troubleshooting).
