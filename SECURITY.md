# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub:
**Security → Report a vulnerability** on this repository
([direct link](https://github.com/jjacke13/nixtropic/security/advisories/new)).
Do not open a public issue for a vulnerability.

Include what you found, how to reproduce it, the firmware version or commit, and the
build (release or debug). You will get an answer as soon as the maintainer can; this
is a personal open-source project with no guaranteed response time.

## Supported versions

| Version | Supported |
|---|---|
| v0.3.x | yes |
| older | no — upgrade |

## Before you report

nixtropic is a **development release**. Several limits are known and documented in
the [security model](https://jjacke13.github.io/nixtropic/security/), among them:

- the public development pairing key (someone holding the dongle can make it sign);
- no read-out protection or secure boot on the STM32;
- Tropic Square's laser fault-injection advisory for this chip;
- the PIN reset that destroys the OpenPGP decryption key (by design).

Reports that go beyond these, or show that a documented protection does not hold, are
very welcome.

## Scope

In scope: the firmware in `firmware/`, the host tools and scripts in `tools/`, the Nix
build and the NixOS module. Vulnerabilities in TROPIC01, libtropic, TinyUSB or
trezor-crypto belong to their upstream projects; a note here is still appreciated if
nixtropic is affected.
