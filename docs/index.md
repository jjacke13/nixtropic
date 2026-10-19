---
hide:
  - navigation
---

# nixtropic

**Open-source firmware that turns the Tropic Square TS1302 USB devkit into a FIDO2 and
OpenPGP security key, with keys held in the TROPIC01 secure element.**

The TROPIC01 is an open-architecture secure element. nixtropic runs on the board's
STM32U535 microcontroller, speaks the two standard security-key protocols over USB,
and keeps the keys inside the chip. It is built reproducibly with Nix and tested
against a simulated chip, with planted bugs, and on real hardware.

!!! warning "Development release — not a production security key"
    v0.3 uses Tropic Square's **public development pairing key**: anyone holding the
    dongle can make it sign. It fixes the known host-side attack paths of v0.2 and stores
    no readable secrets on the chip; it does not defend against physical attacks. Read the [security model](security.md)
    before you rely on it.

<div class="grid cards" markdown>

-   :material-fingerprint:{ .lg .middle } **FIDO2 / WebAuthn**

    ---

    Passkeys and security-key logins. EdDSA and ES256 keys generated and used inside
    TROPIC01; PIN, `alwaysUv`, credential management.

-   :material-key-chain:{ .lg .middle } **OpenPGP card**

    ---

    `gpg` signing, decryption and SSH through `gpg-agent`. Ed25519 keys inside
    TROPIC01; the X25519 decryption key sealed under your PIN.

-   :material-shield-lock-outline:{ .lg .middle } **Chip-enforced PIN limits**

    ---

    Every guess consumes MAC-and-Destroy state on the chip that only the right PIN
    restores. No PIN hash is stored anywhere.

-   :material-database-check-outline:{ .lg .middle } **Fault-tolerant state**

    ---

    Settings and PINs are mirrored and read back. One power cut, lost reply or damaged
    slot never grants access or undoes a completed change
    ([limits](security.md#persistent-state-under-faults)).

-   :material-gesture-tap-button:{ .lg .middle } **User presence**

    ---

    Button SW1 and the LED confirm every FIDO2 registration and login, and by default
    every OpenPGP signature, decryption and SSH login.

-   :simple-nixos:{ .lg .middle } **Reproducible**

    ---

    Every input pinned. `nix build` produces the same firmware from the same commit;
    `nix run` flashes it.

</div>

## Get started

<div class="grid cards" markdown>

-   :material-usb-flash-drive-outline: **[Flashing](flashing.md)**

    Check the chip firmware, enter DFU mode, flash with or without Nix.

-   :material-linux: **[Linux setup](linux-setup.md)**

    `pcscd`, `scdaemon`, udev rules and the libccid patch; a NixOS module does it all.

-   :material-microsoft-windows: **[Windows](windows.md)**

    The OpenPGP card with Gpg4win and Kleopatra; FIDO2 status.

-   :material-card-account-details-outline: **[Card setup](card-setup.md)**

    PINs, touch policy, key generation, resets.

-   :material-lifebuoy: **[Recovery](recovery.md)**

    What each kind of reset changes, and how to get back.

</div>

## Under the hood

[Architecture](architecture.md) · [Hardware](hardware.md) ·
[Design decisions](design.md) · [Security model](security.md) ·
[Testing](testing.md) · [Status](status.md) · [Roadmap](roadmap.md)
