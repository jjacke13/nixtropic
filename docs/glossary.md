# Glossary

AAGUID
:   Authenticator model identifier in WebAuthn. nixtropic's is self-assigned
    (`nixtropic` + version byte), not registered with the FIDO Alliance.

APDU
:   Application Protocol Data Unit: a smart-card command or response, carried over CCID.

CCID
:   USB Chip Card Interface Device class: how a smart-card reader appears on USB. The
    OpenPGP card uses it, through `pcscd` and `libccid` on the host.

CTAP2 / CTAPHID
:   FIDO Alliance protocol between the browser (or libfido2) and the authenticator;
    CTAPHID is its framing over USB HID.

DFU
:   USB Device Firmware Upgrade. The STM32's ROM bootloader speaks it; holding SW1
    while plugging in enters it.

KEK
:   Key Encryption Key: a key whose only job is to lock another key. nixtropic's KEK
    seals the OpenPGP decryption key and is derived from the PW1 binding, never stored.

L1 / L2 / L3
:   TROPIC01's protocol layers: SPI transport, CRC-framed requests, and the encrypted
    application session.

libtropic
:   Tropic Square's C SDK for TROPIC01.

MAC-and-Destroy (M&D)
:   TROPIC01 function: returns 32 bytes that the chip computes from the input and the
    slot’s hidden state, and replaces that state with a new one derived from the input.
    The basis of chip-enforced PIN retry limits. See
    [design](design.md#pins-mac-and-destroy).

Pairing key
:   X25519 key pair that opens the encrypted session with TROPIC01. The chip holds up to
    four public keys (SH0–SH3); the host side holds the private key. nixtropic uses the
    public development key in SH0.

PW1, PW3, Reset Code
:   OpenPGP card PINs. PW1 is the user PIN (used as `81` for signing and `82` for
    decryption and authentication), PW3 the Admin PIN, the Reset Code unblocks PW1.

R-config, I-config
:   TROPIC01 configuration: rewritable and one-way (bits go only from 1 to 0). Together
    they decide which pairing slot may use which command. nixtropic writes neither.

R-memory
:   TROPIC01's 512 user data slots, encrypted at rest inside the chip.

RDP
:   STM32 Read-Out Protection: option-byte levels 0, 0.5, 1 and 2 that restrict the
    debug port and flash read-out. Level 2 is permanent unless an unlock key was set
    beforehand.

Record pair
:   nixtropic's storage unit: one object in two data slots, written one after the other
    and read back, so one fault never grants access or rolls back an acknowledged write
    ([limits](security.md#persistent-state-under-faults)).

SPECT
:   The TROPIC01's elliptic-curve co-processor; it has its own firmware next to the
    chip's RISC-V application firmware.

TS1302
:   Tropic Square's USB devkit: STM32U535 + TROPIC01 + USB-C, one button, one LED.

UIF
:   User Interaction Flag: the OpenPGP card's touch policy (`uif` in gpg).

UV, UP
:   User verification (a PIN) and user presence (a button press) in FIDO2. `alwaysUv`
    requires the PIN for every credential use.
