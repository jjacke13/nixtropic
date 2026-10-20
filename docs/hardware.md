# Hardware

nixtropic targets one board: the **Tropic Square TS1302 USB devkit**. Other TROPIC01
boards are not supported.

## Versions in v0.3.2

| Component | Version | Source |
|---|---|---|
| Secure element | TROPIC01 `TR01-C2P-T101`, silicon revision ACAB (production) | project dongle |
| TROPIC01 application firmware | 2.0.0 (required) | `chip-fw-version` on the project dongle |
| TROPIC01 SPECT firmware | 1.0.0 | same |
| Microcontroller | STM32U535CCTx | board schematic |
| libtropic (TROPIC01 SDK) | 3.2.1 | `flake.lock` |
| TinyUSB | 0.20.0 | `flake.lock` |
| STM32U5 HAL / CMSIS device | 1.6.2 / 1.4.2 | `flake.lock` |
| Toolchain | Arm GNU 15.2 (nixpkgs nixos-26.05) | `flake.lock` |
| Firmware size (release) | 223 460 B of 256 KB flash (85 %) | build of v0.3.2 |

SDK compatibility (from libtropic’s compatibility table): libtropic 3.2.1 and 4.0.0
support chip application firmware 1.0.0–2.0.0; 4.1.0 adds 2.1.0; 4.2.0 adds 2.2.0.
libtropic 4 changes the SDK’s API. Moving to it, and to newer chip firmware, is on the
[roadmap](roadmap.md).

## The board

```text
                TS1302
  USB-C ──── STM32U535CCTx ──── SPI1 ──── TROPIC01
                 │                           │
         SW1 (PH3, also BOOT0)          GPO (PB0)
         LED (PA9)                      power switch (PA0)
```

| Function | STM32 pin | Notes |
|---|---|---|
| TROPIC01 SPI MOSI / MISO / SCK | PA7 / PA6 / PA5 | SPI1, mode 0, MSB first |
| TROPIC01 chip select | PA4 | software-controlled |
| TROPIC01 GPO | PB0 | general-purpose output of the chip |
| TROPIC01 power switch | PA0 | |
| USB D− / D+ | PA11 / PA12 | full speed |
| SW1 | PH3 | BOOT0 strap at reset, user-presence button afterwards |
| LED | PA9 | active high |

## TROPIC01

| Resource | Amount | Notes | Source |
|---|---|---|---|
| ECC key slots | 32 | Ed25519 (EdDSA) or P-256 (ECDSA): generate, store, read public key, sign, erase | DS §7.7 p47; API Tables 28–33 |
| Data slots (R-memory) | 512 | 512 bytes physical each; up to 475 bytes of payload with application firmware ≥ 2.0 (444 with older firmware); a slot is erased before it is rewritten | DS §7.6 p46; API Tables 24–26 |
| MAC-and-Destroy slots | 128 | 32 bytes in, 32 bytes out | API Table 37 p46; PIN app note |
| Monotonic counters | 16 | 32-bit; they **count down** and stop at 0, and can be re-initialised | DS §7.10 pp52–53; API Tables 34–36 |
| Pairing key slots | 4 (SH0–SH3) | X25519 public keys that may open a secure session | DS §7.5 pp42–44 |
| TRNG | 2 | vendor-stated NIST SP 800-90B and AIS 31 compliance | DS front page; ODN_TR01_app_008 |

What the chip does **not** offer for user keys: X25519 key agreement (X25519 is used
only inside the session handshake), RSA, secp256k1, a general AES or hash service.
libtropic 3.2.1's ECDSA helper hashes the message on the host and sends the chip a
32-byte digest.

### Protocol layers

- **L1:** SPI. The chip's timing allows an SCK period down to 37 ns; nixtropic runs the
  bus at 3 MHz, a conservative project setting.
- **L2:** CRC-protected frames, including chip mode, information, and maintenance
  requests.
- **L3:** application commands in an encrypted session,
  `Noise_KK1_25519_AESGCM_SHA256`, opened with a pairing key. Each command and result
  is encrypted with AES-256-GCM (DS §7.3–7.4). Resets and sleep end the chip’s
  session (DS §6.4 p17, §6.6 p18, §7.4 p38). nixtropic’s policy on errors: a result the chip returns inside
  the session keeps the session; after a transport, framing or unknown-result failure the
  firmware discards its own session state, attempts an abort and handshakes again before
  the next command, and never replays the command. Such a failure does not by itself
  prove the chip’s session ended (DS §7.3.7 p37, §7.5 p42).

### Access control

The chip's configuration (R-config, rewritable; I-config, one-way bits) decides per
pairing slot which commands each slot may run, in groups: ECC slots by 8, data slots
by 128, MAC-and-Destroy slots by 32, counters by 4. The effective configuration is the
bitwise AND of both, loaded at boot (DS §7.2 p23; CONFIG §1 p4). nixtropic never writes
either: its only chip-call module, `firmware/src/tropic/tropic.c`, has no configuration,
pairing-key or firmware-update call.

Facts for anyone who plans to change the configuration:

- Erasing R-config sets every bit to 1; it does **not** restore the factory settings,
  and some factory sensor settings exist only in R-config (CONFIG §4.2 p13; Catalog §5.2
  p11).
- The safe procedure is: read the whole configuration, change the copy, erase
  explicitly and check, write the whole copy, reboot, read it back. libtropic 3.2.1's
  "write whole config" helper does **not** erase first. Writing without the erase
  can trigger erratum `OI_TR01_ERR_2026010800`: permanent alarm.
- I-config bits only go from 1 to 0, permanently. Invalidating a pairing slot is
  permanent.

### Chip modes

Start-up (bootloader), Maintenance, Application, Alarm. Ordinary Alarm Mode, entered
when a tamper sensor fires, lasts **until the next power cycle**. The permanent alarm
of the R-config erratum and a fatal I-config failure are separate cases.

### Firmware banks

On ACAB silicon the bootloader keeps protected and unprotected banks for the CPU and
SPECT firmware and accepts only the same or a newer version: a completed update cannot
be reverted.

### Endurance

The datasheet lists 100 000 reprogram cycles (typical, not a guaranteed minimum) and
10 years of retention. A PIN verification writes its record pair once for a wrong PIN and twice for a correct
one (DS §9.6 p61 for the figures).

## STM32U535

From ST’s DS14217 (Rev 5) unless noted.

| Feature | Value |
|---|---|
| Core | Arm Cortex-M33 with TrustZone-M and FPU, up to 160 MHz; nixtropic runs it at 48 MHz |
| Flash | 256 KB |
| SRAM | 274 KB (SRAM1 192 + SRAM2 64 + SRAM4 16 + 2 KB backup SRAM); the firmware uses SRAM1 |
| Crypto hardware | HASH (SHA-2) and TRNG. **No** AES, SAES, PKA or OTFDEC |
| USB | full speed device |
| Secure install | SFI / RSS is supported |
| Backup registers | 32 × 32 bit (128 B) in TAMP; the register map defines a boot-hardware-key lock bit, but without SAES there is no hardware engine that uses such a key |

### Read-out protection (RDP)

RM0456 Rev 7 §3.10.1 Table 22; DS14217 §3.4.1 p23.

| Level | Effect | Going back |
|---|---|---|
| 0 | open (nixtropic today) | — |
| 0.5 | TrustZone only: secure debug and secure flash blocked | to 0, with erase |
| 1 | flash cannot be read through the debug port or the bootloader; with TrustZone, non-secure debug stays possible | to 0 erases flash, backup registers and **all SRAM** (password-gated if an OEM1 key is set) |
| 2 | debug disabled | **permanent**, unless an OEM2 unlock key was provisioned beforehand (then 2 → 1) |

A regression from level 1 erases every SRAM, the backup SRAM included, so no secret
survives it there.

## Corrections to earlier documentation

Earlier project documents (now in
[history](https://github.com/jjacke13/nixtropic/tree/main/docs/history)) stated these
facts wrongly:

| Earlier claim | Correct |
|---|---|
| The secure session is Noise IK | `Noise_KK1_25519_AESGCM_SHA256` |
| Data slots hold 256 bytes by default | 512 bytes physical; payload up to 475 bytes (FW ≥ 2.0) or 444 |
| Monotonic counters count up and cannot be reset | they count down and can be re-initialised |
| MAC-and-Destroy zeroes a slot | it replaces the slot's state deterministically |
| Alarm Mode is always permanent | ordinary alarm clears on power cycle; the erratum case is permanent |
| Erase → "write whole config" is the full R-config procedure | read mirror, explicit checked erase, whole write, reboot, read back |
| A build flag `NIXTROPIC_ENG_KEYS` selects engineering-sample pairing keys | never implemented; the firmware always uses `sh0_prod0` |
| The chip's SPI maximum is 5 MHz | minimum SCK period 37 ns; 3 MHz is a project setting |
| A bad STM32 reflash cannot affect the chip | new STM32 firmware can send the chip any command its pairing key allows |
| The LFI M&D details are embargoed to 2027-Q2 and hardened silicon ships 2026-Q4 | vendor estimates: first half of 2027 (planned Q2), hardened parts expected 2026-Q4, dates to be announced |
| The STM32U535 has no BHK and no SFI | SFI/RSS is supported; TAMP defines the BHK lock bit, but there is no SAES to use it |
| TAMP has 128 backup registers (512 B) | 32 registers (128 B) |
| Back up secrets to backup SRAM before an RDP 1 → 0 regression | the regression erases backup SRAM too |
| TROPIC01 TRNG compliance is unverified | the vendor states SP 800-90B and AIS 31 compliance |
