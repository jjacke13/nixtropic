# Recovery

What to do when the dongle stops working as expected.

## Silicon layout

```
   host PC                       TS1302 USB devkit
   ┌─────────────────┐  USB-C   ┌─────────────────────────────┐
   │ browser / gpg / │ ◄──────► │  STM32U535 host MCU         │
   │ ssh / libfido2 /│          │  ┌───────────────────────┐  │
   │ pcsc-lite       │          │  │ nixtropic firmware    │  │
   └─────────────────┘          │  │  - USB composite      │  │
                                │  │  - FIDO2 + OpenPGP    │  │
                                │  │  - libtropic L1/L2/L3 │  │
                                │  └─────────────┬─────────┘  │
                                │                │ SPI1       │
                                │                ▼            │
                                │  ┌───────────────────────┐  │
                                │  │ TROPIC01 secure elem  │  │
                                │  │  - ECC + M&D slots    │  │
                                │  │  - R-mem (persistent) │  │
                                │  │  - TRNG, L3 AES-GCM   │  │
                                │  │  - chip firmware      │  │
                                │  └───────────────────────┘  │
                                └─────────────────────────────┘
```

DFU operations touch ONLY the STM32 firmware (top half).  TROPIC01
(bottom half) is reachable only through L3 commands the STM32 sends
over SPI, so a bad STM32 reflash can't corrupt the secure element.

## Failure modes

| Failure                                | Recoverable? | How |
|---                                     |---           |---  |
| STM32 firmware corrupt / wrong         | seconds      | DFU re-flash |
| STM32 RDP level 2 lock                 | no           | don't enable RDP=2 in dev |
| TROPIC01 R-config write w/o erase      | no, permanent| see PROJECT.md §5 — never reachable from nixtropic code |
| TROPIC01 SH0 invalidated, no SH1 set   | no           | always set SH1+ before invalidating SH0 |
| TROPIC01 chip firmware out-of-date     | yes          | `nix run .#fw-update-chip` |
| FIDO credentials / PIN / Force-UV flag | yes          | host-side wipe — see README §Factory reset |
| OpenPGP PINs / cardholder / keys       | yes          | `gpg --card-edit > admin > factory-reset` |

## DFU re-flash (most common path)

1. Unplug the dongle.
2. Hold SW1 (BOOT0 strap).
3. Plug in USB.
4. Release SW1 after ~1 s.
5. Verify:

   ```bash
   lsusb | grep 0483:df11
   # Bus … Device …: ID 0483:df11 STMicroelectronics STM Device in DFU Mode
   ```

6. Flash:

   ```bash
   sudo nix run .#flash-stock     # restore stock firmware
   sudo nix run .#flash-open      # install nixtropic open firmware
   ```

The device reboots into the new firmware automatically.

## TROPIC01 chip firmware update

Updates the TROPIC01's internal CPU + SPECT firmware.  One-way — the
chip rejects downgrades after success.  Use this if `nix run .#identify`
reports App FW < 2.0.0.

```bash
sudo nix run .#fw-update-chip
```

Built from `tools/fw-update-chip-main.c` against the pinned libtropic
v3.2.1.  The dongle must be running stock firmware (not the open
firmware) — the chip-FW updater needs the L1 SPI passthrough mode that
stock provides.

## Application-level reset

Wipes credentials / PINs / cardholder state without touching firmware
on either silicon.  See **README → Factory reset** for the FIDO and
OpenPGP recipes.  TL;DR:

- FIDO state: `fido2-token -R …` within 10 s of boot + SW1 confirm
- OpenPGP state: `gpg --card-edit → admin → factory-reset`

## Hardware-level recovery (extreme edge case)

If DFU mode itself won't enumerate (very rare — ROM bootloader is
robust), use SWD via ST-Link or J-Link on the TS1302 debug header
(SWDIO, SWCLK, RST, GND):

```bash
openocd -f interface/stlink.cfg -f target/stm32u5x.cfg \
  -c "init; reset halt; flash erase_address 0x08000000 0x40000; reset run; exit"
```

DFU should work again after this.

## See also

- README §Factory reset — application-level reset recipes
- PROJECT.md §5 — critical facts (TROPIC01 brick erratum + pairing
  key rules)
- `research/stm32u535-inventory.md` — STM32 bootloader details
- Tropic Square's `tropic01-stm32u5-usb-devkit-fw` — upstream DFU
  reference
