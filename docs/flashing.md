# Flashing

nixtropic replaces the firmware of the board's **STM32U535** microcontroller. Flashing
uses the STM32's built-in USB DFU bootloader, which lives in ROM: a bad flash can
always be redone.

!!! danger "Upgrading from v0.2 or an earlier v0.3 build erases your keys"
    The on-chip storage layout changed in v0.3.0 and is **not migrated**. After the
    upgrade you reset both applications, and everything they held is gone:

    - **FIDO2:** every passkey and security-key registration, and the FIDO PIN.
      Register a second authenticator or recovery codes on each site **before**
      upgrading.
    - **OpenPGP:** all three private keys and the PINs. The signing and
      authentication private keys were generated inside the chip and cannot be
      exported, so they have no backup: exporting the public key does not save them.
      Prepare a new key or subkeys, and publish a revocation if others rely on the old
      ones.

    The reset steps are in the [changelog](changelog.md#upgrading). A fresh dongle
    needs none of this.

## The dongle's USB identities

| Mode | VID:PID | What runs |
|---|---|---|
| Stock firmware | `0483:5740` | Tropic Square's devkit firmware: a USB serial ↔ SPI bridge to the chip |
| nixtropic | `cafe:4001` | This firmware: FIDO2 (HID) + OpenPGP card (CCID) |
| DFU bootloader | `0483:df11` | The STM32 ROM bootloader, for flashing |

## Check the TROPIC01 firmware version

nixtropic needs TROPIC01 application firmware **2.0.0** (SPECT firmware 1.0.0).
Some dongles shipped with 0.3.1. The check uses the **stock** firmware's USB-to-SPI
bridge, so flash the stock firmware first ([DFU mode](#enter-dfu-mode) below), replug
normally, then:

```bash
nix run github:jjacke13/nixtropic#chip-fw-version
# App FW    = 2.0.0
# SPECT FW  = 1.0.0
```

The tool reboots the chip before reading; it sends no write command. If the version is
older than 2.0.0, nixtropic does not run on that dongle yet: see
[TROPIC01 firmware older than 2.0.0](#tropic01-firmware-older-than-200).

## Enter DFU mode

1. Unplug the dongle.
2. Hold the button **SW1** while plugging it in; release after about a second.
3. Check:

    ```bash
    lsusb | grep 0483:df11
    # ... ID 0483:df11 STMicroelectronics STM Device in DFU Mode
    ```

SW1 is also the STM32's BOOT0 strap. It is read only at power-on; afterwards it is the
user-presence button.

## Flash with Nix

The flake builds the firmware from pinned sources and flashes it with `dfu-util`. Use
`sudo` unless the [udev rules](linux-setup.md#udev-rules) are installed.

```bash
nix run github:jjacke13/nixtropic#flash-open         # release firmware
nix run github:jjacke13/nixtropic#flash-stock        # back to the stock firmware
```

The dongle restarts into the new firmware by itself. A pinned version:
`nix run github:jjacke13/nixtropic/v0.3.1#flash-open`.

!!! warning "Release and debug builds"
    `flash-open` installs the **release** build: FIDO2 and the OpenPGP card, nothing
    else. `flash-open-debug` adds a USB log console and a debug RPC interface that can
    drive chip operations **without PIN or touch**. The debug build is for development
    on a dongle that holds nothing of value.

## Flash without Nix

The flake is the reference build; this section translates it to `apt`, `git` and
`cmake` on Debian/Ubuntu. It is not tested in CI. Where it disagrees with the flake,
the flake is right.

### 1. Packages

```bash
sudo apt install -y \
    build-essential cmake ninja-build git pkg-config \
    gcc-arm-none-eabi binutils-arm-none-eabi libnewlib-arm-none-eabi \
    libssl-dev dfu-util usbutils
```

The flake builds with the Arm GNU Toolchain 15.2; that is the tested compiler. The
distribution packages (`gcc-arm-none-eabi` 10 on Ubuntu 22.04, 13 on 24.04) are
untested with this firmware and produce different bytes. To check a build against the
flake's, use the Arm release it pins and compare `firmware.bin` hashes.

### 2. Sources at the pinned commits

```bash
mkdir -p ~/src && cd ~/src
git clone https://github.com/jjacke13/nixtropic
mkdir -p nixtropic-deps && cd nixtropic-deps
clone() { git clone "https://github.com/$1" && git -C "$(basename "$1")" checkout "$2"; }
clone tropicsquare/libtropic                  6d058a36c7db9e55549a5e79ed4f9a83def80c0a  # v3.2.1
clone STMicroelectronics/cmsis-core           2327f7224ff212b2436e5a4cadda3288143fd041
clone STMicroelectronics/cmsis-device-u5      6e67187dec98035893692ab2923914cb5f4e0117  # v1.4.2
clone STMicroelectronics/stm32u5xx-hal-driver 2c5e2568fbdb1900a13ca3b2901fdd302cac3444  # v1.6.2
clone hathach/tinyusb                         3af1bec1a9161ee8dec29487831f7ac7ade9e189  # 0.20.0
```

These are the commits pinned in `flake.nix`.

### 3. Build

```bash
cd ~/src/nixtropic/firmware
D=~/src/nixtropic-deps
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=cmake/arm-none-eabi.cmake \
  -DLIBTROPIC_SRC=$D/libtropic \
  -DCMSIS_CORE_SRC=$D/cmsis-core \
  -DCMSIS_DEVICE_U5_SRC=$D/cmsis-device-u5 \
  -DSTM32U5XX_HAL_DRIVER_SRC=$D/stm32u5xx-hal-driver \
  -DTINYUSB_SRC=$D/tinyusb
cmake --build build
ls -l build/firmware.bin     # about 223 KB of the 256 KB flash
```

`-DNIXTROPIC_DEBUG=ON` builds the debug firmware.

### 4. Flash

With the dongle in DFU mode:

```bash
sudo dfu-util -a 0 -s 0x08000000:leave -D build/firmware.bin
```

`dfu-util` usually ends with `Error during download get_status` after `:leave`,
because the STM32 restarts before it answers. Look for `File downloaded successfully`.
The Nix apps recognise this case and report any other failure.

## After flashing

1. Set up the host: [Linux setup](linux-setup.md).
2. Check both interfaces:

    ```bash
    lsusb | grep cafe:4001
    fido2-token -L              # lists the nixtropic FIDO device
    gpg --card-status           # shows the OpenPGP card
    ```

3. Configure the card: [Card setup](card-setup.md).

## What is and is not verified

- **Reproducible from source.** Every input is pinned by commit in `flake.lock`; the
  same inputs build the same `firmware.bin`. Building it yourself is the way to know
  what you flash.
- **No signed releases.** The project publishes no signed binaries, and the dongle has
  no secure boot: the STM32 bootloader accepts any image over DFU, and the dongle
  cannot prove which firmware it runs. Anyone with the dongle in hand can reflash it.
  See the [security model](security.md).
- **The stock firmware is a different trust surface.** It passes raw SPI traffic from
  the host to the chip. Keep it on the dongle only for chip maintenance.

## TROPIC01 firmware older than 2.0.0

Updating the chip's own firmware is **not covered by this guide**. It is separate from
the STM32 firmware that DFU flashes and from the application resets in
[recovery](recovery.md), and it is **irreversible**: the chip's bootloader accepts
only the same or a newer version.

The repository still contains a legacy updater (`fw-update-chip`, written for
libtropic 3.2.1 and application firmware 2.0.0). It is **unsupported**: it does not
perform all the start-up mode checks and per-bank version comparisons of Tropic
Square's firmware-update procedure, nor the controlled-environment and maintenance-mode
steps of their laser fault-injection advisory. A reviewed, device-specific update
procedure is on the [roadmap](roadmap.md#libtropic-4-and-newer-chip-firmware). Until
then, a dongle with older chip firmware cannot run nixtropic.
