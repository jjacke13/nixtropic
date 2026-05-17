# Using nixtropic on Ubuntu (no Nix)

End-to-end recipe to build, flash, and daily-drive the dongle on a stock
Ubuntu host (tested mentally against 22.04 / 24.04 LTS).  The flake stays
the source of truth for reproducibility — this doc translates it into
`apt` + `git` + `cmake` for users who can't or don't want to install Nix.

If anything below drifts from the flake, the flake wins.  Open an issue.

---

## 0. What you are installing

Three host-side binaries and one firmware image:

| Component | Source path | Tool |
|---|---|---|
| **open firmware** (`firmware.bin`) | `firmware/` | Flashes onto the STM32U535 via DFU |
| **lt-util** | `tropicsquare/libtropic-util` | Talks to TROPIC01 over the stock CDC firmware |
| **fw-update-chip** | `tools/fw-update-chip-main.c` | One-shot updater for the TROPIC01's *own* firmware (App + SPECT) |
| **chip-fw-version** | `tools/chip-fw-version-main.c` | Read-only reporter for chip App / SPECT FW versions |

Plus stock OS packages: `dfu-util`, `pcscd`, a patched `libccid`,
`libfido2-1`, `opensc`, `gnupg`.

---

## 1. System packages

```bash
sudo apt update
sudo apt install -y \
    build-essential cmake ninja-build git pkg-config \
    gcc-arm-none-eabi binutils-arm-none-eabi libnewlib-arm-none-eabi \
    libssl-dev \
    dfu-util usbutils \
    pcscd pcsc-tools libccid libpcsclite-dev \
    libfido2-1 libfido2-dev fido2-tools \
    opensc gnupg scdaemon
```

**Toolchain notes.** `gcc-arm-none-eabi` is gcc-10 on 22.04 and gcc-13 on
24.04; firmware builds clean on both. The flake pins gcc-arm-embedded-13;
the Ubuntu 22.04 gcc-10 produces a slightly larger but functionally
identical binary.  If you want exact byte parity with the flake, install
the official Arm toolchain release matching `gcc-arm-embedded-13` from
<https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads> and
put `arm-none-eabi-*` first on PATH.

---

## 2. Clone sources at pinned commits

The flake pins every input by commit hash.  Reproduce that here:

```bash
mkdir -p $HOME/src && cd $HOME/src

# Main repo
git clone https://github.com/jjacke13/nixtropic
(cd nixtropic && git checkout main)

# Pinned vendored sources (used by both firmware and host tools)
mkdir -p nixtropic-deps && cd nixtropic-deps
git clone https://github.com/tropicsquare/libtropic                && \
    (cd libtropic                && git checkout 6d058a36c7db9e55549a5e79ed4f9a83def80c0a)
git clone --recurse-submodules https://github.com/tropicsquare/libtropic-util && \
    (cd libtropic-util           && git checkout cbc30f5ac37e7d0874df6b989d4b4be7d01d93e8 && git submodule update --init --recursive)
git clone https://github.com/STMicroelectronics/cmsis-core         && \
    (cd cmsis-core               && git checkout 2327f7224ff212b2436e5a4cadda3288143fd041)
git clone https://github.com/STMicroelectronics/cmsis-device-u5    && \
    (cd cmsis-device-u5          && git checkout 6e67187dec98035893692ab2923914cb5f4e0117)
git clone https://github.com/STMicroelectronics/stm32u5xx-hal-driver && \
    (cd stm32u5xx-hal-driver     && git checkout 2c5e2568fbdb1900a13ca3b2901fdd302cac3444)
git clone https://github.com/hathach/tinyusb                       && \
    (cd tinyusb                  && git checkout 3af1bec1a9161ee8dec29487831f7ac7ade9e189)
```

Layout after this step:

```
$HOME/src/
├── nixtropic/                  ← main repo
└── nixtropic-deps/             ← vendored sources only
    ├── libtropic/
    ├── libtropic-util/
    ├── cmsis-core/
    ├── cmsis-device-u5/
    ├── stm32u5xx-hal-driver/
    └── tinyusb/
```

---

## 3. Build the firmware

```bash
cd $HOME/src/nixtropic/firmware
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=MinSizeRel \
  -DCMAKE_TOOLCHAIN_FILE=cmake/arm-none-eabi.cmake \
  -DLIBTROPIC_SRC=$HOME/src/nixtropic-deps/libtropic \
  -DCMSIS_CORE_SRC=$HOME/src/nixtropic-deps/cmsis-core \
  -DCMSIS_DEVICE_U5_SRC=$HOME/src/nixtropic-deps/cmsis-device-u5 \
  -DSTM32U5XX_HAL_DRIVER_SRC=$HOME/src/nixtropic-deps/stm32u5xx-hal-driver \
  -DTINYUSB_SRC=$HOME/src/nixtropic-deps/tinyusb
cmake --build build
ls -lh build/firmware.bin
```

Expected size: ~179 KB (68% of the STM32U535's 256 KB flash) with
`MinSizeRel` / `-Os` on Ubuntu's gcc-14.2.  For comparison, the flake's
Release / `-O2` build on gcc-13 lands at ~217 KB (82.8%) — same firmware,
different optimisation goal.

---

## 4. Build the host tools

### 4a. `lt-util` (chip CLI, used by `chip-fw-version` / `fw-update-chip`)

```bash
cd $HOME/src/nixtropic-deps/libtropic-util

# Patch upstream off-by-one in the bundled libtropic v1.0.0 host adapter.
# (Fixed in libtropic >= v3.x; lt-util is dormant and still pins v1.0.0.)
sed -i 's|count < 2 \* tx_data_length|count < tx_data_length|' \
    libtropic/hal/port/unix/lt_port_unix_usb_dongle.c

cmake -S . -B build -DUSB_DONGLE_TS1302=1
cmake --build build
sudo install -m 755 build/lt-util /usr/local/bin/lt-util
```

### 4b. `fw-update-chip` and `chip-fw-version`

These two binaries share a CMakeLists.  Drop it into a build scratch dir:

```bash
mkdir -p $HOME/src/chip-fw-tools && cd $HOME/src/chip-fw-tools
cp $HOME/src/nixtropic/tools/fw-update-chip-main.c   .
cp $HOME/src/nixtropic/tools/chip-fw-version-main.c  .
cp $HOME/src/nixtropic/tools/fw-update-chip-CMakeLists.txt ./CMakeLists.txt

cmake -S . -B build \
  -DLIBTROPIC_SRC=$HOME/src/nixtropic-deps/libtropic \
  -DLT_CPU_FW_UPDATE_DATA_VER=2_0_0
cmake --build build
sudo install -m 755 build/fw-update-chip  /usr/local/bin/fw-update-chip
sudo install -m 755 build/chip-fw-version /usr/local/bin/chip-fw-version
```

---

## 5. udev rules + group

The dongle has three USB identities:

| Mode | VID:PID |
|---|---|
| stock firmware (CDC SPI bridge) | `0483:5740` |
| nixtropic open firmware         | `cafe:4001` |
| STM32 DFU bootloader            | `0483:df11` |

```bash
sudo groupadd -f tropic
sudo usermod -aG tropic "$USER"   # log out + back in for this to take effect

sudo tee /etc/udev/rules.d/70-nixtropic.rules >/dev/null <<'EOF'
# Stock firmware (CDC)
SUBSYSTEM=="tty", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="5740", GROUP="tropic", MODE="0660", SYMLINK+="tropic01", ENV{ID_MM_DEVICE_IGNORE}="1", TAG+="uaccess"
SUBSYSTEM=="usb", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="5740", GROUP="tropic", MODE="0660", ENV{ID_MM_DEVICE_IGNORE}="1", TAG+="uaccess"

# nixtropic open firmware (CDC + HID×2 + CCID)
SUBSYSTEM=="tty", ATTRS{idVendor}=="cafe", ATTRS{idProduct}=="4001", GROUP="tropic", MODE="0660", SYMLINK+="tropic01-open", ENV{ID_MM_DEVICE_IGNORE}="1", TAG+="uaccess"
SUBSYSTEM=="usb", ATTRS{idVendor}=="cafe", ATTRS{idProduct}=="4001", GROUP="tropic", MODE="0660", ENV{ID_MM_DEVICE_IGNORE}="1", TAG+="uaccess"

# DFU bootloader
SUBSYSTEM=="usb", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="df11", GROUP="tropic", MODE="0660", ENV{ID_MM_DEVICE_IGNORE}="1", TAG+="uaccess"
EOF

sudo udevadm control --reload-rules
sudo udevadm trigger
```

`ID_MM_DEVICE_IGNORE=1` keeps ModemManager from holding `/dev/ttyACM*`
hostage.

---

## 6. Patch libccid for `cafe:4001`

`libccid` ships an `Info.plist` whitelist of 607 reader VID:PID pairs.
The nixtropic open firmware uses TinyUSB's demo VID:PID `cafe:4001`, which
isn't in that list — without the patch, `pcscd` silently refuses to drive
the CCID interface and `gpg --card-status` returns "No such device".

```bash
INFO=/usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist
# (path on Ubuntu 22.04+ via the `libccid` apt package)
[ -f "$INFO" ] || { echo "libccid Info.plist not at $INFO"; exit 1; }

sudo cp "$INFO" "$INFO.bak"
sudo awk '
  /<key>ifdVendorID<\/key>/      { stage="vid";  print; next }
  /<key>ifdProductID<\/key>/     { stage="pid";  print; next }
  /<key>ifdFriendlyName<\/key>/  { stage="name"; print; next }
  /<\/array>/ {
    if (stage == "vid")  print "\t\t<string>0xCAFE</string>"
    if (stage == "pid")  print "\t\t<string>0x4001</string>"
    if (stage == "name") print "\t\t<string>nixtropic CCID Reader</string>"
    stage = ""; print; next
  }
  { print }
' "$INFO.bak" | sudo tee "$INFO" >/dev/null

grep -q 0xCAFE "$INFO" || { echo "Patch did not land — restoring backup."; sudo mv "$INFO.bak" "$INFO"; exit 1; }
sudo systemctl restart pcscd
```

If Ubuntu ships an apt upgrade for `libccid`, the patch will be reverted —
re-run this block.  Real fix (pid.codes allocation + upstream PR) is
tracked in `docs/BACKLOG.md §5.2`.

---

## 7. Update the TROPIC01 chip firmware (one-time)

The dongle may ship with chip App FW 0.3.1 (Deprecated).  nixtropic needs
≥ 2.0.0.  Both `chip-fw-version` and `fw-update-chip` require the **stock
TS1302 firmware** to be loaded (because they use the CDC SPI passthrough);
if you've already flashed the open firmware, re-flash stock first via the
DFU steps in §8 with the stock firmware binary.

```bash
sudo chip-fw-version /dev/ttyACM0
# App FW    = 2.0.0
# SPECT FW  = 1.0.0
```

If `< 2.0.0`:

```bash
sudo fw-update-chip /dev/ttyACM0
```

This is **one-way** — chip rejects downgrades after success.  Brick risk
is low (mid-flight power loss leaves chip in recoverable Maintenance
Mode), but use a stable USB port and don't unplug it during the update.

---

## 8. Flash the dongle

1. Unplug the dongle.
2. Hold **SW1** while plugging USB.
3. Verify: `lsusb | grep 0483:df11`
4. Flash:

   ```bash
   sudo dfu-util -a 0 -s 0x08000000:leave -D $HOME/src/nixtropic/firmware/build/firmware.bin
   ```

`dfu-util` exits non-zero with `Error during download get_status` after
`:leave` — this is benign on every STM32 + dfu-util combo.  Look for the
line `File downloaded successfully` to confirm.

After flash, the dongle replugs as `cafe:4001` running the open firmware.

---

## 9. Configure GnuPG

```bash
mkdir -p ~/.gnupg && chmod 700 ~/.gnupg
cat >> ~/.gnupg/scdaemon.conf <<'EOF'
disable-ccid
pcsc-shared
EOF
cat >> ~/.gnupg/gpg-agent.conf <<'EOF'
enable-ssh-support
EOF
gpgconf --kill scdaemon
gpg-connect-agent updatestartuptty /bye
```

**Yubikey co-existence caveat.** `disable-ccid` + `pcsc-shared` makes
scdaemon go through `pcscd`, which is required for the nixtropic dongle
(internal CCID driver doesn't know `cafe:4001`).  But that path also
makes a Yubikey re-prompt the PIN on every operation.  If you carry both
and need cached PIN on the Yubikey, comment those two lines out when the
nixtropic dongle is unplugged.

---

## 10. Initialise keys on the dongle

```bash
gpg --card-edit
> admin
> passwd       # IMMEDIATELY change PW1 (default 123456) and PW3 (default 12345678)
> name         # set cardholder name
> generate     # generates sig + dec + aut directly on the TROPIC01
> quit

gpg --card-status     # verify keys are bound
```

The private keys never leave the chip.

---

## 11. Validate

The two shell scripts under `tools/` are pure Bash + apt-installable
tools — no Nix needed.  They use `lsusb`, `fido2-token`, `opensc-tool`,
`gpg`, and `gpg-connect-agent`.

```bash
cd $HOME/src/nixtropic
bash tools/validate.sh           # full: FIDO2 + OpenPGP — 22 checks
bash tools/validate-fido.sh      # FIDO2 surface only — 5 checks
bash tools/validate-openpgp.sh   # OpenPGP surface only — 17 checks
```

A clean run ends with `FULL VALIDATION PASS`.

---

## 12. Daily-driver use

Same as the README:

```bash
git commit -S -m "..."                # touch SW1 when LED blinks
echo secret | gpg -er self | gpg -d   # encrypt+decrypt round-trip
ssh-add -L                            # print SSH auth key from gpg-agent
```

For FIDO2 / WebAuthn, open <https://webauthn.io> in Firefox and use the
dongle as a security key.

---

## 13. Recovery

See [`RECOVERY.md`](RECOVERY.md).  The DFU recovery + chip-FW check
sequence is identical on Ubuntu — substitute the `dfu-util` /
`chip-fw-version` / `fw-update-chip` commands above for the
`nix run .#…` equivalents.

---

## 14. Things this doc deliberately doesn't do

- **No prebuilt `firmware.bin`.**  No release asset shipped yet; build
  from source.  Tracked informally — open an issue if you'd find a
  prebuilt binary useful.
- **No `.deb` package.**  Out of scope for v0.1.
- **No systemd unit for the dongle itself.**  The dongle is passive; it
  just shows up on USB.  `pcscd` is the only daemon involved.
- **Windows / macOS.**  Untested.  The CCID + HID surfaces should work
  on macOS with Homebrew equivalents; nobody has tried.
