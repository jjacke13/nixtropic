# Linux setup

The dongle needs no kernel driver. What the host needs:

| Component | Needed for | Package (Debian/Ubuntu) |
|---|---|---|
| `libfido2` | FIDO2 command-line tools (`fido2-token`); browsers bring their own FIDO stack | `libfido2-1`, `fido2-tools` |
| `pcscd` + `libccid` | The OpenPGP card (CCID smart-card reader) | `pcscd`, `libccid` |
| `gnupg`, `scdaemon` | gpg signing, decryption, SSH agent | `gnupg`, `scdaemon` |
| udev rules | Access without root; keep ModemManager away | see below |
| libccid patch | libccid does not know `cafe:4001` yet | see below |

On **NixOS** one module does all of it. On other distributions follow the manual
steps.

## NixOS

```nix
{
  inputs.nixtropic.url = "github:jjacke13/nixtropic";

  # configuration.nix
  imports = [ inputs.nixtropic.nixosModules.tropic ];
  services.tropic.enable = true;
  services.tropic.users = [ "your-username" ];   # adds you to the `tropic` group
}
```

The module installs the udev rules for all three USB identities, enables `pcscd`
with a patched `libccid`, and creates the `tropic` group. `services.tropic.enableCcid
= false` skips `pcscd` if you only use FIDO2. Then continue with
[GnuPG configuration](#gnupg).

## Other distributions

```bash
sudo apt install -y pcscd libccid pcsc-tools libfido2-1 fido2-tools gnupg scdaemon opensc
```

### udev rules

```bash
sudo groupadd -f tropic
sudo usermod -aG tropic "$USER"      # log out and back in afterwards

sudo tee /etc/udev/rules.d/70-nixtropic.rules >/dev/null <<'EOF'
# Stock firmware (USB serial bridge)
SUBSYSTEM=="tty", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="5740", GROUP="tropic", MODE="0660", SYMLINK+="tropic01", ENV{ID_MM_DEVICE_IGNORE}="1", TAG+="uaccess"
SUBSYSTEM=="usb", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="5740", GROUP="tropic", MODE="0660", ENV{ID_MM_DEVICE_IGNORE}="1", TAG+="uaccess"
# nixtropic: no GROUP on the usb node, pcscd may run as its own user and needs it
SUBSYSTEM=="usb", ATTRS{idVendor}=="cafe", ATTRS{idProduct}=="4001", MODE="0660", ENV{ID_MM_DEVICE_IGNORE}="1", TAG+="uaccess"
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="cafe", ATTRS{idProduct}=="4001", GROUP="tropic", MODE="0660", TAG+="uaccess"
# STM32 DFU bootloader
SUBSYSTEM=="usb", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="df11", GROUP="tropic", MODE="0660", ENV{ID_MM_DEVICE_IGNORE}="1", TAG+="uaccess"
EOF
sudo udevadm control --reload-rules && sudo udevadm trigger
```

`ID_MM_DEVICE_IGNORE` stops ModemManager from probing the serial port. The `hidraw`
rule lets browsers open the FIDO interface even where the `security-device` tag is
missing.

### The libccid patch

`libccid` drives only readers on its built-in VID:PID list, and nixtropic still uses
TinyUSB's demonstration ID `cafe:4001` (a registered ID is on the
[backlog](backlog.md)). Without the patch `pcscd` sees the device, refuses to drive
it, and `gpg --card-status` says `No such device`.

```bash
INFO=/usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist
sudo cp "$INFO" "$INFO.bak"
sudo awk '
  /<key>ifdVendorID<\/key>/     { stage="vid";  print; next }
  /<key>ifdProductID<\/key>/    { stage="pid";  print; next }
  /<key>ifdFriendlyName<\/key>/ { stage="name"; print; next }
  /<\/array>/ {
    if (stage == "vid")  print "\t\t<string>0xCAFE</string>"
    if (stage == "pid")  print "\t\t<string>0x4001</string>"
    if (stage == "name") print "\t\t<string>nixtropic CCID Reader</string>"
    stage = ""; print; next
  }
  { print }
' "$INFO.bak" | sudo tee "$INFO" >/dev/null
grep -q 0xCAFE "$INFO" && sudo systemctl restart pcscd
```

A `libccid` package update reverts the patch; run the block again afterwards.

## GnuPG

These settings apply to every distribution, NixOS included.

```ini title="~/.gnupg/scdaemon.conf"
disable-ccid
pcsc-shared
```

```ini title="~/.gnupg/gpg-agent.conf"
enable-ssh-support
```

```bash
gpgconf --kill scdaemon
gpg-connect-agent updatestartuptty /bye
gpg --card-status
```

Why both `scdaemon` options:

- **`disable-ccid`** makes `scdaemon` use `pcscd` instead of its own USB driver.
  With the built-in driver, `scdaemon` claims the CCID interface directly; when the
  browser then uses the FIDO interface of the same device, the claim can hang until
  the dongle is replugged. Through `pcscd` the two interfaces stay independent.
- **`pcsc-shared`** opens the reader in shared mode, so a restarted `scdaemon` or a
  second program can attach without restarting `pcscd`.

!!! note "YubiKey users"
    With `disable-ccid` + `pcsc-shared`, a YubiKey also goes through `pcscd` and may
    ask for its PIN more often. If that bothers you, comment the two lines out while
    the nixtropic dongle is not in use.

## After a replug

`scdaemon` keeps a handle to the old USB device. After every flash, reboot or replug:

```bash
gpgconf --kill scdaemon     # host-side handle only, the card loses nothing
gpg --card-status
```

If it still says `No such device`, restart `pcscd` (`sudo systemctl restart pcscd`)
and then unplug and replug the dongle: `pcscd` attaches a reader only on a USB
plug event.

## SSH

With `enable-ssh-support`, `gpg-agent` serves the card's authentication key:

```bash
export SSH_AUTH_SOCK="$(gpgconf --list-dirs agent-ssh-socket)"
ssh-add -L          # the public key to put in authorized_keys
```

## FIDO2 troubleshooting

Work down the list:

1. Enumerated? `lsusb | grep cafe:4001`
2. Seen by libfido2? `fido2-token -L`
3. Answers GetInfo? `fido2-token -I /dev/hidrawN`
4. Browser access? `ls -l /dev/hidrawN` should show a `+` (ACL for your user);
   `udevadm info /dev/hidrawN | grep TAGS` should include `uaccess`.
5. Browser logs: `about:webauthn` in Firefox, `chrome://device-log` in Chromium.

More WebAuthn detail: [WebAuthn notes](webauthn.md).

## Windows and macOS

Windows 11 (tested 18 October 2026 in a VirtualBox VM with USB passthrough):

- **OpenPGP card: works.** Install [Gpg4win](https://gpg4win.org), put the same two lines
  in `%APPDATA%\gnupg\scdaemon.conf`, then `gpgconf --kill scdaemon` (or reboot).
  Kleopatra (*Tools → Manage Smart Cards*) shows the card; signing, encryption and
  decryption work.
- **FIDO2 with a PIN: does not work in v0.3.0.** The dongle sends no CTAPHID KEEPALIVE
  while it works, and Windows abandons a silent request after a few seconds (about
  2.6 s for the PIN token, 6.6 s for a PIN change); PIN operations take longer than that
  since v0.3.0’s crash-safe PIN storage. The operations complete on the dongle, but
  registration loops and a PIN change reports an error. The fix is planned for v0.3.1
  ([backlog 6.7](backlog.md)). v0.2 worked.
- Flashing from Windows and macOS are untested.
