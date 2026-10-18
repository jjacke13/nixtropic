# Windows

The dongle needs no driver on Windows: both interfaces bind to Windows' in-box class
drivers (HID for FIDO2, the Microsoft USB CCID driver for the smart card). Tested on
Windows 11 in a VirtualBox VM with USB passthrough, 18 October 2026, release build.

| Feature | v0.3.0 on Windows 11 |
|---|---|
| USB enumeration, no driver install | works |
| OpenPGP card with Gpg4win / Kleopatra: card view, sign, encrypt, decrypt | works |
| FIDO2 touch (device selection) | works |
| FIDO2 registration and login with a PIN set | **fails** — see [known issue](#known-issue-fido2-with-a-pin) |
| FIDO2 PIN change (Windows Settings) | **reports an error**, although the change completes |
| SSH through gpg-agent | not tested |
| Flashing from Windows | not tested — flash from Linux |

## OpenPGP card

1. Install [Gpg4win](https://gpg4win.org).
2. Create `%APPDATA%\gnupg\scdaemon.conf` (Win+R → `%APPDATA%\gnupg`) with:

    ```text
    disable-ccid
    pcsc-shared
    ```

    The reasons are the same as on Linux: see [Linux setup](linux-setup.md#gnupg).

3. In PowerShell:

    ```powershell
    gpgconf --kill scdaemon
    gpg --card-status
    ```

    If it reports no card, reboot Windows once.

4. Kleopatra → **Tools → Manage Smart Cards** shows the card and its three keys. Import
   your public key (File → Import) and the keys appear with their user IDs:

    ![Kleopatra showing the nixtropic card with its signature, encryption and authentication keys](assets/kleopatra-windows.png)

5. Sign, encrypt and decrypt from Kleopatra's Notepad or the file actions. Each operation
   asks for the user PIN and, with the default touch policy, a press of SW1.

Card setup (PINs, touch policy, key generation) works with `gpg --card-edit` exactly as
described in [card setup](card-setup.md).

## Known issue: FIDO2 with a PIN

In v0.3.0, FIDO2 operations that use the PIN fail on Windows: registration loops back to
the PIN prompt, and a PIN change in *Settings → Accounts → Sign-in options → Security
key* reports "Something went wrong".

The cause is a missing CTAPHID **KEEPALIVE**. While the dongle works on a PIN operation
it sends nothing, and Windows abandons a silent request after a few seconds. USB
captures show it giving up on the PIN token after 2.6 s and on a PIN change after
6.6 s; the dongle's successful answer arrived 1–2 ms later in both cases. v0.3.0's
crash-safe PIN storage makes these operations slower than in v0.2, which worked. Linux
clients wait for the answer and are not affected.

The operations do complete on the dongle, so a PIN change made from Windows may have
taken effect despite the error. The fix — KEEPALIVE packets while the dongle works and
while it waits for a touch, as CTAP recommends — is planned for v0.3.1
([backlog 6.7](backlog.md)).

## Flashing from Windows

Not tested. The STM32 DFU device (`0483:df11`) probably needs [Zadig](https://zadig.akeo.ie/)
to bind WinUSB for `dfu-util.exe`, or ST's STM32CubeProgrammer with its signed driver.
Flash from Linux for now.

## SSH

Not tested. Gpg4win's agent can serve SSH with `enable-win32-openssh-support` in
`gpg-agent.conf` and the built-in `ssh-agent` service disabled.

## Testing in a VirtualBox VM

Pass the dongle through: VM settings → **USB** → enable the USB controller → add a filter
for **nixtropic nixtropic** (`cafe:4001`), or attach it at run time with
**Devices → USB**. While the VM holds the dongle, the Linux host cannot use it; stop the
host's `pcscd` first if it holds the reader.
