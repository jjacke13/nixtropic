# Recovery / Factory-Reset Procedure for TS1302

> **TL;DR:** If your TS1302 dongle stops working after flashing custom firmware, hold SW1 + replug, then run `nix run .#flash-stock`. The TROPIC01 chip itself is **not** affected by STM32 firmware mishaps.

---

## Threat model — what's actually recoverable

The TS1302 dongle has two distinct silicon parts that can fail in different ways. Recovery procedures depend on which has failed.

| Failure | Recoverable? | How |
|---|---|---|
| **STM32U535 firmware corrupt / wrong / unbootable** | ✅ Yes, easily | DFU mode → `nix run .#flash-stock` |
| **STM32U535 brick (RDP level 2)** | ⚠️ Hard — chip is one-way locked | Don't enable RDP=2 in development |
| **TROPIC01 R-config error → Alarm Mode** | ❌ No, permanent | Avoid; see below |
| **TROPIC01 pairing slot SH0 invalidated without replacement** | ❌ No, can't auth | Always set up SH1+ before invalidating SH0 |
| **TROPIC01 firmware corrupt** | ✅ Yes, via `lt_do_mutable_fw_update` | Phase 8 will provide tooling |

**Takeaway:** STM32 firmware mishaps are recoverable in seconds. TROPIC01 mishaps are usually permanent. Phase 0–6 of this project doesn't touch TROPIC01's R-config, so you're in the safe zone.

---

## Standard recovery: re-flash stock firmware via DFU

This is the procedure for any "the dongle isn't behaving right" situation up through Phase 6 of the project.

### Step 1: Enter DFU mode

The STM32U535 has a factory-burned ROM bootloader (CC EAL4+ certified). It always works, regardless of what's in flash, as long as you tell it to run instead of jumping to user firmware. The way to do that is to hold `BOOT0` high at reset.

On TS1302, `BOOT0` is wired to the **SW1 button** (the only button on the dongle).

**Procedure:**
1. **Unplug** the TS1302 dongle from USB
2. **Press and hold** the SW1 button (don't let go yet)
3. **While holding SW1**, plug the dongle into USB
4. **Release SW1** after about 1 second (any time after USB enumeration is fine)
5. The dongle is now in DFU mode

### Step 2: Verify DFU mode

```bash
lsusb | grep "0483:df11"
```

Expected output:
```
Bus XXX Device YYY: ID 0483:df11 STMicroelectronics STM Device in DFU Mode
```

If you don't see this:
- Try unplugging and the SW1-hold sequence again (timing matters)
- Try a different USB cable / port
- If you accidentally see `0483:5740` (CDC-ACM) instead, the dongle is in **app mode**, not DFU mode — that's fine for normal use, only enter DFU if you want to recover

### Step 3: Flash stock firmware

```bash
nix run .#flash-stock
```

This executes `dfu-util -a 0 -s 0x08000000:leave -D <stock-firmware.bin>`:
- `-a 0` — alternate setting 0 (internal flash)
- `-s 0x08000000:leave` — write at address `0x08000000` (start of flash), then automatically jump to user firmware after flashing
- `-D <bin>` — download (host → device) this binary file

The flash takes ~2–3 seconds. The device automatically reboots into the freshly flashed firmware.

### Step 4: Verify recovery

```bash
nix run .#identify
```

Expected: chip ID, firmware versions, certificate info — same as before any custom firmware was flashed.

If `lsusb` shows `0483:5740` and `nix run .#identify` succeeds, the dongle is back to factory state.

---

## What about TROPIC01 itself?

The TROPIC01 chip is a separate piece of silicon connected to the STM32U535 via SPI. It is **completely unaffected** by anything you do to the STM32's firmware:

- Re-flashing the STM32 doesn't touch TROPIC01
- Erasing the STM32's flash doesn't touch TROPIC01
- DFU operations on the STM32 don't touch TROPIC01

The TROPIC01 has its own firmware (Bootloader, Application FW, SPECT FW), its own state (ECC slots, R-mem, R-config, etc.), and its own lifecycle. It can only be modified through libtropic-issued L3 commands over the SPI link.

If you flash random STM32 firmware that opens an L3 session and then issues a malformed `lt_r_config_write`, *that* could brick TROPIC01 (see PROJECT.md §5 critical facts). But Phase 0 firmware (this) and Phases 1–6 (planned) don't touch R-config at all, so the brick path isn't reachable from this project's code.

---

## Edge case: STM32 RDP level 2 lock-out

If — *for some reason* — production firmware sets the STM32U535 Read-Out Protection (RDP) to level 2, the chip enters a permanent locked state where DFU can no longer write to flash. **This is not recoverable.** Don't enable RDP=2 in development. Phase 8 (production polish) is the only phase where RDP=2 is even considered, and only after extensive validation.

This project's development firmware will run at RDP=0 (no lockout, full debug access).

---

## Hardware-level recovery (if all else fails)

If even DFU mode doesn't enumerate (extremely unusual), the STM32U535's SWD debug interface is broken out on the TS1302's debug header (4 pins typically: SWDIO, SWCLK, RST, GND). With an ST-Link or J-Link debugger:

```bash
# In the dev shell
openocd -f interface/stlink.cfg -f target/stm32u5x.cfg -c "init; reset halt; flash erase_address 0x08000000 0x40000; reset run; exit"
```

Then DFU should work again. This is a *very* edge case — DFU mode in factory ROM is extremely robust.

---

## See also

- `PROJECT.md` §4 — TS1302 board pinout, including BOOT0/SW1 (PH3, pin 44)
- `PROJECT.md` §5 — full critical-facts list including the TROPIC01 brick erratum
- `research/stm32u535-inventory.md` §3 — STM32 bootloader details
- Tropic Square's `tropic01-stm32u5-usb-devkit-fw/README.md` — upstream reference for the DFU procedure
