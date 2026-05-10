# Phase 2 Plan — USB CDC ↔ SPI passthrough (replicate stock fw protocol)

> **Audience:** AI coding agents (Claude, Codex, etc.) and the user (Vaios) reviewing before implementation begins.
> **Status:** v1 — DRAFT, awaiting user review. Not started.
> **Goal of this document:** decompose Phase 2 (per `PROJECT.md` §6) into sub-tasks concrete enough to execute, with hardware-in-the-loop pass criteria.
> **Last updated:** 2026-05-10
> **Prerequisite:** Phase 1 complete (commit `4b30bf0`, 11/11 PASS via `validate-phase1`). DO NOT start Phase 2 work until user explicitly approves this plan.

---

## 0. Phase 2 in one sentence

Replace Phase 1's diagnostic-print firmware with a **byte-faithful reimplementation of the stock TS1302 wire protocol** — an ASCII line-based USB CDC protocol that translates hex strings to SPI bytes and exposes a small command set (PWR/CS/CLKDIV/ID/SN/VER/GPO/AUTO/RESET/HELP) — so that **the unmodified host-side `lt-util`** (already packaged via `nix run .#identify`) talks to our firmware as if it were stock and returns the same chip ID byte-for-byte.

**Pass criterion:** with our Phase 2 firmware flashed, `nix run .#identify` succeeds and prints chip ID matching the Phase 0 baseline (`TR01-C2P-T101`, S/N `02001101085B1905090D00000000048B`, silicon rev ACAB) byte-for-byte.

**Stop-here value:** **100% Nix-built, drop-in replacement for stock TS1302 firmware.** Reproducible, auditable, behaves identically over USB. From here onward, every libtropic client (lt-util, libtropic-pkcs11, future lt-rpc, etc.) works against our open firmware exactly as it does against stock.

**Code language:** C only. **Drops** libtropic from the firmware build (Phase 2 is pure passthrough; the host runs libtropic). **Excludes** HID, CCID, FIDO2, OpenPGP, TrustZone, software crypto.

---

## 1. Pre-flight: hardware / protocol concerns

### 1.1 Stock fw wire protocol — VERIFIED ✅
Read end-to-end on 2026-05-10 from stock fw source (`tropic01-stm32u5-usb-devkit-fw` @ `36a40baa`, files: `app/cmd.c`, `app/main.c`, `API.md`) and from the host-side adapter (`libtropic/hal/posix/usb_dongle/libtropic_port_posix_usb_dongle.c`). Confirmed:

- ASCII line protocol over CDC, lines terminated by `\r\n` (firmware) / `\n` (host TX is fine with either)
- Hex-bytes line (e.g. `010202002b98\n`) → CS-low + SPI transfer + CS-high → echo upper-case hex MISO + `\r\n`
- Suffix `x` or `\` keeps CS asserted across multiple hex lines (continuation transfer)
- `lt-util` uses the suffix `x` for every L2 transfer chunk, then issues `CS=0\n` to release CS at end of frame
  - **Naming inversion:** in `lt_port_spi_csn_high()` the host sends `CS=0\n` because firmware's `CS=0` means "CS idle" = wire-level HIGH. (`CS=1` = active = wire-level LOW.) Comment in `libtropic_port_posix_usb_dongle.c:225` flags this.
- Commands: `HELP`, `ID`, `SN`, `VER`, `CS`, `CS=<0|1>`, `PWR`, `PWR=<0|1>`, `GPO`, `CLKDIV`, `CLKDIV=<n>`, `AUTO`, `AUTO=<mode>[,<get_resp>,<no_resp>]`, `RESET`, `BUTTON` (optional)
- Each command terminates with `OK\r\n` on success or `ERROR: <reason>\r\n` on failure
- Lines starting with `#` are silently skipped (remarks) — useful for our boot banner
- Stock baud rate: 115200 (CDC baud is informational; CDC throughput is USB-FS limited regardless)

### 1.2 USB enumeration choice
Currently our firmware enumerates as `0xCAFE:0x4001` (TinyUSB demo defaults from Phase 1 P1.15). Stock fw enumerates as `0x0483:0x5740`. We will **keep `0xCAFE:0x4001`** for Phase 2 (decision P2.3) — this avoids spoofing ST's VID and lets the user distinguish "running custom" from "running stock" via `lsusb`. The `identify` app will be relaxed to accept either VID/PID. `lt-util` itself accepts any device path so this doesn't affect protocol compatibility.

### 1.3 Hardware: same as Phase 1
No new hardware needs. Same TS1302 dongle, same SW1+plug DFU dance, same `sudo nix run .#flash-firmware` (flashes Phase 2 binary in place of Phase 1 once the new derivation builds).

---

## 2. Locked technical decisions

| # | Decision | Rationale |
|---|---|---|
| P2.1 | **Drop libtropic from the firmware build** | Phase 2 is pure byte passthrough. Host's libtropic does L1+L2+L3; firmware just relays bytes USB↔SPI. Saves ~10 KB FLASH, simplifies code, mirrors stock fw exactly. Phase 3+ adds libtropic back when on-chip cryptography is needed. |
| P2.2 | **Reuse Phase 1's clock + USB + GPIO + SPI peripheral init code** | platform/clock.c, platform/gpio.c, usb/usb.c, usb/usb_descriptors.c, usb/tusb_config.h, usb/cdc_io.c stay. tropic/{tropic.c,lt_crypto_stubs.c} are deleted (libtropic gone). New code lives in `firmware/src/cdc_protocol/`. |
| P2.3 | **Keep VID/PID `0xCAFE:0x4001`** | TinyUSB demo defaults, distinct from stock's `0483:5740`. Relax host `identify` app to accept either. Future Phase 8 swaps to a real allocation under [pid.codes](https://pid.codes). |
| P2.4 | **iSerial = `nixtropic-phase2-<chipid8>`** | Static prefix + first 8 hex chars of TROPIC01 chip ID *would be ideal* but requires reading the chip at boot — too complex for Phase 2 since we drop libtropic. Use static `nixtropic-phase2-tsX` (no chip query). `SN` command returns the same string. |
| P2.5 | **Boot banner uses `#` prefix so host parser ignores it** | Stock fw prints `# BUILD DATE: ...\n# RESET TYPE: ...\n` at boot. Lines starting with `#` are silently skipped by `cmd_parse` (verified `cmd.c:400`). Our banner: `# nixtropic phase 2\n# build: <date>\n# fw_id: nixtropic-phase2\n`. |
| P2.6 | **Hex output: upper case, no spaces, line-end `\r\n`** | Match stock fw exactly. `cmd.c:133` uses `OS_PRINTF("%02X", ...)`. Host parser scanf is case-insensitive but match stock byte-for-byte for clean Wireshark/usbmon diffing. |
| P2.7 | **CS state machine** | After hex-bytes line: `if (suffix is 'x' or '\\') keep CS low, else release CS high`. Before hex-bytes line: `if (CS already low) keep it, else assert it`. Manual `CS=1` asserts; `CS=0` releases. Match stock fw `_parse_hex` semantics in `main.c:144`. |
| P2.8 | **CLKDIV: 16 default (3 MHz at 48 MHz fclk)** | Same as Phase 1 SPI prescaler choice. Allowed values: 2, 4, 8, 16, 32, 64, 128, 256 (mapped to `SPI_BAUDRATEPRESCALER_2..256`). Below TROPIC01 max 5 MHz at default. |
| P2.9 | **PWR command toggles PA0 (TROPIC01 power)** | PWR=1 = drives PA0 high (chip on) + 300 ms settle. PWR=0 = drives PA0 low (chip off). State stored in static bool. Same wiring as Phase 1's `tropic_power_on()`. |
| P2.10 | **GPO command reads PB0 (TROPIC01 GPO/IRQ)** | Returns `0` or `1` ASCII line. Configured in Phase 1 already (input pull-down, no IRQ since `LT_USE_INT_PIN` was unset). |
| P2.11 | **AUTO mode: implement** | ~30 LOC. Stock semantics: every 100 ms while CS idle and `auto=1`, send `get_resp` byte; if response != `no_resp`, read 4-byte L2 header then payload+CRC, emit hex line. Used by some L2 reads to avoid host polling. lt-util doesn't use AUTO (it manually polls), but implementing keeps us feature-complete for libtropic-pkcs11 and other clients. |
| P2.12 | **BUTTON command: omit** | TS1302 has only SW1 (BOOT0) which is consumed by DFU entry. Stock fw conditionally compiles BUTTON; we don't include the command at all. lt-util doesn't query BUTTON. |
| P2.13 | **RESET: NVIC_SystemReset()** | Stock fw uses `wd_reset(GPREG_BOOT_REBOOT)` (custom watchdog/GPREG path). We use bare-metal `NVIC_SystemReset()` from CMSIS. Effect: full chip reset; USB re-enumerates within ~2 s. |
| P2.14 | **Line buffer: 1024 B static** | Largest single hex line is L3 ciphertext max (~4112 B → ~8224 hex chars + suffix + newline). But L3 is split across multiple ≤252 B L2 chunks at the TS1302 layer (verified in `libtropic/src/lt_l1.c`). Largest single hex line in practice is L1 max = TR01_L1_LEN_MAX. Use 1024 B for safety; reject longer with `ERROR: USB RX overflow !` (matches stock fw's error message). |
| P2.15 | **Char-at-a-time RX, line-at-a-time dispatch** | TinyUSB CDC RX exposes a byte FIFO; we read bytes via `tud_cdc_read()` non-blocking, accumulate into line buffer, dispatch on `\n` (also accept and strip `\r`). Spaces between hex pairs are tolerated (matches stock `_parse_hex:166-167`). |
| P2.16 | **No libtropic L2/L3 logic on chip** | Firmware does not parse L2 frames, does not validate CRC, does not encrypt. Bytes flow USB→SPI MOSI / SPI MISO→USB exactly. Host's libtropic owns all framing/crypto. |
| P2.17 | **HAL_SPI_TransmitReceive in blocking mode** | Use `HAL_SPI_TransmitReceive(spi, tx, rx, n, HAL_MAX_DELAY)`. Phase 3+ may move to DMA for HID throughput; Phase 2 keeps it simple. At 3 MHz, 252 B chunk = ~700 µs, well under USB CDC SET_LINE_CODING / IN-token deadlines. |
| P2.18 | **No libtropic, but keep the libtropic source pin** | flake.nix keeps the `libtropic` input — host-side `lt-util` and `libtropic-pkcs11` need it. We just don't compile it into the firmware binary. |
| P2.19 | **CMakeLists.txt: COMMENT OUT (don't delete) all libtropic, TROPIC01, lt_crypto_stubs sources from FIRMWARE_SOURCES** | Per user no-delete rule. Sources excluded from build with `# Phase 1 — re-enable in Phase 3 for HID lt-rpc on chip` marker: `libtropic.c`, `lt_crc16.c`, `lt_port_wrap.c`, `lt_l1.c`, `libtropic_l2.c`, `lt_l2_frame_check.c`, `lt_asn1_der.c`, `lt_tr01_attrs.c`, `libtropic_secure_memzero.c`, `libtropic_port_stm32u5xx.c`, `tropic.c`, `lt_crypto_stubs.c`. Defines commented out: `ACAB`, `LT_LOG_ENABLE_ERROR`. **Files stay in tree.** Re-activation in Phase 3 = uncomment ~15 lines. |
| P2.20 | **Heartbeat LED matches stock semantics** | Stock fw: LED ON when "USB connected + ready"; blinking when "powered but USB not OK". Our Phase 2: solid ON when `tud_cdc_connected()` true, slow blink (1 Hz) when CDC not yet enumerated. Brief flash on every SPI transfer (same as stock per `API.md:64`). Replaces Phase 1's heartbeat-only behavior. |
| P2.21 | **Error message strings: byte-exact match with stock** | `ERROR: invalid parameter`, `ERROR: missing parameter`, `ERROR: illegal parameter`, `ERROR: unknown command`, `ERROR: USB RX overflow !` — copy-paste from `cmd.c:21-24` to ensure any host-side error parsing matches. |
| P2.22 | **Spec compliance not stock-byte-exact** | We match the **wire protocol** byte-for-byte, but we are NOT mimicking stock fw's *boot timing*, *USB descriptor strings* (we use `nixtropic phase 2`), or *RESET-type reporting*. Goal is libtropic compatibility, not fingerprint-spoofing stock fw. |
| P2.23 | **Validation app: `validate-phase2` runs `lt-util` and matches output** | New script `tools/validate-phase2.sh`: `lt-util $DEV -i` → grep for `TR01-C2P-T101` + `02001101085B1905090D00000000048B` + ACAB. Exits 0/non-zero. Mirrors validate-phase1's structure. |
| P2.24 | **Combined `flash-and-validate-phase2`** | One-shot regression like Phase 1's `flash-and-validate`: DFU flash → wait for `/dev/ttyACM*` → run validate-phase2. |
| P2.25 | **STATUS.md append + memory note on Phase 2 done** | Same pattern as Phase 1: when validate-phase2 returns PASS, append entry to STATUS.md with byte evidence, write `project_phase2_done.md` memory note. |

---

## 3. Sub-task list

Five groups, sequenced. Each group ends with a build-checkpoint or HW-in-the-loop checkpoint.

### Group A — exclude libtropic from build, scaffold cdc_protocol/

**No-delete rule (per user 2026-05-10):** Phase 1 code stays in tree. Sources are excluded from the CMake build list (commented out with explanatory marker) so they remain visible and one CMake-line edit away from re-activation in Phase 3+.

A1. **Keep** `firmware/src/tropic/{tropic.c,tropic.h,lt_crypto_stubs.c}` on disk. Do NOT delete.
A2. Edit `firmware/CMakeLists.txt`:
    - Comment out (don't delete) libtropic source list and include dirs. Marker: `# Phase 1 — re-enable in Phase 3 for HID lt-rpc on chip.`
    - Comment out `ACAB`, `LT_LOG_ENABLE_ERROR=1` defines (same marker)
    - Comment out `tropic/tropic.c`, `tropic/lt_crypto_stubs.c` from FIRMWARE_SOURCES (same marker)
    - Add new sources: `platform/spi.c` (SPI1 init, direct HAL — replaces what libtropic_port_stm32u5xx.c was doing for us), `cdc_protocol/protocol.c`, `cdc_protocol/parser.c`, `cdc_protocol/hex.c`, `cdc_protocol/cmd.c` (start as stubs)
A3. New file `firmware/src/platform/spi.{h,c}`:
    - `void spi_init(void)` — RCC enable SPI1 + GPIOA AF5 mux on PA5/6/7, configure SPI peripheral mode 0, MSB-first, 8-bit, prescaler /16 (3 MHz at 48 MHz fclk), software NSS (CS managed externally on PA4)
    - `void spi_set_prescaler(uint32_t div)` — for CLKDIV command (Group C)
    - `uint32_t spi_get_prescaler(void)`
    - `int spi_transfer(const uint8_t *tx, uint8_t *rx, size_t n)` — blocking HAL_SPI_TransmitReceive
    - `void spi_cs_assert(void)` / `void spi_cs_release(void)` — drive PA4 low/high
A4. Edit `firmware/src/main.c` (in-place edit, structure preserved):
    - Comment out `#include "tropic/tropic.h"` (same marker)
    - Replace `[boot] nixtropic phase 1 — USB CDC up\n[boot] vid=0xCAFE pid=0x4001\n[hal_rng] ...\n` block with `#`-prefixed banner: `# nixtropic phase 2\n# build: <date>\n# git: <rev>\n`
    - Remove tropic_init/tropic_l2_sweep call + 1.5s deferred init logic
    - Remove `[tick N rng XX]` periodic prints
    - Add `spi_init()` to bringup sequence (between `rng_init()` and `usb_init()`)
    - Add `cdc_protocol_init()` after `usb_init()`
    - Add `cdc_protocol_task()` to main loop (interleaved with `tud_task()`)
A5. **Build checkpoint:** `nix build .#firmware` succeeds; binary boots, LED behavior reasonable; `screen /dev/ttyACMN` shows the `#`-prefixed banner only; no SPI activity (PWR=0 default, chip unpowered).
A6. **HW checkpoint (Group A):** flash, confirm `/dev/ttyACM*` enumerates as `cafe:4001`; banner visible; no protocol activity yet (parser is stub).

### Group B — line buffer + parser core

B1. `firmware/src/cdc_protocol/protocol.h` — public API:
    - `void cdc_protocol_init(void);`
    - `void cdc_protocol_task(void);` — pumps RX byte FIFO, dispatches lines
B2. `firmware/src/cdc_protocol/parser.{h,c}`:
    - 1024 B static line buffer + write index
    - `parser_feed(uint8_t byte)` — accumulate, on `\n` strip trailing `\r`, dispatch via callback
    - On overflow (line > 1023 chars before `\n`): emit `ERROR: USB RX overflow !\r\n`, reset buffer
    - Handle `#` prefix: silently drop
    - Skip leading spaces (matches stock `_tty_rx_parser:200`)
B3. `firmware/src/cdc_protocol/hex.{h,c}`:
    - `hex_to_bin(uint8_t *out, const char *src, size_t out_len)` — parse upper/lower case hex pairs, returns parsed count or -1 on bad char
    - `bin_to_hex_uppercase(char *dest, const uint8_t *src, size_t n)` — emit `%02X` byte hex, no separator
B4. `firmware/src/cdc_protocol/protocol.c`:
    - Wires parser callback to "is it hex bytes? → hex passthrough : → command dispatch"
    - Hex passthrough flow: handle leading `x`/`\` (skip-CS-low), parse hex bytes, optionally drive `CS=low`, do `HAL_SPI_TransmitReceive`, optionally drive `CS=high`, emit hex MISO + `\r\n`
B5. **Build checkpoint:** `nix build .#firmware` succeeds.

### Group C — command implementations

Each command is small (~10 LOC). Order: simple-output first to validate plumbing, then state-changers.

C1. `cmd.c`: command table struct + `cmd_dispatch(line)`:
    - Strip leading spaces
    - Tokenize: `<word>[<= or ?>][<args>]`
    - Lookup case-insensitive
    - Dispatch to handler
    - On success: emit `OK\r\n` (handlers may emit their own data first)
    - On unknown command: `ERROR: unknown command\r\n`

C2. Read-only commands (no `=` form):
    - `HELP` — print help block (terse, matches stock spirit)
    - `ID` — print `ID: nixtropic-phase2\r\n`
    - `SN` — print `SN: <iSerial>\r\n` (same string used in USB descriptor)
    - `VER` — print `VER: FW <git-rev>, HW TS1302, https://github.com/jjacke13/nixtropic\r\n`
    - `GPO` — print `GPO: <0|1>\r\n` based on PB0 read
    - `CS` — print `CS: <0|1>\r\n` (1 if CS line is asserted=LOW)
    - `PWR` — print `PWR: <0|1>\r\n`
    - `CLKDIV` — print `CLKDIV: <n>\r\n` based on current SPI prescaler
    - `AUTO` — print `AUTO: <0>` or `AUTO: 1, <get_resp>, <no_resp>\r\n`
    - `RESET` — print `RESET\r\n`, delay 10 ms, call `NVIC_SystemReset()`

C3. Set commands (`= form`):
    - `CS=<0|1>` — drive PA4 (CS) accordingly
    - `PWR=<0|1>` — drive PA0; on rising edge, 300 ms settle; on falling edge, no special delay
    - `CLKDIV=<n>` — validate n in {2,4,8,16,32,64,128,256}; reconfigure SPI prescaler (must `__HAL_SPI_DISABLE` → write CFG1 PRESC field → `__HAL_SPI_ENABLE`)
    - `AUTO=<state>[,<get_resp>][,<no_resp>]` — set internal flags

C4. AUTO task: 100 ms tick driver in main loop. When `auto=true` and CS idle: send `get_resp` byte via SPI, check response, if != `no_resp` then read 4-byte header + payload + CRC and emit. Match stock `_spi_auto_task:100`.

C5. Heartbeat LED state machine:
    - State 0 (USB not connected): blink 1 Hz
    - State 1 (USB connected, idle): LED solid ON
    - On every SPI transfer: brief LED toggle for ~5 ms (visible as flicker)
    - Driven from main loop's 100 ms tick

C6. **Build checkpoint:** `nix build .#firmware` succeeds; size still under 64 KB FLASH budget.

### Group D — host-side test harness

D1. Edit `nix/apps.nix`:
    - Relax `identify` VID/PID gate from `0483:5740` only to `0483:5740 OR cafe:4001`
    - Add `validate-phase2` app pointing at `tools/validate-phase2.sh`
    - Add `flash-and-validate-phase2` (mirrors `flash-and-validate` but invokes validate-phase2.sh)
D2. `tools/validate-phase2.sh`:
    - Auto-detect `/dev/ttyACMN` (reuse Phase 1's auto-detect snippet)
    - Run `lt-util $DEV -i` with timeout
    - Grep output for: `TR01-C2P-T101`, `02001101085B1905090D00000000048B`, `ACAB` (in lt-util's printed chip ID)
    - 5-check scoreboard: lt-util-runs, long-pn-match, sn-match, silicon-rev-match, lt-util-clean-exit
    - Print PASS / FAIL with diff against Phase 0 baseline on FAIL
D3. **HW checkpoint (Group D):** with Phase 1 firmware still flashed: `nix run .#identify` should now still work against Phase 1 (USB CDC up but not protocol-compatible) → expect failure with informative error. This proves the relaxed-VID gate didn't break Phase 1.

### Group E — first hardware run + iterate

E1. Flash Phase 2 firmware via `sudo nix run .#flash-firmware`.
E2. Confirm `/dev/ttyACM*` enumerates as `cafe:4001`, LED behavior correct (solid ON when host opens CDC).
E3. Manually exercise commands via `nix run .#read`:
    - Type `ID` → expect `ID: nixtropic-phase2\r\nOK\r\n`
    - Type `PWR=1` → LED flickers, expect `OK\r\n`, chip powers up
    - Type `010202002b98x` → expect echo of 6 hex bytes (some MISO), CS stays low
    - Type `CS=0` → CS released, `OK\r\n`
E4. Run `nix run .#identify` → must print full chip ID matching Phase 0 baseline byte-for-byte.
E5. Run `nix run .#validate-phase2` → 5/5 PASS.
E6. **Iterate any failures** until E4 + E5 both pass cleanly.

### Group F — package, document, commit

F1. Update `STATUS.md` with Phase 2 PASS entry: full lt-util output, byte-for-byte match table, scorecard.
F2. Update `PROJECT.md` Last-updated date + mark Phase 2 complete in §6 (mirror what was done for Phase 1).
F3. Memory note: `project_phase2_done.md` with milestone summary + commit hash.
F4. Commit locally as `feat: phase 2 — USB CDC↔SPI passthrough byte-compatible with stock fw`. **Do NOT push** without user permission.

---

## 4. Validation criteria — Phase 2 "complete" when ALL hold

| # | Criterion | How to verify |
|---|---|---|
| 1 | `nix flake check --all-systems` passes | CI |
| 2 | `nix build .#firmware` reproducible (build twice → same hash) | manual `nix-store --query --hash` |
| 3 | Binary size: text+data < 32 KB total | `arm-none-eabi-size firmware.elf` (target: smaller than Phase 1's 35 KB since libtropic is gone) |
| 4 | DFU flash via `sudo nix run .#flash-firmware` succeeds | manual |
| 5 | Host shows `cafe:4001` in `lsusb`; `/dev/ttyACM*` appears within 2 s | manual |
| 6 | `screen /dev/ttyACM0` shows banner: `# nixtropic phase 2` followed by silence (no [boot]/[tick] noise) | manual |
| 7 | All commands respond correctly (manual test of each: HELP, ID, SN, VER, GPO, CS, CS=, PWR, PWR=, CLKDIV, CLKDIV=, AUTO, AUTO=, RESET) | manual |
| 8 | **`nix run .#identify` returns chip ID matching Phase 0 baseline byte-for-byte** | automated via lt-util |
| 9 | `nix run .#validate-phase2` 5/5 PASS | automated |
| 10 | 10/10 cold-boot reset cycles pass `validate-phase2` | manual stress test |
| 11 | DFU recovery via `flash-stock` returns to baseline | proven in Phase 0; recovery path always-on |
| 12 | Phase 1 firmware still works post-Phase 2 build (regression: re-flash Phase 1 via `git checkout 4b30bf0 && nix run .#flash-firmware` → `validate-phase1` 11/11 PASS) | optional: build Phase 1 from stash |

---

## 5. Out of scope (do NOT do in Phase 2)

- HID interface (Phase 3)
- Composite USB descriptors (Phase 3)
- FIDO2 / CTAP2 (Phase 4-5)
- OpenPGP card / CCID (Phase 7)
- TrustZone-M secure-world setup (Phase 4-5)
- Software crypto (TinyCrypt / Monocypher) (Phase 4-5)
- Real VID/PID allocation under pid.codes (Phase 8)
- libtropic on chip — stays host-only (revisited Phase 4-5)
- Stock-byte-exact USB descriptor strings (we keep `nixtropic phase 2` branding)

---

## 6. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Hex parser bug → wrong byte transferred → host gets garbage chip ID | Unit-test hex_to_bin in host build target with edge cases (odd length, mixed case, embedded spaces, invalid chars). Add `tests/host/hex_test.c` compiled in Linux. |
| CS state machine bug → CS released mid-frame → L2 transaction breaks | Match stock `_parse_hex` exactly. Diff our impl against stock byte-for-byte during code review. Validate with manual `nix run .#identify` early in Group E. |
| Race: USB RX byte arrives mid-SPI transfer → reentrancy | RX is polled in main loop via `tud_cdc_read()` only between SPI ops. CDC RX FIFO buffers in TinyUSB — won't lose bytes during a 700-µs SPI burst. |
| AUTO mode interferes with command response timing | Disable AUTO during command dispatch (set internal flag for one tick). Stock fw does same — see `main.c:262`. |
| `NVIC_SystemReset` doesn't trigger USB re-enumeration cleanly | Add 10 ms delay after reset emit so `OK\r\n` flushes. Match stock fw `_cmd_reset:294`. PA12 renumeration trick from Phase 1 still applies post-reset since main re-runs. |
| Line-buffer overflow → DoS | 1024-byte cap + clear error message + reset state. Stock fw also bounds-checks. |
| `lt-util` exits 1 even on success | Read its exit code semantics first; `validate-phase2.sh` may need to grep stdout regardless of exit. Reuse Phase 1's pattern (treat output content as authoritative, exit code as advisory). |
| CLKDIV reconfiguration glitches mid-transfer | Reject `CLKDIV=` if CS is currently asserted (return `ERROR: invalid parameter`). |
| picocom termios race (task #27) returns | We already use `screen` for the `read` app. New `validate-phase2.sh` invokes `lt-util` which has its own termios setup (`libtropic_port_posix_usb_dongle.c:113`). Cleaner than picocom; should not hit this. Verify on first Group E run. |
| Flash binary regressed if HAL warnings re-explode after libtropic removal | Per-source-file warnings disable was on libtropic source files only (already removed). Our new code must be `-Wall -Wextra -Werror` clean from the start. |

---

## 7. Open questions (resolve before Group A starts)

| # | Question | Default if not answered |
|---|---|---|
| Q1 | Keep libtropic input pin in flake.nix (host-side `lt-util` needs it) or switch the firmware build to a separate flake input arrangement? | **Default:** keep current flake.nix structure; libtropic source is already pinned for host packages, just stop compiling it into firmware. |
| Q2 | Do we want a Phase 2 self-test mode (e.g., on first-boot do a TROPIC01 PWR=1 + CS=1 + 0x01 transfer + verify response != 0xFF, blink LED if OK) or pure passthrough only? | **Default:** pure passthrough. Self-test breaks "drop-in replacement" claim and adds code with limited value (host-side `validate-phase2` will exercise the chip end-to-end anyway). |
| Q3 | Should we add a `# git rev: <hash>` line to the boot banner so debugging knows which firmware is running? | **Default:** yes, embed `__GIT_REV__` at build time via Nix (similar to Phase 1's build date approach). Easy + useful. |
| Q4 | LED behavior when chip is unpowered (PWR=0) — same as USB-disconnected (1 Hz blink) or different? | **Default:** USB-state-only LED (1 Hz blink only when CDC not connected, solid ON otherwise). PWR state doesn't affect LED. Matches stock per `API.md:62`. |
| Q5 | Do we need to handle the BUTTON command at all for compatibility? | **Default:** no. lt-util doesn't query BUTTON; libtropic-pkcs11 doesn't either (verified by absence of `BUTTON` string in `libtropic_port_posix_usb_dongle.c`). |

---

## 8. Effort estimate

Phase 2 is narrower than Phase 1 (we already have CDC up + SPI peripheral configured). Estimate:

| Group | Effort | Notes |
|---|---|---|
| A — strip libtropic, scaffold | 30 min | Mechanical edits |
| B — line buffer + parser core | 45 min | Carefully match stock semantics |
| C — command implementations | 75 min | 11 commands, mostly small |
| D — host-side test harness | 30 min | Mostly bash + apps.nix tweaks |
| E — first HW run + iterate | 60 min | Expect ≥1 iteration round |
| F — package + document + commit | 20 min | STATUS, memory, commit |
| **Total** | **~4-5 hours** | Less than Phase 1's ~7 hours |

---

## 9. Once approved → start sequence

1. User reads §2 (locked decisions) and §7 (open questions) and confirms or overrides defaults.
2. User says "go" / "fire it up" / similar.
3. Create Phase 2 task list (Groups A-F).
4. Begin Group A.
5. HW-in-the-loop checkpoints between groups; do NOT skip.
6. After Group F: append STATUS.md, write memory note, commit locally only — wait for user permission to push (matches Phase 1 pattern).

---

*End of PHASE-2-PLAN.md v1*
