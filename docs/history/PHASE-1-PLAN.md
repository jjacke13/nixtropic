# Phase 1 Plan — TROPIC01 L2 round-trip on STM32U535 over USB CDC

> **Audience:** AI coding agents (Claude, Codex, etc.) and the user (Vaios) reviewing before implementation begins.
> **Status:** v3 — **all decisions locked**, ready to begin Group A on user "go".
> **Goal of this document:** decompose Phase 1 (per `PROJECT.md` §6) into sub-tasks concrete enough to execute, with hardware-in-the-loop pass criteria.
> **Last updated:** 2026-05-10
>
> **Version history:**
> - v1 (Path Z): external USB-UART adapter on TS1302 test points. Rejected: requires soldering or flaky SMT clips.
> - v2 (Path Y): USB CDC-ACM via TinyUSB. Eliminates external hardware.
> - **v3 (Path Y, A+C): same USB CDC, but `lt_random_value_get` is dropped from Phase 1 (it requires an L3 secure session, verified against libtropic source). Replaced with broader L2 info command sweep + STM32 onboard HAL_RNG sanity check. Defers all L3-session work to Phase 5 (or an explicit Phase 1.5 if user later wants L3 retired earlier).**

---

## 0. Phase 1 in one sentence

Build the smallest custom firmware that boots on TS1302, brings up **USB CDC-ACM** (`/dev/ttyACM*`) via TinyUSB, powers the TROPIC01 chip, configures SPI1, calls `lt_init` and a sweep of **L2 info commands** (`lt_get_info_chip_id`, `lt_get_info_riscv_fw_ver`, `lt_get_info_spect_fw_ver`, `lt_get_info_fw_bank` for FW1/FW2/SPECT1/SPECT2), plus a side STM32 HAL_RNG sanity check, and prints all of it over USB serial — validating libtropic-on-STM32U535 ↔ TROPIC01 (L1 + L2 layers, **no L3 session**) AND the U535 USB FS path.

Pass criterion: chip ID + RISC-V FW + SPECT FW + FW bank headers all printed via `/dev/ttyACM*` match the Phase 0 baseline (per `STATUS.md` 2026-05-10 entry — `TR01-C2P-T101`, S/N `02001101085B1905090D00000000048B`, silicon rev ACAB).

Stop-here value: first TS1302 firmware that exercises libtropic L1+L2 from the MCU side, with USB CDC ready for Phase 2's class additions.

**Code language:** C only. **Includes USB CDC** for debug/console. **Excludes** L3 secure session, HID, CCID, FIDO2, OpenPGP card, TrustZone, software crypto.

---

## 1. Pre-flight: hardware questions

### 1.1 UART hardware path — RESOLVED ✅
Path Y selected: USB CDC-ACM. No external adapter, no soldering, no test clips. The TS1302's USB-C port is the debug channel.

### 1.2 USB enumeration during Phase 1 — INFORMATIONAL
Our firmware enumerates as USB CDC-ACM with VID/PID `0xCAFE:0x4001` (TinyUSB demo defaults; real allocation deferred). `/dev/ttyACM0` appears after `dfu-util ... :leave` and re-enumeration. `nix run .#identify` (Phase 0 tool) does NOT work — different protocol. Recovery via `sudo nix run .#flash-stock`.

### 1.3 SWD wiring — OPTIONAL, not blocking
TP8/TP9/TP2 + GND for `gdb` breakpoint debug, useful from Phase 4 onward. Not Phase 1 dependency.

---

## 2. Locked technical decisions

| # | Decision | Rationale |
|---|---|---|
| **P1.1** | TZEN = 0 | TZ comes in Phase 5. Phase 1 keeps it simple. |
| **P1.2** | SYSCLK = 48 MHz (matches stock fw); HSI48 + CRS for USB | Stock fw works at this point. HSI48 + CRS independent USB kernel clock per inventory §7. |
| **P1.3** | SPI1 prescaler = ÷16 → 3 MHz | TROPIC01 max SCLK 5 MHz; 48/16 = 3 MHz, safely under. |
| **P1.4** | Driver layer: ST HAL (selectively: SPI, RNG, GPIO, RCC, PWR, CORTEX) | libtropic's U5 port is HAL-based. No `HAL_UART_*`. No `HAL_PCD_*` (TinyUSB owns USB). |
| **P1.5** | Build: CMake + arm-none-eabi-gcc 13.x | Same toolchain as Phase 0 devShell. |
| **P1.6** | No git submodules in `firmware/`; everything fetched via Nix | Reproducibility. |
| **P1.7** | Boot in non-secure flash from `0x0800_0000`. Vector table @ flash base. SRAM1 only (192 KB) | Standard U535 layout, TZEN=0. |
| **P1.8** | No dynamic allocation; libtropic + TinyUSB state are static-allocated | Per PROJECT.md §8. |
| **P1.9** | `LT_USE_INT_PIN` undefined | TS1302 PB0 is GPO, not INT. Per inventory §12. |
| **P1.10** | Pairing keys: `*_prod0` compiled in by default | User's chip is `TR01-C2P-T101` (production). `NIXTROPIC_ENG_KEYS=1` swaps to `*_eng_sample`. **Note: not actually USED in Phase 1 (no L3 session) but compiled in for binary stability across phase boundaries.** |
| **P1.11** | **Phase 1 uses L2 commands only; NO L3 session.** Verified against libtropic source. | **`lt_init` (`src/libtropic.c:39-112`) sets `h->l3.session_status = LT_SECURE_SESSION_OFF` and never starts L3.** **`lt_get_info_chip_id` (`src/libtropic.c:297-330`) uses pure L2 (`lt_l2_send` / `lt_l2_receive`), no session check.** **`lt_random_value_get` (`src/libtropic.c:1196-1222` line 1201) explicitly requires `h->l3.session_status == LT_SECURE_SESSION_ON` and returns `LT_HOST_NO_SESSION` otherwise.** Confirmed by `examples/stm32/nucleo_f439zi/identify_chip/Src/main.c:323` which calls `lt_get_info_chip_id` after `lt_init` only, no `lt_session_start`. |
| **P1.12** | Output format over USB CDC: `[boot]` block + chip ID hex + RISC-V FW + SPECT FW + FW bank headers + HAL_RNG sample. LED solid-on after PASS. | `validate-phase1.sh` parses this. |
| **P1.13** | USB stack: TinyUSB **latest stable tag** (NOT master HEAD), U545 BSP forked → U535 BSP at `firmware/third_party_overlay/tinyusb_bsp_stm32u535/` | PROJECT.md decision #6 already locks TinyUSB. Stable tag minimizes API drift risk. |
| **P1.14** | USB device class: CDC-ACM only (single interface). 4 endpoints used. | Phase 2 adds HID; Phase 7 adds CCID; final composite is CDC + HID + CCID. |
| **P1.15** | VID/PID for Phase 1: `0xCAFE:0x4001` (TinyUSB demo defaults) | Real allocation under [pid.codes](https://pid.codes) deferred to ship-prep. `0x0483:0x5740` (stock) NOT reused — different fw, different identity. |
| **P1.16** | PA12 renumeration trick mirrored from stock fw (drive PA12 LOW for ~50 ms before AF10) | Forces clean USB re-enumeration after firmware swap. Per inventory §7 + stock `app/main.c:42-47`. |
| **P1.17** | `tud_task()` polled in main loop, no RTOS | Adequate for log throughput. |
| **P1.18** | No DMA for SPI or USB | Blocking I/O is fine at this level. DMA is a Phase 8 polish item. |
| **P1.19** | No SWD-based output (ITM/SWO) in Phase 1 | User has no probe yet. Fall back to LED blink codes if pre-CDC failure. |
| **P1.20** | Pre-CDC failure mode: LED blink codes. Post-CDC failure: print to USB CDC AND set LED blink. | Categorical codes — 1=clock, 2=RNG, 3=USB peripheral, 4=USB enumeration, 5=TROPIC01 power-up, 6=`lt_init`, 7=L2 command failure. ~2 Hz rate. |
| **P1.21** | **Phase 1 L2 test surface (chosen for breadth, all exercise different chip subsystems and all are session-less per libtropic source):** `lt_get_info_chip_id`, `lt_get_info_riscv_fw_ver`, `lt_get_info_spect_fw_ver`, `lt_get_info_fw_bank` × 4 banks (FW1, FW2, SPECT1, SPECT2). All proven working in `examples/stm32/nucleo_f439zi/identify_chip/Src/main.c`. | Replaces v2's `lt_random_value_get` (which needs L3). Validates more L2 surface than v2 plan. |
| **P1.22** | **Phase 1 RNG validation: STM32 onboard HAL_RNG, NOT libtropic.** Print 32 bytes from `HAL_RNG_GenerateRandomNumber` over USB CDC. | We're already wiring up `HAL_RNG` for libtropic's `lt_port_random_bytes` (decision B3). Use the same handle for the user-visible "host-side RNG fresh on every reset" sanity check. Decoupled from TROPIC01 RNG (deferred to Phase 5). |
| **P1.23** | Flash app naming: keep `flash-stock` (Phase 0 recovery, unchanged) + add `flash-firmware` for our build | No rename; clear separation between recovery and our firmware. |
| **P1.24** | Heartbeat LED during init: ENABLED (slow blink during boot, solid-on after PASS, blink-code on failure) | More reassuring during multi-second startup, ~30 LOC. |
| **P1.25** | TinyUSB version pin: latest stable tag at flake-input time (not master HEAD) | Reduces API-drift risk vs chasing HEAD. |

---

## 3. Sub-task list

### Group A — Build infrastructure (Nix + CMake + linker, no firmware C)

#### A1. Pin HAL/CMSIS/TinyUSB sources in `flake.nix`
Add inputs as `flake = false`:
- `STMicroelectronics/cmsis_core`
- `STMicroelectronics/cmsis_device_u5`
- `STMicroelectronics/stm32u5xx_hal_driver`
- `hathach/tinyusb` pinned to **latest stable tag** at flake-input time (per P1.25)

Hashes via build-then-fix pattern.
- **Done when:** `flake.nix` evaluates and inputs resolve via `nix flake metadata`.

#### A2. Create `nix/firmware.nix` derivation skeleton
`stdenvNoCC.mkDerivation`, `hardeningDisable = ["all"]`. Build inputs: `gcc-arm-embedded`, `cmake`, `ninja`. Passes `CMSIS_CORE_SRC`, `CMSIS_DEVICE_U5_SRC`, `STM32U5XX_HAL_DRIVER_SRC`, `LIBTROPIC_SRC`, `TINYUSB_SRC` as env vars. `installPhase` copies `firmware.{bin,elf,hex,map}` to `$out/`.
- **Done when:** `nix build .#firmware` runs CMake (errors fine).

#### A3. CMake toolchain file `firmware/cmake/arm-none-eabi.cmake`
`-mcpu=cortex-m33 -mthumb -mfpu=fpv5-sp-d16 -mfloat-abi=hard -DSTM32U535xx`. Strict warnings: `-Wall -Wextra -Werror -Wconversion -Wshadow -Wundef -Wcast-align -Wstrict-prototypes`. Size: `-ffunction-sections -fdata-sections -Wl,--gc-sections`. C standard: `-std=c11`. Define `USE_HAL_DRIVER`, `STM32U535xx`, `CFG_TUSB_MCU=OPT_MCU_STM32U5`.
- **Done when:** CMake configure step succeeds inside Nix build.

#### A4. `firmware/CMakeLists.txt` top-level
Subdirs: `src/`, `linker/`, `third_party_overlay/`. libtropic via `add_subdirectory(${LIBTROPIC_SRC})` with `LT_HAL=stm32u5xx`. TinyUSB compiled directly (`tusb.c` + relevant class drivers + our BSP overlay). Build target `firmware.elf` → custom command produces `.bin` and `.hex` via `arm-objcopy`.
- **Done when:** `nix build .#firmware` reaches linker step.

#### A5. Linker script `firmware/linker/stm32u535.ld`
Flash 256K @ 0x08000000, SRAM1 192K @ 0x20000000. ISR vector at flash base. `.text`, `.rodata`, `.data` (init from flash → SRAM), `.bss`, `_estack` at SRAM end. No TZ splits.
- **Done when:** linker resolves all sections; ELF inspectable.

#### A6. Startup file `firmware/src/platform/startup_stm32u535xx.s`
Reuse from `cmsis_device_u5` if it ships one for U535; otherwise hand-write (default ISR table → `Default_Handler` weak-aliased; `Reset_Handler` copies `.data`, zeros `.bss`, calls `SystemInit()`, then `main()`).
- **Done when:** `Reset_Handler` resolves and `main` is referenced from vector table.

### Group B — Platform basics (firmware C, no USB yet)

#### B1. `platform/clock.c` — clock tree to 48 MHz + HSI48 for USB
HSE 8 MHz crystal X1 → PLL ×96/16 → 48 MHz SYSCLK. `LL_PWR_REGU_VOLTAGE_SCALE3`. Flash latency = 1 wait state.
**Independently:** enable HSI48, configure CRS for SOF auto-trim, route HSI48 to USB peripheral kernel clock. Per inventory §7 and stock fw `sys.c:84-92`.
- **Done when:** SysTick increments at 1 ms; `RCC_CR.HSI48RDY = 1`.

#### B2. `platform/gpio.c` — pin assignments (no UART, no DMA)
- PA9 → output (LED, push-pull)
- PA0 → output (TROPIC01 power switch IC4 enable; default LOW)
- PA4 → output (SPI CS; lt_port_init does the OUTPUT_PP + PULLUP setup, but we still enable GPIOA clock)
- PA5/PA6/PA7 → AF5 (SPI1 SCK/MISO/MOSI; speed HIGH; pull on MISO)
- PA11/PA12 → AF10 USB DM/DP **only after** the renumeration trick (see C4)
- PB0 → input (TROPIC01 GPO; pull-down; no IRQ)
- PH3 → input (BOOT0/SW1; not used in firmware logic; clock enabled for future)
- RCC AHB clocks: GPIOA, GPIOB, GPIOH
- **Done when:** scope or LED probe verifies pin states post `gpio_init()`.

#### B3. `platform/rng.c` — HAL_RNG init (used by both libtropic AND our P1.22 sanity check)
Stock fw doesn't enable RNG. libtropic `lt_port_random_bytes` requires `device->rng_handle` + `HAL_RNG_MODULE_ENABLED`. Init `RNG_HandleTypeDef`, sanity-test (4 bytes, NOT printed yet — USB isn't up). Same handle reused for P1.22 32-byte sanity dump after USB is up.
- **Done when:** RNG self-test passes; LED blink-code 2 on failure.

#### B4. `platform/stm32u5xx_hal_conf.h` — minimal HAL config
Enable: `HAL_RCC_MODULE_ENABLED`, `HAL_GPIO_MODULE_ENABLED`, `HAL_SPI_MODULE_ENABLED`, `HAL_RNG_MODULE_ENABLED`, `HAL_PWR_MODULE_ENABLED`, `HAL_CORTEX_MODULE_ENABLED`. **Disable:** `HAL_UART_*`, `HAL_PCD_*`. HSE_VALUE=8000000, HSI48_VALUE=48000000.
- **Done when:** HAL-using compile units link without unresolved symbols.

#### B5. `platform/blink.c` — LED blink codes + heartbeat (decision P1.24)
Public API:
- `blink_set_pattern(uint8_t code)` — 0 = off, 1+ = N-blink-pause repeating
- `blink_set_solid(void)` — solid on (PASS state)
- `blink_set_heartbeat(void)` — slow ~1 Hz heartbeat during init phase
Driven by SysTick callback.
- **Done when:** `blink_set_heartbeat()` produces visible 1 Hz blink; `blink_set_solid()` produces solid; `blink_set_pattern(3)` produces 3-blink-pause loop.

### Group C — USB CDC stack (highest-risk group)

#### C1. Pull TinyUSB sources via Nix (per P1.25)
Pin TinyUSB at latest stable tag. Verify it includes the U5-relevant FS device driver — likely `src/portable/synopsys/dwc2` for U5xx. Confirm by reading `hw/bsp/stm32u5/family.c`.
- **Done when:** `TINYUSB_SRC` env var points to a tree containing the FS device driver.

#### C2. Fork U545 BSP → U535
Copy `tinyusb/hw/bsp/stm32u5/boards/stm32u545nucleo/` into `firmware/third_party_overlay/tinyusb_bsp_stm32u535/`. Adjust:
- Include `stm32u535xx.h` instead of `stm32u545xx.h`
- Disable BSP LED references (we use our own `blink.c`)
- Verify clock setup uses HSI48 + CRS
- Remove any U545-specific peripheral references (none expected — USB-relevant code identical between U545 and U535)
- **Done when:** BSP `family.c` and `board.h` build cleanly against `stm32u535xx.h`.

#### C3. USB peripheral pre-init — VDDUSB enable
Per inventory §13.5 + stock `sys.c:25`: set `PWR_SVMCR_USV` BEFORE any USB peripheral access.
- **Done when:** `PWR->SVMCR & PWR_SVMCR_USV` reads as 1 before USB init.

#### C4. PA12 renumeration trick (P1.16)
Drive PA12 LOW as GPIO output for ~50 ms before handing to AF10. Mirror stock fw `app/main.c:42-47`.
- **Done when:** scope or kernel log shows USB disconnect → reconnect cycle.

#### C5. TinyUSB device descriptors — `firmware/src/usb/usb_descriptors.c`
- Device descriptor: VID=0xCAFE, PID=0x4001 (P1.15), USB 2.0 FS, manufacturer "nixtropic", product "nixtropic phase 1", serial = "0001"
- Configuration descriptor: 1 interface (CDC), 4 endpoints (control + IN + OUT + interrupt-IN)
- String descriptors: en-US
- **Done when:** descriptor C struct compiles; `tud_descriptor_*` callbacks wired.

#### C6. TinyUSB main bring-up — `firmware/src/usb/usb.c`
- `tusb_init()` after clock + GPIO + VDDUSB ready
- USB IRQ handler routes to `dcd_int_handler(0)`, NVIC priority below SysTick
- Main loop polls `tud_task()`
- **Done when:** `lsusb` shows `0xCAFE:0x4001`; `dmesg | tail` shows `cdc_acm` attaching; `/dev/ttyACM*` exists.

#### C7. CDC TX glue — `firmware/src/usb/cdc_io.c`
- `cdc_putchar(char c)` → `tud_cdc_write_char()` + opportunistic flush
- `_write` retarget for newlib so `printf`/`vprintf` route through `cdc_putchar`
- libtropic's `lt_port_log` (`vprintf` + `fflush(stdout)`) lands here
- **Done when:** `printf("[boot] hello\n")` reaches `picocom -b 115200 /dev/ttyACM0`.

### Group D — TROPIC01 round-trip (libtropic glue + main app)

#### D1. TROPIC01 power sequencing
Drive PA0 HIGH to enable IC4 load switch. Wait ≥50 ms for chip stabilization. Mirror stock `HW_CHIP_PWR_OFF` → init → `HW_CHIP_PWR_ON` (`stock app/main.c:51-54`).
- **Done when:** `[boot] TROPIC01 power: ON` reaches host; subsequent SPI succeeds.

#### D2. Populate `lt_dev_stm32u5xx_t`, call `lt_init`
```c
static lt_dev_stm32u5xx_t device = {
    .spi_instance       = SPI1,
    .baudrate_prescaler = SPI_BAUDRATEPRESCALER_16,  /* 3 MHz */
    .spi_cs_gpio_pin    = GPIO_PIN_4,
    .spi_cs_gpio_bank   = GPIOA,
    .rng_handle         = &g_rng_handle,
};
static lt_handle_t handle;
lt_ret_t r = lt_init(&handle, &device);
```
**Verified behavior** (per P1.11 / `src/libtropic.c:39-112`): `lt_init` initializes handle, calls `lt_l1_init`, sets `session_status = LT_SECURE_SESSION_OFF`, checks chip mode via `lt_get_tr01_mode`, reboots into Application mode if needed. **No L3 session, no pairing keys consumed.**
- **Done when:** `[boot] lt_init: OK` prints over CDC.

#### D3. L2 info command sweep (decision P1.21)
Call in order, print each result over USB CDC in same field layout as Phase 0 `nix run .#identify` output (for diff-friendly comparison):

1. `lt_get_info_chip_id(&handle, &chip_id)` → all chip-ID fields (silicon_rev, package_id, long_pn, S/N, batch_id, fab_id, prov_template_v, MAN_FUNC_TEST)
2. `lt_get_info_riscv_fw_ver(&handle, ver)` → 4 bytes
3. `lt_get_info_spect_fw_ver(&handle, ver)` → 4 bytes
4. `lt_get_info_fw_bank(&handle, TR01_FW_BANK_FW1, header, sizeof(header), &header_read_size)` — and same for `FW2`, `SPECT1`, `SPECT2`

Each function uses pure L2 framing (verified: `src/libtropic.c:297-330` + parallel impls for the FW-version variants); none require L3 session.

Expected output structure (per Phase 0 baseline):
```
[chip_id]
  silicon_rev: 0x41434142 (ACAB)
  package_id:  0x80AA (QFN32)
  long_pn:     TR01-C2P-T101
  serial:      02001101085B1905090D00000000048B
  ...
[riscv_fw]: <hex>
[spect_fw]: <hex>
[fw_bank FW1]: <hex header>
[fw_bank FW2]: <hex header>
[fw_bank SPECT1]: <hex header>
[fw_bank SPECT2]: <hex header>
```
- **Done when:** `validate-phase1.sh` returns zero diff vs Phase 0 baseline for chip_id; FW versions and bank headers also captured.

#### D4. STM32 HAL_RNG sanity dump (decision P1.22)
Call `HAL_RNG_GenerateRandomNumber` 8× to fill a 32-byte buffer. Print over USB CDC. **NOT a TROPIC01 RNG check** — that needs L3 session and is deferred. This validates the host-MCU RNG is alive (we'll need it for libtropic's port and for any future host-MCU crypto).

Sanity heuristics (in `validate-phase1.sh`):
- Not all-zero, not all-`0xff`
- Shannon-entropy estimate > 7.5 bits/byte
- Two cold-boot runs return different bytes
- **Done when:** sanity heuristics pass twice across two cold-boot reset cycles.

#### D5. Cold-boot stress: 10 power-cycles
Unplug + replug 10×. Each cycle: D2/D3/D4 all PASS, output identical (modulo HAL_RNG fresh entropy). **No L3 session = no pairing-key state = no risk of chip-side state corruption.**
- **Done when:** 10/10 cycles PASS.

#### D6. PASS/FAIL LED indicator
After D1–D4 succeed: `blink_set_solid()` → PA9 LED solid ON. On failure: `blink_set_pattern(N)` per P1.20 category code + error text over CDC.
- **Done when:** LED states correctly distinguish PASS vs FAIL vs failure-category.

### Group E — Validation & ship

#### E1. `nix run .#flash-firmware` (decision P1.23)
Mirrors `flash-stock` pattern. Same DFU dance, same benign-tail-error handling.
- **Done when:** `sudo nix run .#flash-firmware` flashes and dongle re-enumerates as `0xCAFE:0x4001` showing `/dev/ttyACM*`.

#### E2. `nix run .#read` — picocom wrapper
`picocom -b 115200 /dev/ttyACM0`. Optional `TROPIC_DEV=/dev/ttyACM1` override.
- **Done when:** opening this app shows boot text seconds after plug.

#### E3. `tools/validate-phase1.sh` — host-side validator
Reads `/dev/ttyACM*` for 5 s after reset. Parses `[chip_id]`, `[riscv_fw]`, `[spect_fw]`, `[fw_bank ...]`, `[hal_rng]` blocks. Compares chip_id + FW versions + bank headers against `STATUS.md` Phase 0 baseline (extracted from STATUS.md so always in sync). Sanity-heuristic checks on `[hal_rng]`. Exits 0 PASS, non-zero FAIL with diff. Wraps as `nix run .#validate-phase1`.
- **Done when:** PASS against freshly-flashed Phase 1 firmware.

#### E4. STATUS.md entry on PASS
`## 2026-MM-DD — Phase 1 FULLY VALIDATED ✅` block in same style as Phase 0. Snapshot libtropic SHA, HAL SHA, TinyUSB tag, firmware ELF hash.
- **Done when:** STATUS.md updated and committed locally.

---

## 4. Validation criteria — Phase 1 "complete" when ALL hold

| # | Criterion | Verify by |
|---|---|---|
| 1 | `nix flake check --all-systems` passes | CI |
| 2 | `nix build .#firmware` reproducible (build twice → same hash) | manual |
| 3 | `firmware.elf` text+data: < 64 KB total | `arm-none-eabi-size` |
| 4 | `sudo nix run .#flash-firmware` succeeds | hardware |
| 5 | Host shows `0xCAFE:0x4001` in `lsusb`; `/dev/ttyACM*` appears within 2 s of reset | `lsusb` + `ls /dev/ttyACM*` |
| 6 | `picocom /dev/ttyACM0` shows full `[boot]` block within 1 s | manual |
| 7 | **All L2 info fields match Phase 0 baseline byte-for-byte: chip ID + RISC-V FW + SPECT FW + 4 FW bank headers** | `validate-phase1.sh` |
| 8 | **STM32 HAL_RNG output: 32 bytes, sanity heuristics pass, fresh per cold-boot** | `validate-phase1.sh` |
| 9 | LED solid-on indicator post-success; categorized blink-code on failure | visual |
| 10 | 10/10 cold-boot reset cycles pass | manual |
| 11 | DFU recovery via `sudo nix run .#flash-stock` returns to baseline (regression check) | manual |

---

## 5. Out of scope (do NOT do in Phase 1)

- **L3 secure session establishment (`lt_session_start`)** — defers to Phase 5 (or explicit Phase 1.5 if user later wants L3 retired earlier)
- **Any libtropic L3 commands**: `lt_random_value_get` (TROPIC01 TRNG), `lt_ecc_*` (key gen, sign, verify), `lt_r_mem_*`, `lt_mac_and_destroy_*`, `lt_session_abort`, `lt_get_log` — **all require L3 session**
- HID interface (Phase 3+)
- CCID / OpenPGP card (Phase 7)
- FIDO2/CTAP2 (Phase 4–5)
- TrustZone-M setup (Phase 5)
- R-mem / R-config / I-config touch
- Pairing-key invalidation
- Software crypto (TinyCrypt, Monocypher) — Phase 5
- Real VID/PID allocation (deferred to ship-prep)
- Power optimization / Stop modes
- 160 MHz clock — stays at 48 MHz
- DMA-driven SPI or USB
- Serial number from STM32 unique device ID (cosmetic; deferred)
- Interactive CDC RX (Phase 1 is TX only)

---

## 6. Risks and mitigations

| Risk | Mitigation |
|---|---|
| ~~`lt_init` requires L3 session before chip-ID query~~ | **RESOLVED v3:** verified against `src/libtropic.c:39-112` + working F439ZI example. P1.11 is correct. |
| U545→U535 BSP fork has hidden assumption | Read U545 BSP top-to-bottom before forking. Diff vs U5A5 BSP for "what's actually different" reference. Worst case: write minimal BSP from scratch using `dcd_stm32_fsdev` directly. |
| HSI48 + CRS not stable enough for USB FS without crystal | Inventory §7 explicit: "no crystal needed for USB" — stock fw proves this. If `usb device descriptor read error`: re-check CRS source register. |
| `PWR_SVMCR_USV` not set → USB hangs silently | Inventory §13.5 explicit. Set in pre-init. Verify by read-back. |
| PA12 renumeration trick missed → host caches stale state | Mirror stock fw exactly. Worst case: physical unplug/replug. |
| TinyUSB stable-tag has API-breaking changes vs documented examples | Pin to a recent stable tag verified to compile against ours BSP. Don't chase HEAD. |
| TS1302 TROPIC01 power-up quirk we don't see in libtropic | Mirror stock OFF→init→ON pattern. Longer delay if flaky. |
| `arm-none-eabi-gcc` 13 vs libtropic CI (typically 11) — strict warnings differ | Drop individual flags before `-Werror`. Last resort: pin gcc-arm-embedded-11. |
| TinyUSB and libtropic symbol collisions | Compile each in own static library; resolve at link time. |
| Firmware stuck wedged | Phase 0 recovery: hold SW1, replug, `sudo nix run .#flash-stock`. Always available. |
| **L2 command output format changes between libtropic versions** | New low-prob risk: pin libtropic to v3.2.1 (already done). If v4 changes `lt_chip_id_t` struct layout, version-aware parser in validate script. |

---

## 7. Open questions — ALL RESOLVED ✅

| # | Question | Resolution (2026-05-10) |
|---|---|---|
| 1 | VID/PID for Phase 1 | TinyUSB demo `0xCAFE:0x4001`. Real allocation deferred to ship-prep. |
| 2 | Flash app naming | Keep `flash-stock` + add `flash-firmware`. No rename. (P1.23) |
| 3 | Heartbeat LED during init | Yes, enabled. (P1.24) |
| 4 | Verify P1.11 (chip-ID query without L3 session) against libtropic source | **Done.** P1.11 split into verified facts: `lt_get_info_chip_id` works without session ✅; `lt_random_value_get` requires session ❌ → dropped from Phase 1, replaced with broader L2 sweep (P1.21) + STM32 HAL_RNG (P1.22). |
| 5 | TinyUSB version pin | Latest stable tag, not master HEAD. (P1.25) |

---

## 8. Effort estimate

| Group | Sub-tasks | Estimated session hours | Notes |
|---|---|---|---|
| A — Build infra | 6 (A1–A6) | 2–4 h | Mostly mechanical Nix/CMake plumbing. |
| B — Platform basics | 5 (B1–B5) | 2–4 h | Clock + GPIO + RNG + HAL config + blink/heartbeat. |
| C — USB CDC | 7 (C1–C7) | 4–7 h | TinyUSB integration + U535 BSP fork. **Highest-risk group.** |
| D — TROPIC01 | 6 (D1–D6) | 1–3 h | L2 sweep + HAL_RNG. Few hundred LOC. |
| E — Ship | 4 (E1–E4) | 1–2 h | Apps + validator + STATUS. |
| **Total** | **28 sub-tasks** | **10–20 h focused** | HW-in-the-loop checkpoints at end of B, C, D, E. |

---

## 9. Once approved → start sequence

1. Update `STATUS.md` with "Phase 1 plan v3 approved YYYY-MM-DD" entry.
2. Begin Group A (build infrastructure). No firmware C until A4 reachable.
3. HW-in-the-loop checkpoint at end of B (LED heartbeat verifies clock + GPIO; blink-code on failure verifies categorized error path).
4. HW-in-the-loop checkpoint at end of C (CDC enumerates as `/dev/ttyACM*`, `picocom` shows boot text).
5. HW-in-the-loop checkpoint at end of D (L2 sweep matches Phase 0 baseline; HAL_RNG sanity passes).
6. HW-in-the-loop checkpoint at end of E (`validate-phase1.sh` returns PASS).
7. Update `PROJECT.md` only on phase boundary completion.

---

*End of Phase 1 plan v3.*
