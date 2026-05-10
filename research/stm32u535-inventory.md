# STM32U535 + TS1302 Inventory

_Captured 2026-05-09. Target: TS1302 USB devkit by Tropic Square. MCU: STM32U535CCTx (LQFP-48). Purpose: ground a Phase-0 firmware design that replaces stock USB-CDC-ACM passthrough with USB HID (FIDO2) + USB CCID (OpenPGP card) composite._

Sources cited inline as `[<short>:<location>]`:
- **DS14217 r2** = STM32U535xx datasheet, July 2023, Rev 2 (300 pp). Cited as `[DS14217 §X]`.
- **TS-SCH** = `tropic01-stm32u5-usb-devkit-hw/TS1302_design/ts1302_schematics.pdf` (KiCad sheet, rev TS1302, 2025-02-25).
- **TS-FW** = `tropicsquare/tropic01-stm32u5-usb-devkit-fw` (master branch; ts1302 tag for shipped FW).
- **lt-port** = `libtropic/hal/stm32/stm32u5xx/libtropic_port_stm32u5xx.{c,h}` (master).

> **Headline finding (read this before everything else):** the **STM32U535 has NO AES, NO PKA, NO SAES, NO MCE, NO BHK, NO SFI**. The "U5 family security" marketing applies to U575/U585; on U535 the only crypto blocks are **HASH (SHA-1, SHA-2/SHA-256)** and **TRNG**. All AES, ECDSA, EdDSA must run in software (or be delegated to TROPIC01). The big U5 security toolkit referenced in many STM AppNotes (BHK / MCE / SAES / OBKey) — none of it is on this die. See [DS14217 §3, Table 2, p17–18] and §3.34, 3.35 (only RNG + HASH peripherals listed).

---

## 1. MCU overview

- **Core**: Arm Cortex-M33 r0p4, single-precision FPU (FPv5-SP-D16), DSP, MPU, **TrustZone-M (Armv8-M Main extension)**. [DS14217 §3.1, p20] [TS-FW: `app/Makefile` → `-mcpu=cortex-m33 -mfpu=fpv4-sp-d16 -mfloat-abi=hard`]
- **Max frequency**: 160 MHz, delivers 240 DMIPS, 651 CoreMark (4.07/MHz). [DS14217 cover, §2 p15]
  - **Note**: TS1302 stock firmware runs the part at only **48 MHz** (HSE-PLL `8/2*96/8 = 48`), set by `LL_RCC_PLL1_ConfigDomain_SYS(LL_RCC_PLL1SOURCE_HSE, 2, 96, 8)` and `LL_PWR_REGU_VOLTAGE_SCALE3` (lowest range). [TS-FW: `sdk/drv_u5/sys.c:71-86`] [TS-FW: `hw/pcd_ts1302.h:7` — `#define SYSCLK 48000000`]. Custom firmware may go higher: SCALE1 → 160 MHz.
- **Process**: ST 40 nm (advertised as 40 nm ULP for STM32U5 series). DS14217 does not state node directly; figure is from STM32U5 marketing decks.
- **Operating voltage**: 1.71 V – 3.6 V (VDD); VDDUSB 3.0–3.6 V; VDDA up to 3.6 V. [DS14217 §3.9.1 p32]
- **Operating temperature**: –40 °C / +85 °C (J-suffix +105 °C junction) or –40 °C / +125 °C (junction +130 °C). [DS14217 §2 p18]
  - **Constraint**: TROPIC01 I-Memory (one-way config) is rated only −20 / +85 °C, narrower than the U535. Don't co-locate the assembled TS1302 in a hot environment if I-config writes are pending.

### STM32U535 vs STM32U545

DS14217 covers **both** STM32U535 and STM32U545 (same datasheet body, ES0587 errata sheet shared). The board on TS1302 is the **U535** (`STM32U535CCTx`, schematic IC2). [TS-SCH p1, IC2 label]

What U545 adds vs U535: the U545 is the same die with **AES, PKA, OEM cryptography (SAES variants), and OTFDEC** enabled (full security stack). U535 has these blocks fused off. _Confirm against ES0587 / latest DS14217 if planning U545 substitution; the part is pin-compatible drop-in._

### Package on TS1302

- **STM32U535CCTx** = `C` (LQFP-48) + `C` (256 KB flash) + `T` (LQFP) + `x` (industrial). [Confirmed: TS-SCH p1, pins 1–48 visible; ST part-number convention.]
- Other variants in the family (informational): `B`=128 K flash, `C`=256 K, `E`=512 K; pin-count letters: `C`=48, `R`=64, `V`=100, `J`=WLCSP56, `N`=WLCSP72. [DS14217 Table 2, p16-18]

---

## 2. Memory map

[DS14217 §3.4, §3.5, p22–26]

| Region | Size | Address (NS alias) | Address (S alias) | Notes |
|---|---|---|---|---|
| Flash | **256 KB** on TS1302 (CC) | `0x0800_0000` | `0x0C00_0000` | 2 banks, read-while-write, ECC, 100 kcycles. 32 pages × 8 KB. |
| OTP | 512 B | inside flash region | n/a | Write-once. |
| SRAM1 | 192 KB | `0x2000_0000` | `0x3000_0000` | 3× 64 KB blocks, can be powered down by block in Stop. |
| SRAM2 | 64 KB | `0x2003_0000` | `0x3003_0000` | 8 KB + 56 KB blocks, optional ECC, retainable in Standby. |
| SRAM4 | 16 KB | `0x2840_0000` | `0x3840_0000` | LPBAM SRAM — accessible by LPDMA1 in Stop 2. |
| BKPSRAM | 2 KB | `0x4003_6400` | `0x5003_6400` | Backup-domain SRAM. Retained in Standby/VBAT, lost in Shutdown. |
| **Total user SRAM** | **272 KB** + 2 KB BKPSRAM = 274 KB | | | [DS14217 cover, §3.5] |

Note: there is **no SRAM3** on STM32U535 (despite RAMCFG references). The "SRAM3" naming in some U5 reference manuals is for U575/U585 only; on U535 the banks are SRAM1/SRAM2/SRAM4/BKPSRAM. [DS14217 §3.5 p26 "Five SRAMs are embedded" — they count SRAM1, SRAM2, SRAM4, BKPSRAM, and the implied secure aliases.]

**TrustZone defaults**: after reset, **all SRAMs are secure** [DS14217 §3.5.1 p26]. CPU starts in secure state (boot address must be in secure flash) [§3.6.2 p27]. Securable peripherals are nonsecure-by-default after reset; GPIOs are secure-by-default. [§3.6.2]

**Vector table** lives at the boot address (`SECBOOTADD0[24:0]` if TZEN=1, default `0x0C00_0000` secure flash; or `0x0800_0000` default with TZEN=0). [DS14217 §3.7, Table 7-8, p28-30]

**Bootloader (system memory)** lives at `0x0BF9_0000` (TZEN=0) — see §3 below.

---

## 3. Bootloader (factory ROM)

[DS14217 §3.7 p28-30; AN2606 covers U535/U545]

- **System bootloader is mask-ROM**, programmed by ST. Supports **USART, I2C, SPI, FDCAN, USB-DFU**.
- **DFU bootloader VID/PID**: standard ST `0x0483 / 0xDF11` ("STM Device in DFU Mode") — confirmed by AN3156 "USB DFU protocol used in the STM32 bootloader" and ts1302 README.
- **Entering DFU on TS1302**: hold the push-button (`PH3-BOOT0`, schematic SW1) **while** plugging in USB. The button connects PH3-BOOT0 to VCC through SW1. PH3 is sampled at reset; high → boot from system memory; bootloader negotiates DFU on USB. Release after enumeration. [TS-FW README; TS-SCH p1, SW1 → PH3 (pin 44)]
- **Flashing the application** (`tropic01-stm32u5-usb-devkit-fw/README.md`):
  ```sh
  dfu-util -a 0 -s 0x08000000:leave -D build/app.bin
  ```
- **Boot space vs RDP** [DS14217 Table 8, p30]: at RDP=0 any boot address allowed; RDP≥1 forces the boot address into secure or nonsecure flash; bootloader address is **disabled by RDP=1+**, i.e. once you raise RDP you lose USB-DFU recovery. Test thoroughly before locking.
- **CC EAL5+ security cert**: claimed for STM32U585 secure subsystem; **not for U535** (U535 lacks the SAES/BHK that backs the EAL5+ claim). See ST PR for U585: "PSA Certified Level 3, SESIP Level 3" — does NOT extend to U535. Don't repeat that claim about U535.

---

## 4. TrustZone-M architecture

[DS14217 §3.6, p26-28; AN5347 "Arm TrustZone for STM32L5/U5/U3"]

- **Activation**: by setting **TZEN** option-bit in `FLASH_OPTR`. Once written, returning to TZEN=0 requires an option-byte reset which is gated by RDP regression (so in development plan to keep TZEN=0 OR set up keyed RDP regression with OEM2KEY before going to RDP=1).
- **SAU**: 8 configurable regions for security attribution. Each region is `[base, limit, NS|NSC]`. [§3.6 p26]
- **IDAU**: implementation-defined — flash, SRAM, peripherals memory aliased twice (S and NS at +`0x1000_0000` offset). External memory NOT aliased. [§3.6 Table 5, p27]
- **MPU**: Cortex-M33 has 16 MPU regions per security state (so 16 secure + 16 nonsecure = 32 regions total). [§3.1 p20]
- **GTZC** (Global TrustZone Controller) [§3.8 p31]:
  - **TZSC** sets secure/privilege state for slave/master peripherals.
  - **TZIC** gathers illegal-access events into a secure NVIC interrupt.
  - **MPCBB** sets per-512-B-page secure/privilege state for SRAM1/2/4. [§3.5.2 p26]
  - **MPCWMx** sets watermark-based secure region for OCTOSPI external memory.
- **NSC (non-secure callable)**: declared via `__attribute__((cmse_nonsecure_entry))`, placed in NSC region by linker. Veneers auto-generated by `arm-none-eabi-gcc -mcmse`. Compiler ≥10.x required.

**Implication for our project**: storing the X25519 pairing private key (used to bring up the TROPIC01 secure channel) in secure-world flash + having an NSC veneer like `int s_l1_handshake(uint8_t *eph_pub_in, uint8_t *eph_pub_out)` is the textbook win — non-secure firmware (USB stacks, app logic) never sees the key. Cost: linker complexity, two-image build, per-veneer perf hit.

**Development gotcha**: TZEN is one-way at RDP≥1. In dev keep RDP=0, develop with TZ=0, then bring up TZ once stack is solid. AN5347 §"How to disable TrustZone in STM32L5xx devices during development phase" wiki page is your friend.

---

## 5. Security features beyond TrustZone

[DS14217 §3.4.1, §3.4.2; §3.7 RSS; §3.37.2 TAMP]

### RDP — Read-Out Protection

[DS14217 Table 8, p30; AN5347 + ST training PDF "STM32U5-Security-Overview"]

| Level | What it does | Reversibility |
|---|---|---|
| **RDP 0** | No protection. Debug, mass-erase, and read-out all enabled. **Default state** for blank parts. | — |
| **RDP 0.5** | Only with TZEN=1. Nonsecure debug allowed; secure debug + secure flash read blocked. Dev-friendly TZ flow. | Reversible (regression to 0). |
| **RDP 1** | All debug blocked. Boot is forced into flash. RAM still accessible to debugger only after RDP regression. | Reversible to 0 ⇒ **mass-erase** triggered. With OEM1KEY set, regression requires that key. |
| **RDP 2** | Debug interface permanently disabled. No regression possible without **OEM2KEY** set in advance. **If you set RDP=2 without OEM2KEY, the part is locked permanently**. | One-way unless OEM2KEY pre-configured. |

ST community confirms: "RDP level 2 cannot be removed (irreversible operation). Regression can be blocked by OEM1 key." [community.st.com U5 RDP regression thread]

### HDP — Hide Protection

[DS14217 §2 p15 "secure hide protection area"; §3.4.1] HDP locks ranges of secure flash so even secure-world code cannot read them after a software-controlled lock. Useful for the immutable secure boot loader stage. Configured in option bytes; granularity is page (8 KB).

### What U535 does NOT have (vs U575/U585):

- ❌ **BHK** (Boot Hardware Key, per-die 256-bit AES key). DS14217 §3.34/§3.35 only list RNG + HASH; no SAES; no BHK. No marketing language about "Hardware Unique Key" for U535.
- ❌ **MCE** (Memory Cipher Engine for external flash encryption) — no `HAL_MCE_*` would link.
- ❌ **SAES** (Secure AES with side-channel hardening, key-protected mode).
- ❌ **OTFDEC** (On-The-Fly Decryption for OCTOSPI).
- ❌ **PKA** with curves.
- ❌ **AES** of any flavor.

### What U535 DOES have

- ✅ **SFI / RSS** (Secure Firmware Install / Root Security Services). Located at `0x0FF8_0000`. Lets ST's RSS unwrap an OEM-encrypted firmware image during factory provisioning. [DS14217 §3.7 p28] **Note**: SFI uses fixed RSS algorithms (AES-GCM with key from BHK). On U535 BHK is absent → SFI is **only useful in the limited form ST provides** — verify with AN4992 before relying on it.
- ✅ **OBL** (Option Byte Loader): standard STM32 option-byte mechanism with secure mirror.
- ✅ **OBKey** = OEM1KEY / OEM2KEY (RDP regression passwords). 64-bit each, stored in option bytes.
- ✅ **TAMP** [DS14217 §3.37.2 p74]: 8 tamper input pins (`TAMP_IN[8:1]`) + 8 outputs in active mode, RTC tamper detection, **128 backup registers** (32-bit each = 512 B). On detection of tamper: backup registers + BKPSRAM are erased by hardware. LQFP-48 exposes 3/3 (without SMPS) tamper pins. [DS14217 Table 2, p17]
- ✅ **PWR security**: PWR registers can be put in secure state via TZSC. [§3.9.6 p44]
- ✅ **Active tampers** in output-sharing mode (one output cycles through inputs to detect cut traces). 2 active tamper pins in LQFP-48. [DS14217 Table 2, p17]
- ✅ **96-bit unique device ID** (read-only), **512 B OTP**. [DS14217 cover features list]

---

## 6. Crypto accelerators

[DS14217 §3.34 p68 — RNG; §3.35 p69 — HASH]

### What's present

- **HASH peripheral** [§3.35 p69]: SHA-1 and SHA-2 family (SHA-224, **SHA-256**). DS14217 cover bullet says "HASH (SHA-256)" only; reference manual RM0456 likely covers full SHA-2. **No SHA-3, no SHA-512** on this part. HMAC available standalone via HASH peripheral. Throughput: not stated in datasheet; for U585 it's ~1 byte/cycle; expect similar.
- **TRNG** [§3.34 p68]: NIST SP 800-90B compliant. Health-tested entropy source. AIS-31 PTG.2 claim only on U585 (not in U535 datasheet). Output via `HAL_RNG_GenerateRandomNumber` in libtropic port [`lt-port:lt_port_random_bytes`].

### What's absent

- ❌ AES (no `HAL_CRYP_*` works because module not present)
- ❌ SAES
- ❌ PKA (so **no hardware ECDSA, ECDH, RSA, Curve25519 acceleration**)
- ❌ HMAC standalone peripheral (use HASH periph in HMAC mode)

### Implication for FIDO2 + CCID firmware

You need a **software crypto library**:
- **mbedTLS** (full): big, mature, Cortex-M-tuned, MIT/Apache. Adds ~200 KB code if you take it whole — pruned aggressively to ~50–80 KB with just P-256 + SHA-256 + AES + ECDSA.
- **MicroECC**: ~3 KB for P-256 ECDSA. Often paired with TweetNaCl for Ed25519 (~10 KB).
- **TinyCrypt** (Intel, BSD-2): smaller, AES-128 + SHA-256 + ECDSA-P256 + HMAC-DRBG. Good fit.
- For Curve25519/X25519: **Monocypher** (~10 KB, public domain) is the cleanest single-file lib. Note libtropic does X25519 internally for the L1 handshake — host doesn't need to expose it.

Recommendation: **TinyCrypt + Monocypher** if your scope is FIDO2-CTAP2 (P-256 ECDSA only) + CCID OpenPGP card (Ed25519 + P-256). Total ~25 KB code.

---

## 7. USB peripheral

[DS14217 §3.44 p83]

- **One USB FS controller** (USB 2.0 FS, 12 Mbps). NOT high-speed. Not OTG on U535 — datasheet labels it "host or device capable" but functionality is full-speed only via embedded transceiver.
- **Endpoints**: configurable **1 to 8** (so up to 8 IN + 8 OUT bidirectional).
- **PMA (packet memory)**: **2048 bytes**, 32-bit access. Allocated by software per endpoint.
- **Double-buffered** support: yes for bulk and isochronous EP. [§3.44 third bullet from end]
- **Embedded PHY**: yes (no external transceiver needed). Uses VDDUSB 3.0–3.6 V supply (board ties to 3V3).
- **Clock**: HSI48 + CRS (clock recovery system) trims HSI48 against USB SOF — **no crystal needed for USB** despite the 8 MHz crystal on TS1302 (the crystal feeds SYSCLK; HSI48 is independent). [TS-FW: `sys.c:84-92` enables HSI48 + CRS sync from USB SOF]
- **Suspend/resume**: full support. Battery-charging spec rev 1.2 supported in device mode. USB 2.0 LPM supported. [§3.44]

### TS1302 USB pinout

| Pin | Function | Schematic |
|---|---|---|
| **PA11** | USB_DM (D−) | LQFP-48 pin 32, after 10 Ω R9, ESD-protected by D2 (PRTR5V0U2X) |
| **PA12** | USB_DP (D+) | LQFP-48 pin 33, after 10 Ω R10, 1.5 kΩ R11 pull-up to VCC_USB_SPI for FS device signaling |

[TS-SCH p1; TS-FW: `hw/pcb_ts1302.h:55-56`: `HW_USB_DP_BIT (12), HW_USB_DP_PORT GPIOA`]

The 1.5 kΩ pull-up is **software-controlled**: stock firmware deliberately drives PA12 low at boot (`GPIO_BIT_CLR` + `GPIO_PIN_INIT(..., GPIO_MODE_OUTPUT)`) to force a USB reset, then reconfigures PA12 to AF (via USB peripheral attaching the internal pull-up). [TS-FW: `app/main.c:42-47`] This is the "renumeration trick" for clean USB re-attach without unplugging.

### USBX vs TinyUSB vs ST USB Device Library

- **Stock TS1302 firmware uses ST USBX** (Microsoft Azure RTOS USBX) [TS-FW: `sdk_stm32u535.mk` references `STM32_USBX_Library`]. USBX is now royalty-free since Microsoft donated it to Eclipse. Heavyweight (~30 KB code), ThreadX-style API.
- **TinyUSB**: STM32U5 BSP exists for **U545 / U575 / U585 / U5A5** but **NOT U535**. [TinyUSB repo `hw/bsp/stm32u5/boards/`: `b_u585i_iot2a, stm32u545nucleo, stm32u575eval, stm32u575nucleo, stm32u5a5nucleo`.] U545 BSP should adapt to U535 with minimal effort (pin-compat, same peripheral block) — verify with `dcd_stm32_fsdev` driver.
- **ST USB Device Library** (classic, "ST USB"): the older non-USBX one. Supported on U5xx via STM32CubeU5 examples. Smaller than USBX.

For a HID + CCID composite, **TinyUSB is the cleanest choice**: composite-class glue is mature, HID descriptors trivial, CCID class supported (`tinyusb/src/class/ccid` exists for some forks; mainline supports HID, CDC, MIDI, but CCID is community-maintained — verify against current `master`).

---

## 8. Peripherals relevant for FIDO2/CCID firmware

[DS14217 §3.40 p79 — SPI; §3.13 GPIO; §3.39 USART; §3.36 timers; §3.17 GPDMA; §3.18 LPDMA]

### SPI

- **3 SPI peripherals**: SPI1, SPI2 (full-feature, configurable 4–32-bit data, 16×8-bit FIFO), SPI3 (limited: 8/16-bit only, 8×8-bit FIFO, but available in Stop 2). [DS14217 Table 22, p80]
- **Max master clock**: kernel-clock / 2. Kernel can be SYSCLK = 160 MHz, so theoretical max **80 MHz** SPI master. Practical: 40–50 MHz with sane PCB. **TROPIC01 max SCLK** is 5 MHz per its datasheet; libtropic STM32 port leaves prescaler configurable [`lt-port:.baudrate_prescaler`].
- **CPHA/CPOL for TROPIC01**: **CPOL=0, CPHA=0** (mode 0). Confirmed in libtropic STM32U5 port: `CLKPolarity = SPI_POLARITY_LOW, CLKPhase = SPI_PHASE_1EDGE` [`libtropic_port_stm32u5xx.c:88-89`]. Also matches stock TS1302 FW: `HW_SPI_SW_CPOL=0, HW_SPI_SW_CPHA=0` [`hw/hardware.h:14-15`].
- **MSB-first**, hardware NSS supported but TS1302 stock + libtropic both use **soft NSS** (CS as GPIO). [`pcb_ts1302.h:42-46`: `HW_SPI_SW_CS_PORT GPIOA, BIT 4`; `lt-port:.spi_cs_gpio_pin`]
- **DMA**: full-duplex DMA on RX+TX channels, used by stock TS1302 FW [`spi.c:_spi_data_transfer` calls `HAL_SPI_TransmitReceive_DMA`].
- **SPI1 is the one wired to TROPIC01 on TS1302**. [TS-SCH p1: SPI1 lines on PA5/PA6/PA7 + CS on PA4]

### GPIO

LQFP-48 exposes **37 I/Os** (or 33 with SMPS variant). [DS14217 Table 2, p17]
- All 5V-tolerant where marked `FT_*` in pin tables.
- `FT_u` indicates USB-tolerant (PA11, PA12). [DS14217 §4.2 pin tables]
- TS1302 uses ~14 of these (see §10). Headroom for adding ~20 GPIOs on a daughter board: feasible if you stack HW_BUTTON / LEDs onto unused PB10–PB15, PA8–PA10.

### UART / USART / LPUART

- **2 USART** (USART1, USART3), **2 UART** (UART4, UART5), **1 LPUART** (LPUART1). [DS14217 Table 2, p17]
- TS1302 wires **LPUART1** to PA2 (TX) / PA3 (RX), pin 12 / pin 13. [TS-SCH p1, TP4/TP5; `pcb_ts1302.h:25-30`].
  - Note: stock firmware names this "UART1" macro but it's actually LPUART1 hardware (`#define HW_UART1_GPIO_EN RCC_AHB2ENR1_GPIOAEN`). Pins broken out at TP4/TP5/TP6 test points for serial debug.
- All UARTs support ISO 7816 (smartcard), LIN, IrDA, modem flow control, autonomous in Stop modes. LPUART1 functional in Stop 2.

### Timers

[DS14217 §3.36 p70]: total **17 timers + 2 watchdogs + 2 SysTick**:
- 2× **advanced-control 16-bit** (TIM1, TIM8) — PWM + dead-time, motor control.
- 4× **general-purpose 32-bit** (TIM2, TIM3, TIM4, TIM5).
- 3× **general-purpose 16-bit** (TIM15, TIM16, TIM17).
- 2× **basic 16-bit** (TIM6, TIM7) — DAC-trigger.
- 4× **low-power 16-bit** (LPTIM1–4) — usable in Stop modes.
- IWDG (independent), WWDG (window).

Useful assignments for our firmware:
- **USB SOF interval (1 ms)**: handled internally by USB peripheral; surface as IRQ via `Sof_enable=ENABLE` in PCD init if you want SOF callbacks (stock FW disables it).
- **Button debounce**: TIM6 / TIM7 basic timers, polling at 10 ms or LPTIM (Stop-mode capable).
- **LED breathing PWM**: any general-purpose timer with PWM output channel; TS1302 uses TIM-less software toggle [`led.c`].
- **CCID activity timeout**: TIM2 (32-bit so no overflow logic) running at 1 kHz.

### DMA

- **GPDMA1**: 16 channels, functional in Stop 0/1. [DS14217 cover features list, §3.17 p49]
- **LPDMA1**: 4 channels, functional in Stop 0/1/2 (LPBAM-aware).
- Both can wake the CPU from Stop on transfer-complete. Useful for DMA-driven SPI bulk transfers to TROPIC01 while the CPU sleeps.

---

## 9. Power and sleep modes

[DS14217 Table 9, p36-44]

| Mode | Vcore reg | CPU | Flash | SRAM | Wake-up time | Typ. current |
|---|---|---|---|---|---|---|
| **Run** Range 1 | LDO/SMPS | run | on | full | n/a | 16.3 µA/MHz @ 3.3 V (cover) |
| **Sleep** | same | halt | on | full | µs | scales with peripherals |
| **Stop 0** | main on | halt | off | full retained | very fast (<1 µs) | "Range 4" peripherals only |
| **Stop 1** | LPR | halt | off | full | µs | ~10 µA |
| **Stop 2** | LPR | halt | off | full | tens µs | **3.0 µA with 16 KB SRAM, 4.6 µA with full SRAM** |
| **Stop 3** | LPR | halt | off | full | hundreds µs | **1.4 µA with 16 KB SRAM, 2.2 µA full** |
| **Standby** | off | reset | off | lost (SRAM2 retain optional) | ms | **200 nA (370 nA with RTC)** |
| **Shutdown** | off | reset | off | all lost (BKPSRAM lost) | ms | **90 nA** (23 wake-up pins) |

[Cover page features list for current numbers; Table 9 for what's functional in each mode.]

**USB suspend handling**: USB peripheral has a Suspend interrupt; stock FW disables `low_power_enable` and `lpm_enable` [`usb_device.c:_usb_drd_fs_pcd_init`]. For battery-conscious (host-bus-powered) HID+CCID firmware: enable LPM and route USB suspend to Stop 2 (USB peripheral retains its state in Stop 2 thanks to LPBAM).

**Wake-up pins**: 23 pins on full LQFP-100 packages; **17 on LQFP-48** (without SMPS) [DS14217 Table 2, p17]. PH3 (the BOOT0 / button pin on TS1302) is one.

---

## 10. TS1302 board specifics

### 10.1 Pinout (LQFP-48, STM32U535CCTx)

[Source: TS-SCH `ts1302_schematics.pdf` (rev TS1302, KiCad sheet 1/1) cross-referenced with DS14217 LQFP-48 pinout (Figure 8, p85) and `tropic01-stm32u5-usb-devkit-fw/hw/pcb_ts1302.h` (header file is the authoritative pin assignment).]

| MCU pin | LQFP-48 # | Net | Function | Source |
|---|---|---|---|---|
| **VBAT** | 1 | T_VCC (via reg) | Battery / RTC backup. On TS1302 tied to VCC = 3.3 V. | DS14217 Fig 8 |
| **PC13** | 2 | (unused) | Available. | TS-SCH (no net) |
| **PC14-OSC32_IN** | 3 | (unused) | LSE crystal IN — not populated on TS1302. | TS-SCH (no LSE crystal X) |
| **PC15-OSC32_OUT** | 4 | (unused) | LSE crystal OUT. | — |
| **PH0-OSC_IN** | 5 | X1 input | **8 MHz HSE crystal X1** + 10 pF caps C11/C12. Used as PLL source (×96/16 → 48 MHz). | TS-SCH; `sys.c:71` |
| **PH1-OSC_OUT** | 6 | X1 output | (paired with above) | TS-SCH |
| **NRST** | 7 | NRST | Reset, with 100 nF C9 to GND, exposed at TP7. | TS-SCH |
| **VSSA** | 8 | T_GND | Analog ground. | TS-SCH |
| **VDDA** | 9 | VCC | Analog supply (3.3 V), 100 nF C7. | TS-SCH |
| **PA0** | 10 | T_PWR_ON | **Output: TROPIC01 power-switch enable** (drives IC4 TPS22917 ON pin). High = TROPIC01 powered. | `pcb_ts1302.h:64-69`: `HW_CHIP_PWR_PORT GPIOA, BIT 0` |
| **PA1** | 11 | (unused) | Available. | TS-SCH |
| **PA2** | 12 | U2_TX → TP4 | **LPUART1 TX** (debug serial). | `pcb_ts1302.h:30`: `HW_UART1_TX_BIT 2` |
| **PA3** | 13 | U2_RX → TP5 | **LPUART1 RX**. | `pcb_ts1302.h:28`: `HW_UART1_RX_BIT 3` |
| **PA4** | 14 | SPI_CS → TROPIC01 CSN | **SPI1 chip-select** (software-controlled GPIO, AF disabled). | `pcb_ts1302.h:42-46`: `HW_SPI_SW_CS_PORT GPIOA, BIT 4`; TS-SCH IC1.CSN |
| **PA5** | 15 | SPI_SCK | **SPI1_SCK** (AF5). 1 kΩ R5 series. | `spi.c:_spi1_pin_init`: `LL_GPIO_PIN_5 ... AF_5`; TS-SCH IC1.SCK |
| **PA6** | 16 | SPI_MISO | **SPI1_MISO** (AF5). 1 kΩ R4 series. Pull-up enabled (`LL_GPIO_PULL_UP`). | `spi.c:_spi1_pin_init`; TS-SCH IC1.SDO |
| **PA7** | 17 | SPI_MOSI | **SPI1_MOSI** (AF5). 1 kΩ R3 series. | `spi.c:_spi1_pin_init`; TS-SCH IC1.SDI |
| **PB0** | 18 | GPO | **TROPIC01 GPO input** (general-purpose output of TROPIC01, monitored as GPIO input on host). 1 kΩ R2 series. | `pcb_ts1302.h:57-60`: `HW_GPO_IN_PORT GPIOB, BIT 0`; TS-SCH IC1.GPO |
| **PB1** | 19 | (unused) | Available. | TS-SCH |
| **PB2** | 20 | (unused) | Available. | TS-SCH |
| **PB10** | 21 | TP10 | Test point. | TS-SCH |
| **VCAP** | 22 | (cap) | Internal regulator decoupling, 4.7 µF C14. | TS-SCH |
| **VSS** | 23 | T_GND | | |
| **VDD** | 24 | VCC_USB_SPI | Main 3.3 V supply (from IC3 LDO TPS7A0533, max 500 mA, fed from USB VBUS through F1 fuse and 5.6 kΩ R8 CC pull-down). | TS-SCH |
| **PB12** | 25 | TP11 | Test point. | TS-SCH |
| **PB13** | 26 | TP12 | Test point. | TS-SCH |
| **PB14** | 27 | (unused) | | |
| **PB15** | 28 | (unused) | | |
| **PA8** | 29 | TP3 | Test point (was MCO/USB_SOF/TIM1). | TS-SCH |
| **PA9** | 30 | LED → D1 | **User LED** (red, 1 kΩ R13, anode to PA9). | `pcb_ts1302.h:14-18`: `HW_LED1_PORT GPIOA, BIT 9` |
| **PA10** | 31 | (unused) | Available. | TS-SCH |
| **PA11** | 32 | USB_N | **USB D−** (after R9=10 Ω + ESD diode D2). | TS-SCH; DS14217 (`USB_DM(boot)`) |
| **PA12** | 33 | USB_P | **USB D+** (after R10=10 Ω + ESD diode D2 + 1.5 kΩ R11 pull-up to VCC). | TS-SCH; DS14217 (`USB_DP(boot)`); `pcb_ts1302.h:71-72` |
| **PA13** | 34 | SWDIO | **SWD data**, exposed at TP8 in SWD test-point group. | TS-SCH (SWD label) |
| **VSS** | 35 | T_GND | | |
| **VDD** | 36 | VCC_USB_SPI | | |
| **PA14** | 37 | SWCLK | **SWD clock**, exposed at TP9. | TS-SCH |
| **PA15** | 38 | (unused) | Available (could be SPI1_NSS in HW NSS mode). | TS-SCH |
| **PB3** | 39 | (unused) | Available. | TS-SCH |
| **PB4** | 40 | (unused) | | |
| **PB5** | 41 | (unused) | | |
| **PB6** | 42 | (unused) | | |
| **PB7** | 43 | (unused) | | |
| **PH3-BOOT0** | 44 | SW1 → BOOT1 | **BOOT0 / button** (connects PH3 to VCC through tact switch SW1, 33 kΩ R1 pull-down). Press at reset → DFU bootloader. Press during run → user button. | `pcb_ts1302.h:20-23`: `HW_BUTTON_PORT GPIOH, BIT 3`; TS-SCH SW1 |
| **PB8** | 45 | (unused) | | |
| **PB9** | 46 | (unused) | (Note: LQFP48 figure 8 in datasheet shows PB9 here for non-SMPS package.) | DS14217 Fig 8, p85 |
| **VSS** | 47 | T_GND | | |
| **VDD** | 48 | VCC_USB_SPI | | |

### 10.2 Power tree

[TS-SCH p1; key parts: F1, IC3, IC4, R8]

```
USB-C VBUS ──┬── F1 (500 mA fuse) ── USB_PWR_5V
             │
             └── R8 (5.1 kΩ to GND on CC pin → USB-C "default 1.5 A" advertisement)

USB_PWR_5V ── IC3 TPS7A0533PDBZR (LDO, 3.3 V, 200 mA) ── VCC (= VCC_USB_SPI)
                                                              │
                                                              ├── STM32U535 VDD/VDDA/VDDUSB
                                                              │
                                                              └── IC4 TPS22917 (load switch, controlled by PA0) ── T_VCC
                                                                    └── TROPIC01 VCC
```

- **Decoupling caps**: `C1`, `C2`, `C3` 100 nF/0603 on TROPIC01 VCC pins; `C5`, `C6` 100 nF on STM32 VDD pins; `C13` 100 nF on TROPIC01 power switch output; `C8` 10 nF on NRST; `C14` 4.7 µF on VCAP.
- **Power isolation**: TROPIC01 VCC is independently switched by PA0 (`HW_CHIP_PWR_*`). Lets stock FW power-cycle the secure element.

### 10.3 Crystal / oscillator

- **HSE**: 8 MHz crystal X1 (between PH0/PH1) with two 10 pF load caps C11, C12. **Assembled on TS1302** (`#define HW_HSE_ENABLED 1` in `pcb_ts1302.h:5`).
- **LSE**: PC14/PC15 are routed but the schematic shows no 32 kHz crystal — LSE not populated. RTC backup oscillator would use LSI (32 kHz internal RC) instead.
- Stock PLL config produces only **48 MHz SYSCLK** (not max). Custom firmware can push to 160 MHz (set VOS=Range 1, increase PLL multiplier, change flash latency).

### 10.4 Test points and headers

[TS-SCH bottom-right test point cluster]

| TP | Net | Use |
|---|---|---|
| TP1 | T_VCC | TROPIC01 VCC monitor |
| TP2 | NRST | MCU reset signal |
| TP3 | PA8 | Spare GPIO test |
| TP4 | U2_TX | LPUART1 TX (debug) |
| TP5 | U2_RX | LPUART1 RX (debug) |
| TP6 | (extra UART tap) | |
| TP7 | NRST (alt) | |
| **TP8** | **SWDIO** | **SWD data** |
| **TP9** | **SWCLK** | **SWD clock** |
| TP10 | PB10 | Spare GPIO |
| TP11 | PB12 | Spare GPIO |
| TP12 | PB13 | Spare GPIO |
| PAD1–PAD7 | TROPIC01 direct pads | Pads for direct SPI tap to TROPIC01 (bypass MCU). PAD3 = GPO; PAD4–PAD7 = SDI/SDO/SCK/CSN. |
| H1–H8 | mounting holes | |
| H9 | 2.2 mm hole | |

**SWD header**: TS1302 has TP8/TP9 (data + clock) but **no separate dedicated 4/10-pin SWD connector** — solder-on/clip-on workflow. Add TP2 (NRST) and TP1 (VCC) for full SWD pinout (SWDIO, SWCLK, NRST, VCC, GND).

---

## 11. Toolchain options for our Nix flake

### 11.1 Compiler

- **GCC**: `arm-none-eabi-gcc` ≥ **10.x** is required for Cortex-M33 + TrustZone (`-mcmse`, NSC veneers). 13.x is current best.
  - Nix: `pkgs.gcc-arm-embedded` (currently 13.3) or `pkgs.gcc-arm-embedded-13`. Both wrap upstream `gcc-arm-none-eabi`.
  - TS1302 stock FW just calls `arm-none-eabi-gcc` from PATH [`sdk_stm32u535.mk:14-19`].
- **Clang**: works (LLVM ≥ 14 supports Cortex-M33 + CMSE), but ST HAL has GCC-isms; expect tweaks.

### 11.2 Build system options

| Option | Pros | Cons |
|---|---|---|
| **Stock TS1302 Make + ST LL drivers** | Minimal, fast. Only LL drivers + USBX subset. ~150 KB flash output. | Tied to ST USBX. Tropic-only build conventions. Needs git submodules. |
| **CMake + STM32CubeMX-generated** | Standard ST workflow. Easy device-tree-style pin config. | CubeMX generates a lot of code. Hard to reproduce in Nix without imperative steps. |
| **Custom Make + CMSIS only** | Smallest possible. No HAL bloat. | Re-implement all peripheral init by hand. |
| **PlatformIO** | Quick start, board manager. | Heavy, hard to wedge into Nix. |
| **Zephyr RTOS** | Real OS, USB-class infra ready (HID, MSC, CCID-class), TF-M integration. | ~200 KB overhead. Steep learning curve. |

**Recommendation**: **CMake + ST HAL (selective) + TinyUSB**. Use `pkgs.gcc-arm-embedded` + `pkgs.cmake` + the STM32U5 HAL fetched as a Nix `fetchFromGitHub` (from `STMicroelectronics/stm32u5xx_hal_driver`, the same submodule TS-FW uses) + TinyUSB also as a fetched source. Build outputs `.elf`, `.hex`, `.bin`. Keep target-side application separate from libtropic-pulled-in HAL.

### 11.3 Debugger / programmer

- **OpenOCD**: `pkgs.openocd` supports STM32U5 since 0.12. SWD via TS1302 TP8/TP9 + ST-Link/V3 or J-Link.
- **STLink/v2 or v3 dongle**: cheapest. Works with `pkgs.stlink` (open source `st-flash`/`st-info`/`st-util`) or `pkgs.openocd`.
- **DFU flashing** (no SWD probe needed): `pkgs.dfu-util`. The stock TS1302 README uses this; it's the simplest first-flash path.
- **STM32_Programmer_CLI** (proprietary, ST): avoid in Nix flake; not redistributable cleanly.

### 11.4 USB stack (recommended)

For HID + CCID composite:
1. **TinyUSB** `master` — best HID and composite support. CCID-class support exists in forks (e.g. `solokeys/tinycbor`-style; also `oscourse/tinyusb-ccid`). Verify against current upstream before committing.
2. **USBX** (Eclipse Azure RTOS) — works on this part (stock FW proves it), composite-class supported, but more code and licensing complexity than needed.
3. **ST USB Device Library** classic — possible, no CCID-class out of the box.

### 11.5 Recommended Nix toolchain combo

```nix
# devShell inputs (sketch)
buildInputs = with pkgs; [
  gcc-arm-embedded   # 13.x, supports -mcpu=cortex-m33 + -mcmse
  cmake
  ninja
  dfu-util           # primary flash path on TS1302
  openocd            # for SWD debug via STLink/V3
  stlink             # st-flash, st-info CLI
  pkgsCross.arm-embedded.buildPackages.binutils-unwrapped  # if needed for arm-objcopy
];
```

Source pinning:
- `STMicroelectronics/cmsis-device-u5` (CMSIS device headers)
- `STMicroelectronics/stm32u5xx_hal_driver`
- `hathach/tinyusb`
- `tropicsquare/libtropic` + this project's HAL extension

---

## 12. Existing libtropic STM32U5 HAL

[`libtropic/hal/stm32/stm32u5xx/`]

Two files: `libtropic_port_stm32u5xx.{c,h}` (~250 LOC total).

### What it expects from the application

The application provides a populated `lt_dev_stm32u5xx_t` struct (`libtropic_port_stm32u5xx.h`) with:

```c
typedef struct lt_dev_stm32u5xx_t {
    SPI_TypeDef *spi_instance;          // e.g. SPI1
    uint32_t baudrate_prescaler;        // SPI_BAUDRATEPRESCALER_2 ... DIV256
    uint16_t spi_cs_gpio_pin;           // GPIO_PIN_4 (PA4 on TS1302)
    GPIO_TypeDef *spi_cs_gpio_bank;     // GPIOA
#if LT_USE_INT_PIN
    uint16_t int_gpio_pin;
    GPIO_TypeDef *int_gpio_bank;
#endif
    RNG_HandleTypeDef *rng_handle;      // for lt_port_random_bytes
    SPI_HandleTypeDef spi_handle;       // private; populated by lt_port_init
} lt_dev_stm32u5xx_t;
```

### SPI configuration applied by `lt_port_init`

[`libtropic_port_stm32u5xx.c:84-115`]

```c
SPI_MODE_MASTER, 2-line full-duplex, 8-bit data
CLKPolarity = SPI_POLARITY_LOW  (CPOL=0)
CLKPhase    = SPI_PHASE_1EDGE   (CPHA=0)
NSS         = SPI_NSS_SOFT      (CS as GPIO)
FirstBit    = SPI_FIRSTBIT_MSB
CRC disabled, FIFO threshold 1 data
NSSPolarity LOW, MasterKeepIOState DISABLE, IOSwap DISABLE
ReadyMasterManagement INTERNALLY, ReadyPolarity HIGH
```

Then `HAL_SPIEx_SetConfigAutonomousMode()` is called with `SPI_AUTO_MODE_DISABLE` — autonomous mode wired up but not active. (Reserved for future LPBAM use.)

### CS GPIO setup

[`libtropic_port_stm32u5xx.c:121-128`]

- Mode: `GPIO_MODE_OUTPUT_PP`
- Pull: `GPIO_PULLUP` (idle high)
- Speed: `GPIO_SPEED_FREQ_MEDIUM`
- CS asserted low / deasserted high with a **read-back verify loop** (`LT_STM32U5XX_GPIO_OUTPUT_CHECK_ATTEMPTS = 10`). Defensive against rail noise.

### IRQ / READY pin (optional)

When `LT_USE_INT_PIN` is defined at compile time:
- The INT pin is configured as `GPIO_MODE_INPUT, GPIO_NOPULL, GPIO_SPEED_FREQ_LOW`.
- `lt_port_delay_on_int()` polls `HAL_GPIO_ReadPin(int_gpio_bank, int_gpio_pin) == 0` and returns LT_OK when the pin goes high (or `LT_L1_INT_TIMEOUT`).
- **NOT** an EXTI / interrupt-driven implementation — it's polling. For Phase 0 firmware this is fine; for power-conscious sleep, replace with EXTI-line wake.

On TS1302 there is **no dedicated INT line wired** — the only signal back from TROPIC01 is the **GPO pin (TROPIC01 → STM32 PB0)**, which is a general-purpose output, not an L2-protocol "ready" signal in the libtropic sense. Stock FW polls SPI directly (the `READY` semantics are inferred from the L1 protocol bytes). [`pcb_ts1302.h:57-60`; libtropic L1 protocol uses BUSY byte detection on SPI.]

### Random bytes

`lt_port_random_bytes()` calls `HAL_RNG_GenerateRandomNumber()` in a loop, copies 4-byte chunks, secure-zeroes the temporary on return. Standard HAL_RNG dependency — don't forget `HAL_RNG_MODULE_ENABLED` in your `stm32u5xx_hal_conf.h` (the stock TS1302 FW does NOT enable RNG; you'll need to add it for libtropic-on-MCU).

### `lt_port_*` functions implemented

| Function | Behaviour |
|---|---|
| `lt_port_init` | Configures SPI + CS GPIO (+ INT GPIO if `LT_USE_INT_PIN`). |
| `lt_port_deinit` | `HAL_SPI_DeInit`. |
| `lt_port_spi_csn_low` / `_high` | Drives CS, verifies via read-back. |
| `lt_port_spi_transfer` | `HAL_SPI_TransmitReceive` blocking, with `timeout_ms` from caller. |
| `lt_port_delay` | `HAL_Delay(ms)`. |
| `lt_port_delay_on_int` | Polls INT pin. |
| `lt_port_random_bytes` | `HAL_RNG_GenerateRandomNumber` loop. |
| `lt_port_log` | `vprintf` to stdout. |

---

## 13. Known caveats / footguns

### 13.1 No on-die AES / PKA / SAES on U535

This is the biggest design constraint. Anything you'd "just hand to SAES" (key wrap, key derivation with hidden keys) you must do in software. **TROPIC01 fills part of this gap** (Ed25519/P-256 sign, AES-256-GCM L3 channel) but only behind the L3 secure-channel handshake, with bandwidth limited by SPI throughput.

### 13.2 TrustZone-M setup is fiddly

- TZEN is an option-bit, programmed by `STM32_Programmer_CLI` or via OBL register (`FLASH_OPTKEYR` unlock dance).
- Once TZEN=1, you cannot debug nonsecure code without a TrustZone-aware debugger (OpenOCD ≥0.12 OK, ST-LINK-Server OK, plain `st-flash` insufficient).
- **You CAN return to TZEN=0** via option-byte regression at RDP=0. So in development: keep RDP=0 so TZEN flips are reversible.
- Linker scripts get hairy: secure image at `0x0C00_0000`, NSC region at `0x0C00_FE00`, nonsecure image at `0x0800_8000` (typical layout).

### 13.3 DFU bootloader timing quirks

- BOOT0 (PH3 on this part) is sampled **only at reset**. So press button → power-cycle (or NRST). Release after enumeration.
- Some host USB stacks rate-limit re-enumeration after RDP/option-byte changes; if `dfu-util -l` doesn't see the device, unplug for 5 s and retry.
- `dfu-util` on Linux needs the user in the right udev group (`plugdev` typical) or run as root. ST's official bootloader VID/PID `0483:df11` should be auto-claimed; on Windows you may need WinUSB via Zadig.

### 13.4 Stock firmware has SOME quirks

- Stock FW runs SYSCLK at 48 MHz (range 3 voltage scaling). Custom firmware can run at 160 MHz but must switch to range 1 BEFORE bumping clock, or the VOS interlock will refuse the change. [DS14217 §3.9.1]
- Stock FW disables `Sof_enable` and `low_power_enable` in PCD init. For battery-pack USB device profiles, re-enable both.
- Stock FW uses **soft-CS** with a read-back verify loop in libtropic — slow (~10 GPIO reads per CS edge). For high-throughput firmware, switch to hardware NSS (PA15 = SPI1_NSS AF) and accept the trade-off (less defensive).

### 13.5 Power-domain interlock

- `VDDUSB` must be enabled BEFORE USB peripheral init, via `PWR_SVMCR_USV` bit. Stock FW does this in `sys_init()`. Forget it → USB peripheral hangs in reset state with no error code. [`sys.c:25`]
- VBAT is shorted to VCC on TS1302 (no battery), so don't enable VBAT-only modes during dev — they will work but the BKPSRAM benefit is moot.

### 13.6 OBL / option-byte gotchas

- Option-byte writes require an **OBL launch** (`HAL_FLASH_OB_Launch`) which **resets the MCU**. Plan for the reset, don't sit in a busy-wait expecting return.
- A botched option-byte write at RDP≥1 can brick the part. Always test the sequence on a sacrificial board first.

### 13.7 Mass-erase on RDP regression

- RDP 1 → 0 triggers a **mass erase** of secure + nonsecure flash. Backup any secrets you want to preserve to BKPSRAM (which survives, since it's in the backup domain) BEFORE attempting regression.

### 13.8 The TROPIC01 GPO is not an interrupt line

- On TS1302, PB0 ← TROPIC01 GPO is just a general-purpose output of the secure element. It does not signal "secure channel ready" or "operation complete" by default — it's whatever you configured it to via `lt_r_config_*`. Don't mistake it for the libtropic INT/READY pin.

---

## 14. Quick action items for Phase 0

1. **Verify TinyUSB U545 BSP runs on U535** (probably trivial — same FS controller, same PMA, just different RAM size). If yes, fork the U545 BSP into a `stm32u535_ts1302` BSP.
2. **Pick a software crypto lib early** — TinyCrypt + Monocypher recommended, fits comfortably in 256 KB flash with ~150 KB headroom for app + USB stacks.
3. **Set up SWD debug via TP8 (SWDIO) / TP9 (SWCLK) + TP2 (NRST)** with an STLink/V3 (or J-Link) and OpenOCD config. Do NOT try to build with TZ enabled until plain (TZ=0) firmware boots and enumerates as a HID device.
4. **Confirm libtropic links cleanly at non-secure level** (libtropic doesn't depend on TZ). Then later we can move it to secure world to keep the X25519 pairing key off non-secure firmware.
5. **Keep RDP=0 throughout development.** Plan keyed-RDP transition as a separate hardening Phase.
6. **Add HAL_RNG_MODULE_ENABLED** to the `stm32u5xx_hal_conf.h` for our firmware (stock TS1302 FW disables it; libtropic needs it).

---

## 15. Quick reference: schematic-derived connections

```
USB-C (J1) ──┬── VBUS ── F1(500mA) ── IC3(LDO 3V3) ── VCC ──┬── STM32 VDD/VDDA/VDDUSB
             │                                              └── IC4(load switch, en=PA0) ── T_VCC ── TROPIC01 VCC
             ├── D+ (PA12, USB_DP, AF10) via R10(10R) + R11(1k5 pull-up to VCC) + D2(ESD)
             ├── D− (PA11, USB_DM, AF10) via R9(10R) + D2(ESD)
             └── CC ── R8(5k1 to GND, USB-C "default 1.5A" advert)

STM32 ──[SPI1 mode 0, MSB-first]── TROPIC01
   PA4  ── (soft CS) ── R7(1k) ── CSN
   PA5  ── (AF5 SCK) ── R6(1k) ── SCK
   PA6  ── (AF5 MISO) ── R4(1k) ── SDO    [STM32 PA6 has internal pull-up]
   PA7  ── (AF5 MOSI) ── R3(1k) ── SDI
   PB0  ──── R2(1k) ──── GPO
   PA0  ── (output) ── IC4.ON (VCC switch enable for TROPIC01)

STM32 ── (debug)
   PA2  ── LPUART1_TX (TP4)
   PA3  ── LPUART1_RX (TP5)
   PA13 ── SWDIO (TP8)
   PA14 ── SWCLK (TP9)
   NRST ── (TP2)

STM32 ── (UI)
   PA9  ── LED1 (R13=1k, anode-side)  [active high → LED on]
   PH3  ── BOOT0 / button SW1  [pull-down R1=33k; press → high → DFU at reset]
```

---

## Sources

- [STM32U535xx datasheet, DS14217 Rev 2 (July 2023)](https://www.st.com/resource/en/datasheet/stm32u535cb.pdf) (also mirrored at https://cdn-reichelt.de/documents/datenblatt/A300/STM32U535CE.pdf)
- [STM32U535-545 product page](https://www.st.com/en/microcontrollers-microprocessors/stm32u535-545.html)
- [STM32U5 Series page](https://www.st.com/en/microcontrollers-microprocessors/stm32u5-series.html)
- [AN5347 — Arm TrustZone features for STM32L5/U5/U3](https://www.st.com/resource/en/application_note/an5347-arm-trustzone-features-for-stm32l5-and-stm32u5-series-stmicroelectronics.pdf)
- [AN2606 — STM32 system memory boot mode](https://www.st.com/resource/en/application_note/an2606-introduction-to-system-memory-boot-mode-on-stm32-mcus-stmicroelectronics.pdf)
- [AN3156 — USB DFU protocol used in STM32 bootloader](https://www.st.com/resource/en/application_note/an3156-how-to-use-usb-dfu-protocol-in-bootloader-on-stm32-mcus-stmicroelectronics.pdf)
- [STM32U5 Security Overview training PDF (SECOVW)](https://www.st.com/content/ccc/resource/training/technical/product_training/group1/5f/7a/5e/5e/db/cf/49/98/STM32U5-Security-Overview_SECOVW/files/STM32U5-Security-Overview_SECOVW.pdf/_jcr_content/translations/en.STM32U5-Security-Overview_SECOVW.pdf)
- [STM32U5 Crypto update training PDF](https://www.st.com/content/ccc/resource/training/technical/product_training/group1/1e/1d/0f/1d/70/42/41/bb/STM32U5-Security-Crypto-CRYPTO/files/STM32U5-Security-Crypto-CRYPTO.pdf/_jcr_content/translations/en.STM32U5-Security-Crypto-CRYPTO.pdf)
- [TS1302 hardware repo (schematic, KiCad)](https://github.com/tropicsquare/tropic01-stm32u5-usb-devkit-hw)
- [TS1302 firmware repo (stock USB-CDC-ACM)](https://github.com/tropicsquare/tropic01-stm32u5-usb-devkit-fw)
- [libtropic STM32U5 HAL port](https://github.com/tropicsquare/libtropic/tree/master/hal/stm32/stm32u5xx)
- [TinyUSB STM32U5 BSPs (no U535 yet, U545 closest)](https://github.com/hathach/tinyusb/tree/master/hw/bsp/stm32u5/boards)
- [STM32 RDP regression community thread — STM32U5 keyed RDP](https://community.st.com/t5/stm32-mcus/how-to-regress-from-rdp-level-2-to-rdp-level-0-on-the-stm32u5/ta-p/568476)
