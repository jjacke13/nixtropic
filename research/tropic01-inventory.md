# TROPIC01 — Technical Inventory

Reference document for what the **TROPIC01 secure element** (Tropic Square) actually exposes to a host MCU. Compiled from the libtropic SDK headers, the docs site, and the chip product repo. Cited by `path:line` for source files and by URL for docs.

Sources:
- `https://github.com/tropicsquare/libtropic` — official C SDK (ref: branch `master`, downloaded 2026-05-09)
- `https://github.com/tropicsquare/tropic01` — chip product repo (datasheets, app notes, errata index)
- `https://tropicsquare.github.io/libtropic/latest/` — public docs site

When a constant is given as `TR01_*`, the citation is to `libtropic/include/...`. Where the public source does not nail down a value precisely, the section says so and points at the relevant datasheet or app note.

---

## 1. Chip overview

### Package, fab, part numbers

```c
#define TR01_CHIP_PKG_BARE_SILICON_ID 0x8000   // libtropic_common.h:476
#define TR01_CHIP_PKG_QFN32_ID        0x80AA   // libtropic_common.h:478
#define TR01_FAB_ID_TROPIC_SQUARE_LAB 0xF00    // libtropic_common.h:480
#define TR01_FAB_ID_EPS_BRNO          0x001    // production line #1
```

Production parts (`tropic01/doc/pages/part-numbers.md`), all QFN32:

| PN | Default App FW | Default SPECT FW | Status |
|---|---|---|---|
| TR01-C2P-T310 | 2.0.0 | 1.0.0 | On request |
| TR01-C2P-T301 | 1.0.0 | 1.0.0 | Recommended for new designs |
| TR01-C2P-T202 / T103 / T101 | 0.5.0 / 0.3.1 / 0.3.1 | 0.3.1 | Deprecated |
| TR01-B2S-T005 | 0.2.0 | 0.3.1 | Engineering sample — **TS1302 USB devkit** |

### Chip modes

`lt_tr01_mode_t` — libtropic's interpretation of the datasheet's Chip Mode + CHIP_STATUS bits (`libtropic_common.h:173-210`):

| Enum                | Datasheet Chip Mode  | CHIP_STATUS (READY/ALARM/START) |
|---------------------|----------------------|---------------------------------|
| `LT_TR01_MAINTENANCE` | Start-up           | 1 / 0 / 1                       |
| `LT_TR01_APPLICATION` | Idle / Secure Channel / Sleep | 1 / 0 / 0          |
| `LT_TR01_ALARM`       | Alarm              | ? / 1 / ?                       |

CHIP_STATUS bit definitions (`libtropic/src/lt_l1.h`):

```c
#define TR01_L1_CHIP_MODE_READY_bit   0x01
#define TR01_L1_CHIP_MODE_ALARM_bit   0x02
#define TR01_L1_CHIP_MODE_STARTUP_bit 0x04
```

### Boot / reboot

```c
typedef enum lt_startup_id_t {                 // libtropic_common.h:161
    TR01_REBOOT             = 0x01,
    TR01_MAINTENANCE_REBOOT = 0x03
} lt_startup_id_t;
#define LT_TR01_REBOOT_DELAY_MS 250            // libtropic_common.h:409
```

`TR01_REBOOT` performs a power-cycle-equivalent restart and loads mutable Application FW. `TR01_MAINTENANCE_REBOOT` restarts but keeps the chip in Start-up Mode running only the immutable Bootloader FW (used for FW update).

### Architecture

- **RISC-V CPU** runs immutable Bootloader FW (ROM) at power-up, then hands off to mutable Application FW in R-Memory.
- **SPECT co-processor** ("Secure Programmable ECC Tropic") accelerates ECC scalar mul. Has its own mutable FW bank.
- **Silicon revisions** appear in `lt_chip_id_t.silicon_rev[4]` as ASCII (`libtropic_common.h:512`):
  - **ABAB** (older): host manages banks (`TR01_FW_BANK_FW1/FW2/SPECT1/SPECT2`). Max FW size **25600 B** (`libtropic.h:220`).
  - **ACAB** (newer): chip handles banks itself. Max FW size **30720 B** (`libtropic.h:249`). Two-phase update API.

L2 Get_Info object IDs (`lt_l2_api_structs.h`): `0x01` CHIP_ID, `0x02` RISC-V FW ver, `0x04` SPECT FW ver, `0xb0` FW bank header, `0x00` X.509 cert (paged). In Start-up Mode, version queries return MSB-set values; SPECT version reads `0x80000000` (it's part of immutable FW at boot).

---

## 2. Storage inventory

### ECC key slots — exactly 32

```c
typedef enum lt_ecc_slot_t { TR01_ECC_SLOT_0 = 0, ..., TR01_ECC_SLOT_31 } lt_ecc_slot_t;
                                                          // libtropic_common.h:861-894
```

Each slot can hold one of two curve types:

```c
typedef enum lt_ecc_curve_type_t {                        // libtropic_common.h:897
    TR01_CURVE_P256    = 1,
    TR01_CURVE_ED25519
} lt_ecc_curve_type_t;
```

Wire-level curve IDs from `src/lt_l3_api_structs.h`:

```c
#define TR01_L3_ECC_KEY_GENERATE_CMD_CURVE_P256    0x01
#define TR01_L3_ECC_KEY_GENERATE_CMD_CURVE_ED25519 0x02
```

Key origin (returned by `lt_ecc_key_read`, `libtropic_common.h:907`):

```c
typedef enum lt_ecc_key_origin_t {
    TR01_CURVE_GENERATED = 1,    // key generated on-chip via lt_ecc_key_generate
    TR01_CURVE_STORED            // key imported via lt_ecc_key_store
} lt_ecc_key_origin_t;
```

Key sizes (`libtropic_common.h:899-910`):

```c
#define TR01_CURVE_P256_PUBKEY_LEN    64   // X||Y, 32B each
#define TR01_CURVE_ED25519_PUBKEY_LEN  32
#define TR01_CURVE_PRIVKEY_LEN         32   // both curves
#define TR01_ECDSA_EDDSA_SIGNATURE_LENGTH 64   // R||S, raw, no DER
```

### Pairing key slots — exactly 4

```c
typedef enum lt_pkey_index_t {                            // libtropic_common.h:721
    TR01_PAIRING_KEY_SLOT_INDEX_0,
    TR01_PAIRING_KEY_SLOT_INDEX_1,
    TR01_PAIRING_KEY_SLOT_INDEX_2,
    TR01_PAIRING_KEY_SLOT_INDEX_3,
} lt_pkey_index_t;
```

Each slot stores an X25519 public key (32 B) — the host MCU's `S_HiPub` for Secure Channel handshake (`libtropic_common.h:734-769`):

```c
#define TR01_X25519_KEY_LEN 32
#define TR01_SHIPUB_LEN     TR01_X25519_KEY_LEN   // host pub stored on chip
#define TR01_SHIPRIV_LEN    TR01_X25519_KEY_LEN   // host priv kept on host
#define TR01_STPUB_LEN      TR01_X25519_KEY_LEN   // chip's static pub (in cert)
```

Operations: `lt_pairing_key_write/read/invalidate`. **`invalidate` is one-way** — once invalidated a slot can never be reused (per Pairing_Key_Invalidate semantics in datasheet; libtropic surfaces it via `LT_L3_SLOT_INVALID = 19`).

### MAC-and-Destroy slots — exactly 128

```c
typedef enum lt_mac_and_destroy_slot_t {                  // libtropic_common.h:943
    TR01_MAC_AND_DESTROY_SLOT_0 = 0, ..., TR01_MAC_AND_DESTROY_SLOT_127
} lt_mac_and_destroy_slot_t;

#define TR01_MAC_AND_DESTROY_DATA_SIZE 32u                // libtropic_common.h:938
#define TR01_MACANDD_ROUNDS_MAX        128                // libtropic_common.h:940
```

Each call to `lt_mac_and_destroy(slot, data_out, data_in)` computes `data_in = MAC(slot_secret, data_out)` and **physically destroys** the slot's secret. `data_out` and `data_in` are both fixed at 32 B. Wire IDs (`src/lt_l3_api_structs.h`): `TR01_L3_MAC_AND_DESTROY_CMD_ID = 0x90`, command/result sizes 36 B each (32 B data + 1 B opcode + 3 B padding/header).

### R-Memory user partition — 512 slots

```c
#define TR01_R_MEM_DATA_SIZE_MIN  (1)        // libtropic_common.h:851
#define TR01_R_MEM_DATA_SLOT_MAX  (511)      // libtropic_common.h:853 — slots 0..511
```

Per-slot max size is FW-dependent, exposed at runtime as `lt_tr01_attrs_t.r_mem_udata_slot_size_max`:

- **App FW ≤ 1.0.1**: 444 B (errata "L3 commands R_Mem_Data_Write/Read limited to 444B", 2025-08-07).
- **App FW ≥ 2.0.0**: 475 B (per `part-numbers.md`).

Raw capacity: ~227 KiB (older) or ~243 KiB (newer). Actual addressable partition is set at factory provisioning — see datasheet.

### Monotonic counters — exactly 16

```c
typedef enum lt_mcounter_index_t {                        // libtropic_common.h:917
    TR01_MCOUNTER_INDEX_0 = 0, ..., TR01_MCOUNTER_INDEX_15 = 15
} lt_mcounter_index_t;
#define TR01_MCOUNTER_VALUE_MAX 0xFFFFFFFE                // libtropic_common.h:914
```

`lt_mcounter_init(idx, value)` sets initial value (range `[0, TR01_MCOUNTER_VALUE_MAX]`). `lt_mcounter_update(idx)` decrements by 1 (irreversibly). `lt_mcounter_get(idx)` reads the current value. When a counter hits zero, subsequent `update` returns `LT_L3_UPDATE_ERR = 16` ("mcounter done at 0", `libtropic_common.h:326`); subsequent `get` returns `LT_L3_COUNTER_INVALID = 17` if the counter is disabled or locked.

### Certificate store — 4 certificates

```c
#define TR01_L2_GET_INFO_REQ_CERT_SIZE_TOTAL  3840   // libtropic_common.h:413
#define TR01_L2_GET_INFO_REQ_CERT_SIZE_SINGLE 700    // libtropic_common.h:414
#define LT_NUM_CERTIFICATES                   4      // libtropic_common.h:424
#define LT_CERT_STORE_VERSION                 1
```

`lt_cert_kind_t` (`libtropic_common.h:416`): `0 LT_CERT_KIND_DEVICE` (chip device cert, holds STPUB), `1 LT_CERT_KIND_XXXX` (named XXXX in libtropic — likely intermediate/batch; verify in datasheet), `2 LT_CERT_KIND_TROPIC01` (product CA), `3 LT_CERT_KIND_TROPIC_ROOT`. Read via `lt_get_info_cert_store()`, paged 128 B chunks. **`lt_verify_chip_and_start_secure_session` does NOT validate the chain** — only parses STPUB. Validate the chain externally. See `ODN_TR01_app_003` PKI App Note.

### CHIP_ID — 128 bytes

```c
#define TR01_L2_GET_INFO_CHIP_ID_SIZE 128                 // libtropic_common.h:437
```

Layout (`lt_chip_id_t`, `libtropic_common.h:488-586`):

```c
typedef struct lt_chip_id_t {
    uint8_t chip_id_ver[4];          // CHIP_ID structure version (Tropic Square BP)
    uint8_t fl_chip_info[16];        // Factory-level test info (silicon provider)
    uint8_t func_test_info[8];       // Manufacturing-level test info
    uint8_t silicon_rev[4];          // ASCII "ABAB" / "ACAB" / etc.
    uint8_t packg_type_id[2];        // 0x8000 bare silicon, 0x80AA QFN32
    uint8_t rfu_1[2];
    uint8_t prov_ver_fab_id_pn[4];   // 8b prov ver, 12b fab ID, 12b part-number ID
    uint8_t provisioning_date[2];
    uint8_t hsm_ver[4];              // RFU/Major/Minor/Patch
    uint8_t prog_ver[4];
    uint8_t rfu_2[2];
    struct lt_ser_num_t ser_num;     // 16 B serial: see below
    uint8_t part_num_data[16];
    uint8_t prov_templ_ver[2];
    uint8_t prov_templ_tag[4];
    uint8_t prov_spec_ver[2];
    uint8_t prov_spec_tag[4];
    uint8_t batch_id[5];
    uint8_t rfu_3[3];
    uint8_t rfu_4[24];               // padding to 128 B
} __attribute__((packed));
```

Serial number sub-structure (`lt_ser_num_t`, `libtropic_common.h:445`):

```c
typedef struct lt_ser_num_t {
    uint8_t  sn;          // 8 b
    uint8_t  fab_data[3]; // 12 b fab ID + 12 b part-number ID
    uint16_t fab_date;
    uint8_t  lot_id[5];
    uint8_t  wafer_id;
    uint16_t x_coord;
    uint16_t y_coord;
} __attribute__((packed));   // total 16 B
```

---

## 3. Public API inventory

All `lt_*` functions return `lt_ret_t`. All take `lt_handle_t *h` as first argument unless noted. The grouping below mirrors the doxygen "1. Libtropic API" group in `libtropic.h`.

### Lifecycle, info, session

| Function | Notes |
|---|---|
| `lt_init(h)` | Init transport, read mode, reboot if needed, populate `tr01_attrs`. On failure do **not** call `lt_deinit`. (`libtropic.h:42`, `libtropic.c:39`) |
| `lt_deinit(h)` | Tear down transport. Always invalidates session. (`libtropic.h:58`) |
| `lt_get_tr01_mode(h, *mode)` | Read CHIP_STATUS → `LT_TR01_MAINTENANCE/APPLICATION/ALARM`. (`libtropic.h:71`) |
| `lt_reboot(h, startup_id)` | Startup_Req. Waits 250 ms, re-reads mode, returns `LT_REBOOT_UNSUCCESSFUL` on mismatch. (`libtropic.h:216`) |
| `lt_sleep(h, sleep_kind)` | Only `TR01_L2_SLEEP_KIND_SLEEP = 0x05` is accepted. (`libtropic.h:204`) |
| `lt_get_info_cert_store(h, *store)` | Paged read of the 4-cert chain (128 B chunks). |
| `lt_get_st_pub(*store, *stpub)` | Extract STPUB from device cert (does NOT validate chain). |
| `lt_get_info_chip_id(h, *chip_id)` | 128 B CHIP_ID. |
| `lt_get_info_riscv_fw_ver(h, *ver)` / `lt_get_info_spect_fw_ver` | 4 B FW version each. |
| `lt_get_info_fw_bank(h, bank_id, ...)` | FW header from bank. Maintenance Mode only. v1 header = 20 B, v2 = 52 B. |
| `lt_session_start(h, stpub, pkey_idx, shipriv, shipub)` | Secure Channel handshake (`HANDSHAKE_REQ 0x02`, 35 B → 49 B). Derives AES-256 key + IVs. (`libtropic.h:175`) |
| `lt_session_abort(h)` | `ENCRYPTED_SESSION_ABT 0x08`, zeros host session state. |
| `lt_verify_chip_and_start_secure_session(h, shipriv, shipub, pkey_idx)` | Helper: read certs, parse STPUB, start session. **No chain validation** (`libtropic.h:734-738`). |

### Pairing keys (`slot` 0..3, all live in I-Memory; tighter temp range)

- `lt_pairing_key_write(h, pubkey32, slot)` (`libtropic.h:322`)
- `lt_pairing_key_read (h, pubkey32, slot)` (`libtropic.h:335`)
- `lt_pairing_key_invalidate(h, slot)` — **one-way, irreversible** (`libtropic.h:352`)

FW <2.0.0 fails silently when writing pairing keys outside -20..+85 °C; FW ≥2.0.0 returns an error.

### R-config / I-config

- `lt_r_config_write(h, addr, obj_u32)` (`libtropic.h:369`)
- `lt_r_config_read (h, addr, *obj)` (`libtropic.h:384`)
- `lt_r_config_erase(h)` (`libtropic.h:396`)
- `lt_i_config_write(h, addr, bit_index)` — clears one bit, 1→0 only (`libtropic.h:414`)
- `lt_i_config_read (h, addr, *obj)` (`libtropic.h:428`)

**HAZARD**: Writing R-config without erasing first triggers erratum `OI_TR01_ERR_2026010800` (permanent Alarm Mode = brick). Always use the erase→write-whole pattern via the `lt_write_whole_R_config` / `lt_read_whole_R_config` / `lt_write_whole_I_config` / `lt_read_whole_I_config` helpers (`libtropic.h:685-728`, gated on `LT_HELPERS`). Helper table: `extern lt_config_obj_desc_t cfg_desc_table[LT_CONFIG_OBJ_CNT];`.

### R-memory user data (`slot` 0..511)

- `lt_r_mem_data_write(h, slot, data, size)` (`libtropic.h:443`)
- `lt_r_mem_data_read (h, slot, *data, max, *read_size)` (`libtropic.h:459`)
- `lt_r_mem_data_erase(h, slot)` (`libtropic.h:472`)

`size ∈ [1, r_mem_udata_slot_size_max]` — 444 B for App FW ≤1.0.1, 475 B for ≥2.0.0.

### Crypto / counters / M&D

- `lt_random_value_get(h, *rnd, count)` — count ≤ 255 (`libtropic.h:485`)
- `lt_ecc_key_generate(h, slot, curve)`, `lt_ecc_key_store(h, slot, curve, key32)`, `lt_ecc_key_read(h, slot, *key, max, *curve, *origin)`, `lt_ecc_key_erase(h, slot)` — slot 0..31 (`libtropic.h:499-549`)
- `lt_ecc_ecdsa_sign(h, slot, msg, msg_len_u32, rs64)` — `msg` is a pre-computed 32 B digest (chip cmd is fixed 48 B); returns 64 B R||S (`libtropic.h:565`)
- `lt_ecc_eddsa_sign(h, slot, msg, msg_len_u16, rs64)` — `msg` raw bytes ≤ 4096 (chip pre-hashes); returns 64 B R||S (`libtropic.h:582`)
- `lt_mcounter_init/update/get(h, idx, ...)` — idx 0..15 (`libtropic.h:597-624`)
- `lt_mac_and_destroy(h, slot, data_out32, data_in32)` — slot 0..127, **destructive** (`libtropic.h:641`)

### FW update + misc

- `lt_do_mutable_fw_update(h, data, size, bank_id)` — wraps ABAB/ACAB difference. **Re-init handle after success.** (`libtropic.h:808`)
- `lt_ping(h, msg_out, msg_in, len)` — Echo via Secure Channel, max 4096 B
- `lt_get_log_req(h, *msg, max, *read)` — RISC-V FW log; disabled on production chips
- `lt_ret_verbose(ret)` — string name of an `lt_ret_t`
- `lt_print_bytes`, `lt_print_chip_id`, `lt_print_fw_header` — printf-helpers

---

## 4. Configuration objects

The chip has two parallel ACL/policy register banks: **R-config** (rewritable, in R-Memory) and **I-config** (irreversible OTP, in I-Memory). Same address space; both are written via L3 commands once a Secure Session is up.

### Bootloader-side configuration objects (`tropic01_bootloader_co.h`)

| Address | Name | Bits | Purpose |
|---------|------|------|---------|
| `0x00`  | `BOOTLOADER_CO_CFG_START_UP` | RFU(0), MBIST_DIS(1), RNGTEST_DIS(2), MAINTENANCE_ENA(3) | Power-on self-test toggles, maintenance-mode reboot enable |
| `0x08`  | `BOOTLOADER_CO_CFG_SENSORS` | 18 separate `*_DIS` bits | Disable individual side-channel / fault-injection sensors: PTRNG0/1 test, oscillator monitor, shield, voltage monitor, glitch detector, temperature sensor, laser detector, EM pulse detector, CPU alert, pin-verif/SCB/CPB/ECC/R-mem/EKDB/I-mem/platform bit-flip detectors |
| `0x10`  | `BOOTLOADER_CO_CFG_DEBUG` | FW_LOG_EN(0) | Enable RISC-V FW logging output (always disabled on production parts) |

### Application-side configuration objects (`tropic01_application_co.h`)

| Address | Name | Layout |
|---------|------|--------|
| `0x14`  | `CFG_GPO` | `GPO_FUNC[2:0]` default `0x1` (added in App FW 0.4.0) |
| `0x18`  | `CFG_SLEEP_MODE` | `SLEEP_MODE_EN[0]` |
| `0x20/0x24/0x28` | `CFG_UAP_PAIRING_KEY_{WRITE,READ,INVALIDATE}` | 4 ACL bytes, one per pairing slot 0..3 |
| `0x30/0x34` | `CFG_UAP_R_CONFIG_{WRITE_ERASE,READ}` | 1-2 ACL bytes |
| `0x40/0x44` | `CFG_UAP_I_CONFIG_{WRITE,READ}` | CFG+FUNC bytes |
| `0x100` | `CFG_UAP_PING` | 1 ACL byte |
| `0x110/0x114/0x118` | `CFG_UAP_R_MEM_DATA_{WRITE,READ,ERASE}` | 4 ACL bytes, one per **quartile** (slots 0-127 / 128-255 / 256-383 / 384-511) |
| `0x120` | `CFG_UAP_RANDOM_VALUE_GET` | 1 ACL byte |
| `0x130-0x13C` | `CFG_UAP_ECC_KEY_{GENERATE,STORE,READ,ERASE}` | 4 ACL bytes, one per ECC octet (0-7 / 8-15 / 16-23 / 24-31) |
| `0x140/0x144` | `CFG_UAP_{ECDSA,EDDSA}_SIGN` | Same ECC-octet layout |
| `0x150/0x154/0x158` | `CFG_UAP_MCOUNTER_{INIT,GET,UPDATE}` | 4 ACL bytes per counter quad (0-3 / 4-7 / 8-11 / 12-15) |
| `0x160` | `CFG_UAP_MAC_AND_DESTROY` | 4 ACL bytes per M&D 32-tuple (0-31 / 32-63 / 64-95 / 96-127) |

There are **27 config objects total** (`#define LT_CONFIG_OBJ_CNT 27`, `libtropic_common.h:1132`).

### ACL byte layout

For each of the per-slot/per-quartile bytes, the bits select which Secure Sessions are authorized:

```c
#define LT_SESSION_SH0_HAS_ACCESS  0x01   // libtropic_common.h:1116
#define LT_SESSION_SH1_HAS_ACCESS  0x02
#define LT_SESSION_SH2_HAS_ACCESS  0x04
#define LT_SESSION_SH3_HAS_ACCESS  0x08
```

So a byte of `0x05` = "SH0 and SH2 may execute this op on this asset". Helper macros `LT_TO_PAIRING_KEY_SH{0,1,2,3}(x)`, `LT_TO_MCOUNTER_*(x)`, `LT_TO_ECC_KEY_SLOT_*(x)`, `LT_TO_MACANDD_SLOT_*(x)` shift a byte into the right field of the 32-bit register (`libtropic_common.h:1080-1113`).

### Default values

The libtropic public source does **not** ship hard-coded factory defaults for the config objects. Defaults are set per part number at provisioning time and documented in the Configuration Objects Application Note `ODN_TR01_app_006` (`tropic01/doc/application_notes/ODN_TR01_app_006_config_obj_1v2.pdf`). For TR01-C2P-T301 / T310 the defaults grant SH0 full access and SH1-SH3 none — see that PDF for exact bytes.

### Brick erratum: `OI_TR01_ERR_2026010800` — "R-Config write triggers permanent Alarm Mode"

Published 2026-01-08, listed for both TR01-C2P-T301 and TR01-C2P-T310. **Trigger**: `lt_r_config_write` without prior `lt_r_config_erase`. **Result**: chip enters Alarm Mode permanently — bricked from host's standpoint. **Recovery**: none documented. **Workaround**: always `erase → write whole config` (use `lt_write_whole_R_config`). The doxygen explicitly warns at `libtropic.h:357-360, 675-677`. **This is the most critical hazard in the public API** — host firmware should refuse to expose raw `lt_r_config_write` outside the erase→batch-write sequence.

---

## 5. L1 / L2 / L3 protocol structure

### L1 — physical / SPI

- 4-wire SPI (CS / SCK / MOSI / MISO). See `https://tropicsquare.github.io/libtropic/latest/reference/libtropic_architecture/`.
- A chip-status byte is exchanged with every L2 transaction:

```c
#define TR01_L1_CHIP_STATUS_SIZE 1u                       // libtropic_common.h:24
#define TR01_L1_LEN_MIN          TR01_L1_CHIP_STATUS_SIZE
#define TR01_L1_LEN_MAX          (TR01_L1_CHIP_STATUS_SIZE + TR01_L2_MAX_FRAME_SIZE)

#define TR01_L1_CHIP_MODE_READY_bit   0x01    // src/lt_l1.h
#define TR01_L1_CHIP_MODE_ALARM_bit   0x02
#define TR01_L1_CHIP_MODE_STARTUP_bit 0x04
#define TR01_L1_GET_RESPONSE_REQ_ID   0xAA    // L1 poll for status
```

Timing constants (`src/lt_l1.h`):

```c
#define LT_L1_READ_MAX_TRIES    50
#define LT_L1_READ_RETRY_DELAY  25      // ms
#define LT_L1_TIMEOUT_MS_MIN    5
#define LT_L1_TIMEOUT_MS_DEFAULT 70
#define LT_L1_TIMEOUT_MS_MAX    150
```

### L2 — framed, unencrypted, request-response

```c
#define TR01_L2_REQ_ID_OFFSET            0u   // libtropic_common.h:31
#define TR01_L2_REQ_LEN_OFFSET           1u
#define TR01_L2_REQ_DATA_REQ_CRC_OFFSET  2u

#define TR01_L2_CHIP_STATUS_OFFSET       0u   // response
#define TR01_L2_STATUS_OFFSET            1u
#define TR01_L2_RSP_LEN_OFFSET           2u
#define TR01_L2_RSP_DATA_RSP_CRC_OFFSET  3u

#define TR01_L2_CHUNK_MAX_DATA_SIZE      252u
#define TR01_L2_MAX_FRAME_SIZE \
    (TR01_L2_STATUS_SIZE + TR01_L2_REQ_RSP_LEN_SIZE + 252 + TR01_L2_REQ_RSP_CRC_SIZE)
                                                // = 1 + 1 + 252 + 2 = 256
```

A single L2 chunk carries up to 252 B of payload + 2 B CRC + headers. Larger payloads are split client-side into multiple chunks; the chip responds with `TR01_L2_STATUS_REQUEST_CONT` (`0x03`) / `TR01_L2_STATUS_RESULT_CONT` (`0x04`) to ask for/announce continuation. See `src/lt_l2_frame_check.h`:

```c
#define TR01_L2_STATUS_REQUEST_OK    0x01
#define TR01_L2_STATUS_RESULT_OK     0x02
#define TR01_L2_STATUS_REQUEST_CONT  0x03
#define TR01_L2_STATUS_RESULT_CONT   0x04
#define TR01_L2_STATUS_RESP_DISABLED 0x78
#define TR01_L2_STATUS_HSK_ERR       0x79
#define TR01_L2_STATUS_NO_SESSION    0x7A
#define TR01_L2_STATUS_TAG_ERR       0x7B
#define TR01_L2_STATUS_CRC_ERR       0x7C
#define TR01_L2_STATUS_UNKNOWN_ERR   0x7E
#define TR01_L2_STATUS_GEN_ERR       0x7F
#define TR01_L2_STATUS_NO_RESP       0xFF
```

### L2 request IDs (`src/lt_l2_api_structs.h`)

| ID    | Name                              | Notes |
|-------|-----------------------------------|-------|
| `0x01`| `GET_INFO_REQ`                    | Object_id selects: 0x00 cert (paged), 0x01 chip ID, 0x02 RISC-V FW ver, 0x04 SPECT FW ver, 0xb0 FW bank header |
| `0x02`| `HANDSHAKE_REQ`                   | Length 33 B (req), 48 B (rsp) — establishes Secure Session |
| `0x04`| `ENCRYPTED_CMD_REQ`               | Min 19 B, ciphertext 1..4096 B — wraps an L3 command |
| `0x08`| `ENCRYPTED_SESSION_ABT_ID`        | Tear down Secure Session |
| `0x10`| `RESEND_REQ`                      | Resend last response chunk |
| `0x20`| `SLEEP_REQ`                       | Sleep_kind = 0x05 (only) |
| `0xa2`| `GET_LOG_REQ`                     | Read RISC-V debug log |
| `0xb0`| `MUTABLE_FW_UPDATE_REQ` (ACAB)    | FW update request header |
| `0xb1`| `MUTABLE_FW_UPDATE_DATA_REQ` (ACAB) / `MUTABLE_FW_UPDATE_REQ` (ABAB) | Stream FW data (ABAB sees this as the only update opcode) |
| `0xb2`| `MUTABLE_FW_ERASE_REQ` (ABAB)     | Erase a bank |
| `0xb3`| `STARTUP_REQ`                     | Reboot |
| `0xAA`| `GET_RESPONSE_REQ` (L1)           | Poll CHIP_STATUS only |

### L3 — encrypted, AEAD-wrapped

```c
#define TR01_L3_IV_SIZE                  12u    // libtropic_common.h:66
#define TR01_L3_TAG_SIZE                 16u    // libtropic_common.h:71
#define TR01_L3_SIZE_SIZE                2u    // length prefix
#define TR01_L3_CMD_CIPHERTEXT_MAX_SIZE  4112u  // EDDSA_Sign worst case
#define TR01_L3_RES_CIPHERTEXT_MAX_SIZE  4097u  // Ping result worst case
#define TR01_L3_PACKET_MAX_SIZE          4130   // SIZE + CIPHERTEXT + TAG
#define TR01_AES256_KEY_LEN              32     // libtropic_common.h:249
```

**AEAD = AES-256-GCM** (confirmed by `src/lt_aesgcm.h` — the file defines `lt_aesgcm_encrypt/decrypt`). Architecture page mentions "Noise Protocol Framework" at the high level; libtropic's implementation:

- 256-bit key from handshake KDF
- 12 B IV per direction (`encryption_IV`, `decryption_IV` in `lt_l3_state_t`, `libtropic_common.h:233`)
- 16 B auth tag
- **Empty AAD** (`add_len = 0`, `lt_l3_process.c:78`)
- 32-bit little-endian counter at IV[0..3], `++` per packet, overflow → `LT_NONCE_OVERFLOW = 46` (`lt_l3_process.c:24-44`)

Errata: "Nonce endianity of Noise Protocol" (2025-06-30) — chip's nonce byte-order does not match strict Noise reading; libtropic matches the chip (LE counter).

### Session establishment

`lt_session_start` performs an X25519 KX:

1. Host generates ephemeral `(EHPRIV, EHPUB)`.
2. Send `HANDSHAKE_REQ {0x02 | 0x21 | EHPUB[32] | pkey_index | crc[2]}` (35 B).
3. Chip generates `(ETPRIV, ETPUB)`, fetches `STPRIV` and `SHiPUB[pkey_index]`. Computes ≥3 X25519 shared secrets, HKDF (`src/lt_hkdf.h`) → session AES key + IVs + handshake tag.
4. Chip responds `HANDSHAKE_RSP {chip_status | status | 0x30 | ETPUB[32] | tag[16]}` (49 B).
5. Host re-derives, verifies tag, sets `session_status = LT_SECURE_SESSION_ON = 0x5A5A5A5A`.

`TR01_L2_HANDSHAKE_REQ_ID 0x02`, REQ_LEN 33u, RSP_LEN 48u.

### L3 command IDs (`src/lt_l3_api_structs.h`)

| ID    | Command            | CMD size       | RES size        |
|-------|--------------------|----------------|-----------------|
| `0x01`| Ping               | 1+(0..4096)    | 1+(0..4096)+1   |
| `0x10`| Pairing_Key_Write  | 36 B           | 1 B             |
| `0x11`| Pairing_Key_Read   | 3 B            | 36 B            |
| `0x12`| Pairing_Key_Invalidate | 3 B        | 1 B             |
| `0x20`| R_Config_Write     | 8 B            | 1 B             |
| `0x21`| R_Config_Read      | 3 B            | 8 B             |
| `0x22`| R_Config_Erase     | 1 B            | 1 B             |
| `0x30`| I_Config_Write     | 4 B            | 1 B             |
| `0x31`| I_Config_Read      | 3 B            | 8 B             |
| `0x40`| R_Mem_Data_Write   | ≥5 B           | 1 B             |
| `0x41`| R_Mem_Data_Read    | 3 B            | ≥4 B            |
| `0x42`| R_Mem_Data_Erase   | 3 B            | 1 B             |
| `0x50`| Random_Value_Get   | 2 B            | 4..259 B        |
| `0x60`| ECC_Key_Generate   | 4 B            | 1 B             |
| `0x61`| ECC_Key_Store      | 48 B           | 1 B             |
| `0x62`| ECC_Key_Read       | 3 B            | 48..80 B        |
| `0x63`| ECC_Key_Erase      | 3 B            | 1 B             |
| `0x70`| ECDSA_Sign         | 48 B           | 80 B            |
| `0x71`| EDDSA_Sign         | 16..4112 B     | 80 B            |
| `0x80`| MCounter_Init      | 8 B            | 1 B             |
| `0x81`| MCounter_Update    | 3 B            | 1 B             |
| `0x82`| MCounter_Get       | 3 B            | 8 B             |
| `0x90`| MAC_And_Destroy    | 36 B           | 36 B            |

### L3 result codes (`src/lt_l3_process.h:31-60`)

```c
#define TR01_L3_RESULT_OK             0xC3   // success
#define TR01_L3_RESULT_FAIL           0x3C   // generic L3 failure
#define TR01_L3_RESULT_UNAUTHORIZED   0x01   // ACL denied
#define TR01_L3_RESULT_INVALID_CMD    0x02
#define TR01_L3_RESULT_SLOT_NOT_EMPTY 0x10
#define TR01_L3_RESULT_SLOT_EXPIRED   0x11
#define TR01_L3_RESULT_INVALID_KEY    0x12
#define TR01_L3_RESULT_UPDATE_ERR     0x13   // mcounter done at 0
#define TR01_L3_RESULT_COUNTER_INVALID 0x14
#define TR01_L3_RESULT_SLOT_EMPTY     0x15
#define TR01_L3_RESULT_SLOT_INVALID   0x16
#define TR01_L3_RESULT_HARDWARE_FAIL  0x17   // added in datasheet REV A.11 (FW 2.0.0)
```

These are the on-wire byte values. Libtropic translates each to a host-side `lt_ret_t` enum (see §7).

---

## 6. Cryptographic primitives

| Primitive | Use | Source |
|---|---|---|
| **X25519** (Curve25519, 32 B key, 255-bit clamping) | Secure Channel handshake (host eph + chip eph + chip static + pairing); pairing slots store host X25519 pubkeys; STPUB in cert | `src/lt_x25519.h`, `libtropic_common.h:739-769` |
| **AES-256-GCM** | L3 AEAD: 12 B IV, 16 B tag, empty AAD | `src/lt_aesgcm.h`, `lt_l3_process.c` |
| **HKDF** | Session key derivation from KX outputs | `src/lt_hkdf.h` |
| **SHA-256** | FW header hash, HKDF, cert digest | `src/lt_sha256.h` |
| **HMAC-SHA-256** | Internal (MAC-and-Destroy, etc.) | `src/lt_hmac_sha256.h` |
| **Ed25519 (EdDSA)** | On-chip signing, 32 ECC slots, msg ≤ 4096 B, 64 B R‖S | `lt_ecc_eddsa_sign` |
| **ECDSA P-256** | On-chip signing, host pre-hashes (32 B digest into cmd), 64 B R‖S | `lt_ecc_ecdsa_sign` |
| **TRNG (PTRNG0+PTRNG1)** | Two physical entropy sources (`CFG_SENSORS` bits 0,1) → ephemeral keys + `Random_Value_Get` | `tropic01_bootloader_co.h:42-46` |
| **SPECT co-processor** | HW accelerator for ECC scalar mul; mutable SPECT FW | Architecture docs |

NIST SP 800-90B compliance: not explicitly claimed in libtropic source. Verify in `ODN_TR01_app_008_sec_arch_1v0.pdf` and the datasheet RNG section. The presence of `PTRNG0_TEST_DIS`/`PTRNG1_TEST_DIS` config bits implies startup health tests consistent with an SP 800-90B entropy source.

**Absent primitives** (design constraints): no secp256k1 (no Bitcoin/Lightning); no exposed AES/HMAC/hash/ECDH (host does its own); no RSA at all.

---

## 7. Error codes — full `lt_ret_t` enum (`libtropic_common.h:275-407`)

| Value | Name | Meaning / handling |
|-------|------|---------------------|
| 0  | `LT_OK` | Success |
| 1  | `LT_FAIL` | Generic failure |
| 2  | `LT_HOST_NO_SESSION` | Host code tried L3 op without a session — call `lt_session_start` |
| 3  | `LT_PARAM_ERR` | Argument out of range / NULL — bug in caller |
| 4  | `LT_CRYPTO_ERR` | Host crypto backend failed — usually AEAD tag mismatch or KX failure |
| 5  | `LT_APP_FW_TOO_NEW` | Update libtropic |
| 6  | `LT_REBOOT_UNSUCCESSFUL` | Wanted Application but landed in Start-up (or vice versa) — chip refused load |
| 7  | `LT_L1_SPI_ERROR` | Transport-level SPI error |
| 8  | `LT_L1_DATA_LEN_ERROR` | Unexpected length on the wire |
| 9  | `LT_L1_CHIP_STARTUP_MODE` | Chip is in Start-up — caller wanted Application FW |
| 10 | `LT_L1_CHIP_ALARM_MODE` | Chip is in Alarm — likely bricked (see erratum) |
| 11 | `LT_L1_CHIP_BUSY` | CHIP_STATUS.READY=0 after retries — chip still booting |
| 12 | `LT_L1_INT_TIMEOUT` | Interrupt pin didn't fire in time |
| 13 | `LT_L3_SLOT_NOT_EMPTY` | R-mem write target was already written |
| 14 | `LT_L3_SLOT_EXPIRED` | Flash slot exhausted |
| 15 | `LT_L3_INVALID_KEY` | EdDSA/ECDSA/Read on a bad slot |
| 16 | `LT_L3_UPDATE_ERR` | mcounter done at 0 |
| 17 | `LT_L3_COUNTER_INVALID` | mcounter disabled or locked |
| 18 | `LT_L3_SLOT_EMPTY` | Pairing_Key_Read on empty slot |
| 19 | `LT_L3_SLOT_INVALID` | Pairing_Key_Read on invalidated slot |
| 20 | `LT_L3_OK` | L3 success bubbled up (rarely surfaces) |
| 21 | `LT_L3_FAIL` | Generic L3 failure |
| 22 | `LT_L3_UNAUTHORIZED` | ACL denied (current pairing slot lacks permission) |
| 23 | `LT_L3_INVALID_CMD` | Unknown L3 cmd ID |
| 24 | `LT_L3_HARDWARE_FAIL` | HW write error during pairing/I/R-config/R-mem write (added in FW 2.0.0) |
| 25 | `LT_L3_DATA_LEN_ERROR` | L3 length doesn't match expectation |
| 26 | `LT_L3_RES_SIZE_ERROR` | L3 response RES_SIZE bogus — possible attack/bug |
| 27 | `LT_L3_BUFFER_TOO_SMALL` | L3 result doesn't fit caller's buffer |
| 28 | `LT_L3_R_MEM_DATA_READ_SLOT_EMPTY` | Read on empty user slot |
| 29 | `LT_L3_RESULT_UNKNOWN` | Wire returned unknown RESULT byte |
| 30 | `LT_L2_REQ_CONT` | More chunks expected (request side) |
| 31 | `LT_L2_RES_CONT` | More chunks pending (response side) |
| 32 | `LT_L2_RESP_DISABLED` | Frame disabled by config |
| 33 | `LT_L2_HSK_ERR` | Handshake failed — bad pairing key or STPUB |
| 34 | `LT_L2_NO_SESSION` | Chip-side: no session |
| 35 | `LT_L2_TAG_ERR` | AEAD tag mismatch |
| 36 | `LT_L2_CRC_ERR` | L2 CRC mismatch (chip detected) |
| 37 | `LT_L2_GEN_ERR` | Generic L2 error |
| 38 | `LT_L2_NO_RESP` | Chip has nothing to send (poll too soon) |
| 39 | `LT_L2_UNKNOWN_REQ` | Unknown L2 req ID |
| 40 | `LT_L2_IN_CRC_ERR` | Host-side L2 CRC mismatch |
| 41 | `LT_L2_RSP_LEN_ERROR` | Length field invalid |
| 42 | `LT_L2_STATUS_UNKNOWN` | Unknown STATUS byte |
| 43 | `LT_CERT_STORE_INVALID` | Cert store header bad |
| 44 | `LT_CERT_UNSUPPORTED` | ASN.1 features beyond libtropic's parser |
| 45 | `LT_CERT_ITEM_NOT_FOUND` | Cert lacks requested OID/field |
| 46 | `LT_NONCE_OVERFLOW` | 32-bit AEAD counter wrapped — must restart session |
| 47 | `LT_RET_T_LAST_VALUE` | Sentinel |

`lt_ret_verbose(ret)` (`libtropic.h:669`) gives a string name.

---

## 8. Firmware components

### Three FW images coexist

1. **Bootloader FW** (immutable, ROM-resident, RISC-V CPU). Versions referenced in libtropic: `v1.0.1` and `v2.0.1`. Header layouts differ — `lt_header_boot_v1_t` is 20 B (`type/version/size/git_hash/hash`, all 4 B), `lt_header_boot_v2_t` is 52 B with full SHA-256 hash + `pair_version` field (`libtropic_common.h:648-714`).
2. **Application FW** (mutable, R-Memory, RISC-V CPU). Implements all L2/L3 user commands. Versions 0.2.0 → 2.0.0 documented; 2.0.0 introduces `LT_L3_HARDWARE_FAIL` and bumps R-mem slot max to 475.
3. **SPECT FW** (mutable, R-Memory, SPECT co-processor). Versions 0.3.1 → 1.0.0. Helps with ECC operations. Comment in `lt_l2_api_structs.h:64-67`: in Start-up Mode, SPECT version reads `0x80000000` because SPECT FW is part of the immutable image at boot.

### Bank IDs (`libtropic_common.h:636`)

```c
typedef enum lt_bank_id_t {
    TR01_FW_BANK_FW1     = 1,
    TR01_FW_BANK_FW2     = 2,
    TR01_FW_BANK_SPECT1  = 17,
    TR01_FW_BANK_SPECT2  = 18,
} lt_bank_id_t;
```

### Compatibility matrix (libtropic README)

| Libtropic | App FW         | SPECT FW | Bootloader FW |
|-----------|----------------|----------|---------------|
| 1.0.0     | 1.0.0          | 1.0.0    | 1.0.1 – 2.0.1 |
| 2.0.0     | 1.0.0 – 1.0.1  | 1.0.0    | 2.0.1         |
| 2.0.1     | 1.0.0 – 1.0.1  | 1.0.0    | 2.0.1         |
| 3.0.0     | 1.0.0 – 2.0.0  | 1.0.0    | 2.0.1         |
| 3.1.0     | 1.0.0 – 2.0.0  | 1.0.0    | 2.0.1         |
| 3.2.0     | 1.0.0 – 2.0.0  | 1.0.0    | 2.0.1         |
| 3.2.1     | 1.0.0 – 2.0.0  | 1.0.0    | 2.0.1         |

### Update mechanism

- **ABAB silicon**: host drives bank logic. `lt_mutable_fw_erase(h, bank)` then `lt_mutable_fw_update(h, fw_data, size, bank)`. Chunks ≤ 248 B (`TR01_L2_MUTABLE_FW_UPDATE_REQ_DATA_LEN_MAX = 248u`). Max image **25600 B**.
- **ACAB silicon**: two-phase. Step 1 `lt_mutable_fw_update(h, update_request)` sends 0x68-byte header (req_id `0xb0`); step 2 `lt_mutable_fw_update_data(h, data, size)` streams body (req_id `0xb1`). Max image **30720 B**. FW 2.0.0+ restricts data chunks to 4..216 B (was 4..220).
- **`fw-packager`** (separate tool, not in libtropic) produces signed FW images. The Bootloader verifies each image's signature against a built-in public key. See `ODN_TR01_app_007_fw_update_1v4.pdf`.

`lt_do_mutable_fw_update` (`libtropic.h:808`) hides ABAB/ACAB branching. **Caller must re-init handle after update.**

Watch for FW-update erratas before fleet rollouts: "Mutable_FW_Update_Req fails with GEN_ERR" (2025-08-19), "Secondary FW boot failure" (2025-08-26).

---

## 9. Performance characteristics

Latency / throughput are not in the libtropic public source — see `ODD_TR01_datasheet_vA_11.pdf`, §Electrical Characteristics / §Timing. The source does pin down these limits:

| Limit | Value |
|---|---|
| `lt_random_value_get` per call | ≤ 255 B (`TR01_RANDOM_VALUE_GET_LEN_MAX`) |
| EdDSA message | ≤ 4096 B (`TR01_L3_EDDSA_SIGN_CMD_SIZE_MAX = 4112` incl. framing) |
| Ping payload | ≤ 4096 B (`TR01_PING_LEN_MAX`) |
| L3 cmd / rsp ciphertext | 4112 / 4097 B max |
| L2 chunk payload | 252 B (`TR01_L2_CHUNK_MAX_DATA_SIZE`) |
| AES-GCM nonce | 2³² packets per session before `LT_NONCE_OVERFLOW` |
| L1 read retries | 50 × 25 ms |
| L1 default timeout | 70 ms (`LT_L1_TIMEOUT_MS_DEFAULT`) |
| Reboot delay | 250 ms (`LT_TR01_REBOOT_DELAY_MS`) |

Chunking: host loops 252 B chunks while chip returns `LT_L2_REQ_CONT` / `LT_L2_RES_CONT` until full ciphertext is delivered.

**Sleep current**: not in libtropic source. Reported as **945 µA** in the CDC Badge/TS1302 README — verify against datasheet §Electrical Characteristics.

---

## 10. Operational quirks

### Operating temperature

- **Main chip / R-Memory ops**: full datasheet operating range (verify; typ. -40..+85 °C industrial).
- **I-Memory ops** (pairing keys, I-config writes): **-20 to +85 °C only**. FW <2.0.0 fails silently outside; FW ≥2.0.0 returns error. (`libtropic.h:308-312, 339-343, 400-404, 715-719`)

### Sleep / reboot

- `TR01_L2_SLEEP_KIND_SLEEP = 0x05` is the only accepted sleep kind. `DEEP_SLEEP_MODE` was removed in FW 0.2.0. Wake via any L2 request.
- `TR01_REBOOT = 0x01` (load App FW), `TR01_MAINTENANCE_REBOOT = 0x03` (stay in Bootloader). 250 ms delay before mode re-read.

### Default pairing keys (engineering vs production)

`src/libtropic_default_sh0_keys.c` ships 4 hard-coded 32-B keypairs:

```c
sh0{priv,pub}_eng_sample[]  // TR01-B2S-T005 engineering samples (TS1302 ships these)
sh0{priv,pub}_prod0[]       // TR01-C2P-T101..T310 production parts
```

These are **public** (committed to the repo). Anyone with physical access can open SH0 on a fresh chip — ACLs are effectively bypassable until production keys are replaced.

**Replacement procedure** (canonical, per docs site `reference/default_pairing_keys/` and `ODN_TR01_app_005`):

1. Open Secure Session via SH0 with the matching key set.
2. Host generates X25519 keypair; `lt_pairing_key_write(h, your_pub, 1)` to SH1.
3. Update R-config: grant SH1 the rights you want, strip SH0 to nothing (`erase → write_whole`).
4. After testing, `lt_pairing_key_invalidate(h, 0)` — permanent lock of SH0.
5. Burn relevant I-config bits to make the policy permanent.

CMake option `LT_SH0_KEYS` selects the key set in examples/tests.

### Alarm Mode

Triggered by: the brick erratum `OI_TR01_ERR_2026010800`; any active sensor in `CFG_SENSORS` firing (voltage glitch, laser, EM pulse, temp, shield, oscillator, 8 different bit-flip detectors, CPU alert); I-Memory write errors (errata "Verification of Irreversible Memory writes", 2025-12-01). **Recovery: none.** Build option `LT_RETRIEVE_ALARM_LOG` pulls an alarm log (`libtropic.c:149-153`) but does not reset. Treat as bricked.

### Firmware logging

Gated by `BOOTLOADER_CO_CFG_DEBUG_FW_LOG_EN` (`tropic01_bootloader_co.h:98`). Always disabled on production parts (`libtropic.h:275-277`).

### TS1302 USB devkit specifics

- Ships TR01-B2S-T005 engineering sample (FW 0.2.0/0.3.1), uses `sh0*_eng_sample` keys.
- Stock STM32U535 firmware is a USB-CDC-ACM passthrough; host sees a serial port, libtropic's USB transport (`examples/linux/usb_devkit/`) drives it.
- USB transport is **example-resident, not a reusable HAL** (no `hal/linux/usb_devkit/`). Custom STM32 firmware replaces it entirely.

---

## 11. Sequence diagrams (text)

### Init → first signature → teardown

```
HOST                                          TROPIC01
====                                          ========

lt_init(h):
  L1 SPI init
  Get_Response req 0xAA                  ──►  ◄── CHIP_STATUS byte
    (poll until READY=1, max 50 retries × 25ms)
  Get_Info(obj=0x02 RISCV_FW)            ──►  ◄── 4 B FW version
    → set r_mem_udata_slot_size_max (444 or 475)

lt_get_info_cert_store(h):
  Loop: Get_Info(obj=0x00, block_index=0..29)
                                         ──►  ◄── 128 B chunk × ~30
  Parse 4 X.509 certs into store->certs[0..3]

lt_get_st_pub(&store, stpub32):
  Walk DEVICE cert ASN.1, extract 32 B X25519 SubjectPublicKey

lt_session_start(h, stpub, SH0, sh0priv, sh0pub):
  Generate (EHPRIV, EHPUB) host-side
  HANDSHAKE_REQ {0x02 | 0x21 | EHPUB[32] | pkey_idx | crc[2]}  ──►   (35 B)
                                                ◄──  HANDSHAKE_RSP
                                                     {chip_status | status |
                                                      0x30 | ETPUB[32] |
                                                      auth_tag[16]}  (49 B)
  Compute X25519: EHPRIV×ETPUB, EHPRIV×STPUB, SH0PRIV×ETPUB
  HKDF → AES-256 session key + 12 B encryption_IV + 12 B decryption_IV
  Verify auth_tag (AES-GCM, 16 B)
  session_status = LT_SECURE_SESSION_ON

lt_ecc_eddsa_sign(h, slot, msg, msg_len, rs64):
  L3 plaintext = [cmd_id=0x71 | slot | msg | pad]   (≤ 4112 B)
  AES-256-GCM encrypt(encryption_IV, "", plaintext) → ciphertext+tag
  encryption_IV counter[0..3] += 1 (little-endian)
  Wrap as L2 ENCRYPTED_CMD (req=0x04), chunked at 252 B payload each:
    chunk_i {0x04 | len_i | ciphertext_part_i | crc_i}  ──►
                                                 ◄── status REQUEST_CONT (0x03)
                                                       for each non-last chunk
                                                 ◄── status RESULT_OK (0x02)
                                                       on last chunk
  Reassemble result ciphertext (≤ 4097 B). AES-256-GCM decrypt(decryption_IV).
  decryption_IV counter += 1.
  Switch plaintext[0]:
    0xC3 (OK) → copy R[32]||S[32] into rs64
    else      → map to lt_ret_t per §7

lt_session_abort(h):
  ENCRYPTED_SESSION_ABT_REQ {0x08, len=0}            ──►
                                                ◄── status RESULT_OK
  Zero host-side session keys + IVs.

lt_deinit(h):
  Final memzero of L3 state, close transport.
```

### Wire-level byte counts

| Step | Bytes out | Bytes in |
|------|-----------|----------|
| CHIP_STATUS poll | 1 | 1 |
| Get_Info (4-byte object) | 6 | 9 |
| Cert store full read | ~30 × 6 | ~30 × 133 |
| `lt_session_start` | 35 | 49 |
| `lt_ecc_eddsa_sign` (32 B digest) | 1 chunk ≈ 85 B | 1 chunk ≈ 99 B |
| `lt_ecc_eddsa_sign` (4096 B msg) | ~17 chunks × 256 B | 1 chunk ≈ 99 B |
| `lt_session_abort` | 4 | 4 |

USB-CDC-ACM transport (TS1302) adds USB packet overhead (typ. 64 B max packet, full-speed) per L1 frame.

---

## Appendix A — file map

Sources inspected in full:

- `libtropic/include/libtropic.h`, `libtropic_common.h`, `libtropic_l2.h`, `libtropic_l3.h`
- `libtropic/include/tropic01_application_co.h`, `tropic01_bootloader_co.h`
- `libtropic/src/libtropic.c`, `libtropic_default_sh0_keys.c`, `lt_l3_process.{c,h}`, `lt_aesgcm.h`
- `libtropic/src/lt_l2_api_structs.h`, `lt_l3_api_structs.h`, `lt_l1.h`, `lt_l2_frame_check.h`
- `libtropic/README.md`
- `tropic01/doc/pages/{part-numbers.md, FAQ.md, part-number-and-firmware-version.md, parts/TR01-{B2S-T005,C2P-T301,C2P-T310}.md}`
- Docs site: `https://tropicsquare.github.io/libtropic/latest/{,reference/default_pairing_keys/,reference/tropic01_fw/,reference/libtropic_architecture/,faq/}`

PDFs referenced but not parsed (source-of-truth for any value marked "verify against datasheet"):

- `ODN_TR01_app_002_pin_verif_1v2.pdf` — PIN protocol (MAC-and-Destroy)
- `ODN_TR01_app_003_pki_1v3.pdf` — Cert chain validation
- `ODN_TR01_app_005_first_pairing_key_1v2.pdf` — Pairing-key bootstrap
- `ODN_TR01_app_006_config_obj_1v2.pdf` — Default config values + recommended ACLs
- `ODN_TR01_app_007_fw_update_1v4.pdf` — FW packager + update protocol
- `ODN_TR01_app_008_sec_arch_1v0.pdf` — Security architecture, TRNG cert claims
- `ODD_TR01_datasheet_vA_11.pdf` — Datasheet rev A.11 (FW 2.0.0): timing, power, temp
- `ODU_TR01_user_api_v1_4_0.pdf` — User API rev 1.4.0
