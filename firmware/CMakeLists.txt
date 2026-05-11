# Firmware top-level CMakeLists.
#
# Build flow:
#   nix build .#firmware
#     → derivation passes -DLIBTROPIC_SRC=... and friends
#     → CMake configures with arm-none-eabi.cmake toolchain file
#     → ninja builds firmware.elf
#     → POST_BUILD generates firmware.bin and firmware.hex
#
# Phase 1 used libtropic on the MCU for an L1+L2 round-trip with TROPIC01.
# Phase 2 is byte-passthrough (host runs libtropic over USB CDC), so the
# libtropic source list + tropic/ application code are excluded from the
# build via comment markers. They stay on disk — re-enabling for Phase 3+
# is uncomment-only.

cmake_minimum_required(VERSION 3.21)

project(nixtropic-firmware C ASM)

# ----- Required source roots (passed by Nix; fail fast if missing) -----
# LIBTROPIC_SRC stays required because flake.nix still pins libtropic for the
# host-side `lt-util` package and may want to re-enable on-MCU libtropic in
# Phase 3 (HID lt-rpc). The path always exists from Nix; we just don't compile
# from it during Phase 2.
foreach(var
    LIBTROPIC_SRC
    CMSIS_CORE_SRC
    CMSIS_DEVICE_U5_SRC
    STM32U5XX_HAL_DRIVER_SRC
    TINYUSB_SRC)
  if(NOT DEFINED ${var})
    message(FATAL_ERROR "${var} not set. Pass via -D${var}=<path> from Nix.")
  endif()
  if(NOT EXISTS "${${var}}")
    message(FATAL_ERROR "${var} = ${${var}} does not exist on disk.")
  endif()
endforeach()

set(FIRMWARE_NAME firmware)
set(FIRMWARE_ELF  ${FIRMWARE_NAME}.elf)
set(LINKER_SCRIPT ${CMAKE_SOURCE_DIR}/linker/stm32u535.ld)

# ----- ST-provided startup + system files -----
set(CMSIS_STARTUP "${CMSIS_DEVICE_U5_SRC}/Source/Templates/gcc/startup_stm32u535xx.s")
set(CMSIS_SYSTEM  "${CMSIS_DEVICE_U5_SRC}/Source/Templates/system_stm32u5xx.c")

if(NOT EXISTS "${CMSIS_STARTUP}")
  message(FATAL_ERROR "CMSIS startup file missing: ${CMSIS_STARTUP}")
endif()
if(NOT EXISTS "${CMSIS_SYSTEM}")
  message(FATAL_ERROR "CMSIS system file missing: ${CMSIS_SYSTEM}")
endif()

# ----- HAL .c files we link in (matches modules enabled in hal_conf.h) -----
set(HAL_SOURCES
    ${STM32U5XX_HAL_DRIVER_SRC}/Src/stm32u5xx_hal.c
    ${STM32U5XX_HAL_DRIVER_SRC}/Src/stm32u5xx_hal_rcc.c
    ${STM32U5XX_HAL_DRIVER_SRC}/Src/stm32u5xx_hal_rcc_ex.c
    ${STM32U5XX_HAL_DRIVER_SRC}/Src/stm32u5xx_hal_flash.c
    ${STM32U5XX_HAL_DRIVER_SRC}/Src/stm32u5xx_hal_flash_ex.c
    ${STM32U5XX_HAL_DRIVER_SRC}/Src/stm32u5xx_hal_gpio.c
    ${STM32U5XX_HAL_DRIVER_SRC}/Src/stm32u5xx_hal_pwr.c
    ${STM32U5XX_HAL_DRIVER_SRC}/Src/stm32u5xx_hal_pwr_ex.c
    ${STM32U5XX_HAL_DRIVER_SRC}/Src/stm32u5xx_hal_cortex.c
    ${STM32U5XX_HAL_DRIVER_SRC}/Src/stm32u5xx_hal_rng.c
    ${STM32U5XX_HAL_DRIVER_SRC}/Src/stm32u5xx_hal_rng_ex.c
    ${STM32U5XX_HAL_DRIVER_SRC}/Src/stm32u5xx_hal_spi.c
    ${STM32U5XX_HAL_DRIVER_SRC}/Src/stm32u5xx_hal_spi_ex.c
    ${STM32U5XX_HAL_DRIVER_SRC}/Src/stm32u5xx_hal_dma.c
    ${STM32U5XX_HAL_DRIVER_SRC}/Src/stm32u5xx_hal_dma_ex.c
    ${STM32U5XX_HAL_DRIVER_SRC}/Src/stm32u5xx_hal_exti.c
)

foreach(src ${HAL_SOURCES})
  if(NOT EXISTS "${src}")
    message(FATAL_ERROR "HAL source missing: ${src}")
  endif()
endforeach()

# ----- libtropic core (re-activated in Phase 3 M3 for libtropic-on-chip) -----
# Phase 2 stripped this out for pure byte passthrough. M3 brings it back so
# the firmware can run L2 commands like lt_get_info_chip_id locally and
# expose them over the HID lt-rpc transport. M4 adds the L3 secure session.
#
# Note: lt_crypto_stubs.c provides LT_FAIL stubs for L3 crypto. L3 paths are
# not reachable in M3 (only L2 commands invoked) so the stubs are correct.
# M4 swaps these out for libtropic's trezor_crypto CAL.
set(LIBTROPIC_SOURCES
    ${LIBTROPIC_SRC}/src/libtropic.c
    ${LIBTROPIC_SRC}/src/lt_crc16.c
    ${LIBTROPIC_SRC}/src/lt_port_wrap.c
    ${LIBTROPIC_SRC}/src/lt_l1.c
    ${LIBTROPIC_SRC}/src/libtropic_l2.c
    ${LIBTROPIC_SRC}/src/lt_l2_frame_check.c
    ${LIBTROPIC_SRC}/src/lt_asn1_der.c
    ${LIBTROPIC_SRC}/src/lt_tr01_attrs.c
    ${LIBTROPIC_SRC}/src/libtropic_secure_memzero.c
    ${LIBTROPIC_SRC}/hal/stm32/stm32u5xx/libtropic_port_stm32u5xx.c
    # M4: L3 secure session
    ${LIBTROPIC_SRC}/src/libtropic_l3.c
    ${LIBTROPIC_SRC}/src/lt_l3_process.c
    ${LIBTROPIC_SRC}/src/lt_hkdf.c
    # M4: default sh0 pairing keys (sh0pub_prod0/sh0priv_prod0 etc.)
    ${LIBTROPIC_SRC}/src/libtropic_default_sh0_keys.c
)

foreach(src ${LIBTROPIC_SOURCES})
  if(NOT EXISTS "${src}")
    message(FATAL_ERROR "libtropic source missing: ${src}")
  endif()
endforeach()

# ----- Crypto Abstraction Layer (trezor_crypto) — M4 -----
# Provides AES-GCM, SHA256, HMAC-SHA256, X25519 for libtropic's L3
# secure session. Replaces our Phase 1 lt_crypto_stubs.c (which returned
# LT_FAIL for everything). Trezor's ed25519-donna gives us X25519 via the
# curve25519_scalarmult{,_basepoint} wrappers in ed25519.c.
set(LT_CAL_SOURCES
    ${LIBTROPIC_SRC}/cal/trezor_crypto/lt_trezor_crypto_common.c
    ${LIBTROPIC_SRC}/cal/trezor_crypto/lt_trezor_crypto_aesgcm.c
    ${LIBTROPIC_SRC}/cal/trezor_crypto/lt_trezor_crypto_sha256.c
    ${LIBTROPIC_SRC}/cal/trezor_crypto/lt_trezor_crypto_hmac_sha256.c
    ${LIBTROPIC_SRC}/cal/trezor_crypto/lt_trezor_crypto_x25519.c
)

set(TREZOR_VENDOR ${LIBTROPIC_SRC}/vendor/trezor_crypto)
set(TREZOR_CRYPTO_SOURCES
    # AES + GCM
    ${TREZOR_VENDOR}/aes/aescrypt.c
    ${TREZOR_VENDOR}/aes/aeskey.c
    ${TREZOR_VENDOR}/aes/aestab.c
    ${TREZOR_VENDOR}/aes/aes_modes.c
    ${TREZOR_VENDOR}/aes/aesgcm.c
    ${TREZOR_VENDOR}/aes/gf128mul.c
    # SHA256 / SHA512 (both in sha2.c) + HMAC + hasher dispatcher.
    ${TREZOR_VENDOR}/sha2.c
    ${TREZOR_VENDOR}/hmac.c
    ${TREZOR_VENDOR}/hasher.c
    # Hasher dispatcher references all these even when we only ever ask for
    # HASHER_SHA2. --gc-sections strips the unused code paths, but the
    # linker still needs the symbols to resolve at link time. Cheaper to
    # include them than to fork hasher.c.
    ${TREZOR_VENDOR}/blake256.c
    ${TREZOR_VENDOR}/blake2b.c
    ${TREZOR_VENDOR}/blake2s.c
    ${TREZOR_VENDOR}/sha3.c
    ${TREZOR_VENDOR}/groestl.c
    ${TREZOR_VENDOR}/ripemd160.c
    ${TREZOR_VENDOR}/memzero.c
    # X25519 via ed25519-donna's curve25519_scalarmult wrappers.
    ${TREZOR_VENDOR}/ed25519-donna/ed25519.c
    ${TREZOR_VENDOR}/ed25519-donna/curve25519-donna-32bit.c
    ${TREZOR_VENDOR}/ed25519-donna/curve25519-donna-helpers.c
    ${TREZOR_VENDOR}/ed25519-donna/curve25519-donna-scalarmult-base.c
    ${TREZOR_VENDOR}/ed25519-donna/ed25519-donna-impl-base.c
    ${TREZOR_VENDOR}/ed25519-donna/ed25519-donna-basepoint-table.c
    ${TREZOR_VENDOR}/ed25519-donna/ed25519-donna-32bit-tables.c
    ${TREZOR_VENDOR}/ed25519-donna/modm-donna-32bit.c
    # rand.c — trezor uses it for ed25519 batch verify; we don't, but
    # linker still wants the symbol.
    ${TREZOR_VENDOR}/rand.c
    # Phase 5 M3: P-256 ECDH for CTAP2 ClientPIN keyAgreement (ecdh_multiply
    # + ecdsa_get_public_key65). bignum256 + nist256p1 curve params + zkp
    # stubs come along — secp256k1 is also referenced by ecdsa.c even when
    # we only use P-256 (functions get GC'd by --gc-sections but symbols
    # must resolve at link time).
    ${TREZOR_VENDOR}/ecdsa.c
    ${TREZOR_VENDOR}/nist256p1.c
    ${TREZOR_VENDOR}/secp256k1.c
    ${TREZOR_VENDOR}/bignum.c
    ${TREZOR_VENDOR}/rfc6979.c
)

foreach(src ${LT_CAL_SOURCES} ${TREZOR_CRYPTO_SOURCES})
  if(NOT EXISTS "${src}")
    message(FATAL_ERROR "CAL/vendor source missing: ${src}")
  endif()
endforeach()

# ----- TinyUSB sources (CDC subset) -----
# Only the files we actually use:
#   tusb.c            — top-level dispatcher
#   tusb_fifo.c       — common FIFO util (used by CDC class for tx/rx buffers)
#   usbd.c, usbd_control.c — TinyUSB device stack
#   cdc_device.c      — CDC class driver
#   dcd_stm32_fsdev.c — STM32 PMA-based FS device controller (U535's USB DRD)
# We deliberately do NOT include dcd_dwc2.c — U535 has no OTG controller.
set(TINYUSB_SOURCES
    ${TINYUSB_SRC}/src/tusb.c
    ${TINYUSB_SRC}/src/common/tusb_fifo.c
    ${TINYUSB_SRC}/src/device/usbd.c
    ${TINYUSB_SRC}/src/device/usbd_control.c
    ${TINYUSB_SRC}/src/class/cdc/cdc_device.c
    ${TINYUSB_SRC}/src/class/hid/hid_device.c
    ${TINYUSB_SRC}/src/portable/st/stm32_fsdev/dcd_stm32_fsdev.c
)

foreach(src ${TINYUSB_SOURCES})
  if(NOT EXISTS "${src}")
    message(FATAL_ERROR "TinyUSB source missing: ${src}")
  endif()
endforeach()

# ----- Application sources -----
set(APP_SOURCES
    src/main.c
    src/platform/clock.c
    src/platform/gpio.c
    src/platform/blink.c
    src/platform/rng.c
    src/platform/spi.c
    src/usb/usb.c
    src/usb/usb_descriptors.c
    src/usb/cdc_io.c
    src/cdc_protocol/protocol.c
    src/cdc_protocol/parser.c
    src/cdc_protocol/hex.c
    src/cdc_protocol/cmd.c
    src/hid_rpc/rpc.c
    src/hid_rpc/rpc_cmds.c
    src/fido_hid/ctaphid.c
    src/fido_hid/cbor.c
    src/fido_hid/ctap2.c
    src/fido_hid/ctap2_creds.c
    src/fido_hid/credstore.c
    src/fido_hid/slots.c
    src/fido_hid/pin.c
    src/fido_hid/pin_md.c
    src/tropic/tropic.c
    # src/tropic/lt_crypto_stubs.c  — M4: replaced by trezor_crypto CAL below
    ${CMSIS_STARTUP}
    ${CMSIS_SYSTEM}
    ${HAL_SOURCES}
    ${TINYUSB_SOURCES}
    ${LIBTROPIC_SOURCES}
    ${LT_CAL_SOURCES}
    ${TREZOR_CRYPTO_SOURCES}
)

add_executable(${FIRMWARE_ELF} ${APP_SOURCES})

target_compile_definitions(${FIRMWARE_ELF} PRIVATE
    USE_HAL_DRIVER
    CFG_TUSB_MCU=OPT_MCU_STM32U5
    ACAB                        # libtropic: TROPIC01 silicon revision (user's chip)
    LT_LOG_ENABLE_ERROR=1
    LT_LOG_ENABLE_WARN=0
    LT_LOG_ENABLE_INFO=0
    LT_LOG_ENABLE_DEBUG=0
)

target_include_directories(${FIRMWARE_ELF} PRIVATE
    src
    src/platform                # for stm32u5xx_hal_conf.h
    src/usb                     # for tusb_config.h (TinyUSB looks here)
    ${CMSIS_CORE_SRC}/CMSIS/Core/Include
    ${CMSIS_DEVICE_U5_SRC}/Include
    ${STM32U5XX_HAL_DRIVER_SRC}/Inc
    ${TINYUSB_SRC}/src          # TinyUSB public headers (tusb.h, etc.)
    ${LIBTROPIC_SRC}/include
    ${LIBTROPIC_SRC}/src        # libtropic private headers (lt_l1.h etc.)
    ${LIBTROPIC_SRC}/hal/stm32/stm32u5xx
    # M4: trezor_crypto CAL + vendor crypto headers
    ${LIBTROPIC_SRC}/cal/trezor_crypto
    ${LIBTROPIC_SRC}/vendor/trezor_crypto
)

# Suppress warnings on ST HAL sources only. Application code stays strict.
foreach(hal_src ${HAL_SOURCES})
  set_source_files_properties(${hal_src} PROPERTIES
    COMPILE_FLAGS "-Wno-strict-prototypes -Wno-unused-parameter -Wno-undef -Wno-maybe-uninitialized -Wno-cast-align -Wno-conversion")
endforeach()

# Same suppressions for TinyUSB sources — different upstream, same idea
# (we don't own the code; warning-noise isn't actionable here).
foreach(tu_src ${TINYUSB_SOURCES})
  set_source_files_properties(${tu_src} PROPERTIES
    COMPILE_FLAGS "-Wno-strict-prototypes -Wno-unused-parameter -Wno-undef -Wno-maybe-uninitialized -Wno-cast-align -Wno-conversion")
endforeach()

foreach(lt_src ${LIBTROPIC_SOURCES} ${LT_CAL_SOURCES} ${TREZOR_CRYPTO_SOURCES})
  set_source_files_properties(${lt_src} PROPERTIES
    COMPILE_FLAGS "-Wno-strict-prototypes -Wno-unused-parameter -Wno-undef -Wno-maybe-uninitialized -Wno-cast-align -Wno-conversion -Wno-shadow -Wno-pointer-sign -Wno-sign-compare -Wno-unused-function -Wno-implicit-fallthrough")
endforeach()

# Trezor-vendor crypto needs four extra defines per upstream's
# tests/functional/src/CMakeLists.txt:134 build recipe:
#   AES_VAR                      — enable variable-key AES dispatcher (so
#                                  aes_encrypt_key(key, key_len, ctx)
#                                  resolves to 128/192/256 variants)
#   USE_INSECURE_PRNG            — rand.c uses a non-secure stub PRNG;
#                                  fine for us since we never call into
#                                  ed25519 batch verify (key gen/sign
#                                  happen on TROPIC01, not the MCU)
#   ed25519_verify=...           — collision-avoidance no-op for us
#   USE_PRECOMPUTED_CP=0         — Phase 5 M3: disable the 127 KB
#                                  precomputed multiplication table for
#                                  nist256p1.cp. ECDH gets slower (~50ms
#                                  vs ~10ms) but flash drops back into
#                                  the 256 KB budget. ClientPIN is
#                                  user-initiated and infrequent, so the
#                                  slowdown is invisible.
foreach(tz_src ${TREZOR_CRYPTO_SOURCES})
  set_source_files_properties(${tz_src} PROPERTIES
    COMPILE_DEFINITIONS "AES_VAR;USE_INSECURE_PRNG;USE_PRECOMPUTED_CP=0;ed25519_verify=trezor_crypto_ed25519_verify")
endforeach()

target_link_options(${FIRMWARE_ELF} PRIVATE
    -T${LINKER_SCRIPT}
    -Wl,-Map=${FIRMWARE_NAME}.map
    -Wl,--print-memory-usage
    --specs=nano.specs
    --specs=nosys.specs
)

set_target_properties(${FIRMWARE_ELF} PROPERTIES LINK_DEPENDS ${LINKER_SCRIPT})

add_custom_command(TARGET ${FIRMWARE_ELF} POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:${FIRMWARE_ELF}> ${FIRMWARE_NAME}.bin
    COMMAND ${CMAKE_OBJCOPY} -O ihex   $<TARGET_FILE:${FIRMWARE_ELF}> ${FIRMWARE_NAME}.hex
    COMMAND ${CMAKE_SIZE}              $<TARGET_FILE:${FIRMWARE_ELF}>
    BYPRODUCTS ${FIRMWARE_NAME}.bin ${FIRMWARE_NAME}.hex
    COMMENT "Generating ${FIRMWARE_NAME}.bin and ${FIRMWARE_NAME}.hex"
)
