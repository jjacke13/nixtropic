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

# ----- libtropic core: Phase 1 — re-enable in Phase 3 for HID lt-rpc on chip -----
# Phase 2 is pure byte passthrough (host runs libtropic). The L1+L2 round-trip
# work proven in Phase 1 (commit 4b30bf0) lives in firmware/src/tropic/ and
# stays on disk per user no-delete rule. Re-activation = uncomment this block
# and the LIBTROPIC_SOURCES reference in APP_SOURCES below.
#
# set(LIBTROPIC_SOURCES
#     ${LIBTROPIC_SRC}/src/libtropic.c
#     ${LIBTROPIC_SRC}/src/lt_crc16.c
#     ${LIBTROPIC_SRC}/src/lt_port_wrap.c
#     ${LIBTROPIC_SRC}/src/lt_l1.c
#     ${LIBTROPIC_SRC}/src/libtropic_l2.c
#     ${LIBTROPIC_SRC}/src/lt_l2_frame_check.c
#     ${LIBTROPIC_SRC}/src/lt_asn1_der.c
#     ${LIBTROPIC_SRC}/src/lt_tr01_attrs.c
#     ${LIBTROPIC_SRC}/src/libtropic_secure_memzero.c
#     ${LIBTROPIC_SRC}/hal/stm32/stm32u5xx/libtropic_port_stm32u5xx.c
# )
#
# foreach(src ${LIBTROPIC_SOURCES})
#   if(NOT EXISTS "${src}")
#     message(FATAL_ERROR "libtropic source missing: ${src}")
#   endif()
# endforeach()

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
    # Phase 1 — re-enable in Phase 3 for HID lt-rpc on chip
    # src/tropic/tropic.c
    # src/tropic/lt_crypto_stubs.c
    ${CMSIS_STARTUP}
    ${CMSIS_SYSTEM}
    ${HAL_SOURCES}
    ${TINYUSB_SOURCES}
    # Phase 1 — re-enable in Phase 3 for HID lt-rpc on chip
    # ${LIBTROPIC_SOURCES}
)

add_executable(${FIRMWARE_ELF} ${APP_SOURCES})

target_compile_definitions(${FIRMWARE_ELF} PRIVATE
    USE_HAL_DRIVER
    CFG_TUSB_MCU=OPT_MCU_STM32U5
    # Phase 1 — re-enable in Phase 3 for HID lt-rpc on chip
    # ACAB                        # libtropic: TROPIC01 silicon revision
    # LT_LOG_ENABLE_ERROR=1
    # LT_LOG_ENABLE_WARN=0
    # LT_LOG_ENABLE_INFO=0
    # LT_LOG_ENABLE_DEBUG=0
)

target_include_directories(${FIRMWARE_ELF} PRIVATE
    src
    src/platform                # for stm32u5xx_hal_conf.h
    src/usb                     # for tusb_config.h (TinyUSB looks here)
    ${CMSIS_CORE_SRC}/CMSIS/Core/Include
    ${CMSIS_DEVICE_U5_SRC}/Include
    ${STM32U5XX_HAL_DRIVER_SRC}/Inc
    ${TINYUSB_SRC}/src          # TinyUSB public headers (tusb.h, etc.)
    # Phase 1 — re-enable in Phase 3 for HID lt-rpc on chip
    # ${LIBTROPIC_SRC}/include
    # ${LIBTROPIC_SRC}/src        # libtropic private headers (lt_l1.h etc.)
    # ${LIBTROPIC_SRC}/hal/stm32/stm32u5xx
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

# Phase 1 — re-enable in Phase 3 for HID lt-rpc on chip
# foreach(lt_src ${LIBTROPIC_SOURCES})
#   set_source_files_properties(${lt_src} PROPERTIES
#     COMPILE_FLAGS "-Wno-strict-prototypes -Wno-unused-parameter -Wno-undef -Wno-maybe-uninitialized -Wno-cast-align -Wno-conversion -Wno-shadow")
# endforeach()

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
