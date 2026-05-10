# arm-none-eabi-gcc cross-compile toolchain for STM32U535 (TS1302).
#
# Cortex-M33 with FPv5-SP-D16 hard-float ABI. Per PROJECT.md §8 we want
# strict warnings; -Werror is parked until past the skeleton stage so we
# can integrate ST HAL noise without fighting it (Group D restores it).

set(CMAKE_SYSTEM_NAME      Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

# Don't run try-compile as a host executable — there is no host runtime
# on a Cortex-M33 freestanding target.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(CMAKE_C_COMPILER   arm-none-eabi-gcc)
set(CMAKE_CXX_COMPILER arm-none-eabi-g++)
set(CMAKE_ASM_COMPILER arm-none-eabi-gcc)

# FORCE these so Nix's cmakeBuilder hooks (which pass empty -DCMAKE_AR=
# -DCMAKE_RANLIB= -DCMAKE_STRIP= for stdenvNoCC) do NOT clobber the cross
# toolchain. Without FORCE the empty CLI -D wins over the cache value and
# CMake's try-compile invokes literal "" qc which fails.
set(CMAKE_AR      arm-none-eabi-ar      CACHE FILEPATH "ar"      FORCE)
set(CMAKE_RANLIB  arm-none-eabi-ranlib  CACHE FILEPATH "ranlib"  FORCE)
set(CMAKE_STRIP   arm-none-eabi-strip   CACHE FILEPATH "strip"   FORCE)
set(CMAKE_OBJCOPY arm-none-eabi-objcopy CACHE FILEPATH "objcopy" FORCE)
set(CMAKE_OBJDUMP arm-none-eabi-objdump CACHE FILEPATH "objdump" FORCE)
set(CMAKE_SIZE    arm-none-eabi-size    CACHE FILEPATH "size"    FORCE)

set(CPU_FLAGS "-mcpu=cortex-m33 -mthumb -mfpu=fpv5-sp-d16 -mfloat-abi=hard")

set(WARN_FLAGS "-Wall -Wextra -Wconversion -Wshadow -Wundef -Wcast-align -Wstrict-prototypes")

set(SIZE_FLAGS "-ffunction-sections -fdata-sections")

# Toolchain-global defines: ONLY chip selection. HAL and TinyUSB defines
# (USE_HAL_DRIVER, CFG_TUSB_MCU) are per-target and added in CMakeLists
# only on targets that actually pull in those headers — otherwise the
# CMSIS device header chains into stm32u5xx_hal.h which needs a
# stm32u5xx_hal_conf.h that doesn't exist yet (task B4).
set(COMMON_DEFS "-DSTM32U535xx")

set(CMAKE_C_FLAGS_INIT   "${CPU_FLAGS} ${WARN_FLAGS} ${SIZE_FLAGS} ${COMMON_DEFS} -std=gnu11 -fno-builtin")
set(CMAKE_ASM_FLAGS_INIT "${CPU_FLAGS} -x assembler-with-cpp")
set(CMAKE_EXE_LINKER_FLAGS_INIT "${CPU_FLAGS} -Wl,--gc-sections")
