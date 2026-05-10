{ stdenvNoCC
, lib
, cmake
, ninja
, gcc-arm-embedded
, libtropicSrc
, cmsisCoreSrc
, cmsisDeviceU5Src
, stm32u5xxHalDriverSrc
, tinyusbSrc
}:

# Phase 1 firmware build.
#
# Bare-metal target: stdenvNoCC (no C compiler in stdenv — we provide
# arm-none-eabi-gcc via gcc-arm-embedded). hardeningDisable = ["all"]
# because hardening flags are host-targeted and don't make sense on a
# Cortex-M33 freestanding target.
#
# Source roots are passed to CMake as cache variables. The CMakeLists
# expects them and aborts if any are missing — this guards against the
# "I forgot to wire one up" failure mode.
#
# See docs/PHASE-1-PLAN.md for the multi-group bring-up plan; this
# derivation is the A2 deliverable.

stdenvNoCC.mkDerivation {
  pname = "nixtropic-firmware";
  version = "0.1.0-phase1-C-usb-cdc";

  src = ../firmware;

  nativeBuildInputs = [
    cmake
    ninja
    gcc-arm-embedded
  ];

  hardeningDisable = [ "all" ];

  # No host code, so don't try to strip with the host strip.
  dontStrip = true;

  cmakeFlags = [
    "-DCMAKE_TOOLCHAIN_FILE=${../firmware/cmake/arm-none-eabi.cmake}"
    "-DLIBTROPIC_SRC=${libtropicSrc}"
    "-DCMSIS_CORE_SRC=${cmsisCoreSrc}"
    "-DCMSIS_DEVICE_U5_SRC=${cmsisDeviceU5Src}"
    "-DSTM32U5XX_HAL_DRIVER_SRC=${stm32u5xxHalDriverSrc}"
    "-DTINYUSB_SRC=${tinyusbSrc}"
    "-GNinja"
  ];

  installPhase = ''
    runHook preInstall
    mkdir -p $out
    cp firmware.elf $out/firmware.elf
    cp firmware.bin $out/firmware.bin
    cp firmware.hex $out/firmware.hex
    if [ -f firmware.map ]; then
      cp firmware.map $out/firmware.map
    fi
    runHook postInstall
  '';

  meta = with lib; {
    description = "Custom STM32U535 firmware for TS1302 (Phase 1 skeleton)";
    longDescription = ''
      Phase 1 deliverable: STM32U535 firmware that brings up USB CDC-ACM
      via TinyUSB, powers and queries TROPIC01 over SPI1, prints L2 chip-ID
      and RNG over /dev/ttyACM*. Currently at the A4 build-pipeline-skeleton
      stage; see docs/PHASE-1-PLAN.md for full plan.
    '';
    platforms = platforms.linux;
    # License finalized in Phase 8 polish.
    license = licenses.mit;
  };
}
