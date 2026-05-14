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

# nixtropic open firmware build — STM32U535 bare-metal.
#
# stdenvNoCC: no C compiler in stdenv — we provide arm-none-eabi-gcc
# via gcc-arm-embedded.  hardeningDisable = ["all"] because hardening
# flags are host-targeted and don't make sense on a Cortex-M33
# freestanding target.
#
# Source roots are passed to CMake as cache variables.  The CMakeLists
# expects them and aborts if any are missing — guards against the
# "I forgot to wire one up" failure mode.

stdenvNoCC.mkDerivation {
  pname = "nixtropic-firmware";
  version = "0.3.0";

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
    description = "Custom STM32U535 firmware exposing TS1302 as a FIDO2 + OpenPGP USB security key";
    longDescription = ''
      Composite USB device (CDC + HID×2 + CCID) on the Tropic Square
      TS1302 dongle.  FIDO2 / WebAuthn over CTAPHID + OpenPGP card over
      USB CCID + lt-rpc vendor HID + CDC console.  All cryptographic
      operations route through the TROPIC01 secure element via libtropic
      L3 sessions.
    '';
    platforms = platforms.linux;
    license = licenses.mit;
  };
}
