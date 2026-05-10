{ lib
, stdenvNoCC
, gcc-arm-embedded-13
, src
, version ? "stock-master-36a40ba"
}:

# Reproducible build of Tropic Square's stock TS1302 USB devkit firmware.
#
# Source: https://github.com/tropicsquare/tropic01-stm32u5-usb-devkit-fw
# Pinned: master @ 36a40baa802cf226e07296604afea24780fd09d1 (2025-08-27)
#
# This builds the unmodified upstream "USB-to-SPI passthrough" firmware that
# the dongle ships with. It serves as our recovery image — flashing this back
# to a TS1302 returns it to factory behavior.
#
# Build system: GNU Make. Outputs build/app.{bin,hex,elf}. Single submodule
# (STM32U5xx_HAL_Driver) is fetched via fetchSubmodules = true at the input
# fetch level (see flake.nix).

stdenvNoCC.mkDerivation {
  pname = "tropic01-ts1302-stock-firmware";
  inherit version src;

  nativeBuildInputs = [ gcc-arm-embedded-13 ];

  hardeningDisable = [ "all" ];
  dontConfigure = true;
  dontFixup = true;
  enableParallelBuilding = true;

  buildPhase = ''
    runHook preBuild
    cd app
    make clean
    make
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out
    cp build/app.bin $out/firmware.bin
    cp build/app.hex $out/firmware.hex
    cp build/app.elf $out/firmware.elf
    runHook postInstall
  '';

  meta = with lib; {
    description = "Stock USB-to-SPI passthrough firmware for TROPIC01 TS1302 USB devkit (STM32U535)";
    longDescription = ''
      Unmodified upstream firmware from Tropic Square. Used as the
      factory-reset / recovery image for the TS1302 dongle. Flashes via
      DFU mode to address 0x08000000.
    '';
    homepage = "https://github.com/tropicsquare/tropic01-stm32u5-usb-devkit-fw";
    license = licenses.bsd3;
    platforms = platforms.linux;
    maintainers = [ ];
  };
}
