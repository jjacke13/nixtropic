{
  stdenv,
  cmake,
  pkg-config,
  openssl,
  libtropicSrc,

  # TROPIC01 target App FW version to flash.  Options correspond to what's
  # bundled inside libtropic's TROPIC01_fw_update_files/boot_v_2_0_1/
  # directory: "1_0_0", "1_0_1", "2_0_0".  Default to the latest (2.0.0).
  cpuFwVersion ? "2_0_0",
}:

stdenv.mkDerivation {
  pname = "nixtropic-fw-update-chip";
  version = "0.1.0-fw-${cpuFwVersion}";

  src = ../tools;

  # The tools/ directory has many files (validate scripts, etc.).  We only
  # want the two for this tool.  unpackPhase puts us in ./tools; rewrite
  # the layout into ./tools/build/ with the right filenames + CMakeLists.txt.
  postUnpack = ''
    mkdir -p source-build
    cp $sourceRoot/fw-update-chip-main.c source-build/main.c
    cp $sourceRoot/fw-update-chip-CMakeLists.txt source-build/CMakeLists.txt
    sed -i 's|fw-update-chip-main.c|main.c|g' source-build/CMakeLists.txt
    sourceRoot=source-build
  '';

  cmakeFlags = [
    "-DLIBTROPIC_SRC=${libtropicSrc}"
    "-DLT_CPU_FW_UPDATE_DATA_VER=${cpuFwVersion}"
  ];

  nativeBuildInputs = [ cmake pkg-config ];
  buildInputs = [ openssl ];

  # libtropic's own CMakeLists may flag warnings as errors — relax that
  # for the host-tool build path.  Application code stays strict.
  NIX_CFLAGS_COMPILE = "-Wno-error";

  meta = {
    description = "One-shot TROPIC01 application-firmware updater (host tool)";
    longDescription = ''
      Updates the TROPIC01's mutable application firmware (CPU FW + SPECT
      FW) on a TS1302 USB dongle running nixtropic's open firmware.

      Targets ACAB silicon (TR01-C2P-T101+) with bootloader v2.0.1.  Writes
      both FW bank pairs (1+2 with the required Maintenance reboot between
      them; see libtropic v3.2.1 CHANGELOG for the why).

      ⚠ IRREVERSIBLE: chip rejects FW downgrade after a successful update.
        Once moved to e.g. v2.0.0, the original 0.3.1 / 0.3.x is unreachable.

      Brick risk: very low.  Mid-flight power loss / disconnect leaves chip
      in Maintenance Mode; the same tool re-run will pick up and complete.
      No JTAG / DFU / recovery hardware required.  Factory data (pairing
      keys, chip ID, certs, R-config, I-config) is untouched by the update
      path.
    '';
    mainProgram = "fw-update-chip";
    license = "MIT";  # libtropic is MIT; our wrapper is also MIT.
  };
}
