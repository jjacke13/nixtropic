{ lib, stdenv, bash, gawk, coreutils, libtropicSrc }:

# Host-side tests (Phase 9 M0): firmware modules built for the build machine
# and run against tests/host/mock_tropic.c, plus the shell-script tests.
# The build fails if any test fails.  `nix build .#host-tests` or
# `nix flake check`.  No dongle involved.

let
  trezor = "${libtropicSrc}/vendor/trezor_crypto";
in
stdenv.mkDerivation {
  pname = "nixtropic-host-tests";
  version = "0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [ ../firmware/src ../tests/host ../tools ];
  };

  nativeBuildInputs = [ bash gawk coreutils ];

  # ASan/UBSan with fortify on top is noisy and redundant here.
  hardeningDisable = [ "fortify" ];

  buildPhase = ''
    runHook preBuild
    SAN="-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g -O1"
    INC="-Ifirmware/src -Itests/host -I${trezor} -I${libtropicSrc}/include -I${libtropicSrc}/src"
    STRICT="-std=c11 -Wall -Wextra -Werror"

    # Vendored crypto: built as-is (gnu11 for explicit_bzero, no -Werror).
    for f in hmac sha2 memzero; do
      $CC -std=gnu11 $SAN -w $INC -c ${trezor}/$f.c -o $f.o
    done

    $CC $STRICT $SAN $INC tests/host/test_cbor.c firmware/src/fido_hid/cbor.c -o test_cbor
    $CC $STRICT $SAN $INC tests/host/test_pin_md_kernel.c tests/host/mock_tropic.c \
      firmware/src/tropic/pin_md_kernel.c hmac.o sha2.o memzero.o -o test_pin_md_kernel
    $CC $STRICT $SAN $INC tests/host/test_passthrough_guard.c \
      firmware/src/cdc_protocol/guard.c -o test_passthrough_guard
    runHook postBuild
  '';

  doCheck = true;
  checkPhase = ''
    runHook preCheck
    ./test_cbor
    ./test_pin_md_kernel
    ./test_passthrough_guard
    bash tests/host/test-dfu-flash.sh
    bash tests/host/test-lib-fixture.sh
    runHook postCheck
  '';

  installPhase = ''
    mkdir -p $out
    echo "host tests passed" > $out/result
  '';
}
