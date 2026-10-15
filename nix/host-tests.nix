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
    INC="-Ifirmware/src -Itests/host -I${trezor} -I${libtropicSrc}/include"
    STRICT="-std=c11 -Wall -Wextra -Werror"

    # Vendored crypto: built as-is (gnu11 for explicit_bzero, no -Werror).
    for f in hmac sha2 memzero; do
      $CC -std=gnu11 $SAN -w $INC -c ${trezor}/$f.c -o $f.o
    done
    # P-256 ECDH + AES-CBC for the ClientPIN handler test (as the firmware links them).
    P256=""
    for f in ecdsa nist256p1 secp256k1 bignum rfc6979 hmac_drbg rand \
             aes/aescrypt aes/aeskey aes/aestab aes/aes_modes; do
      o=$(echo $f | tr / _).o
      $CC -std=gnu11 $SAN -w $INC -ffunction-sections -fdata-sections -c ${trezor}/$f.c -o $o
      P256="$P256 $o"
    done

    $CC $STRICT $SAN $INC tests/host/test_cbor.c firmware/src/fido_hid/cbor.c -o test_cbor
    $CC $STRICT $SAN $INC tests/host/test_ctap2_parse.c firmware/src/fido_hid/ctap2_parse.c \
      firmware/src/fido_hid/cbor.c -o test_ctap2_parse
    $CC $STRICT $SAN $INC tests/host/test_pin_token.c firmware/src/fido_hid/pin_token.c \
      hmac.o sha2.o memzero.o -o test_pin_token
    $CC $STRICT $SAN $INC tests/host/test_cose.c firmware/src/fido_hid/cose.c \
      firmware/src/fido_hid/cbor.c -o test_cose
    $CC $STRICT $SAN $INC tests/host/test_l3_result.c -o test_l3_result
    $CC $STRICT $SAN $INC tests/host/test_trezor_rng.c firmware/src/platform/trezor_rng.c -o test_trezor_rng
    $CC $STRICT $SAN $INC tests/host/test_pin_md_legacy.c tests/host/mock_tropic.c \
      firmware/src/tropic/pin_md_legacy.c hmac.o sha2.o memzero.o -o test_pin_md_legacy
    $CC $STRICT $SAN $INC tests/host/test_pin_md_kernel.c tests/host/mock_tropic.c \
      firmware/src/tropic/pin_md_kernel.c firmware/src/tropic/rec_pair.c \
      hmac.o sha2.o memzero.o -o test_pin_md_kernel
    $CC $STRICT $SAN $INC -DNIXTROPIC_HOST_TEST -ffunction-sections -Wl,--gc-sections \
      tests/host/test_fido_state.c tests/host/mock_tropic.c firmware/src/fido_hid/credstore.c \
      firmware/src/fido_hid/fido_state.c firmware/src/fido_hid/pin_md.c firmware/src/fido_hid/slots.c \
      firmware/src/tropic/pin_md_kernel.c firmware/src/tropic/rec_pair.c \
      hmac.o sha2.o memzero.o -o test_fido_state
    $CC $STRICT $SAN $INC -DNIXTROPIC_HOST_TEST -ffunction-sections -Wl,--gc-sections \
      tests/host/test_fido_pin_cmd.c tests/host/mock_tropic.c \
      firmware/src/fido_hid/pin.c firmware/src/fido_hid/pin_token.c firmware/src/fido_hid/cbor.c \
      firmware/src/fido_hid/fido_state.c firmware/src/fido_hid/pin_md.c firmware/src/fido_hid/slots.c \
      firmware/src/tropic/pin_md_kernel.c firmware/src/tropic/rec_pair.c \
      $P256 hmac.o sha2.o memzero.o -o test_fido_pin_cmd
    $CC $STRICT $SAN $INC tests/host/test_rec_pair.c tests/host/mock_tropic.c \
      firmware/src/tropic/rec_pair.c hmac.o sha2.o memzero.o -o test_rec_pair
    runHook postBuild
  '';

  doCheck = true;
  checkPhase = ''
    runHook preCheck
    ./test_cbor
    ./test_ctap2_parse
    ./test_pin_token
    ./test_cose
    ./test_l3_result
    ./test_trezor_rng
    ./test_pin_md_legacy
    ./test_pin_md_kernel
    ./test_fido_state
    ./test_fido_pin_cmd
    ./test_rec_pair
    bash tests/host/test-dfu-flash.sh
    bash tests/host/test-lib-fixture.sh
    runHook postCheck
  '';

  installPhase = ''
    mkdir -p $out
    echo "host tests passed" > $out/result
  '';
}
