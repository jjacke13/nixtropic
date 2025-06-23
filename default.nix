{ lib
, stdenv
, fetchFromGitHub
, cmake
, pkg-config
}:

stdenv.mkDerivation rec {
  pname = "libtropic-util";
  version = "1.0"; 
  src = fetchFromGitHub {
    owner = "tropicsquare";
    repo = "libtropic-util";
    rev = "cf9a73cba8865bfcf04fff7ec58ac7f982704e20"; 
    sha256 = "sha256-lCdjHYbuX5AN8rlcA20t9NwjZF0jXR3p8mRo3UDZd4Y=";
    fetchSubmodules = true;
  };
  
  
  nativeBuildInputs = [
    cmake
    pkg-config
  ];

  cmakeFlags = [
    "-DUSB_DONGLE_TS1302=1"
  ];

  installPhase = ''
    mkdir -p $out/bin
    cp ./lt-util $out/bin/lt-util
  '';

  meta = with lib; {
    description = "Command line utility for interfacing TROPIC01 chip";
    homepage = "https://github.com/tropicsquare/libtropic-util";
    license = licenses.bsd3;
    maintainers = with maintainers; [ ];
    platforms = platforms.linux;
  };
}