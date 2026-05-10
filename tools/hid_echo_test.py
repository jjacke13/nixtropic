#!/usr/bin/env python3
"""hid_echo_test.py — Phase 3 M1 sanity check.

Validates that the nixtropic open firmware's HID interface enumerates and
echoes 64-byte OUT reports back as IN reports. No protocol parsing in M1 —
just byte-for-byte echo.

Run from the nixtropic dev shell (nix develop), which provides the `hid`
Python package backed by hidapi.
"""

from __future__ import annotations

import sys

try:
    import hid  # type: ignore
except ImportError:
    print("ERROR: 'hid' module missing. Enter the dev shell first:")
    print("  nix develop")
    sys.exit(2)


VID = 0xCAFE
PID = 0x4001
REPORT_LEN = 64


def find_path() -> bytes:
    devices = list(hid.enumerate(VID, PID))
    if not devices:
        print(f"ERROR: no HID device with VID:PID {VID:04x}:{PID:04x} found.")
        print("  Is the nixtropic Phase 3 firmware flashed?")
        sys.exit(3)
    # On Linux a composite device lists CDC and HID separately; HID is
    # interface 2 on our device.
    for d in devices:
        if d.get("interface_number", -1) == 2:
            return d["path"]
    return devices[0]["path"]


def main() -> int:
    path = find_path()
    h = hid.Device(path=path)
    print(f"opened {h.manufacturer} / {h.product} at {path!r}")
    print()

    failures = 0
    for trial in range(8):
        tx = bytes([trial] * 4 + list(range(60)))
        assert len(tx) == REPORT_LEN

        # hidapi convention: prepend a leading 0x00 report-ID byte when
        # the device has no report IDs (our case).
        h.write(b"\x00" + tx)

        rx = bytes(h.read(REPORT_LEN, timeout=1000))
        if rx == tx:
            print(f"trial {trial}: PASS (64 B round-trip)")
        else:
            print(f"trial {trial}: FAIL")
            print(f"  sent: {tx.hex()}")
            print(f"  got:  {rx.hex() if rx else '(empty)'}")
            failures += 1

    h.close()
    print()
    if failures == 0:
        print("✓ HID echo PASS — composite descriptor + raw 64-byte transport working")
        return 0
    print(f"✗ {failures}/8 trials failed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
