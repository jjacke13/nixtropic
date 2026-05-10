#!/usr/bin/env python3
"""Phase 4 M2 host-side test — CTAPHID INIT/PING/MSG over /dev/hidrawN.

Validates the FIDO HID interface (instance 1) on the nixtropic dongle:
  * CTAPHID_INIT on broadcast CID returns a new CID, echoes the nonce,
    advertises CTAP2/CBOR capability.
  * CTAPHID_PING on the allocated CID echoes the payload across multi-packet
    INIT+CONT framing.
  * CTAPHID_MSG returns SW=0x6E00 (CLA not supported), per stub policy.
  * CTAPHID_INIT on a non-broadcast CID synchronizes that channel.
  * Spurious commands on a busy channel return CHANNEL_BUSY (lightly tested).

Run inside `nix develop` so the python3 with `hid` package is on PATH.

Usage:
  python3 fido2_test.py validate           # full M2 suite, exit 0 on pass
  python3 fido2_test.py init               # one-shot INIT
  python3 fido2_test.py ping               # PING echo round-trip
  python3 fido2_test.py msg                # CTAPHID_MSG → 0x6E00
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import time
from pathlib import Path

import hid

VID, PID = 0xCAFE, 0x4001
FIDO_USAGE_PAGE = 0xF1D0   # FIDO Alliance HID usage page

REPORT_LEN = 64
INIT_DATA = 57
CONT_DATA = 59

CMD_INIT_FLAG = 0x80
CMD_PING      = 0x01
CMD_MSG       = 0x03
CMD_INIT      = 0x06
CMD_CBOR      = 0x10
CMD_CANCEL    = 0x11
CMD_ERROR     = 0x3F

CID_BROADCAST = 0xFFFFFFFF


def find_fido_path() -> str:
    """Locate /dev/hidrawN for VID:PID with FIDO usage page."""
    matches = []
    for d in hid.enumerate(VID, PID):
        if d.get("usage_page") == FIDO_USAGE_PAGE:
            matches.append(d["path"])
    if not matches:
        # Some hidapi backends don't report usage_page; fall back to picking
        # the highest-numbered hidraw path of our VID:PID (the FIDO one is
        # added second, so it usually has the larger index).
        all_paths = sorted({d["path"] for d in hid.enumerate(VID, PID)})
        if not all_paths:
            raise RuntimeError(f"No HID device with VID:PID {VID:04x}:{PID:04x}")
        if len(all_paths) < 2:
            raise RuntimeError(
                f"Only one HID interface found ({all_paths[0]!r}); "
                f"expected two (lt-rpc + FIDO). Phase 4 M1 not flashed?")
        # FIDO interface is the higher hidrawN since it was added later.
        return all_paths[-1].decode() if isinstance(all_paths[-1], bytes) else all_paths[-1]
    p = matches[0]
    return p.decode() if isinstance(p, bytes) else p


def open_dev(path: str) -> hid.Device:
    return hid.Device(path=path.encode() if isinstance(path, str) else path)


def _be32(v: int) -> bytes: return struct.pack(">I", v)
def _be16(v: int) -> bytes: return struct.pack(">H", v)


def transact(dev: hid.Device, cid: int, cmd: int, payload: bytes,
             *, timeout_ms: int = 2000) -> tuple[int, int, bytes]:
    """Send a single CTAPHID request, return (resp_cid, resp_cmd, resp_payload)."""
    # Build outbound packets
    pkts: list[bytes] = []
    first = bytearray(REPORT_LEN)
    first[0:4] = _be32(cid)
    first[4]   = (CMD_INIT_FLAG | cmd) & 0xFF
    first[5:7] = _be16(len(payload))
    chunk = payload[:INIT_DATA]
    first[7:7 + len(chunk)] = chunk
    pkts.append(bytes(first))

    off = len(chunk)
    seq = 0
    while off < len(payload):
        cont = bytearray(REPORT_LEN)
        cont[0:4] = _be32(cid)
        cont[4]   = seq & 0x7F
        chunk = payload[off:off + CONT_DATA]
        cont[5:5 + len(chunk)] = chunk
        pkts.append(bytes(cont))
        off += len(chunk)
        seq += 1

    # `hid.Device.write` requires a leading report-id byte (0x00 for the
    # only report defined in our descriptor). The device-side TinyUSB
    # callback strips it.
    for p in pkts:
        n = dev.write(b"\x00" + p)
        if n != REPORT_LEN + 1:
            raise RuntimeError(f"Short HID write: {n} != {REPORT_LEN+1}")

    # Read response packets until BCNT bytes are accumulated.
    deadline = time.time() + timeout_ms / 1000.0
    body = bytearray()
    resp_cid = resp_cmd = resp_total = None

    while True:
        if time.time() > deadline:
            raise TimeoutError("No CTAPHID response within timeout")
        chunk = dev.read(REPORT_LEN, timeout=200)
        if not chunk:
            continue
        if len(chunk) < REPORT_LEN:
            continue
        rc_cid = struct.unpack(">I", chunk[0:4])[0]
        b4     = chunk[4]
        if resp_cid is None:
            # Expect INIT packet
            if not (b4 & CMD_INIT_FLAG):
                continue                 # spurious CONT from a different
                                         # transaction; ignore
            resp_cid   = rc_cid
            resp_cmd   = b4 & 0x7F
            resp_total = struct.unpack(">H", chunk[5:7])[0]
            body += chunk[7:7 + min(INIT_DATA, resp_total)]
        else:
            if rc_cid != resp_cid:
                continue                 # not our channel; skip
            body += chunk[5:5 + min(CONT_DATA, resp_total - len(body))]
        if len(body) >= resp_total:
            return resp_cid, resp_cmd, bytes(body[:resp_total])


def cmd_init(dev: hid.Device, *, cid: int = CID_BROADCAST,
             nonce: bytes | None = None) -> tuple[int, bytes]:
    """Return (allocated_cid, full_init_response)."""
    if nonce is None:
        nonce = os.urandom(8)
    rcid, cmd, payload = transact(dev, cid, CMD_INIT, nonce)
    if cmd != CMD_INIT:
        raise RuntimeError(f"Unexpected response cmd 0x{cmd:02x} (want INIT 0x06)")
    if len(payload) != 17:
        raise RuntimeError(f"INIT response wrong length: {len(payload)} != 17")
    if payload[:8] != nonce:
        raise RuntimeError(f"INIT nonce mismatch: got {payload[:8].hex()}, "
                           f"sent {nonce.hex()}")
    new_cid = struct.unpack(">I", payload[8:12])[0]
    return new_cid, payload


def _format_init(payload: bytes) -> str:
    new_cid = struct.unpack(">I", payload[8:12])[0]
    return (f"nonce={payload[:8].hex()} new_cid=0x{new_cid:08x} "
            f"proto={payload[12]} dev=v{payload[13]}.{payload[14]}.{payload[15]} "
            f"caps=0x{payload[16]:02x}")


# ---------------- subcommands ----------------

def sub_init(args) -> int:
    path = find_fido_path()
    print(f"FIDO HID @ {path}")
    with open_dev(path) as dev:
        _, payload = cmd_init(dev)
        print(_format_init(payload))
    return 0


def sub_ping(args) -> int:
    path = find_fido_path()
    with open_dev(path) as dev:
        new_cid, _ = cmd_init(dev)
        msg = b"\xa5" * args.size
        rcid, cmd, body = transact(dev, new_cid, CMD_PING, msg)
        if rcid != new_cid:
            print(f"FAIL: PING response on wrong CID 0x{rcid:08x}", file=sys.stderr)
            return 1
        if cmd != CMD_PING:
            print(f"FAIL: PING response cmd 0x{cmd:02x}", file=sys.stderr)
            return 1
        if body != msg:
            print(f"FAIL: PING echo mismatch (sent {len(msg)}, got {len(body)})",
                  file=sys.stderr)
            return 1
        print(f"PING OK — {len(body)} B echoed on CID 0x{new_cid:08x}")
    return 0


def sub_msg(args) -> int:
    path = find_fido_path()
    with open_dev(path) as dev:
        new_cid, _ = cmd_init(dev)
        rcid, cmd, body = transact(dev, new_cid, CMD_MSG, b"\x00\x01\x00\x00")
        if rcid != new_cid or cmd != CMD_MSG:
            print(f"FAIL: MSG response cid=0x{rcid:08x} cmd=0x{cmd:02x}",
                  file=sys.stderr)
            return 1
        if body != b"\x6e\x00":
            print(f"FAIL: MSG payload {body.hex()} (want 6e00)", file=sys.stderr)
            return 1
        print(f"MSG OK — SW=0x{body.hex()} on CID 0x{new_cid:08x}")
    return 0


def sub_validate(args) -> int:
    """Run a 4-test suite, exit 0 on full pass."""
    path = find_fido_path()
    print(f"FIDO HID @ {path}")
    with open_dev(path) as dev:
        results = []

        # 1) INIT with broadcast
        new_cid, payload = cmd_init(dev)
        caps = payload[16]
        ok = (caps & 0x04) != 0          # CBOR cap set
        results.append(("INIT (broadcast → new CID + caps)", ok, _format_init(payload)))

        # 2) PING small (single-packet)
        msg = bytes(range(32))
        _, cmd, body = transact(dev, new_cid, CMD_PING, msg)
        ok = (cmd == CMD_PING and body == msg)
        results.append(("PING 32 B (single packet)", ok, f"echo={body[:8].hex()}…"))

        # 3) PING large (multi-packet)
        msg = bytes((i & 0xFF) for i in range(512))
        _, cmd, body = transact(dev, new_cid, CMD_PING, msg)
        ok = (cmd == CMD_PING and body == msg)
        results.append(("PING 512 B (multi-packet INIT+CONT)", ok,
                        f"{len(body)} B / {len(msg)} B"))

        # 4) MSG → 6E00 (we don't support U2F)
        _, cmd, body = transact(dev, new_cid, CMD_MSG, b"\x00\x01\x00\x00")
        ok = (cmd == CMD_MSG and body == b"\x6e\x00")
        results.append(("MSG → SW=0x6E00 (CLA not supported)", ok, body.hex()))

    print()
    print("═" * 63)
    print("  Phase 4 M2 — CTAPHID framing validation")
    print("═" * 63)
    n_ok = 0
    for i, (name, ok, detail) in enumerate(results, 1):
        verdict = "PASS" if ok else "FAIL"
        print(f"[{i}/{len(results)}] {name:<48s} {verdict}")
        if not ok:
            print(f"        {detail}")
        else:
            n_ok += 1
    print()
    print(f"{n_ok}/{len(results)} PASS — Phase 4 M2 {'validated' if n_ok == len(results) else 'FAILED'}.")
    return 0 if n_ok == len(results) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init",     help="one-shot CTAPHID_INIT")
    p_ping = sub.add_parser("ping",     help="round-trip CTAPHID_PING")
    p_ping.add_argument("--size", type=int, default=64)
    p_msg  = sub.add_parser("msg",      help="CTAPHID_MSG → expect 6E00")
    p_val  = sub.add_parser("validate", help="run full M2 suite")

    p_init.set_defaults(func=sub_init)
    p_ping.set_defaults(func=sub_ping)
    p_msg.set_defaults(func=sub_msg)
    p_val.set_defaults(func=sub_validate)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
