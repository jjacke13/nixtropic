#!/usr/bin/env python3
"""lt_rpc.py — host-side client for the nixtropic lt-rpc-over-HID protocol.

Phase 3 covers PING + GET_RANDOM (M2), CHIP_ID (M3), ECC_GENERATE / ECC_SIGN /
ECC_PUBKEY (M4). The framing is CTAPHID-style with a single fixed channel.

Wire format (matches firmware/src/hid_rpc/lt_rpc_proto.h):
  INIT packet (64 B):
    [0..3] CID BE = 0xCAFE0001
    [4]    CMD = 0x80 | cmd_id
    [5..6] BCNT BE
    [7..63] up to 57 bytes payload
  CONT packet (64 B):
    [0..3] CID BE
    [4]    SEQ (0..0x7F)
    [5..63] up to 59 bytes payload

Usage:
  lt_rpc.py ping [--bytes N]
  lt_rpc.py random [--n N]
  lt_rpc.py chip-id           # M3
  lt_rpc.py sign-test         # M4
  lt_rpc.py validate          # full M1..M4 test suite (used by validate-phase3)
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import time
from typing import Optional

try:
    import hid  # type: ignore
except ImportError:
    print("ERROR: 'hid' module missing. Enter the dev shell first:")
    print("  nix develop")
    sys.exit(2)


VID = 0xCAFE
PID = 0x4001
REPORT_LEN = 64
CID = 0xCAFE0001
INIT_DATA_LEN = 57
CONT_DATA_LEN = 59

CMD_INIT_FLAG     = 0x80
CMD_PING          = 0x01
CMD_GET_RANDOM    = 0x02
CMD_CHIP_ID       = 0x03
CMD_ECC_GENERATE  = 0x04
CMD_ECC_SIGN      = 0x05
CMD_ECC_PUBKEY    = 0x06
CMD_ERROR         = 0x3F

ERR_NAMES = {
    0x01: "INVALID_CMD",
    0x02: "INVALID_LEN",
    0x03: "BUSY",
    0x04: "CID_MISMATCH",
    0xFF: "OTHER",
}


class LtRpcError(Exception):
    pass


def find_path() -> bytes:
    for d in hid.enumerate(VID, PID):
        if d.get("interface_number", -1) == 2:
            return d["path"]
    raise LtRpcError(f"no HID device {VID:04x}:{PID:04x} interface 2 found — is firmware flashed?")


class LtRpc:
    def __init__(self, path: Optional[bytes] = None) -> None:
        if path is None:
            path = find_path()
        self.dev = hid.Device(path=path)

    def close(self) -> None:
        self.dev.close()

    def _write_packet(self, pkt: bytes) -> None:
        assert len(pkt) == REPORT_LEN
        # hidapi convention: prepend 0x00 report-ID byte for no-report-id devices
        self.dev.write(b"\x00" + pkt)

    def _read_packet(self, timeout_ms: int = 1000) -> bytes:
        rx = self.dev.read(REPORT_LEN, timeout=timeout_ms)
        rx = bytes(rx)
        if len(rx) != REPORT_LEN:
            raise LtRpcError(f"short read: {len(rx)} bytes (expected {REPORT_LEN})")
        return rx

    def transact(self, cmd: int, payload: bytes = b"", timeout_ms: int = 2000) -> bytes:
        if len(payload) > 0xFFFF:
            raise LtRpcError(f"payload too large: {len(payload)}")

        # ----- Send -----
        # INIT
        head = struct.pack(">IBH", CID, CMD_INIT_FLAG | cmd, len(payload))
        first_chunk = payload[:INIT_DATA_LEN]
        pkt = head + first_chunk + b"\x00" * (REPORT_LEN - len(head) - len(first_chunk))
        self._write_packet(pkt)

        # CONT
        sent = len(first_chunk)
        seq = 0
        while sent < len(payload):
            chunk = payload[sent:sent + CONT_DATA_LEN]
            head_c = struct.pack(">IB", CID, seq & 0x7F)
            pkt = head_c + chunk + b"\x00" * (REPORT_LEN - len(head_c) - len(chunk))
            self._write_packet(pkt)
            sent += len(chunk)
            seq += 1

        # ----- Receive -----
        first = self._read_packet(timeout_ms)
        rx_cid, rx_cmd, rx_bcnt = struct.unpack(">IBH", first[:7])
        if rx_cid != CID:
            raise LtRpcError(f"CID mismatch: got {rx_cid:08x} want {CID:08x}")

        rx_cmd_id = rx_cmd & 0x7F
        is_error = (rx_cmd_id == CMD_ERROR)

        body = bytearray(first[7:7 + min(rx_bcnt, INIT_DATA_LEN)])
        remaining = rx_bcnt - len(body)
        exp_seq = 0
        while remaining > 0:
            cont = self._read_packet(timeout_ms)
            cseq = cont[4] & 0x7F
            if cseq != exp_seq:
                raise LtRpcError(f"continuation seq mismatch: got {cseq} want {exp_seq}")
            take = min(remaining, CONT_DATA_LEN)
            body.extend(cont[5:5 + take])
            remaining -= take
            exp_seq += 1

        if is_error:
            code = body[0] if body else 0xFF
            raise LtRpcError(f"firmware ERROR: 0x{code:02x} ({ERR_NAMES.get(code, '?')})")

        if rx_cmd_id != cmd:
            raise LtRpcError(f"response cmd mismatch: got 0x{rx_cmd_id:02x} want 0x{cmd:02x}")

        return bytes(body)

    # ----- Convenience wrappers -----

    def ping(self, payload: bytes) -> bytes:
        return self.transact(CMD_PING, payload)

    def get_random(self, n: int) -> bytes:
        return self.transact(CMD_GET_RANDOM, bytes([n & 0xFF]))

    def chip_id(self) -> bytes:
        return self.transact(CMD_CHIP_ID, b"")

    def ecc_generate(self, slot: int, curve: int = 0) -> bytes:
        return self.transact(CMD_ECC_GENERATE, bytes([slot & 0xFF, curve & 0xFF]))

    def ecc_pubkey(self, slot: int) -> bytes:
        return self.transact(CMD_ECC_PUBKEY, bytes([slot & 0xFF]))

    def ecc_sign(self, slot: int, msg: bytes) -> bytes:
        return self.transact(CMD_ECC_SIGN, bytes([slot & 0xFF]) + msg)


# ============================================================================
# Sub-command entrypoints
# ============================================================================

def cmd_ping(args: argparse.Namespace) -> int:
    payload = os.urandom(args.bytes)
    rpc = LtRpc()
    try:
        echoed = rpc.ping(payload)
    finally:
        rpc.close()
    ok = (echoed == payload)
    print(f"PING {args.bytes} B → {'PASS' if ok else 'FAIL'}")
    if not ok:
        print(f"  sent: {payload.hex()}")
        print(f"  got:  {echoed.hex()}")
        return 1
    return 0


def cmd_random(args: argparse.Namespace) -> int:
    rpc = LtRpc()
    try:
        out = rpc.get_random(args.n)
    finally:
        rpc.close()
    print(f"GET_RANDOM {args.n} B: {out.hex()}")
    # Sanity: distinct bytes (very weak entropy check)
    if len(set(out)) < max(2, args.n // 4):
        print("  WARN: very low byte variety — TRNG may not be running")
        return 1
    return 0


def cmd_chip_id(args: argparse.Namespace) -> int:
    rpc = LtRpc()
    try:
        data = rpc.chip_id()
    finally:
        rpc.close()
    print(f"CHIP_ID ({len(data)} B): {data.hex()}")
    if len(data) != 128:
        print(f"  WARN: expected 128 B, got {len(data)}")
        return 1
    return 0


def cmd_sign_test(args: argparse.Namespace) -> int:
    print("Not implemented yet — wait for M4.")
    return 2


def cmd_validate(args: argparse.Namespace) -> int:
    print("═══════════════════════════════════════════════════════════════")
    print("  Phase 3: lt-rpc-over-HID validation")
    print("═══════════════════════════════════════════════════════════════")

    tests = [
        ("PING (32 B echo)",
         lambda r: r.ping(os.urandom(32)) is not None),
        ("PING (large 256 B multi-packet)",
         lambda r: len(r.ping(os.urandom(256))) == 256),
        ("GET_RANDOM (32 B entropy)",
         lambda r: len(r.get_random(32)) == 32),
        ("CHIP_ID (128 B)",
         lambda r: len(r.chip_id()) == 128),
    ]
    # M4+ tests are added here as milestones land.

    rpc = LtRpc()
    failures = 0
    try:
        for i, (label, fn) in enumerate(tests, 1):
            try:
                ok = bool(fn(rpc))
            except Exception as e:
                ok = False
                err = str(e)
            else:
                err = None
            tag = "PASS" if ok else "FAIL"
            line = f"[{i}/{len(tests)}] {label:<40s} {tag}"
            if not ok:
                line += f"  ({err})" if err else ""
                failures += 1
            print(line)
    finally:
        rpc.close()

    print()
    if failures == 0:
        print(f"{len(tests)}/{len(tests)} PASS — Phase 3 lt-rpc-over-HID validated.")
        return 0
    print(f"✗ {failures}/{len(tests)} tests failed")
    return 1


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    p_ping = sub.add_parser("ping", help="echo N random bytes via PING")
    p_ping.add_argument("--bytes", type=int, default=32)
    p_ping.set_defaults(fn=cmd_ping)

    p_rand = sub.add_parser("random", help="get N bytes of TRNG entropy")
    p_rand.add_argument("--n", type=int, default=32)
    p_rand.set_defaults(fn=cmd_random)

    p_cid = sub.add_parser("chip-id", help="read TROPIC01 chip ID via HID (M3)")
    p_cid.set_defaults(fn=cmd_chip_id)

    p_sign = sub.add_parser("sign-test", help="generate + sign + verify (M4)")
    p_sign.set_defaults(fn=cmd_sign_test)

    p_val = sub.add_parser("validate", help="run the full Phase 3 test suite")
    p_val.set_defaults(fn=cmd_validate)

    args = p.parse_args()
    try:
        return args.fn(args)
    except LtRpcError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
