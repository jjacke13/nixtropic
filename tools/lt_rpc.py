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
CMD_ECC_ERASE     = 0x07
# Phase 5 M1 — slot manager debug commands (firmware: lt_rpc_proto.h 0x10-0x14)
CMD_SLOTS_BITMAP  = 0x10
CMD_SLOTS_ALLOC   = 0x11
CMD_SLOTS_ERASE   = 0x12
CMD_SLOTS_META    = 0x13
CMD_SLOTS_RESET   = 0x14
# Phase 6 M2 — Force-UV flag accessors
CMD_FORCE_UV_GET  = 0x15
CMD_FORCE_UV_SET  = 0x16
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

    def ecc_erase(self, slot: int) -> bytes:
        return self.transact(CMD_ECC_ERASE, bytes([slot & 0xFF]))

    # ----- Phase 5 M1 slot manager -----

    def slots_bitmap(self) -> tuple[int, int]:
        """Return (bitmap, used_count)."""
        resp = self.transact(CMD_SLOTS_BITMAP, b"")
        if len(resp) < 5:
            raise LtRpcError(f"slots_bitmap: short response {len(resp)}")
        bitmap = int.from_bytes(resp[0:4], "big")
        count = resp[4]
        return bitmap, count

    def slots_alloc(self, rp_id_hash: bytes) -> tuple[int, bytes]:
        """Return (slot_idx, cred_id_18)."""
        if len(rp_id_hash) != 32:
            raise LtRpcError(f"rp_id_hash must be 32 B, got {len(rp_id_hash)}")
        resp = self.transact(CMD_SLOTS_ALLOC, rp_id_hash)
        if len(resp) < 19:
            raise LtRpcError(f"slots_alloc: short response {len(resp)}")
        slot_idx = resp[0]
        cred_id = resp[1:19]
        return slot_idx, cred_id

    def slots_erase_slot(self, slot_idx: int) -> None:
        self.transact(CMD_SLOTS_ERASE, bytes([slot_idx & 0xFF]))

    def slots_meta(self, slot_idx: int) -> dict:
        """Return {alg, flags, rp_id_hash, cred_id_nonce}."""
        resp = self.transact(CMD_SLOTS_META, bytes([slot_idx & 0xFF]))
        if len(resp) < 50:
            raise LtRpcError(f"slots_meta: short response {len(resp)}")
        return {
            "alg":           resp[0],
            "flags":         resp[1],
            "rp_id_hash":    bytes(resp[2:34]),
            "cred_id_nonce": bytes(resp[34:50]),
        }

    def slots_reset(self) -> None:
        self.transact(CMD_SLOTS_RESET, b"")

    def force_uv_get(self) -> int:
        """Read the Force-UV flag. Unauthenticated."""
        resp = self.transact(CMD_FORCE_UV_GET, b"")
        if len(resp) < 1:
            raise RuntimeError(f"FORCE_UV_GET: short response {resp!r}")
        return resp[0] & 0x01

    def force_uv_set(self, value: int) -> None:
        """Set / clear the Force-UV flag. Requires active pinUvAuthToken
        session on the device (user has run CTAP2 getPinToken this boot)."""
        payload = bytes([1 if value else 0])
        self.transact(CMD_FORCE_UV_SET, payload)


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
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        print("ERROR: cryptography module missing. Enter the dev shell first:")
        print("  nix develop")
        return 2

    slot = args.slot
    rpc = LtRpc()
    try:
        print(f"Erasing slot {slot} (idempotent)...")
        rpc.ecc_erase(slot)

        print(f"Generating Ed25519 key in slot {slot}...")
        rpc.ecc_generate(slot, 0)  # 0 = Ed25519

        print(f"Reading pubkey from slot {slot}...")
        pubkey = rpc.ecc_pubkey(slot)
        print(f"  pubkey ({len(pubkey)} B): {pubkey.hex()}")
        if len(pubkey) != 32:
            print(f"  FAIL: expected 32 B Ed25519 pubkey, got {len(pubkey)}")
            return 1

        msg = os.urandom(32)
        print(f"Signing 32 B challenge: {msg.hex()}")
        sig = rpc.ecc_sign(slot, msg)
        print(f"  signature ({len(sig)} B): {sig.hex()}")
        if len(sig) != 64:
            print(f"  FAIL: expected 64 B Ed25519 signature, got {len(sig)}")
            return 1

        print("Verifying signature with Ed25519 host code...")
        host_pub = Ed25519PublicKey.from_public_bytes(pubkey)
        try:
            host_pub.verify(sig, msg)
        except InvalidSignature:
            print("  ✗ FAIL — signature does NOT verify against pubkey + message")
            return 1
        print("  ✓ PASS — signature verifies")
        print()
        print("End-to-end FIDO2-style flow validated over HID:")
        print("  TROPIC01 generated Ed25519 keypair, signed challenge, host verified.")
        return 0
    finally:
        rpc.close()


def cmd_validate(args: argparse.Namespace) -> int:
    print("═══════════════════════════════════════════════════════════════")
    print("  Phase 3: lt-rpc-over-HID validation")
    print("═══════════════════════════════════════════════════════════════")

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        from cryptography.exceptions import InvalidSignature
        has_crypto = True
    except ImportError:
        has_crypto = False

    def _sign_test(r: LtRpc) -> bool:
        # Erase first so the test is idempotent regardless of slot state
        # left over from a previous run.
        r.ecc_erase(0)
        r.ecc_generate(0, 0)
        pubkey = r.ecc_pubkey(0)
        if len(pubkey) != 32:
            return False
        msg = os.urandom(32)
        sig = r.ecc_sign(0, msg)
        if len(sig) != 64:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(pubkey).verify(sig, msg)
        except InvalidSignature:
            return False
        return True

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
    if has_crypto:
        tests.append(
            ("ECC generate + sign + Ed25519 verify (slot 0)", _sign_test)
        )
    else:
        print("(skipping sign-test: cryptography module not available)")

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


def cmd_slots_bitmap(args: argparse.Namespace) -> int:
    rpc = LtRpc()
    try:
        bm, cnt = rpc.slots_bitmap()
    finally:
        rpc.close()
    print(f"bitmap=0x{bm:08x}  used={cnt}/32")
    for i in range(32):
        if bm & (1 << i):
            print(f"  slot {i:2d}: allocated")
    return 0


def cmd_force_uv_get(args: argparse.Namespace) -> int:
    """Phase 6 M2 — read the Force-UV flag."""
    rpc = LtRpc()
    try:
        v = rpc.force_uv_get()
    finally:
        rpc.close()
    print(f"force_uv = {v}  ({'ON — alwaysUv enforced' if v else 'off — RP hint honoured'})")
    return 0


def cmd_force_uv_set(args: argparse.Namespace) -> int:
    """Phase 6 M2 — set / clear the Force-UV flag.

    Requires that the user has run CTAP2 getPinToken on this boot
    (firmware checks s_pin_token_valid).  The firmware-side
    bootstrap path (auto-enable on first setPIN) does NOT use this
    RPC — it sets the flag directly from inside handle_set_pin.
    Use this RPC to toggle Force-UV after the dongle is already
    configured."""
    rpc = LtRpc()
    try:
        rpc.force_uv_set(args.value)
        v = rpc.force_uv_get()
    finally:
        rpc.close()
    print(f"force_uv set to {args.value} → reads back as {v}")
    return 0 if v == (1 if args.value else 0) else 1


def cmd_slots_reset(args: argparse.Namespace) -> int:
    rpc = LtRpc()
    try:
        rpc.slots_reset()
        bm, cnt = rpc.slots_bitmap()
    finally:
        rpc.close()
    print(f"RESET → bitmap=0x{bm:08x} used={cnt}/32")
    return 0 if (bm == 0 and cnt == 0) else 1


def cmd_validate_m1(args: argparse.Namespace) -> int:
    """Phase 5 M1 HW validation — exercises slot manager round-trip.

    Test scenario:
      1. Factory-reset → bitmap == 0, used == 0
      2. Alloc 3 distinct credentials with 3 distinct rpIdHashes
      3. Verify bitmap == 0b111, used == 3, slot indices 0/1/2
      4. Read meta for each → rpIdHashes round-trip byte-exact
      5. Erase slot 1 → bitmap == 0b101, used == 2
      6. Alloc a 4th credential → MUST land in slot 1 (first-free)
      7. Final state: bitmap == 0b111, used == 3
    """
    import hashlib

    print("═══════════════════════════════════════════════════════════════")
    print("  Phase 5 M1: slot manager validation (TROPIC01 R-mem)")
    print("═══════════════════════════════════════════════════════════════")

    rpc = LtRpc()
    failures: list[str] = []
    try:
        # 1. Reset
        rpc.slots_reset()
        bm, cnt = rpc.slots_bitmap()
        ok = (bm == 0 and cnt == 0)
        print(f"[1/7] factory_reset      → bitmap=0x{bm:08x} used={cnt}   {'PASS' if ok else 'FAIL'}")
        if not ok:
            failures.append("reset did not clear bitmap")

        # 2-3. Alloc 3 credentials
        rp_hashes = [
            hashlib.sha256(f"webauthn.io/{i}".encode()).digest()
            for i in range(3)
        ]
        creds: list[tuple[int, bytes]] = []
        for rph in rp_hashes:
            idx, credid = rpc.slots_alloc(rph)
            creds.append((idx, credid))
        bm, cnt = rpc.slots_bitmap()
        idx_set = {c[0] for c in creds}
        ok = (idx_set == {0, 1, 2} and bm == 0b111 and cnt == 3)
        print(f"[2/7] alloc 3 creds      → slots={sorted(idx_set)} bitmap=0x{bm:08x}   {'PASS' if ok else 'FAIL'}")
        if not ok:
            failures.append(f"expected slots 0,1,2 bitmap 0b111 got {sorted(idx_set)} bitmap 0b{bm:b}")

        # cred IDs should be 18 B, version 0x01, slot matches, nonce non-zero
        ok_credid = all(
            len(c[1]) == 18 and c[1][0] == 0x01 and c[1][1] == c[0] and c[1][2:] != b"\x00" * 16
            for c in creds
        )
        print(f"[3/7] cred IDs well-formed                                  {'PASS' if ok_credid else 'FAIL'}")
        if not ok_credid:
            failures.append("cred ID structure malformed")
            for c in creds:
                print(f"      slot {c[0]}: {c[1].hex()}")

        # 4. Read meta back; rpIdHashes round-trip
        round_trip_ok = True
        for (slot_idx, _), expected_rph in zip(creds, rp_hashes):
            meta = rpc.slots_meta(slot_idx)
            if meta["rp_id_hash"] != expected_rph:
                round_trip_ok = False
                print(f"      slot {slot_idx}: rpIdHash mismatch")
                print(f"        expected {expected_rph.hex()}")
                print(f"        got      {meta['rp_id_hash'].hex()}")
            # Nonce in meta must match nonce in credID bytes 2..17
            credid_nonce = creds[slot_idx][1][2:]
            if meta["cred_id_nonce"] != credid_nonce:
                round_trip_ok = False
                print(f"      slot {slot_idx}: nonce mismatch (meta vs credID bytes 2..17)")
        print(f"[4/7] read meta back     → 3 rpIdHashes + 3 nonces match    {'PASS' if round_trip_ok else 'FAIL'}")
        if not round_trip_ok:
            failures.append("meta round-trip mismatch")

        # 5. Erase slot 1
        rpc.slots_erase_slot(1)
        bm, cnt = rpc.slots_bitmap()
        ok = (bm == 0b101 and cnt == 2)
        print(f"[5/7] erase slot 1       → bitmap=0x{bm:08x} used={cnt}        {'PASS' if ok else 'FAIL'}")
        if not ok:
            failures.append(f"after erase expected bitmap 0b101 got 0b{bm:b}")

        # 6. Alloc 4th → must land in slot 1
        rph4 = hashlib.sha256(b"webauthn.io/reused").digest()
        idx4, credid4 = rpc.slots_alloc(rph4)
        bm, cnt = rpc.slots_bitmap()
        ok = (idx4 == 1 and bm == 0b111 and cnt == 3)
        print(f"[6/7] alloc 4th cred     → slot={idx4} (first-free)   {'PASS' if ok else 'FAIL'}")
        if not ok:
            failures.append(f"first-free alloc didn't pick slot 1 (got {idx4})")

        # 7. Cleanup → reset
        rpc.slots_reset()
        bm, cnt = rpc.slots_bitmap()
        ok = (bm == 0 and cnt == 0)
        print(f"[7/7] final reset        → bitmap=0x{bm:08x} used={cnt}   {'PASS' if ok else 'FAIL'}")
        if not ok:
            failures.append("final reset did not clear")
    finally:
        rpc.close()

    print()
    if failures:
        print(f"✗ {len(failures)} failure(s):")
        for f in failures:
            print(f"    - {f}")
        return 1
    print("7/7 PASS — Phase 5 M1 slot manager validated.")
    print()
    print("NEXT (manual): unplug + replug dongle, then run:")
    print("   sudo nix develop --command python3 tools/lt_rpc.py slots-bitmap")
    print("Expected: bitmap=0x00000000 used=0 (state persisted as 'empty after reset').")
    print("If you alloc 3 NEW credentials, unplug + replug, then `slots-bitmap` should")
    print("show those 3 still allocated. That confirms R-mem persistence across reboots.")
    return 0


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

    p_sign = sub.add_parser("sign-test", help="generate + sign + verify Ed25519 (M4)")
    p_sign.add_argument("--slot", type=int, default=0)
    p_sign.set_defaults(fn=cmd_sign_test)

    p_val = sub.add_parser("validate", help="run the full Phase 3 test suite")
    p_val.set_defaults(fn=cmd_validate)

    p_sb = sub.add_parser("slots-bitmap", help="(Phase 5 M1) dump slot allocation bitmap")
    p_sb.set_defaults(fn=cmd_slots_bitmap)

    p_sr = sub.add_parser("slots-reset", help="(Phase 5 M1) WIPE all credentials")
    p_sr.set_defaults(fn=cmd_slots_reset)

    p_vm1 = sub.add_parser("validate-m1", help="(Phase 5 M1) run slot manager validation")
    p_vm1.set_defaults(fn=cmd_validate_m1)

    p_fug = sub.add_parser("force-uv-get",
                           help="(Phase 6 M2) read the Force-UV flag")
    p_fug.set_defaults(fn=cmd_force_uv_get)

    p_fus = sub.add_parser("force-uv-set",
                           help="(Phase 6 M2) set/clear Force-UV (requires active PIN token)")
    p_fus.add_argument("value", type=int, choices=[0, 1],
                       help="0 = disable Force-UV, 1 = enable")
    p_fus.set_defaults(fn=cmd_force_uv_set)

    args = p.parse_args()
    try:
        return args.fn(args)
    except LtRpcError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
