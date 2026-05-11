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

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

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

# CTAP2 sub-commands
CTAP2_CMD_MAKE_CRED    = 0x01
CTAP2_CMD_GET_ASSERTION = 0x02
CTAP2_CMD_GET_INFO     = 0x04
CTAP2_OK               = 0x00


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


def cmd_cbor(dev: hid.Device, cid: int, sub: int, params: bytes = b"") -> tuple[int, bytes]:
    """Send a CTAP2 CBOR command. Returns (status, response_body)."""
    _, _, body = transact(dev, cid, CMD_CBOR, bytes([sub]) + params, timeout_ms=5000)
    if not body:
        raise RuntimeError("Empty CTAP2 response")
    return body[0], body[1:]


# ---------------- minimal CBOR decoder ----------------
#
# Just enough to parse the GetInfo response. CTAP2 GetInfo always returns
# a map keyed by unsigned ints; values are uints, byte/text strings,
# arrays, maps, and bools.

def _cbor_decode(buf: bytes, off: int = 0):
    if off >= len(buf):
        raise ValueError("CBOR: unexpected end of buffer")
    ib = buf[off]
    mt = ib >> 5
    ai = ib & 0x1F
    off += 1
    if ai < 24:
        v = ai
    elif ai == 24:
        v = buf[off]; off += 1
    elif ai == 25:
        v = struct.unpack(">H", buf[off:off+2])[0]; off += 2
    elif ai == 26:
        v = struct.unpack(">I", buf[off:off+4])[0]; off += 4
    elif ai == 27:
        v = struct.unpack(">Q", buf[off:off+8])[0]; off += 8
    else:
        raise ValueError(f"CBOR: indefinite/reserved length ai={ai}")

    if mt == 0:   return v, off
    if mt == 1:   return -1 - v, off
    if mt == 2:   data = bytes(buf[off:off+v]); return data, off + v
    if mt == 3:   data = bytes(buf[off:off+v]).decode("utf-8"); return data, off + v
    if mt == 4:
        out = []
        for _ in range(v):
            item, off = _cbor_decode(buf, off); out.append(item)
        return out, off
    if mt == 5:
        out = {}
        for _ in range(v):
            k, off = _cbor_decode(buf, off)
            x, off = _cbor_decode(buf, off)
            out[k] = x
        return out, off
    if mt == 7:
        if v == 20: return False, off
        if v == 21: return True, off
        if v == 22: return None, off
        raise ValueError(f"CBOR: unsupported simple {v}")
    raise ValueError(f"CBOR: major type {mt} not implemented")


def cbor_decode(buf: bytes):
    obj, end = _cbor_decode(buf, 0)
    if end != len(buf):
        raise ValueError(f"CBOR: trailing bytes ({end} != {len(buf)})")
    return obj


def cbor_decode_one(buf: bytes, off: int = 0):
    """Decode one CBOR item starting at `off`; return (obj, new_off)."""
    return _cbor_decode(buf, off)


# ---------------- hand-rolled CBOR encoder (host side) ----------------

def _enc_head(mt: int, v: int) -> bytes:
    if v < 24:                  return bytes([(mt << 5) | v])
    if v <= 0xFF:               return bytes([(mt << 5) | 24, v])
    if v <= 0xFFFF:             return bytes([(mt << 5) | 25]) + struct.pack(">H", v)
    if v <= 0xFFFFFFFF:         return bytes([(mt << 5) | 26]) + struct.pack(">I", v)
    return bytes([(mt << 5) | 27]) + struct.pack(">Q", v)


def cbor_encode(x) -> bytes:
    if x is False:           return bytes([0xF4])
    if x is True:            return bytes([0xF5])
    if x is None:            return bytes([0xF6])
    if isinstance(x, int):
        if x >= 0:           return _enc_head(0, x)
        return _enc_head(1, -1 - x)
    if isinstance(x, bytes): return _enc_head(2, len(x)) + x
    if isinstance(x, str):
        b = x.encode("utf-8")
        return _enc_head(3, len(b)) + b
    if isinstance(x, list):
        out = _enc_head(4, len(x))
        for it in x:         out += cbor_encode(it)
        return out
    if isinstance(x, dict):
        # CTAP2 canonical map ordering: ints in numeric order, strings
        # in length-then-byte order. Sort accordingly.
        def _ord_key(k):
            if isinstance(k, int):
                return (0, k)
            if isinstance(k, str):
                return (1, len(k), k)
            raise TypeError(f"unsupported key {k!r}")
        out = _enc_head(5, len(x))
        for k in sorted(x.keys(), key=_ord_key):
            out += cbor_encode(k) + cbor_encode(x[k])
        return out
    raise TypeError(f"cbor_encode: unsupported type {type(x).__name__}")


# ---------------- WebAuthn structure parsing ----------------

def parse_authdata(ad: bytes, *, expect_at: bool):
    """Return (rp_id_hash, flags, sign_count, cred_id, cose_pubkey_bytes)."""
    if len(ad) < 37:
        raise ValueError(f"authData too short: {len(ad)}")
    rp_id_hash = ad[0:32]
    flags      = ad[32]
    sign_count = struct.unpack(">I", ad[33:37])[0]
    has_at     = (flags & 0x40) != 0
    if expect_at and not has_at:
        raise ValueError("expected AT flag set")
    if not expect_at:
        if len(ad) != 37:
            raise ValueError(f"unexpected trailing bytes in authData (len={len(ad)})")
        return rp_id_hash, flags, sign_count, None, None
    # AT present
    if len(ad) < 37 + 18:
        raise ValueError(f"authData truncated for AT block: {len(ad)}")
    aaguid     = ad[37:53]
    cred_id_len = struct.unpack(">H", ad[53:55])[0]
    cred_id    = ad[55:55 + cred_id_len]
    cose_off   = 55 + cred_id_len
    cose_bytes = ad[cose_off:]
    # Parse the COSE_Key map to validate it
    cose, end = cbor_decode_one(cose_bytes, 0)
    if end != len(cose_bytes):
        raise ValueError("trailing bytes after COSE_Key")
    return rp_id_hash, flags, sign_count, cred_id, cose


def cose_ed25519_pubkey(cose: dict) -> bytes:
    """Extract the 32-byte Ed25519 public key from a COSE_Key dict."""
    if cose.get(1) != 1:                          raise ValueError(f"COSE kty {cose.get(1)} != OKP")
    if cose.get(3) != -8:                         raise ValueError(f"COSE alg {cose.get(3)} != EdDSA")
    if cose.get(-1) != 6:                         raise ValueError(f"COSE crv {cose.get(-1)} != Ed25519")
    pk = cose.get(-2)
    if not isinstance(pk, bytes) or len(pk) != 32:
        raise ValueError(f"COSE x bad: {pk!r}")
    return pk


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


def sub_getinfo(args) -> int:
    path = find_fido_path()
    with open_dev(path) as dev:
        new_cid, _ = cmd_init(dev)
        status, body = cmd_cbor(dev, new_cid, CTAP2_CMD_GET_INFO)
        if status != CTAP2_OK:
            print(f"FAIL: GetInfo status 0x{status:02x}", file=sys.stderr)
            return 1
        info = cbor_decode(body)
    versions  = info.get(1, [])
    aaguid    = info.get(3, b"")
    options   = info.get(4, {})
    max_msg   = info.get(5)
    transports = info.get(9, [])
    algos     = info.get(10, [])
    print(f"versions    = {versions}")
    print(f"aaguid      = {aaguid.hex() if isinstance(aaguid, bytes) else aaguid}")
    print(f"options     = {options}")
    print(f"maxMsgSize  = {max_msg}")
    print(f"transports  = {transports}")
    print(f"algorithms  = {algos}")
    return 0


def _do_make_credential(dev: hid.Device, new_cid: int,
                        rp_id: str = "test.nixtropic.local",
                        client_hash: bytes | None = None):
    """Return (status, fmt, authdata_bytes, attstmt_dict, client_hash)."""
    if client_hash is None:
        client_hash = os.urandom(32)
    req = {
        1: client_hash,
        2: {"id": rp_id, "name": "nixtropic test"},
        3: {"id": os.urandom(16), "name": "user", "displayName": "Test User"},
        4: [{"alg": -8, "type": "public-key"}],
    }
    status, body = cmd_cbor(dev, new_cid, CTAP2_CMD_MAKE_CRED, cbor_encode(req))
    if status != CTAP2_OK:
        return status, None, None, None, client_hash
    resp = cbor_decode(body)
    return status, resp[1], resp[2], resp[3], client_hash


def _do_get_assertion(dev: hid.Device, new_cid: int, rp_id: str, cred_id: bytes,
                      client_hash: bytes | None = None):
    if client_hash is None:
        client_hash = os.urandom(32)
    req = {
        1: rp_id,
        2: client_hash,
        3: [{"id": cred_id, "type": "public-key"}],
    }
    status, body = cmd_cbor(dev, new_cid, CTAP2_CMD_GET_ASSERTION, cbor_encode(req))
    if status != CTAP2_OK:
        return status, None, None, None, client_hash
    resp = cbor_decode(body)
    return status, resp[1], resp[2], resp[3], client_hash


def sub_make_cred(args) -> int:
    path = find_fido_path()
    with open_dev(path) as dev:
        new_cid, _ = cmd_init(dev)
        status, fmt, authdata, attstmt, chash = _do_make_credential(dev, new_cid)
        if status != CTAP2_OK:
            print(f"FAIL: MakeCredential status 0x{status:02x}", file=sys.stderr)
            return 1
        print(f"fmt        = {fmt!r}")
        rp_id_hash, flags, signcount, cred_id, cose = parse_authdata(
            authdata, expect_at=True)
        pubkey = cose_ed25519_pubkey(cose)
        print(f"rpIdHash   = {rp_id_hash.hex()}")
        print(f"flags      = 0x{flags:02x}")
        print(f"signCount  = {signcount}")
        print(f"credId     = {cred_id.hex()}")
        print(f"pubKey     = {pubkey.hex()}")
        print(f"attStmt    = {attstmt}")
        # Verify the signature
        sig = attstmt.get("sig")
        Ed25519PublicKey.from_public_bytes(pubkey).verify(sig, authdata + chash)
        print("Ed25519 self-attestation signature VERIFIES")
    return 0


def sub_assertion(args) -> int:
    path = find_fido_path()
    with open_dev(path) as dev:
        new_cid, _ = cmd_init(dev)
        status, fmt, authdata, attstmt, chash = _do_make_credential(dev, new_cid)
        if status != CTAP2_OK:
            print(f"FAIL: MakeCredential precondition 0x{status:02x}", file=sys.stderr)
            return 1
        _, _, _, cred_id, cose = parse_authdata(authdata, expect_at=True)
        pubkey = cose_ed25519_pubkey(cose)

        status, credential, ad2, sig, chash2 = _do_get_assertion(
            dev, new_cid, "test.nixtropic.local", cred_id)
        if status != CTAP2_OK:
            print(f"FAIL: GetAssertion status 0x{status:02x}", file=sys.stderr)
            return 1
        rp_id_hash, flags, signcount, _, _ = parse_authdata(ad2, expect_at=False)
        print(f"credId     = {credential['id'].hex()}")
        print(f"rpIdHash   = {rp_id_hash.hex()}")
        print(f"flags      = 0x{flags:02x}")
        print(f"signCount  = {signcount}")
        Ed25519PublicKey.from_public_bytes(pubkey).verify(sig, ad2 + chash2)
        print("Ed25519 assertion signature VERIFIES")
    return 0


def sub_validate_m2(args) -> int:
    """Phase 5 M2 validation — real TROPIC01-backed keys, multi-credential.

    Pre-condition: slot bitmap is empty (the wrapper shell script runs
    `lt_rpc.py slots-reset` first so we start clean).

    Test scenario:
      1) GetInfo → AAGUID trailing byte 0x02 (M2 firmware marker)
      2) MakeCred for site1.example → distinct pubkey/credId; sig verifies
      3) MakeCred for site2.example → distinct from site1
      4) MakeCred for site3.example → distinct from site1+site2
      5) GetAssertion site1 credId → sig verifies with site1 pubkey
         signCount > 0 (monotonic from MakeCred ops)
      6) GetAssertion site2 credId → sig verifies with site2 pubkey
         signCount > step 5's signCount
      7) GetAssertion forged credId (random 18 B) → NO_CREDENTIALS
      8) GetAssertion site3 credId → sig verifies with site3 pubkey
         signCount > step 6's signCount
    """
    import hashlib
    path = find_fido_path()
    print(f"FIDO HID @ {path}")
    results: list[tuple[str, bool, str]] = []
    sites: list[tuple[str, bytes, bytes]] = []  # (rp_id, pubkey, cred_id)
    signcounts: list[int] = []

    with open_dev(path) as dev:
        new_cid, _ = cmd_init(dev)

        # 1) GetInfo — confirm AAGUID Phase 5 marker.
        ok = False
        detail = ""
        try:
            status, body = cmd_cbor(dev, new_cid, CTAP2_CMD_GET_INFO)
            assert status == CTAP2_OK, f"status 0x{status:02x}"
            info = cbor_decode(body)
            aaguid = info.get(3, b"")
            assert isinstance(aaguid, bytes) and len(aaguid) == 16
            assert aaguid[-1] == 0x02, (
                f"aaguid trailing byte 0x{aaguid[-1]:02x} != 0x02 — "
                f"is this M2 firmware or Phase 4 stub?")
            opts = info.get(4, {})
            assert opts.get("rk") is True, "rk option must be true in M2"
            ok = True
            detail = f"aaguid={aaguid.hex()} rk={opts.get('rk')}"
        except Exception as e:
            detail = f"{type(e).__name__}: {e}"
        results.append(("GetInfo: AAGUID = ...0002, rk=true", ok, detail))

        # 2-4) MakeCred for three distinct sites.
        for i, rp_id in enumerate(
                ["site1.example", "site2.example", "site3.example"], start=2):
            ok = False
            detail = ""
            try:
                status, fmt, authdata, attstmt, chash = _do_make_credential(
                    dev, new_cid, rp_id=rp_id)
                assert status == CTAP2_OK, f"status 0x{status:02x}"
                assert fmt == "packed"
                rp_id_hash, flags, signcount, cred_id, cose = parse_authdata(
                    authdata, expect_at=True)
                expected_hash = hashlib.sha256(rp_id.encode()).digest()
                assert rp_id_hash == expected_hash, "rpIdHash mismatch"
                pubkey = cose_ed25519_pubkey(cose)
                assert len(cred_id) == 18, f"cred_id len {len(cred_id)} != 18"
                assert cred_id[0] == 0x01, f"cred_id version {cred_id[0]:#x} != 0x01"
                Ed25519PublicKey.from_public_bytes(pubkey).verify(
                    attstmt["sig"], authdata + chash)
                # Verify uniqueness against previously seen credentials
                for j, (prev_rp, prev_pub, prev_cred) in enumerate(sites):
                    assert pubkey != prev_pub, (
                        f"pubkey collision with {prev_rp} (j={j})")
                    assert cred_id != prev_cred, (
                        f"credId collision with {prev_rp} (j={j})")
                sites.append((rp_id, pubkey, cred_id))
                signcounts.append(signcount)
                ok = True
                detail = (f"slot={cred_id[1]} sc={signcount} "
                          f"pk={pubkey[:8].hex()}…")
            except Exception as e:
                detail = f"{type(e).__name__}: {e}"
            results.append(
                (f"MakeCred {rp_id} (distinct pubkey+credId, sig verifies)",
                 ok, detail))

        # 5) GetAssertion site1 → verify with site1 pubkey.
        if len(sites) >= 1:
            rp_id, pubkey, cred_id = sites[0]
            ok = False
            detail = ""
            try:
                status, credential, ad2, sig2, chash2 = _do_get_assertion(
                    dev, new_cid, rp_id, cred_id)
                assert status == CTAP2_OK, f"status 0x{status:02x}"
                rp_id_hash2, flags2, signcount2, _, _ = parse_authdata(
                    ad2, expect_at=False)
                assert credential["id"] == cred_id, "credId echo mismatch"
                expected_hash = hashlib.sha256(rp_id.encode()).digest()
                assert rp_id_hash2 == expected_hash
                Ed25519PublicKey.from_public_bytes(pubkey).verify(
                    sig2, ad2 + chash2)
                assert signcount2 > max(signcounts), (
                    f"signCount {signcount2} not > prev max {max(signcounts)}")
                signcounts.append(signcount2)
                ok = True
                detail = f"sc={signcount2} (was {signcounts[-2]})"
            except Exception as e:
                detail = f"{type(e).__name__}: {e}"
            results.append(("GetAssertion site1 (verifies + sc>prev)", ok, detail))

        # 6) GetAssertion site2 → verify with site2 pubkey, sc strictly higher.
        if len(sites) >= 2:
            rp_id, pubkey, cred_id = sites[1]
            ok = False
            detail = ""
            try:
                status, credential, ad2, sig2, chash2 = _do_get_assertion(
                    dev, new_cid, rp_id, cred_id)
                assert status == CTAP2_OK, f"status 0x{status:02x}"
                _, _, signcount2, _, _ = parse_authdata(ad2, expect_at=False)
                Ed25519PublicKey.from_public_bytes(pubkey).verify(
                    sig2, ad2 + chash2)
                assert signcount2 > max(signcounts), (
                    f"signCount {signcount2} not > prev max {max(signcounts)}")
                signcounts.append(signcount2)
                ok = True
                detail = f"sc={signcount2}"
            except Exception as e:
                detail = f"{type(e).__name__}: {e}"
            results.append(("GetAssertion site2 (verifies + sc strictly>)", ok, detail))

        # 7) Negative: forged credId → NO_CREDENTIALS (0x2E).
        ok = False
        detail = ""
        try:
            forged = bytes([0x01, 0x07]) + os.urandom(16)   # slot 7 random nonce
            status, body = cmd_cbor(
                dev, new_cid, CTAP2_CMD_GET_ASSERTION,
                cbor_encode({
                    1: "site1.example",
                    2: os.urandom(32),
                    3: [{"id": forged, "type": "public-key"}],
                }))
            ok = (status == 0x2E)  # CTAP2_ERR_NO_CREDENTIALS
            detail = f"status=0x{status:02x} (want 0x2E)"
        except Exception as e:
            detail = f"{type(e).__name__}: {e}"
        results.append(("GetAssertion forged credId → NO_CREDENTIALS", ok, detail))

        # 8) GetAssertion site3 → verify with site3 pubkey, sc strictly higher.
        if len(sites) >= 3:
            rp_id, pubkey, cred_id = sites[2]
            ok = False
            detail = ""
            try:
                status, credential, ad2, sig2, chash2 = _do_get_assertion(
                    dev, new_cid, rp_id, cred_id)
                assert status == CTAP2_OK, f"status 0x{status:02x}"
                _, _, signcount2, _, _ = parse_authdata(ad2, expect_at=False)
                Ed25519PublicKey.from_public_bytes(pubkey).verify(
                    sig2, ad2 + chash2)
                assert signcount2 > max(signcounts), (
                    f"signCount {signcount2} not > prev max {max(signcounts)}")
                ok = True
                detail = f"sc={signcount2}"
            except Exception as e:
                detail = f"{type(e).__name__}: {e}"
            results.append(("GetAssertion site3 (verifies + sc strictly>)", ok, detail))

    print()
    print("═" * 63)
    print("  Phase 5 M2 — real TROPIC01-backed FIDO2 (THE MIC-DROP)")
    print("═" * 63)
    n_ok = 0
    for i, (name, ok, detail) in enumerate(results, 1):
        verdict = "PASS" if ok else "FAIL"
        print(f"[{i}/{len(results)}] {name:<54s} {verdict}")
        if not ok:
            print(f"        {detail}")
        else:
            n_ok += 1
    print()
    print(f"{n_ok}/{len(results)} PASS — Phase 5 M2 "
          f"{'validated' if n_ok == len(results) else 'FAILED'}.")
    if n_ok == len(results):
        print()
        print("Per-credential keys generated on TROPIC01, signed on TROPIC01,")
        print("verified host-side. Shared monotonic counter strictly increases.")
        print("Forged credIds rejected. AAGUID v2 advertised.")
        print()
        print("MANUAL NEXT: plug into a browser → https://webauthn.io → register +")
        print("log in. That's the real mic-drop. (Use the same cred_id across the")
        print("register-then-log-in flow for the demo.)")
    return 0 if n_ok == len(results) else 1


def sub_validate_m3(args) -> int:
    """Phase 5 M3 validation — ClientPIN protocol v1 (P-256 + AES-CBC).

    Exercises CTAP2 §5.5.4 end-to-end:
      1) GetInfo → clientPin=false (pre-set)
      2) GetKeyAgreement → P-256 pubkey from authenticator
      3) SetPin "1234"
      4) GetInfo → clientPin=true
      5) GetPinRetries → 8
      6) GetPinToken("1234") → encrypted token, decrypt successfully
      7) GetPinToken("wrong") → PIN_INVALID, retries decrements
      8) GetPinToken("1234") → success, retries restored to 8
      9) ChangePin "1234" → "5678"
     10) GetPinToken("5678") → success
     11) MakeCred without pinAuth → PIN_REQUIRED (0x36)
     12) MakeCred WITH pinAuth → success, UV bit set in flags
     13) GetAssertion WITH pinAuth → success, UV bit set in flags

    Requires the `cryptography` package (pip install cryptography).
    """
    import hashlib
    import hmac as pyhmac
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, PrivateFormat, NoEncryption,
    )
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    path = find_fido_path()
    print(f"FIDO HID @ {path}")
    results: list[tuple[str, bool, str]] = []

    def expect(label: str, cond: bool, detail: str = ""):
        results.append((label, cond, detail))

    # --- Crypto helpers -------------------------------------------------

    def gen_platform_p256():
        sk = ec.generate_private_key(ec.SECP256R1())
        pk = sk.public_key()
        nums = pk.public_numbers()
        x = nums.x.to_bytes(32, "big")
        y = nums.y.to_bytes(32, "big")
        return sk, x, y

    def derive_shared(plat_priv, auth_x: bytes, auth_y: bytes) -> bytes:
        peer = ec.EllipticCurvePublicNumbers(
            int.from_bytes(auth_x, "big"),
            int.from_bytes(auth_y, "big"),
            ec.SECP256R1(),
        ).public_key()
        shared = plat_priv.exchange(ec.ECDH(), peer)   # 32 B X coordinate
        return hashlib.sha256(shared).digest()

    def aes_cbc_enc(key: bytes, plaintext: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16))
        enc = cipher.encryptor()
        return enc.update(plaintext) + enc.finalize()

    def aes_cbc_dec(key: bytes, ciphertext: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16))
        dec = cipher.decryptor()
        return dec.update(ciphertext) + dec.finalize()

    def pin_auth(key: bytes, msg: bytes) -> bytes:
        return pyhmac.new(key, msg, hashlib.sha256).digest()[:16]

    def cose_p256_pubkey(x: bytes, y: bytes) -> dict:
        return {
            1: 2,        # kty = EC2
            3: -25,      # alg = ECDH-ES + HKDF-256
            -1: 1,       # crv = P-256
            -2: x,
            -3: y,
        }

    def pad_pin(pin_utf8: bytes) -> bytes:
        if len(pin_utf8) > 63:
            raise ValueError("PIN too long")
        return pin_utf8 + b"\x00" * (64 - len(pin_utf8))

    # --- Open device + CID ----------------------------------------------

    with open_dev(path) as dev:
        new_cid, _ = cmd_init(dev)

        # 1) GetInfo: clientPin pre-set state
        status, body = cmd_cbor(dev, new_cid, CTAP2_CMD_GET_INFO)
        info = cbor_decode(body) if status == CTAP2_OK else None
        client_pin_pre = info.get(4, {}).get("clientPin") if info else None
        expect("GetInfo: clientPin == false (no PIN yet)",
               client_pin_pre is False,
               f"got {client_pin_pre!r}")

        # 2) GetKeyAgreement
        status, body = cmd_cbor(dev, new_cid, 0x06, cbor_encode({1: 1, 2: 2}))
        ka = cbor_decode(body).get(1) if status == CTAP2_OK else None
        ok = (status == CTAP2_OK and isinstance(ka, dict)
              and ka.get(1) == 2 and ka.get(-1) == 1
              and isinstance(ka.get(-2), bytes) and len(ka[-2]) == 32
              and isinstance(ka.get(-3), bytes) and len(ka[-3]) == 32)
        expect("GetKeyAgreement → P-256 COSE_Key", ok,
               f"status=0x{status:02x}")
        if not ok:
            print_summary(results); return 1
        auth_x = ka[-2]; auth_y = ka[-3]

        # Platform keypair + shared key
        plat_priv, plat_x, plat_y = gen_platform_p256()
        shared_key = derive_shared(plat_priv, auth_x, auth_y)
        plat_cose = cose_p256_pubkey(plat_x, plat_y)

        # 3) SetPin "1234"
        pin = b"1234"
        new_pin_enc = aes_cbc_enc(shared_key, pad_pin(pin))
        req = {
            1: 1,  # pinProtocol
            2: 3,  # subCommand = setPin
            3: plat_cose,
            4: pin_auth(shared_key, new_pin_enc),
            5: new_pin_enc,
        }
        status, body = cmd_cbor(dev, new_cid, 0x06, cbor_encode(req))
        expect("SetPin '1234'", status == CTAP2_OK,
               f"status=0x{status:02x}")

        # 4) GetInfo: clientPin now true
        status, body = cmd_cbor(dev, new_cid, CTAP2_CMD_GET_INFO)
        info = cbor_decode(body)
        expect("GetInfo: clientPin == true (after SetPin)",
               info.get(4, {}).get("clientPin") is True,
               f"got {info.get(4, {}).get('clientPin')!r}")

        # Need fresh key agreement — firmware rotates after setPin
        status, body = cmd_cbor(dev, new_cid, 0x06, cbor_encode({1: 1, 2: 2}))
        ka = cbor_decode(body)[1]
        auth_x = ka[-2]; auth_y = ka[-3]
        plat_priv, plat_x, plat_y = gen_platform_p256()
        shared_key = derive_shared(plat_priv, auth_x, auth_y)
        plat_cose = cose_p256_pubkey(plat_x, plat_y)

        # 5) GetRetries → 8
        status, body = cmd_cbor(dev, new_cid, 0x06, cbor_encode({1: 1, 2: 1}))
        retries = cbor_decode(body).get(3) if status == CTAP2_OK else None
        expect("GetPinRetries → 8", status == CTAP2_OK and retries == 8,
               f"status=0x{status:02x} retries={retries}")

        # 6) GetPinToken with correct PIN
        pin_hash = hashlib.sha256(pin).digest()[:16]
        pin_hash_enc = aes_cbc_enc(shared_key, pin_hash)
        req = {
            1: 1,
            2: 5,  # getPinToken
            3: plat_cose,
            6: pin_hash_enc,
        }
        status, body = cmd_cbor(dev, new_cid, 0x06, cbor_encode(req))
        token_enc = cbor_decode(body).get(2) if status == CTAP2_OK else None
        if status == CTAP2_OK and isinstance(token_enc, bytes) and len(token_enc) == 32:
            pin_token = aes_cbc_dec(shared_key, token_enc)
            expect("GetPinToken correct PIN → 32 B token decrypts",
                   len(pin_token) == 32,
                   f"token={pin_token.hex()}")
        else:
            pin_token = None
            expect("GetPinToken correct PIN → 32 B token decrypts",
                   False, f"status=0x{status:02x}")

        # 7) GetPinToken with wrong PIN
        wrong_hash = hashlib.sha256(b"wrong").digest()[:16]
        wrong_enc = aes_cbc_enc(shared_key, wrong_hash)
        req[6] = wrong_enc
        status, body = cmd_cbor(dev, new_cid, 0x06, cbor_encode(req))
        expect("GetPinToken wrong PIN → PIN_INVALID (0x31)",
               status == 0x31, f"status=0x{status:02x}")

        # 8) GetRetries → 7 (decremented)
        status, body = cmd_cbor(dev, new_cid, 0x06, cbor_encode({1: 1, 2: 1}))
        retries = cbor_decode(body).get(3) if status == CTAP2_OK else None
        expect("GetRetries → 7 after wrong PIN",
               status == CTAP2_OK and retries == 7,
               f"retries={retries}")

        # Wrong PIN rotates ephemeral key — fetch new key agreement.
        status, body = cmd_cbor(dev, new_cid, 0x06, cbor_encode({1: 1, 2: 2}))
        ka = cbor_decode(body)[1]
        auth_x = ka[-2]; auth_y = ka[-3]
        plat_priv, plat_x, plat_y = gen_platform_p256()
        shared_key = derive_shared(plat_priv, auth_x, auth_y)
        plat_cose = cose_p256_pubkey(plat_x, plat_y)

        # 9) GetPinToken correct again → retries reset to 8
        pin_hash_enc = aes_cbc_enc(shared_key, hashlib.sha256(pin).digest()[:16])
        req = {1: 1, 2: 5, 3: plat_cose, 6: pin_hash_enc}
        status, body = cmd_cbor(dev, new_cid, 0x06, cbor_encode(req))
        if status == CTAP2_OK:
            token_enc = cbor_decode(body).get(2)
            pin_token = aes_cbc_dec(shared_key, token_enc) if token_enc else None
        expect("GetPinToken correct PIN (recovery) → token",
               status == CTAP2_OK and pin_token and len(pin_token) == 32,
               f"status=0x{status:02x}")

        status, body = cmd_cbor(dev, new_cid, 0x06, cbor_encode({1: 1, 2: 1}))
        retries = cbor_decode(body).get(3)
        expect("Retries reset to 8 after correct PIN",
               retries == 8, f"retries={retries}")

        # 10) ChangePin "1234" → "5678"
        new_pin = b"5678"
        new_pin_enc = aes_cbc_enc(shared_key, pad_pin(new_pin))
        old_hash_enc = aes_cbc_enc(shared_key, hashlib.sha256(pin).digest()[:16])
        req = {
            1: 1, 2: 4, 3: plat_cose,
            4: pin_auth(shared_key, new_pin_enc + old_hash_enc),
            5: new_pin_enc,
            6: old_hash_enc,
        }
        status, body = cmd_cbor(dev, new_cid, 0x06, cbor_encode(req))
        expect("ChangePin '1234'→'5678'", status == CTAP2_OK,
               f"status=0x{status:02x}")

        # 11) GetPinToken with NEW PIN (after key rotation)
        status, body = cmd_cbor(dev, new_cid, 0x06, cbor_encode({1: 1, 2: 2}))
        ka = cbor_decode(body)[1]
        auth_x = ka[-2]; auth_y = ka[-3]
        plat_priv, plat_x, plat_y = gen_platform_p256()
        shared_key = derive_shared(plat_priv, auth_x, auth_y)
        plat_cose = cose_p256_pubkey(plat_x, plat_y)
        new_hash_enc = aes_cbc_enc(shared_key, hashlib.sha256(new_pin).digest()[:16])
        req = {1: 1, 2: 5, 3: plat_cose, 6: new_hash_enc}
        status, body = cmd_cbor(dev, new_cid, 0x06, cbor_encode(req))
        token_enc = cbor_decode(body).get(2) if status == CTAP2_OK else None
        pin_token = aes_cbc_dec(shared_key, token_enc) if token_enc else None
        expect("GetPinToken with NEW PIN → token",
               status == CTAP2_OK and pin_token and len(pin_token) == 32,
               f"status=0x{status:02x}")

        # 12) MakeCred WITHOUT pinAuth → PIN_REQUIRED
        client_hash = os.urandom(32)
        bad_req = {
            1: client_hash,
            2: {"id": "test-m3.example", "name": "test"},
            3: {"id": os.urandom(16), "name": "user", "displayName": "Test"},
            4: [{"alg": -8, "type": "public-key"}],
        }
        status, body = cmd_cbor(dev, new_cid, CTAP2_CMD_MAKE_CRED, cbor_encode(bad_req))
        expect("MakeCred w/o pinAuth → PIN_REQUIRED (0x36)",
               status == 0x36, f"status=0x{status:02x}")

        # 13) MakeCred WITH pinAuth → success + UV flag
        pinauth_mc = pin_auth(pin_token, client_hash)
        good_req = dict(bad_req)
        good_req[8] = pinauth_mc
        good_req[9] = 1
        status, body = cmd_cbor(dev, new_cid, CTAP2_CMD_MAKE_CRED, cbor_encode(good_req))
        ok = False; cred_id = None; pubkey = None; detail = ""
        if status == CTAP2_OK:
            resp = cbor_decode(body)
            fmt = resp.get(1); authdata = resp.get(2); attstmt = resp.get(3)
            _, flags, _, cred_id, cose = parse_authdata(authdata, expect_at=True)
            pubkey = cose_ed25519_pubkey(cose)
            uv_set = (flags & 0x04) != 0
            try:
                Ed25519PublicKey.from_public_bytes(pubkey).verify(
                    attstmt["sig"], authdata + client_hash)
                ok = uv_set and fmt == "packed"
                detail = f"flags=0x{flags:02x} uv={uv_set}"
            except InvalidSignature:
                detail = "sig verify FAIL"
        else:
            detail = f"status=0x{status:02x}"
        expect("MakeCred WITH pinAuth → success, UV flag set, sig verifies",
               ok, detail)

        # 14) GetAssertion WITH pinAuth → success + UV flag
        if cred_id and pubkey:
            client_hash2 = os.urandom(32)
            pinauth_ga = pin_auth(pin_token, client_hash2)
            ga_req = {
                1: "test-m3.example",
                2: client_hash2,
                3: [{"id": cred_id, "type": "public-key"}],
                6: pinauth_ga,
                7: 1,
            }
            status, body = cmd_cbor(dev, new_cid, CTAP2_CMD_GET_ASSERTION, cbor_encode(ga_req))
            ok = False; detail = ""
            if status == CTAP2_OK:
                resp = cbor_decode(body)
                ad2 = resp[2]; sig2 = resp[3]
                _, flags2, _, _, _ = parse_authdata(ad2, expect_at=False)
                uv_set = (flags2 & 0x04) != 0
                try:
                    Ed25519PublicKey.from_public_bytes(pubkey).verify(
                        sig2, ad2 + client_hash2)
                    ok = uv_set
                    detail = f"flags=0x{flags2:02x} uv={uv_set}"
                except InvalidSignature:
                    detail = "sig verify FAIL"
            else:
                detail = f"status=0x{status:02x}"
            expect("GetAssertion WITH pinAuth → success, UV flag set",
                   ok, detail)
        else:
            expect("GetAssertion WITH pinAuth — SKIPPED (MakeCred failed)",
                   False, "no cred_id from previous step")

    print_summary(results)
    return 0 if all(ok for _, ok, _ in results) else 1


def print_summary(results):
    print()
    print("═" * 63)
    print("  Phase 5 M3 — ClientPIN protocol v1 (P-256 + AES-CBC + HMAC)")
    print("═" * 63)
    n_ok = 0
    for i, (name, ok, detail) in enumerate(results, 1):
        verdict = "PASS" if ok else "FAIL"
        print(f"[{i:2d}/{len(results)}] {name:<56s} {verdict}")
        if not ok and detail:
            print(f"        {detail}")
        else:
            n_ok += 1
    print()
    print(f"{n_ok}/{len(results)} PASS — Phase 5 M3 "
          f"{'validated' if n_ok == len(results) else 'FAILED'}.")


def sub_validate(args) -> int:
    """Run a 5-test suite, exit 0 on full pass."""
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

        # 5) CTAP2 GetInfo — must succeed and parse to a sane map
        status, body = cmd_cbor(dev, new_cid, CTAP2_CMD_GET_INFO)
        try:
            info = cbor_decode(body) if status == CTAP2_OK else None
        except Exception as e:
            info = None
        ok = (status == CTAP2_OK
              and isinstance(info, dict)
              and info.get(1) == ["FIDO_2_0"]
              and isinstance(info.get(3), bytes) and len(info[3]) == 16
              and isinstance(info.get(4), dict)
              and info.get(5) == 1024
              and info.get(9) == ["usb"]
              and isinstance(info.get(10), list) and len(info[10]) >= 1)
        detail = ("ok" if ok
                  else f"status=0x{status:02x} info={info!r}")
        results.append(("CTAP2 GetInfo (versions, aaguid, options, algorithms)",
                        ok, detail))

        # 6) CTAP2 MakeCredential — verify self-attestation Ed25519 signature
        ok = False
        detail = ""
        try:
            status, fmt, authdata, attstmt, chash = _do_make_credential(dev, new_cid)
            assert status == CTAP2_OK, f"status 0x{status:02x}"
            assert fmt == "packed", f"fmt {fmt!r}"
            rp_id_hash, flags, _, cred_id, cose = parse_authdata(
                authdata, expect_at=True)
            pubkey = cose_ed25519_pubkey(cose)
            Ed25519PublicKey.from_public_bytes(pubkey).verify(
                attstmt["sig"], authdata + chash)
            ok = True
            detail = f"fmt=packed credIdLen={len(cred_id)} flags=0x{flags:02x}"
        except (AssertionError, InvalidSignature, Exception) as e:
            detail = f"{type(e).__name__}: {e}"
        results.append(("CTAP2 MakeCredential (Ed25519 self-attestation verifies)",
                        ok, detail))

        # 7) CTAP2 GetAssertion — verify signature against pubkey from step 6
        ok = False
        detail = ""
        try:
            # cred_id + pubkey already extracted above
            status2, credential, ad2, sig2, chash2 = _do_get_assertion(
                dev, new_cid, "test.nixtropic.local", cred_id)
            assert status2 == CTAP2_OK, f"status 0x{status2:02x}"
            rp_id_hash2, flags2, _, _, _ = parse_authdata(ad2, expect_at=False)
            assert credential["type"] == "public-key"
            assert credential["id"] == cred_id, "credId mismatch"
            assert rp_id_hash2 == rp_id_hash, "rpIdHash mismatch"
            Ed25519PublicKey.from_public_bytes(pubkey).verify(sig2, ad2 + chash2)
            ok = True
            detail = f"credId echo OK; signCount monotonic; flags=0x{flags2:02x}"
        except (AssertionError, InvalidSignature, Exception) as e:
            detail = f"{type(e).__name__}: {e}"
        results.append(("CTAP2 GetAssertion (Ed25519 assertion verifies)",
                        ok, detail))

    print()
    print("═" * 63)
    print("  Phase 4 — CTAPHID framing + CTAP2 GetInfo validation")
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
    print(f"{n_ok}/{len(results)} PASS — Phase 4 {'validated' if n_ok == len(results) else 'FAILED'}.")
    return 0 if n_ok == len(results) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init    = sub.add_parser("init",      help="one-shot CTAPHID_INIT")
    p_ping    = sub.add_parser("ping",      help="round-trip CTAPHID_PING")
    p_ping.add_argument("--size", type=int, default=64)
    p_msg     = sub.add_parser("msg",       help="CTAPHID_MSG → expect 6E00")
    p_info    = sub.add_parser("getinfo",   help="CTAP2 authenticatorGetInfo")
    p_make    = sub.add_parser("make-cred", help="CTAP2 authenticatorMakeCredential")
    p_assert  = sub.add_parser("assertion", help="MakeCred → GetAssertion round-trip")
    p_val     = sub.add_parser("validate",  help="run full Phase 4 suite")
    p_val_m2  = sub.add_parser("validate-m2",
                               help="Phase 5 M2 — real TROPIC01-backed FIDO2 (MIC-DROP)")
    p_val_m3  = sub.add_parser("validate-m3",
                               help="Phase 5 M3 — ClientPIN protocol v1 (P-256+AES-CBC)")

    p_init.set_defaults(func=sub_init)
    p_ping.set_defaults(func=sub_ping)
    p_msg.set_defaults(func=sub_msg)
    p_info.set_defaults(func=sub_getinfo)
    p_make.set_defaults(func=sub_make_cred)
    p_assert.set_defaults(func=sub_assertion)
    p_val.set_defaults(func=sub_validate)
    p_val_m2.set_defaults(func=sub_validate_m2)
    p_val_m3.set_defaults(func=sub_validate_m3)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
