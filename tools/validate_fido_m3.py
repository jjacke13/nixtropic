#!/usr/bin/env python3
"""Phase 9 M3 hardware validation — FIDO2 fixes, permission tokens,
authenticatorConfig, touch-wait dispatch (docs/PHASE-9-M3-WORKPLAN.md §3).

DESTRUCTIVE (FIDO only): starts with authenticatorReset, which wipes every
FIDO credential and the FIDO PIN; then sets the PIN from tools/fixture.env
(NIXTROPIC_FIDO_PIN).  OpenPGP keys and PINs are not touched (the CCID check
only SELECTs the OpenPGP application).

Run it within 10 s of plugging the dongle in (the reset window).  The script
asks for SW1 presses on the console; one check asks you NOT to press.

Ends with: FIDO PIN = NIXTROPIC_FIDO_PIN, alwaysUv off, no FIDO credentials.

    nix develop -c python3 tools/validate_fido_m3.py
"""

from __future__ import annotations

import hashlib
import hmac
import os
import shutil
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fido2_test as ft  # noqa: E402  (transport + CBOR helpers)

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402

OK = 0x00
INVALID_PARAMETER = 0x02
CREDENTIAL_EXCLUDED = 0x19
INVALID_OPTION = 0x2C
KEEPALIVE_CANCEL = 0x2D
NO_CREDENTIALS = 0x2E
NOT_ALLOWED = 0x30
PIN_AUTH_INVALID = 0x33
PUAT_REQUIRED = 0x36
UNAUTHORIZED_PERMISSION = 0x40

PERM_MC, PERM_GA, PERM_CM, PERM_BE, PERM_ACFG = 0x01, 0x02, 0x04, 0x08, 0x20

RP_A, RP_B = "a.m3.nixtropic.test", "b.m3.nixtropic.test"
UP_MS = 35000

results: list[tuple[str, bool, str]] = []


def expect(label: str, cond: bool, detail: str = "") -> bool:
    results.append((label, bool(cond), detail))
    mark = "ok  " if cond else "FAIL"
    print(f"  [{mark}] {label}" + ("" if cond else f"  ({detail})"))
    return bool(cond)


def touch(why: str) -> None:
    print(f"\n  >>> PRESS SW1 now: {why}")


def fixture_pin() -> bytes:
    path = os.environ.get("NIXTROPIC_FIXTURE", os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "fixture.env"))
    try:
        with open(path) as f:
            for line in f:
                key, _, val = line.strip().partition("=")
                if key == "NIXTROPIC_FIDO_PIN" and val:
                    return val.encode()
    except FileNotFoundError:
        pass
    sys.exit(f"NIXTROPIC_FIDO_PIN missing in {path} (see fixture.env.example)")


# ---------------- device + PIN protocol 1 ----------------

class Dev:
    def __init__(self, hid_dev):
        self.h = hid_dev
        self.cid, _ = ft.cmd_init(hid_dev)

    def cbor(self, cmd: int, params=None, timeout_ms: int = 5000):
        raw = ft.cbor_encode(params) if params is not None else b""
        st, body = ft.cmd_cbor(self.h, self.cid, cmd, raw, timeout_ms=timeout_ms)
        return st, (ft.cbor_decode(body) if st == OK and body else None)

    def info(self) -> dict:
        st, info = self.cbor(0x04)
        assert st == OK, f"GetInfo 0x{st:02x}"
        return info


def aes(key: bytes, data: bytes, enc: bool) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16))
    op = c.encryptor() if enc else c.decryptor()
    return op.update(data) + op.finalize()


def auth(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()[:16]


def key_agreement(d: Dev):
    """Return (platform COSE key, shared secret) for protocol 1."""
    st, r = d.cbor(0x06, {1: 1, 2: 2})
    assert st == OK, f"getKeyAgreement 0x{st:02x}"
    ka = r[1]
    sk = ec.generate_private_key(ec.SECP256R1())
    n = sk.public_key().public_numbers()
    peer = ec.EllipticCurvePublicNumbers(int.from_bytes(ka[-2], "big"),
                                         int.from_bytes(ka[-3], "big"),
                                         ec.SECP256R1()).public_key()
    shared = hashlib.sha256(sk.exchange(ec.ECDH(), peer)).digest()
    cose = {1: 2, 3: -25, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}
    return cose, shared


def set_pin(d: Dev, pin: bytes) -> int:
    cose, shared = key_agreement(d)
    enc = aes(shared, pin + b"\x00" * (64 - len(pin)), True)
    st, _ = d.cbor(0x06, {1: 1, 2: 3, 3: cose, 4: auth(shared, enc), 5: enc})
    return st


def token(d: Dev, pin: bytes, perms: int | None = None, rp: str | None = None,
          extra: dict | None = None):
    """perms None = legacy getPinToken (0x05).  Returns (status, token)."""
    cose, shared = key_agreement(d)
    req = {1: 1, 2: 5 if perms is None else 9, 3: cose,
           6: aes(shared, hashlib.sha256(pin).digest()[:16], True)}
    if perms is not None:
        req[9] = perms
    if rp is not None:
        req[10] = rp
    req.update(extra or {})
    st, r = d.cbor(0x06, req)
    return st, (aes(shared, r[2], False) if st == OK else None)


# ---------------- WebAuthn operations ----------------

def parse_ad(ad: bytes):
    """(flags, signCount, credId or None, Ed25519 pubkey or None, extensions)."""
    flags, sc = ad[32], struct.unpack(">I", ad[33:37])[0]
    if not flags & 0x40:
        return flags, sc, None, None, None
    n = struct.unpack(">H", ad[53:55])[0]
    cred_id = ad[55:55 + n]
    cose, off = ft.cbor_decode_one(ad, 55 + n)
    ext = ft.cbor_decode_one(ad, off)[0] if flags & 0x80 else None
    return flags, sc, cred_id, ft.cose_ed25519_pubkey(cose), ext


def make_cred(d: Dev, rp: str, user: bytes, *, rk: bool, tok: bytes | None = None,
              exclude: list[bytes] | None = None, cred_props: bool = False):
    cdh = os.urandom(32)
    req = {1: cdh, 2: {"id": rp, "name": rp}, 3: {"id": user, "name": "m3"},
           4: [{"alg": -7, "type": "public-key"}, {"alg": -8, "type": "public-key"}]}
    if rk:
        req[7] = {"rk": True}
    if tok is not None:
        req[8], req[9] = auth(tok, cdh), 1
    if exclude:
        req[5] = [{"id": c, "type": "public-key"} for c in exclude]
    if cred_props:
        req[6] = {"credProps": True}
    st, r = d.cbor(0x01, req, timeout_ms=UP_MS)
    if st != OK:
        return st, None
    flags, sc, cred_id, pk, ext = parse_ad(r[2])
    return st, {"id": cred_id, "pk": pk, "flags": flags, "sc": sc, "ext": ext}


def get_assertion(d: Dev, rp: str, allow: list[bytes] | None = None, *,
                  tok: bytes | None = None, up: bool | None = None):
    cdh = os.urandom(32)
    req = {1: rp, 2: cdh}
    if allow is not None:
        req[3] = [{"id": c, "type": "public-key"} for c in allow]
    if up is not None:
        req[5] = {"up": up}
    if tok is not None:
        req[6], req[7] = auth(tok, cdh), 1
    st, r = d.cbor(0x02, req, timeout_ms=UP_MS)
    return st, r, cdh


def sig_ok(pk: bytes, r: dict, cdh: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(r[3], r[2] + cdh)
        return True
    except Exception:
        return False


def toggle_uv(d: Dev, tok: bytes | None = None) -> int:
    req = {1: 0x02}
    if tok is not None:
        msg = b"\xff" * 32 + bytes([0x0D, 0x02])
        req[3], req[4] = 1, auth(tok, msg)
    return d.cbor(0x0D, req)[0]


def cm(d: Dev, sub: int, tok: bytes | None, params: dict | None = None):
    req = {1: sub}
    if params is not None:
        req[2] = params
    if tok is not None:
        raw = ft.cbor_encode(params) if params is not None else b""
        req[3], req[4] = 1, auth(tok, bytes([sub]) + raw)
    return d.cbor(0x0A, req)


# ---------------- raw CTAPHID for CANCEL / INIT during a wait ----------------

def send_packets(h, cid: int, cmd: int, payload: bytes) -> None:
    first = bytearray(64)
    first[0:4] = struct.pack(">I", cid)
    first[4] = 0x80 | cmd
    first[5:7] = struct.pack(">H", len(payload))
    first[7:7 + min(57, len(payload))] = payload[:57]
    pkts, off, seq = [bytes(first)], 57, 0
    while off < len(payload):
        cont = bytearray(64)
        cont[0:4] = struct.pack(">I", cid)
        cont[4] = seq
        cont[5:5 + len(payload[off:off + 59])] = payload[off:off + 59]
        pkts.append(bytes(cont))
        off, seq = off + 59, seq + 1
    for p in pkts:
        h.write(b"\x00" + p)


def read_reply(h, cid: int, timeout_s: float):
    """First complete reply on `cid`: (cmd, payload) or None on timeout."""
    deadline, body, cmd, total = time.time() + timeout_s, b"", None, 0
    while time.time() < deadline:
        pkt = h.read(64, timeout=100)
        if not pkt or len(pkt) < 64 or struct.unpack(">I", pkt[0:4])[0] != cid:
            continue
        if cmd is None:
            if not pkt[4] & 0x80:
                continue
            cmd, total = pkt[4] & 0x7F, struct.unpack(">H", pkt[5:7])[0]
            body = bytes(pkt[7:7 + min(57, total)])
        else:
            body += bytes(pkt[5:5 + min(59, total - len(body))])
        if len(body) >= total:
            return cmd, body
    return None


def ga_request(rp: str, allow: list[bytes]) -> bytes:
    return bytes([0x02]) + ft.cbor_encode(
        {1: rp, 2: os.urandom(32), 3: [{"id": c, "type": "public-key"} for c in allow]})


# ---------------- the suite ----------------

def run(d: Dev, pin: bytes) -> None:
    print("\n== 1. reset (wipes FIDO credentials + FIDO PIN)")
    touch("authenticatorReset (needed if a PIN or credentials exist)")
    st, _ = d.cbor(0x07, timeout_ms=UP_MS)
    if not expect("authenticatorReset", st == OK, f"0x{st:02x} (0x30 = replug, run within 10 s)"):
        raise SystemExit(1)

    print("\n== 2. GetInfo announces what exists")
    info = d.info()
    opt = info.get(4, {})
    expect("versions == [FIDO_2_0]", info.get(1) == ["FIDO_2_0"], repr(info.get(1)))
    expect("AAGUID ends 04", info.get(3, b"")[-1:] == b"\x04", info.get(3, b"").hex())
    want = {"rk": True, "up": True, "plat": False, "alwaysUv": False, "credMgmt": True,
            "authnrCfg": True, "clientPin": False, "pinUvAuthToken": True,
            "makeCredUvNotRqd": True}
    expect("options exactly as implemented", opt == want, repr(opt))
    expect("algorithms == EdDSA only",
           info.get(10) == [{"alg": -8, "type": "public-key"}], repr(info.get(10)))

    print("\n== 3. alwaysUv without a PIN")
    expect("toggleAlwaysUv without PIN needs no auth", toggle_uv(d) == OK)
    opt = d.info()[4]
    expect("alwaysUv on, makeCredUvNotRqd off",
           opt.get("alwaysUv") is True and opt.get("makeCredUvNotRqd") is False, repr(opt))
    st, _, _ = get_assertion(d, RP_A)
    expect("alwaysUv + no PIN: GetAssertion → PUAT_REQUIRED", st == PUAT_REQUIRED, f"0x{st:02x}")
    expect("toggle back off", toggle_uv(d) == OK and d.info()[4]["alwaysUv"] is False)

    print("\n== 4. PIN and permission tokens")
    expect("setPIN from fixture", set_pin(d, pin) == OK)
    opt = d.info()[4]
    expect("setPIN auto-enables alwaysUv (Phase 6 policy)",
           opt.get("clientPin") is True and opt.get("alwaysUv") is True, repr(opt))
    expect("toggle with PIN, no auth → PUAT_REQUIRED", toggle_uv(d) == PUAT_REQUIRED)
    st, legacy = token(d, pin)
    expect("legacy getPinToken (0x05)", st == OK, f"0x{st:02x}")
    expect("legacy token refused for authenticatorConfig",
           toggle_uv(d, legacy) == PIN_AUTH_INVALID)
    st, t_acfg = token(d, pin, PERM_ACFG)
    expect("0x09 token with acfg", st == OK, f"0x{st:02x}")
    expect("acfg token turns alwaysUv off", toggle_uv(d, t_acfg) == OK
           and d.info()[4]["alwaysUv"] is False)
    expect("0x09 permissions 0 → INVALID_PARAMETER", token(d, pin, 0)[0] == INVALID_PARAMETER)
    expect("0x09 be permission → UNAUTHORIZED_PERMISSION",
           token(d, pin, PERM_BE)[0] == UNAUTHORIZED_PERMISSION)
    expect("0x05 with permissions → INVALID_PARAMETER",
           token(d, pin, None, extra={9: PERM_GA})[0] == INVALID_PARAMETER)
    st, t_cm = token(d, pin, PERM_CM)
    st, _, _ = get_assertion(d, RP_A, [os.urandom(18)], tok=t_cm)
    expect("cm-only token refused for GetAssertion", st == PIN_AUTH_INVALID, f"0x{st:02x}")
    st, t_b = token(d, pin, PERM_MC | PERM_GA, RP_B)
    st, _ = make_cred(d, RP_A, b"u1", rk=True, tok=t_b)
    expect("token bound to site B refused for site A", st == PIN_AUTH_INVALID, f"0x{st:02x}")
    st, _ = make_cred(d, RP_A, b"u1", rk=True)
    expect("PIN set, rk without token → PUAT_REQUIRED", st == PUAT_REQUIRED, f"0x{st:02x}")

    print("\n== 5. credentials (touches)")
    st, t = token(d, pin, PERM_MC | PERM_GA, RP_A)
    touch("register A1 (discoverable)")
    st, a1 = make_cred(d, RP_A, b"user-1", rk=True, tok=t, cred_props=True)
    expect("A1 made with token: UV set, credProps rk true",
           st == OK and a1["flags"] & 0x04 and a1["ext"] == {"credProps": {"rk": True}},
           f"0x{st:02x} {a1 and a1['ext']}")
    st, _, _ = get_assertion(d, RP_A, [a1["id"]], tok=t)
    expect("token spent after one touch-tested use", st == PIN_AUTH_INVALID, f"0x{st:02x}")
    st, t = token(d, pin, PERM_MC | PERM_GA, RP_A)
    touch("register A2 (discoverable)")
    st, a2 = make_cred(d, RP_A, b"user-2", rk=True, tok=t)
    expect("A2 made", st == OK, f"0x{st:02x}")
    touch("register A3 (NOT discoverable, no token: makeCredUvNotRqd)")
    st, a3 = make_cred(d, RP_A, b"user-3", rk=False, cred_props=True)
    expect("A3 made without token, UV 0, credProps rk false",
           st == OK and not a3["flags"] & 0x04 and a3["ext"] == {"credProps": {"rk": False}},
           f"0x{st:02x}")
    st, t = token(d, pin, PERM_MC | PERM_GA, RP_B)
    touch("register B1")
    st, b1 = make_cred(d, RP_B, b"user-b", rk=True, tok=t)
    expect("B1 made", st == OK, f"0x{st:02x}")

    st, _, _ = get_assertion(d, RP_B, [a1["id"]])
    expect("site A credential refused for site B", st == NO_CREDENTIALS, f"0x{st:02x}")
    touch("login site A with allowList [unknown, A2]")
    st, r, cdh = get_assertion(d, RP_A, [os.urandom(18), a2["id"]])
    expect("allowList: second entry used, signature verifies",
           st == OK and r[1]["id"] == a2["id"] and sig_ok(a2["pk"], r, cdh), f"0x{st:02x}")
    sc_first = parse_ad(r[2])[1] if st == OK else 0

    st, r, cdh = get_assertion(d, RP_A, up=False)
    ok = st == OK and r.get(5) == 2 and r[1]["id"] == a2["id"] and r[4] == {"id": b"user-2"}
    expect("discoverable, up=false: 2 creds, newest (A2) first, no touch",
           ok and not parse_ad(r[2])[0] & 0x01 and sig_ok(a2["pk"], r, cdh),
           f"0x{st:02x} {r and {k: r[k] for k in r if k != 2 and k != 3}}")
    sc_second = parse_ad(r[2])[1] if st == OK else 0
    st, r2 = d.cbor(0x08)
    expect("GetNextAssertion → A1", st == OK and r2[1]["id"] == a1["id"]
           and r2[4] == {"id": b"user-1"} and 5 not in r2, f"0x{st:02x}")
    sc_third = parse_ad(r2[2])[1] if st == OK else 0
    expect("GetNextAssertion past the end → NOT_ALLOWED", d.cbor(0x08)[0] == NOT_ALLOWED)
    expect("signCount strictly increases", sc_first < sc_second < sc_third,
           f"{sc_first} {sc_second} {sc_third}")

    touch("register with excludeList [A1] — press, the answer is EXCLUDED")
    st, _ = make_cred(d, RP_A, b"user-9", rk=False, exclude=[a1["id"]])
    expect("excludeList hit → CREDENTIAL_EXCLUDED", st == CREDENTIAL_EXCLUDED, f"0x{st:02x}")
    st, t = token(d, pin, PERM_MC | PERM_GA, RP_A)
    touch("re-register user-1 (replaces A1)")
    st, a1b = make_cred(d, RP_A, b"user-1", rk=True, tok=t)
    expect("same RP + user replaces the old credential", st == OK, f"0x{st:02x}")
    st, _, _ = get_assertion(d, RP_A, [a1["id"]])
    expect("old A1 ID no longer resolves", st == NO_CREDENTIALS, f"0x{st:02x}")

    print("\n== 6. credential management")
    st, legacy = token(d, pin)          # fresh: every new token kills the old one
    expect("legacy token refused for credMgmt",
           st == OK and cm(d, 0x01, legacy)[0] == PIN_AUTH_INVALID)
    st, t_cm = token(d, pin, PERM_CM)
    st, m = cm(d, 0x01, t_cm)
    expect("metadata: 4 existing, 25 remaining (29 slots)",
           st == OK and m.get(1) == 4 and m.get(2) == 25, f"0x{st:02x} {m}")
    st, r = cm(d, 0x02, t_cm)
    st2, _ = cm(d, 0x03, None)
    expect("enumerate RPs: 2, GetNextRP without pinUvAuthParam",
           st == OK and r.get(5) == 2 and st2 == OK, f"0x{st:02x} 0x{st2:02x}")
    rp_a_hash = hashlib.sha256(RP_A.encode()).digest()
    st, r = cm(d, 0x04, t_cm, {1: rp_a_hash})
    nexts = [cm(d, 0x05, None)[0] for _ in range(2)]
    expect("enumerate site A: 3 credentials, GetNext without auth",
           st == OK and r.get(9) == 3 and nexts == [OK, OK], f"0x{st:02x} {nexts}")
    st, t_cmb = token(d, pin, PERM_CM, RP_B)
    expect("cm token bound to B: RP enumeration refused", cm(d, 0x02, t_cmb)[0] == PIN_AUTH_INVALID)
    expect("cm token bound to B: site A list refused",
           cm(d, 0x04, t_cmb, {1: rp_a_hash})[0] == PIN_AUTH_INVALID)
    expect("cm token bound to B: delete A2 refused",
           cm(d, 0x06, t_cmb, {2: {"id": a2["id"], "type": "public-key"}})[0] == PIN_AUTH_INVALID)
    expect("cm token bound to B: delete B1",
           cm(d, 0x06, t_cmb, {2: {"id": b1["id"], "type": "public-key"}})[0] == OK)

    print("\n== 7. touch-wait dispatch (CANCEL, INIT, CCID during a wait)")
    print("  >>> do NOT press SW1 during this part")
    send_packets(d.h, d.cid, 0x10, ga_request(RP_A, [a2["id"]]))
    time.sleep(1.0)
    nonce = os.urandom(8)
    send_packets(d.h, 0xFFFFFFFF, 0x06, nonce)
    init = read_reply(d.h, 0xFFFFFFFF, 2.0)
    expect("INIT answered during a touch wait", init is not None and init[1][:8] == nonce,
           repr(init and init[0]))
    ccid_done = ccid_select_during(d)
    t0 = time.time()
    send_packets(d.h, d.cid, 0x11, b"")               # CANCEL
    rep = read_reply(d.h, d.cid, 3.0)
    expect("CANCEL ends the wait: KEEPALIVE_CANCEL, no echo",
           rep is not None and rep[0] == 0x10 and rep[1][:1] == bytes([KEEPALIVE_CANCEL]),
           repr(rep))
    if ccid_done is not None:
        ccid_done.join(10)
        ok, finished = ccid_done.result
        expect("CCID APDU sent during the wait answered after it",
               ok and finished >= t0 - 0.05, f"ok={ok} finished-cancel={finished - t0:+.2f}s")

    # A multi-packet request plus a stray next-sequence CONT during its wait:
    # before M3 review fixes the CONT dispatched the request a second time.
    req = ga_request(RP_A, [os.urandom(18), os.urandom(18), a2["id"]])
    n_cont = (len(req) - 57 + 58) // 59
    send_packets(d.h, d.cid, 0x10, req)
    time.sleep(1.0)
    stray = bytearray(64)
    stray[0:4] = struct.pack(">I", d.cid)
    stray[4] = n_cont
    d.h.write(b"\x00" + bytes(stray))
    time.sleep(0.5)
    send_packets(d.h, d.cid, 0x11, b"")
    first = read_reply(d.h, d.cid, 3.0)
    extra = read_reply(d.h, d.cid, 1.0)
    expect("stray CONT during a wait: one request, one answer",
           n_cont >= 1 and first is not None and first[1][:1] == bytes([KEEPALIVE_CANCEL])
           and extra is None, f"n_cont={n_cont} first={first!r} extra={extra!r}")

    print("\n== 8. token lifetime")
    st, t = token(d, pin, PERM_GA, RP_A)
    print("  waiting 31 s (initial-use limit is 30 s)...")
    time.sleep(31)
    st, _, _ = get_assertion(d, RP_A, [a2["id"]], tok=t)
    expect("token unused for 30 s is dead", st == PIN_AUTH_INVALID, f"0x{st:02x}")

    print("\n== 9. alwaysUv matrix with a PIN")
    st, t = token(d, pin, PERM_ACFG)
    expect("alwaysUv on (acfg token)", toggle_uv(d, t) == OK and d.info()[4]["alwaysUv"])
    st, _, _ = get_assertion(d, RP_A, [a2["id"]])
    expect("alwaysUv: GetAssertion without token → PUAT_REQUIRED", st == PUAT_REQUIRED,
           f"0x{st:02x}")
    st, _ = make_cred(d, RP_A, b"user-8", rk=False)
    expect("alwaysUv: MakeCredential without token → PUAT_REQUIRED", st == PUAT_REQUIRED,
           f"0x{st:02x}")
    st, t = token(d, pin, PERM_ACFG)
    expect("alwaysUv off again", toggle_uv(d, t) == OK and not d.info()[4]["alwaysUv"])

    print("\n== 10. clean up: delete the test credentials")
    st, t_cm = token(d, pin, PERM_CM)
    gone = [cm(d, 0x06, t_cm, {2: {"id": c["id"], "type": "public-key"}})[0]
            for c in (a1b, a2, a3)]
    st, m = cm(d, 0x01, t_cm)
    expect("test credentials deleted, store empty",
           gone == [OK, OK, OK] and m.get(1) == 0 and m.get(2) == 29, f"{gone} {m}")


class _CcidThread(threading.Thread):
    def __init__(self, cmd):
        super().__init__(daemon=True)
        self.cmd, self.result = cmd, (False, 0.0)

    def run(self):
        p = subprocess.run(self.cmd, capture_output=True, text=True)
        self.result = (p.returncode == 0 and "90 00" in p.stdout.upper().replace(":", " "),
                       time.time())


def ccid_select_during(d: Dev):
    """Start an OpenPGP SELECT over PC/SC; None if the tools are missing."""
    tool = shutil.which("opensc-tool")
    if tool is None:
        print("  (opensc-tool not found: CCID check skipped)")
        return None
    if shutil.which("gpgconf"):
        subprocess.run(["gpgconf", "--kill", "scdaemon"], capture_output=True)
    th = _CcidThread([tool, "--reader", "0", "-s", "00:A4:04:00:06:D2:76:00:01:24:01"])
    th.start()
    time.sleep(1.5)
    return th


def wait_for_replug() -> str:
    """Wait for the dongle to go away and come back, so the reset lands in
    its 10 s post-boot window."""
    import hid
    def present() -> bool:
        return any(True for _ in hid.enumerate(ft.VID, ft.PID))
    print(">>> unplug the dongle and plug it back in (normal mode)")
    while present():
        time.sleep(0.2)
    while not present():
        time.sleep(0.2)
    time.sleep(0.8)                     # enumeration + chip boot
    return ft.find_fido_path()


def main() -> int:
    pin = fixture_pin()
    with ft.open_dev(wait_for_replug()) as h:
        d = Dev(h)
        try:
            run(d, pin)
        except SystemExit:
            pass
    ft.print_summary(results, title="Phase 9 M3 — FIDO2 fixes, tokens, config, dispatch",
                     short_name="Phase 9 M3")
    return 0 if results and all(ok for _, ok, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())
