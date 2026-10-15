# Phase 9 M4 — Design: PIN + persistent-state integrity

Status: **draft for review** (2026-10-15). Contract: `PHASE-9-PLAN.md` §6 (items 1–7)
plus the M4 inputs from the M3 reviews (§5 end). Chip facts marked **[J1a]…[J4]**
come from Jan's answers (§9), from the documents, not measured.

Like `history/PHASE-5-M4-DESIGN.md`, this is reviewed **before** code. The work plan
(order, commits) is §8.

---

## 0. What is wrong today (code facts)

| # | Finding | Where |
|---|---|---|
| F1 | FIDO R-mem slot 0 is **one record for everything**: credential bitmap, PIN hash, retry counter, M&D state (tag, ci[8]), alwaysUv. Every PIN attempt rewrites it 3–4 times (retry decrement, M&D advance, M&D restore, retry reset). Each rewrite is erase-then-write (DS §7.6), not atomic. | `slots.c:163-199`, `pin.c:706,714,725`, `pin_md_kernel.c` |
| F2 | A torn rewrite leaves the slot **empty** — and an empty slot is exactly what "never written" looks like. Worse, `SLOT_EMPTY` is also what a **damaged** slot reads as: the chip returns length 0 on a failed decrypt and the SDK turns that into `SLOT_EMPTY` [J1b]. `slots_init` writes fresh state on empty, read error or magic mismatch: bitmap 0, no PIN, no M&D, alwaysUv 0. So rule 7 ("init only on `SLOT_EMPTY`") is **not enough**: an empty read never proves a fresh device. | `slots.c:412-430` |
| F3 | **OpenPGP R33 has the same shape, with worse consequences.** It is rewritten on every VERIFY (retry mirror), every signature (counter) and every PUT DATA. Empty or magic mismatch → bootstrap: PW1/PW3 back to `123456`/`12345678`, M&D state wiped — but the keys in ECC slots 29 and 31 are **not** touched. A power cut at the right moment resets the PINs while the signing and authentication keys stay. | `openpgp_state.c:222-257` |
| F4 | **Software PIN fallback.** OpenPGP checks the R33 hash with a software counter whenever M&D is "inactive"; `pin_md_kernel_is_active` reports a read error as inactive. Factory PINs are never M&D-bound (only after the first change). Every M&D setup result in `pgp_pin.c` is ignored. | `pgp_pin.c:121,157,231,259,289,335`, `pin_md_kernel.c` `is_active` |
| F5 | **Setup overwrites the live binding.** The kernel re-keys the same slot range and only then writes the record; FIDO changePin writes the new hash before the M&D setup. A failure in between leaves hash and M&D disagreeing → the PIN is lost. | `pin_md_kernel.c` setup, `pin.c:592-601` |
| F6 | Two retry counters per PIN (software mirror + M&D `next_slot`) that can disagree; readers fall back to "full retries" on a read error. | `pin.c:248`, `openpgp_state.c:299` |
| F7 | Stored PIN hashes (FIDO slot 0, R33) are offline-guessable verifiers next to the M&D tag. (PLAN puts their removal in M5; see decision D6.) | `slots.c:181`, `openpgp_state.c:132-164` |
| F8 | OpenPGP has **one** PW1 flag for 81 and 82; DO C4 byte 0 is stored inverted (`force_verify = 0` is read back as C4 `00`, which per spec means "one signature per VERIFY") and never enforced; the PIN state is cleared only on TERMINATE/ACTIVATE, not on card reset (IccPowerOff/On) or a different SELECT. | `openpgp_applet.c:213,527,979,1056,1078` |
| F9 | M3 inputs: other `write_global` callers do not mark an uncertain write; orphan scrub covers one direction only. | `slots.c:163`, `PHASE-9-PLAN.md` §5 |

F2+F3 are the root: **any persistent object that is rewritten in place can be lost by
one power cut, and losing it looks like a fresh device.** M4 fixes that once, in one
place, and puts every PIN and state object on top of it.

---

## 1. Decisions

- **D1. Ping-pong record pairs** (§2) for every persistent object M4 touches. Never
  erase or overwrite the current record; write the other slot with generation + 1.
  Both slots keep a valid record at rest: the older one is the fallback when the
  newer one reads damaged. A write that removes a secret goes to both slots.
- **D2. Empty proves nothing on its own** [J1b]. One power cut cannot make an object
  read "both empty", but damage can. An object that reads absent is trusted as
  absent only when a **guard** in another object agrees (§2.5); the absent path of an
  application wipes everything that application owns before it initialises. A read
  error (anything but `SLOT_EMPTY`) fails closed — no init, no migration, no
  fallback.
- **D3. M&D kernel v2** (§3): two slot ranges per PIN (A/B), the binding record says
  which range is live; setup writes the inactive range; commit = the record write;
  then the old range is **retired** (one M&D call with random data per slot). The
  kernel returns `k = HMAC-SHA256(s, 0x02)` on setup/verify/change.
- **D4. PIN change keeps s** inside the kernel (`pin_md_kernel_change`): s never
  leaves the kernel, so k survives a PIN change (M5 depends on it). Resets (RC, PW3
  reset of PW1, FIDO reset) use a fresh s.
- **D5. The M&D record is the only PIN state**: no software path, no second counter,
  retries = `rounds − next_slot`. The PIN length (OpenPGP needs it to split CHANGE
  REFERENCE DATA) lives **in the binding record**, so it commits with the PIN.
- **D6. Stored PIN hashes are dropped in M4** (PLAN M5 item 1, moved forward): M4
  rewrites these records anyway, and with D5 nothing reads the hash. M5 shrinks to
  the DEC key wrap.
- **D7. One explicit destructive migration** from the v0.2/M3 layout (PLAN rule 8,
  §6 item 6): recognised old layout → wipe that application (FIDO: credentials,
  keys, PIN; OpenPGP: keys 29–31, PINs, state) → fresh bootstrap. Anything
  unrecognised fails closed. Release notes say so.
- **D8. Order rule for destructive operations: keys first, PINs last.** A crash in a
  reset/terminate must never leave keys under no PIN or a factory PIN (rule 8).
- **D9. OpenPGP PIN semantics per spec**: separate PW1.81 / PW1.82 flags; DO C4
  byte 0 stored with spec meaning (`00` = one CDS per VERIFY, `01` = until reset),
  **default `01`** (Vaios: PIN once per plug-in); flags cleared on IccPowerOff/On,
  USB reset, SELECT of another AID, TERMINATE/ACTIVATE, PIN change/reset.
- **D10. FIDO changePin follows CTAP 2.1**: a wrong `pinUvAuthParam` returns
  `PIN_AUTH_INVALID` without counting an attempt. The 2026-05 audit (H1) counted it
  first to deny a "probe oracle", but the MAC check reveals nothing about the PIN, and
  with the M&D record as the only counter a count without an M&D call would be a
  second kind of attempt. Every attempt that reaches the PIN check consumes an M&D slot.

---

## 2. Record pairs (`firmware/src/tropic/rec_pair.{c,h}`)

### 2.1 Format

Every record (≤ 444 B, rule 6):

| off | len | field |
|---|---|---|
| 0 | 4 | magic `NXR1` |
| 4 | 1 | object id (O1…O6, §2.4) |
| 5 | 1 | object schema |
| 6 | 4 | generation (u32 BE, starts at 1) |
| 10 | 2 | payload length n |
| 12 | n | payload |
| 12+n | 8 | `SHA-256(bytes 0 … 12+n−1)[:8]` |

The checksum catches torn or garbled content and a record read from the wrong slot.
It is **not** a MAC: an attacker with L3 access can write R-mem anyway; integrity
against a reflashed STM32 is Phase 10 (pairing keys / UAP).

### 2.2 Reading a pair

Each slot classifies as `VALID(gen)`, `EMPTY` (`SLOT_EMPTY`), `BAD` (read OK, header,
length, object id or checksum wrong) or `ERR` (chip error after the M2 session
policy). Result:

| slot A | slot B | result |
|---|---|---|
| ERR | any | **ERROR** (fail closed) |
| EMPTY | EMPTY | **ABSENT** — never written, cleared, *or both damaged*: see §2.5 |
| VALID | EMPTY | A |
| VALID(g1) | VALID(g2) | the higher generation (normal state at rest); equal generations → ERROR |
| VALID | BAD | A — the BAD one is a torn write; R-mem writes are not documented as atomic [J1a] |
| BAD | EMPTY / BAD | **CORRUPT** (fail closed; only the application's reset clears it) |

(and symmetric). Falling back to the older record rolls the object back by one
write. Why that never opens access:
- **PIN record**: `next_slot` one lower. That does not revive a useful attempt: the
  slot the lost write counted was consumed on the chip, and a verify through a
  consumed slot always fails. Intact slots only go down until a correct PIN re-keys
  them (which needs s). Or the binding before a change: its range was retired, so
  that PIN is locked — fail-safe, reset needed.
- **OpenPGP state**: counters and DOs one write older.
- **FIDO bitmap**: the newest credential is hidden, or a deleted one reappears with
  its key erased (signing fails).

### 2.3 Writing a pair

```
write(obj, payload):
  cur = read_pair(obj)              # ERROR/CORRUPT → refuse
  target = the slot that is not cur # ABSENT → slot A
  erase(target); write(target, gen = cur.gen + 1)    # ← commit point
```

A failed write is **re-read**, not guessed: target `VALID(gen+1)` → committed;
`EMPTY` or `BAD` → not committed (the current record is intact, we never touched it);
`ERR` → **uncertain**: that object refuses everything until the next boot
(generalises the M3 `s_store_uncertain` flag to every object, F9). Generation is u32:
no wrap in the device's life.

**Scrub write**: when a write drops a secret (O3 losing the DEC key on TERMINATE or
key replacement), the same payload is written a second time, so the older slot no
longer holds the secret.

Cost per write: 1 erase + 1 write, as today, spread over two slots. Endurance is
100 000 reprogram cycles per slot, typical, 10-year retention (DS §9.6) [J1c]; no
guaranteed minimum is documented. A PIN verify is 2 writes (advance + restore) on
alternating slots ≈ 100 k attempts per PIN, typical — today FIDO rewrites slot 0
four times per attempt.

### 2.4 Objects and R-mem slots

| Obj | What | Slots (A / B) | Written by |
|---|---|---|---|
| O1 | FIDO global: bitmap, alwaysUv, `pin_bound` | 0 / 40 | alloc, erase, alwaysUv, first setPin, reset |
| O2 | FIDO PIN binding | 41 / 42 | setPin, changePin, every PIN attempt, reset |
| O3 | OpenPGP state: lifecycle, `rc_set`, DOs, sig counter, C4, UIF, DEC key (until M5) | 33 / 43 | PUT DATA, CDS counter, generate, terminate, activate (no longer VERIFY) |
| O4 | OpenPGP PW1 binding | 50 / 53 | VERIFY 81/82, CHANGE, RESET RETRY COUNTER |
| O5 | OpenPGP PW3 binding | 51 / 54 | VERIFY 83, CHANGE |
| O6 | OpenPGP RC binding | 52 / 55 | PUT DATA D3, RESET RETRY COUNTER (RC) |

Credential metadata (R-mem 1–29) stays one slot per credential: it is written once
at creation and erased at deletion, never rewritten in place. The M3 bitmap commit
rules stay.

O3 now carries the DEC private key (until M5); the scrub write (§2.3) keeps a
replaced or terminated key from lingering in the older slot.

### 2.5 Guards: when "absent" is believed

Because an empty read can be damage [J1b], a pair that reads ABSENT is cross-checked:

| Pair reads ABSENT | Guard | Guard says present → | Guard says absent → |
|---|---|---|---|
| O2 FIDO PIN | O1 `pin_bound` | **ERROR** (never "PIN not set") | PIN not set |
| O4 PW1 / O5 PW3 | O3 lifecycle OPERATIONAL | **ERROR** | (TERMINATED: expected) |
| O6 RC | O3 `rc_set` | **ERROR** | RC not set |
| O1 FIDO global | none | — | wipe all FIDO-owned data, then fresh |
| O3 OpenPGP state | none | — | wipe keys 29–31 + PINs, then bootstrap |

The last two have no guard: their absent path destroys keys **before** any PIN goes
back to a default, so even a damaged-looking state never leaves keys under a
factory PIN or no PIN (D8). Guard flags are written **after** the guarded object
commits and cleared **after** it is cleared; a crash between leaves a state that is
either still consistent (object present, guard 0 → trust the object) or ERROR (the
application's reset repairs it).

---

## 3. M&D kernel v2 (`firmware/src/tropic/pin_md_kernel.{c,h}`)

### 3.1 Binding record payload

`range` (0 = A, 1 = B) · `retire_pending` · `next_slot` · `pin_len` (0 if unused) ·
`tag[32]` · `ci[rounds][32]`. FIDO: 8 rounds (≈ 320 B record); OpenPGP: 3 rounds.

M&D slot ranges (128 M&D slots, 0–127 [J2d]):

| PIN | A (today) | B (new) |
|---|---|---|
| FIDO | 0–7 | 17–24 |
| PW1 | 8–10 | 25–27 |
| PW3 | 11–13 | 28–30 |
| RC | 14–16 | 31–33 |

### 3.2 API

```c
typedef enum { PMD_ABSENT, PMD_ACTIVE, PMD_BLOCKED, PMD_ERROR } pmd_state_t;

pmd_state_t pin_md_kernel_status(const pin_md_layout_t *L, uint8_t *attempts, uint8_t *pin_len);
int pin_md_kernel_setup (const pin_md_layout_t *L, const uint8_t *mat, uint8_t pin_len,
                         uint8_t out_k[32] /* nullable */);                 /* fresh s */
int pin_md_kernel_verify(const pin_md_layout_t *L, const uint8_t *mat,
                         int *out_correct, uint8_t out_k[32] /* nullable */);
int pin_md_kernel_change(const pin_md_layout_t *L, const uint8_t *old_mat,
                         const uint8_t *new_mat, uint8_t new_pin_len,
                         int *out_correct, uint8_t out_k[32] /* nullable */); /* keeps s */
int pin_md_kernel_clear (const pin_md_layout_t *L);   /* retire both ranges, erase both records */
```

`status` replaces `is_active` / `attempts_remaining`, which reported read errors as
"not set" / "full retries" (F4, F6). `out_k` is written only on success, after the
tag matched **and** the restore/commit is written; on every other path the kernel
wipes it. s, u, k_i never leave the kernel. Tag comparison stays constant-time.

### 3.3 Algorithms (crypto unchanged from `PHASE-5-M4-DESIGN.md`)

`t = HMAC(s, 0x00)`, `u = HMAC(s, 0x01)`, `k = HMAC(s, 0x02)` **[J2c]**,
`v = HMAC(0³², mat)`, `w_i = M&D(slot_i, v)` after `M&D(slot_i, u)`,
`ci_i = s ⊕ HMAC(w_i, mat)`.

**setup(mat, s)** — s fresh from the TRNG, or recovered (change):
1. settle; `cur` = current binding (or none); `R` = the range `cur` does not use (A if none).
2. For each slot of R: `M&D(u)`, `w_i = M&D(v)`, `M&D(u)`; `ci_i = s ⊕ HMAC(w_i, mat)`.
3. **Commit**: record `{R, retire_pending = (cur existed), next 0, pin_len, t, ci}`.
4. If `cur` existed: retire its range — one `M&D(slot, fresh random)` per slot, every
   result checked [J2a] — then write the record again with `retire_pending = 0`. That
   second write lands in the older slot, so the old binding's record is gone too.
5. `k` out.

A crash before 3: the old binding is untouched and still works. After 3: the new one
works; step 4 is finished by `settle`.

**verify(mat)** — range R from the record:
1. settle; ABSENT → not set; `next ≥ rounds` → blocked.
2. Commit the attempt: record with `next + 1` (before the destructive op, as today).
3. `w = M&D(slot_{R,next}, v)`; `s' = ci_next ⊕ HMAC(w, mat)`; compare `HMAC(s', 0) == t`.
4. Wrong → attempts left = `rounds − next − 1`. Right → `M&D(u')` on every slot of
   R, then record with `next 0`, then `k` out.

**change(old, new)**: verify(old) with s' kept on the stack → setup(new, s') →
wipe. Crash after the verify: the old PIN works (restored). After the setup commit:
the new PIN works. Never neither, never both after settle.

**clear**: retire both ranges, then erase the older record, then the current one.

### 3.4 settle

Runs at the start of every kernel call: if the current record has
`retire_pending = 1`, retire the other range and rewrite the record with 0 (step 4
above). Idempotent: an interrupted settle is repeated by the next call. A failed or
lost M&D reply leaves `retire_pending = 1` — never marked done on a guess, never a
blind replay of a verify (rule 5).

Why retire at all: s is kept across a change, so `u` is the same for both ranges. An
attacker who copied the old record (L3 access, the dev pairing key is public) and
knows the **old** PIN could otherwise still recover s through the old range. After
`M&D(slot, random)` the old range no longer answers the old binding; putting it back
needs `M&D(u)`, and u needs s [J2a]. This is a **logical** retirement: the PIN app
note assumes physical slot readout may be possible (Appendix B), and s/k survive in
the new binding by design.

### 3.5 Timing

M&D takes 28.2 ms per call (DS §9.3, typical) [J2d]. FIDO PIN change ≈ 1 + 8 + 24 + 8
= 41 calls ≈ 1.2 s plus ~6 R-mem pair writes; first setPin ≈ 24 calls ≈ 0.7 s; a
verify ≈ 9 calls ≈ 0.25 s. Inside every client timeout (KEEPALIVE stays BACKLOG 6.7).

---

## 4. FIDO

- **O1** keeps the bitmap, alwaysUv and the `pin_bound` guard; PIN fields leave
  slot 0 (F1). O1 is written by allocation, erase, alwaysUv, first setPin and reset —
  never by a PIN attempt.
- **O2** = kernel binding (8 rounds). PIN set = binding present (ABSENT with
  `pin_bound` = ERROR, §2.5); retries = `status().attempts`; no PIN hash (D6).
  getRetries, getPinToken, 0x09, setPin and changePin all go through
  `status/verify/setup/change`. The RAM `s_consec_fails`/`pinAuthBlocked` rule stays.
- **setPin**: only when O2 is ABSENT and `pin_bound` = 0; kernel setup (fresh s);
  then one O1 write: `pin_bound` = 1 and, on this first PIN, alwaysUv auto-enable
  (Phase 6). A crash between leaves the PIN set, guard 0 and alwaysUv off (= "the site
  decides", Vaios's current choice); the next O1 write sets the guard (O2 present,
  guard 0 → fix the guard).
- **changePin**: pinAuth check first (D10), then `kernel_change`.
- **authenticatorReset order (D8)**: erase each credential's key, then its metadata;
  O1 → bitmap 0, alwaysUv 0 (guard still 1); `kernel_clear` on O2; O1 → `pin_bound`
  0. A crash before `kernel_clear` leaves the old PIN guarding whatever is left; a
  crash after it is an ERROR that the next Reset completes. Never credentials without
  the PIN.
- **Boot (`slots_init`)**:
  - O1 VALID → orphan scrub as today (bit set, metadata missing → clear bit).
  - O1 ABSENT (a genuine first boot, an interrupted migration, or both slots
    damaged) → wipe what FIDO owns (credential keys 0–28, metadata 1–29,
    `kernel_clear` O2), then write O1. Damage costs the credentials, never the PIN
    protection.
  - O1 old layout (`NX7K` v4, full length, slot 40 empty) → destructive migration
    (D7): the same wipe, plus retire FIDO range A, then erase slot 0 → ABSENT path.
  - ERROR / CORRUPT / uncertain → FIDO refuses everything except
    authenticatorReset (the documented way out; it erases blindly and writes fresh).
  - The M3 counter rule is unchanged: the signature counter is initialised only on a
    genuine fresh store or a reset.

---

## 5. OpenPGP

- **O3** state: lifecycle, `rc_set` guard, DOs, signature counter, C4 byte 0 (spec
  meaning, default `01`), UIF, DEC key (M5 moves it). No PIN hashes, no retry
  mirrors, no PIN lengths (D5, D6). DO C4 bytes 4–6 come from `status()` of
  O4/O5/O6; a PIN in ERROR shows 0.
- **O4/O5/O6** = kernel bindings (3 rounds) for PW1, PW3, RC. RC ABSENT with
  `rc_set` = 0 is "RC not set", a valid state distinct from ERROR (§2.5).
- **VERIFY** 81/82 → PW1, 83 → PW3. Success sets the flag for **that** P2 only.
  `P1 = FF` clears the flag (§7.2.2). Empty body = status (9000 or 63CX).
- **PSO:CDS** needs PW1.81; with C4 `00` the flag is cleared after one CDS that
  passed the access check. **PSO:DEC** and **INTERNAL AUTHENTICATE** need PW1.82.
- **CHANGE REFERENCE DATA** 81/83: split the body with `pin_len` from the binding
  record, then `kernel_change` (s kept, length committed with the PIN).
- **RESET RETRY COUNTER** (RC, or PW3 verified): new PW1 binding with a **fresh s**
  (the old one is unrecoverable without the old PW1). This is the "k changed" event
  M5 hooks into (DEC key destroyed).
- **PUT DATA D3** (PW3 verified): RC set → kernel setup, then O3 `rc_set` = 1; empty
  → `kernel_clear`, then `rc_set` = 0.
- **Flags cleared** (D9): IccPowerOff/On (`usb_ccid.c:225-229`), USB reset, SELECT of
  another AID, TERMINATE, ACTIVATE, any change/reset of that PIN.
- **Bootstrap** (O3 ABSENT — never bootstrapped, an interrupted migration, or both
  slots damaged): erase keys 29–31, `kernel_clear` PW1/PW3/RC, bind PW1 = `123456`,
  PW3 = `12345678` (fresh s each), **then** write O3 OPERATIONAL. A crash before the
  O3 write repeats the whole bootstrap; the keys are gone before any PIN is factory.
- **TERMINATE (D8)**: erase keys 29/31 → scrub-write O3 TERMINATED (drops the DEC
  key, `rc_set` 0) → `kernel_clear` all three PINs. **ACTIVATE**: `kernel_clear` all
  three → bind factory PINs → write O3 OPERATIONAL. A crash leaves TERMINATED (send
  ACTIVATE again) or a complete state.
- **Old layout** (`PG7R` schema 6 in slot 33, slot 43 empty) → destructive migration:
  erase keys 29–31, retire ranges 8–16, erase 50–52, erase 33 → bootstrap.
- ERROR / CORRUPT on O3 → every command fails `6F00` except SELECT, VERIFY 83 and
  TERMINATE / ACTIVATE; a PIN in ERROR refuses VERIFY. Recovery = TERMINATE (PW3) +
  ACTIVATE, which erase blindly when the state is unreadable. Open (§10 Q5): does
  OpenPGP 3.4.1 allow TERMINATE without PW3 when PW3 is blocked?

---

## 6. Fail-closed summary

| State | FIDO | OpenPGP |
|---|---|---|
| global/state ABSENT | wipe all FIDO data, then fresh | wipe keys + PINs, then bootstrap |
| PIN ABSENT, guard says set | ERROR | ERROR |
| `retire_pending` | settle, continue | settle, continue |
| ERROR (read error) | refuse all but Reset | refuse; TERMINATE erases blindly |
| CORRUPT | same as ERROR | same as ERROR |
| uncertain write | refuse until reboot | refuse until reboot |
| old layout | destructive migration | destructive migration |

Never: init on a read error, a software PIN check, a default value for a counter that
could not be read.

---

## 7. Validation

**Host (mock chip, ASan/UBSan):**
- R-mem mock with empty / error / torn-erase / torn-write injection; a torn or
  damaged slot reads either `BAD` or `SLOT_EMPTY` (both, per [J1a, J1b]).
- M&D mock that models the chip: each call replaces the slot value with
  `F1(data ‖ slot)` and returns `F2(old, new, slot)` (PIN app note §3.2, App. A) — so
  retire and re-key behave as on silicon, and a consumed slot answers OK with a wrong
  value [J2a, J2b].
- **Power-cut sweep**: for setup, verify (right/wrong), change, clear, reset,
  terminate, activate, bootstrap and migration, cut after every chip call n, reboot
  (re-read + settle), and check the invariants:
  - I1 after a change: exactly one of old/new PIN works (never neither, never both);
  - I2 attempts never increase without a correct PIN;
  - I3 no state where keys exist under no PIN or a factory PIN;
  - I4 k unchanged by change, changed by RC/PW3 reset;
  - I5 a read error never causes init, migration or a write;
  - I6 a one-write rollback (newer slot damaged) never revives a usable attempt and
    never makes a set PIN read "not set".
- Pair selection table (§2.2) row by row; generation compare; checksum.
- OpenPGP: 81/82 separation, C4 `00`/`01`, flag clearing events, CHANGE split by
  stored length.

**Hardware (fixture PINs only):**
- First flash = the migration: FIDO and OpenPGP come up fresh; logged.
- `validate-pin-md.sh --destroy-my-pin` (FIDO lockout, then reset).
- FIDO setPin/changePin/getRetries; webauthn.io login after a change.
- OpenPGP: VERIFY 81 then CDS ✓, DEC ✗ until VERIFY 82; C4 `00` → second CDS ✗;
  card reset clears; CHANGE PW1/PW3; RC set + RESET RETRY COUNTER; PW3 reset of PW1;
  TERMINATE + ACTIVATE; `gpg --card-status` retries match.
- Optional: PIN-change loop while Vaios pulls the dongle at random; after each
  replug old or new PIN verifies (I1 on silicon). A good FOSSCOMM demo.

---

## 8. Work plan (Fri 16 Oct)

1. `rec_pair` + host tests (selection table, write/re-read, torn injection).
2. Kernel v2 + M&D mock model + power-cut sweep.
3. FIDO: O1/O2 split, pin.c on `status/verify/setup/change`, reset order, boot rules,
   migration.
4. OpenPGP: O3 + O4–O6, 81/82/C4/flags, bootstrap/terminate/activate order, migration.
5. Both builds, host tests, hardware (dongle at the end, one session), cpp-reviewer +
   Jan, STATUS/PROJECT/BACKLOG/PLAN + memory.

Not in M4: the DEC key wrap (M5), credProtect / FIDO_2_1 (BACKLOG 2.4), integrity
against a reflashed STM32 (Phase 10).

---

## 9. Chip facts (Jan, 2026-10-15)

Sources: DS A.11, API 1.4.0, PIN app note 1.2, CPU app 2.0.0 (`ts-tr01-app@61cd511`),
SDK 3.2.1 (`libtropic@51044cdc`), SPECT 1.0.0 (`ts-spect-fw@4507dd4`). Documents
only; nothing here is measured on our dongle.

- **J1a** All-or-nothing R-mem write under power loss is **not documented** (DS §7.6,
  API Tables 24–26). The CPU checks "erased", then programs one encrypted sector with
  no shadow copy (`main/ts_l3.c:234-247`, `drv/flash.c:585-614`). Design for torn or
  invalid content.
- **J1b** A completed erase is meant to read empty; a torn erase is undocumented
  (`main/ts_l3.c:274-287`). **`SLOT_EMPTY` does not prove an erased slot**: a failed
  decrypt or invalid size returns length 0 (`drv/flash.c:495-521`, `:178-190`), the
  chip answers OK (`main/ts_l3.c:250-271`) and SDK 3 maps length 0 to
  `LT_L3_R_MEM_DATA_READ_SLOT_EMPTY` (`libtropic_l3.c:847-867`).
- **J1c** 100 000 R-mem reprogram cycles, **typical** column, 10-year retention
  (DS §9.6 p61). No guaranteed minimum documented.
- **J2a** M&D replaces the slot value with `F1(input ‖ slot)`; the output depends on
  old value, new value and slot (PIN §3.2 p6, App. A pp20–21). One successful call
  with fresh random data per old slot logically retires a binding — inferred, not a
  prescribed API procedure; check every result. `M&D(u)` re-creates the initialised
  value (that is how a correct verify restores slots, PIN §3.5). App. B assumes
  physical slot readout may be possible: no absolute unrecoverability claim.
- **J2b** A consumed slot is not an error: the call returns OK and a deterministic
  output from the current and new values (`main/ts_l3.c:502-534`,
  `drv/macandd.c:48-73`).
- **J2c** `k = KDF(s, 0x02)`; with HMAC-SHA256: key s, message one byte `0x02`
  (PIN §3.4 p7 step 7, §3.5 p10 step 13). §3.4 Note: "Optionally, the master secret
  s can be provided as an input to the New PIN Setup procedure" — same s, same k. The
  note gives no crash-safe change procedure; §3 of this doc is ours.
- **J2d** 128 M&D slots, 0–127, enabled by default subject to UAP (API Table 37 p46,
  PIN §3.3, §4.2). 28.207 ms per call, typical (DS §9.3 p58). No per-second throttle
  documented.
- **J4** No official A/B R-mem recipe or prohibition. Two slots do not commit M&D,
  ECC and R-mem changes together — hence the explicit orders in §3–§5.

ES256 (for M3b, same answer): any ECC slot 0–31 holds a P-256 key (API Table 28);
the chip signs a 32-byte digest, and SDK 3 `lt_ecc_ecdsa_sign` hashes the message
with SHA-256 **on the host** (`libtropic_l3.c:1205-1245`) — pass
`authData ‖ clientDataHash`, not its digest. Output raw `r ‖ s` (64 B, API Table 32);
`ECC_Key_Read` returns curve, origin and 64-byte `x ‖ y`. Nonce: deterministic keyed
derivation inside SPECT (not RFC 6979). No P-256 erratum found; exhaustive absence
unverified.

## 10. Open for the review

- **Q5** Does OpenPGP card 3.4.1 allow TERMINATE DF without PW3 when PW3 is blocked
  (today a blocked PW3 leaves no way out but a reflash)?
- Is D10 (CTAP 2.1 changePin: a bad pinUvAuthParam does not count) right against the
  spec text?
- Anything in §2.2/§2.5 that still lets "empty" become "PIN not set" or "factory PIN
  with keys present".
