# Phase 9 M4 — Design: PIN + persistent-state integrity

Status: **APPROVED** by Jan at r3 (8f3a743, 2026-10-15). r1 (09fe256) and r2 (ffb1471):
CHANGES REQUIRED both times; §11 maps every finding to its change. Contract:
`PHASE-9-PLAN.md` §6 (items 1–7) plus the M4 inputs from the M3 reviews (§5 end).
Chip facts marked **[J1a]…[J4]** come from Jan (§9), from the documents, not
measured.

Like `history/PHASE-5-M4-DESIGN.md`, this is reviewed **before** code. The work plan
is §8.

---

## 0. What is wrong today (code facts)

| # | Finding | Where |
|---|---|---|
| F1 | FIDO R-mem slot 0 is **one record for everything**: credential bitmap, PIN hash, retry counter, M&D state (tag, ci[8]), alwaysUv. Every PIN attempt rewrites it 3–4 times (retry decrement, M&D advance, M&D restore, retry reset). Each rewrite is erase-then-write (DS §7.6), not atomic. | `slots.c:163-199`, `pin.c:706,714,725`, `pin_md_kernel.c` |
| F2 | A torn rewrite **may** read as an empty slot, which is what "never written" looks like. And `SLOT_EMPTY` is also what a **damaged** slot reads as: the chip returns length 0 on a failed decrypt and the SDK reports `SLOT_EMPTY` [J1b]. `slots_init` writes fresh state on empty, read error or magic mismatch: bitmap 0, no PIN, no M&D, alwaysUv 0. So rule 7 ("init only on `SLOT_EMPTY`") is **not enough**: an empty read never proves a fresh device. | `slots.c:412-430` |
| F3 | **OpenPGP R33 has the same shape, with worse consequences.** It is rewritten on every VERIFY (retry mirror), every signature (counter) and every PUT DATA. Empty or magic mismatch → bootstrap: PW1/PW3 back to `123456`/`12345678`, M&D state wiped — but the keys in ECC slots 29 and 31 are **not** touched. A power cut at the right moment resets the PINs while the signing and authentication keys stay. | `openpgp_state.c:222-257` |
| F4 | **Software PIN fallback.** OpenPGP checks the R33 hash with a software counter whenever M&D is "inactive"; `pin_md_kernel_is_active` reports a read error as inactive. Factory PINs are never M&D-bound (only after the first change). Every M&D setup result in `pgp_pin.c` is ignored. | `pgp_pin.c:121,157,231,259,289,335`, `pin_md_kernel.c` `is_active` |
| F5 | **Setup overwrites the live binding.** The kernel re-keys the same slot range and only then writes the record; FIDO changePin writes the new hash before the M&D setup. A failure in between leaves hash and M&D disagreeing → the PIN is lost. | `pin_md_kernel.c` setup, `pin.c:592-601` |
| F6 | Two retry counters per PIN (software mirror + M&D `next_slot`) that can disagree; readers fall back to "full retries" on a read error. | `pin.c:248`, `openpgp_state.c:299` |
| F7 | Stored PIN hashes (FIDO slot 0, R33) are offline-guessable verifiers next to the M&D tag. (PLAN puts their removal in M5; see D6.) | `slots.c:181`, `openpgp_state.c:132-164` |
| F8 | OpenPGP has **one** PW1 flag for 81 and 82; DO C4 byte 0 is stored inverted (`force_verify = 0` is read back as C4 `00`, which per spec means "one signature per VERIFY") and never enforced; the PIN state is cleared only on TERMINATE/ACTIVATE, not on card reset (IccPowerOff/On) or a different SELECT. | `openpgp_applet.c:213,527,979,1056,1078` |
| F9 | M3 inputs: other `write_global` callers do not mark an uncertain write; orphan scrub clears a bit on a read error, not only on an empty metadata slot. | `slots.c:163`, `slots.c` `orphan_scrub` |

F2+F3 are the root: **any persistent object that is rewritten in place can be lost by
one power cut, and losing it looks like a fresh device.** M4 fixes that once, in one
place, and puts every PIN and state object on top of it.

---

## 1. Fault model and decisions

### 1.1 Fault model

M4 tolerates **one fault**, at any point of any operation:
- one power cut or one lost chip reply, or
- one R-mem slot that reads damaged (`BAD`, or `SLOT_EMPTY` masking damage [J1b]).

"Tolerates" means: no access is gained (no PIN reads "not set", no key ends under a
factory PIN or no PIN, no extra usable PIN attempt, no weaker policy or revived
credential), and the device ends either in the state before the operation or the one
after it — with one exception that M&D itself imposes: a fault inside a correct
verification that uses a PIN's **last remaining slot** leaves that PIN blocked (§3.3,
"Last slot"); and one that R-mem imposes: a cut **inside** an init or clear can leave
that object CORRUPT (§13), which fails closed and is recovered by the application's
reset / TERMINATE. Combinations of faults (a cut **and then** a damaged slot before the next
boot repairs it) are listed as residuals in §10; where it costs nothing, they fail
closed too. Hardware fault injection is not used (PLAN rule 9): all fault cases run
on the host mock.

### 1.2 Decisions

- **D1. Mirrored record pairs** (§2). Every persistent object M4 touches lives in two
  R-mem slots holding the **same** record (same generation) at rest. A write commits
  copy A (read back and compared), then copy B (read back and compared). Boot repairs
  a pair whose copies differ. So one damaged slot never rolls an object back: the
  other copy is the same record.
- **D2. Empty proves nothing on its own** [J1b]. An object reads ABSENT only when both
  copies read empty; a **guard** in another object must agree (§2.5). Every
  (re)initialisation starts with a **checked erase of both copies** (a masked old
  record must not come back later), and the absent path of an application wipes
  everything that application owns first. A read error fails closed — no init, no
  migration, no fallback.
- **D3. M&D kernel v2** (§3): two slot ranges per FIDO/PW1/PW3 PIN (A/B), the binding
  record says which range is live; setup writes the inactive range; commit = the
  record write; then the old range is **retired** (one checked M&D call with fresh
  random data per slot [J2a]). The kernel returns `k = HMAC-SHA256(s, 0x02)` on
  setup/verify/change.
- **D4. PIN change keeps s** inside the kernel (`pin_md_kernel_change`): s never
  leaves the kernel, so k survives a PIN change (M5 depends on it) [J2c]. Resets (RC,
  PW3 reset of PW1, FIDO reset) use a fresh s.
- **D5. The M&D record is the only PIN state**: no software path, no second counter,
  retries = `rounds − next_slot`. The PIN length (OpenPGP needs it to split CHANGE
  REFERENCE DATA) lives **in the binding record**, so it commits with the PIN.
- **D6. Stored PIN hashes are dropped in M4** (PLAN M5 item 1, moved forward): M4
  rewrites these records anyway, and with D5 nothing reads the hash. M5 shrinks to
  the DEC key wrap.
- **D7. One explicit destructive migration** from the v0.2/M3 layout (PLAN rule 8,
  §6 item 6), **global** (§2.6): while either application still shows its old
  layout, neither serves anything; the migration retires every old M&D slot, wipes
  both applications (checked), and only then do they initialise fresh. Anything
  unrecognised fails closed. Release notes say so.
- **D8. Destruction before defaults, as hard barriers.** Reset, TERMINATE, bootstrap,
  migration: keys and secret-bearing records are erased and **checked** first; any
  failure stops the sequence before a PIN is cleared or set to a factory value (rule 8).
- **D9. OpenPGP PIN semantics per spec**: separate PW1.81 / PW1.82 flags; DO C4
  byte 0 stored with spec meaning (`00` = one CDS per VERIFY, `01` = until reset),
  **default `01`** (Vaios: PIN once per plug-in); flags cleared on IccPowerOff/On,
  USB reset, SELECT of another AID, TERMINATE/ACTIVATE, PIN change/reset.
- **D10. FIDO changePin follows CTAP 2.1 §6.5.5.6** (Jan verified the step order): a
  wrong `pinUvAuthParam` returns `PIN_AUTH_INVALID` before any decrement or M&D call.
  The 2026-05 audit (H1) counted it first to deny a "probe oracle", but the MAC check
  reveals nothing about the PIN. Token revocation, key-agreement regeneration on a
  mismatch and the RAM `pinAuthBlocked` throttle stay.
- **D11. ACTIVATE only from a cleanly read TERMINATED state.** Unknown or unreadable
  OpenPGP state recovers through TERMINATE, which OpenPGP 3.4.1 §7.2.16 allows without
  PW3 when PW3 is blocked or inaccessible (Q5, verified by Jan), and which destroys
  first (D8).

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

Each copy classifies as `VALID(gen, payload)`, `EMPTY` (`SLOT_EMPTY`), `BAD` (read
OK, header, length, object id or checksum wrong) or `ERR` (chip error after the M2
session policy).

| copy A | copy B | result | single-fault cause |
|---|---|---|---|
| VALID(g) | VALID(g), same payload | **OK** | normal |
| ERR | any | **ERROR** | — |
| VALID(g) | VALID(g), different payload | **ERROR** | none (a bug) |
| VALID(g+1) | VALID(g) | the newer; repair B | cut after A was committed |
| VALID | EMPTY / BAD | that copy; repair | cut inside a write, or one damaged copy |
| EMPTY | EMPTY | **ABSENT** → guards, §2.5 | never written, or cleared |
| BAD | EMPTY / BAD | **CORRUPT** | a cut inside the first write of an init, or inside the last erase of an init/clear (§13) |

(and symmetric). Under one fault the result is never older than the last
acknowledged write: a write is acknowledged only after **both** copies hold it, so a
single damaged copy leaves the other with the same record, and a cut inside a write
leaves either the old record (not acknowledged) or the new one in A (rolled forward).

**Repair** runs at init for every object, before it serves anything: the winning
record is written into the other copy (same generation). A failed repair makes the
object uncertain (§2.3).

### 2.3 Writing a pair

```
write(obj, payload):
  cur = read_pair(obj)                    # must be OK (after repair), else refuse
  if cur.gen == UINT32_MAX: refuse         # object read-only, ERROR
  for copy in (A, B):
      erase(copy); write(copy, gen + 1, payload)
      if read(copy) != (gen + 1, payload): object uncertain → refuse until reboot
  acknowledge
```

**Commit proof = read-back.** A write is committed only when the copy reads back with
exactly the new generation and payload [J1a]. Anything else (write error, `EMPTY`,
`BAD`, mismatch) leaves the object **uncertain**: it refuses every operation until
the next boot, where §2.2 decides from what the chip then returns — the old record
(the operation was never acknowledged) or the new one (rolled forward). Never a guess
in the running session (generalises the M3 `s_store_uncertain` flag, F9).

**Init** (first write of an object, or re-initialisation): checked erase of both
copies, then the write above with generation 1. Erase failure = stop.

**Clear**: checked erase of B, then of A. A cut between leaves one valid copy; the
next boot repairs it back, so a clear that was not acknowledged has not happened.

Cost: 2 erases + 2 writes + 2 reads per write (today 1 + 1). Endurance is 100 000
reprogram cycles per slot, typical, 10-year retention (DS §9.6) [J1c]; no guaranteed
minimum is documented. A PIN verify is 2 writes (attempt + restore) → every slot of
that pair is written twice per attempt ≈ 50 k attempts per PIN, typical. Today FIDO
rewrites slot 0 four times per attempt.

### 2.4 Objects and R-mem slots

| Obj | What | Copies (A / B) | Written by |
|---|---|---|---|
| O1 | FIDO global: bitmap, alwaysUv, `pin_bound` | 0 / 40 | alloc, erase, alwaysUv, first setPin, reset |
| O2 | FIDO PIN binding | 41 / 42 | setPin, changePin, every PIN attempt, reset |
| O3 | OpenPGP state: lifecycle, `rc_set`, DOs, sig counter, C4, UIF, DEC key (until M5) | 33 / 43 | PUT DATA, CDS counter, generate, terminate, activate (no longer VERIFY) |
| O4 | OpenPGP PW1 binding | 50 / 53 | VERIFY 81/82, CHANGE, RESET RETRY COUNTER |
| O5 | OpenPGP PW3 binding | 51 / 54 | VERIFY 83, CHANGE |
| O6 | OpenPGP RC binding | 52 / 55 | PUT DATA D3, RESET RETRY COUNTER (RC) |

Credential metadata (R-mem 1–29) stays one slot per credential: written once at
creation, erased at deletion, never rewritten in place. The M3 bitmap commit rules
stay.

O3 carries the DEC private key (until M5). Both copies hold it, and every path that
drops it (TERMINATE, key replacement, bootstrap, migration) **erases both copies,
checked**, before writing the new state (D8).

### 2.5 Guards: when "absent" is believed

Both copies empty needs two faults (or never written), but an empty read can be
damage [J1b], so a pair that reads ABSENT is cross-checked:

| Pair reads ABSENT | Guard | Guard says present → | Guard says absent → |
|---|---|---|---|
| O2 FIDO PIN | O1 `pin_bound` | **ERROR** (never "PIN not set") | PIN not set |
| O4 PW1 / O5 PW3 | O3 lifecycle OPERATIONAL | **ERROR** | (TERMINATED: expected) |
| O6 RC | O3 `rc_set` | **ERROR** | RC not set |
| O1 FIDO global | none | — | checked wipe of all FIDO data, then fresh |
| O3 OpenPGP state | none | — | checked wipe (keys, DEC, PINs), then bootstrap |

A guard is set **after** its object is committed in both copies and cleared **after**
the object is cleared. A cut between leaves "object present, guard 0", which boot
repairs (sets the guard), or "object absent, guard 1" = ERROR, which the
application's reset/TERMINATE recovers. Residual: §10 R1.

### 2.6 Migration from the v0.2/M3 layout (global barrier)

The new M&D layout reuses slots of the old one (new FIDO B 8–15 and PW1 A 16–18 lie in
the old OpenPGP ranges 8–16), and M&D slots belong to no application on the chip (PIN
§3.2, API Table 37). So the migration is one routine for the whole device, run at
boot before either application serves:

- **Old-layout markers**: FIDO R-mem slot 0 = `NX7K` v4 (full length) with slot 40
  empty; OpenPGP slot 33 = `PG7R` schema 6 with slot 43 empty.
- While **either** marker is present, FIDO and OpenPGP refuse every command (except
  GetInfo / SELECT), and the routine (re)runs from step 1:
  1. retire M&D slots 0–16 (checked; nothing of the new layout exists yet);
  2. FIDO checked wipe (keys 0–28, metadata 1–29), then checked erase of slot 0;
  3. `pgp_wipe` plus checked erase of 50–52, then checked erase of slot 33.
- Any failure stops; the next boot repeats from step 1, which is safe because no
  new-layout binding can exist while a marker remains.
- With both markers gone, both applications find their objects ABSENT and initialise
  fresh (§4, §5).

---

## 3. M&D kernel v2 (`firmware/src/tropic/pin_md_kernel.{c,h}`)

### 3.1 Binding record payload

`range` (0 = A, 1 = B) · `retire_pending` · `next_slot` · `pin_len` (0 if unused) ·
`tag[32]` · `ci[rounds][32]`. FIDO: 8 rounds (≈ 320 B record); OpenPGP: 3 rounds.

M&D slot layout, all inside slots 0–31 so no second UAP group is touched (Jan; the
128 slots are 0–127 [J2d]). The destructive migration (D7) retires the old ranges
first, so the layout is free:

| PIN | A | B |
|---|---|---|
| FIDO | 0–7 | 8–15 |
| PW1 | 16–18 | 19–21 |
| PW3 | 22–24 | 25–27 |
| RC | 28–30 | — (single range, §3.3) |

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
int pin_md_kernel_clear (const pin_md_layout_t *L);   /* retire ranges, then clear the pair */
```

`status` replaces `is_active` / `attempts_remaining`, which reported read errors as
"not set" / "full retries" (F4, F6). `out_k` is written only on success, after the
tag matched **and** the restore/commit is acknowledged; on every other path the
kernel wipes it. s, u, k_i never leave the kernel. Tag comparison stays
constant-time.

### 3.3 Algorithms (crypto unchanged from `PHASE-5-M4-DESIGN.md`)

`t = HMAC(s, 0x00)`, `u = HMAC(s, 0x01)`, `k = HMAC(s, 0x02)` [J2c],
`v = HMAC(0³², mat)`, `w_i = M&D(slot_i, v)` after `M&D(slot_i, u)`,
`ci_i = s ⊕ HMAC(w_i, mat)`.

**setup(mat, s)** — s fresh from the TRNG, or recovered (change):
1. settle; `cur` = current binding (or none); `R` = the range `cur` does not use (A if none).
2. For each slot of R: `M&D(u)`, `w_i = M&D(v)`, `M&D(u)`; `ci_i = s ⊕ HMAC(w_i, mat)`.
3. **Commit** (both copies): `{R, retire_pending = (cur existed), next 0, pin_len, t, ci}`.
4. If `cur` existed: retire its range — `M&D(slot, fresh random)` per slot, every
   result checked [J2a] — then write the record again (both copies) with
   `retire_pending = 0`.
5. `k` out.

Before 3 the old binding is untouched and works; after 3 the new one works and
`settle` finishes 4. The old range is retired only after the new record is in **both**
copies, so no single fault leaves neither PIN usable.

RC has one range: RC is set and cleared only by PW3 (admin) and its s/k are unused,
so `setup` re-keys the same range: clear first (retire, clear pair, `rc_set` 0),
then setup, then `rc_set` 1. A fault in between leaves RC not set or ERROR; the admin
sets it again.

**verify(mat)** — range R from the record:
1. settle; ABSENT → (guards) not set; `next ≥ rounds` → blocked.
2. Reserve the attempt: record with `next + 1` (both copies) **before** the M&D call.
3. `w = M&D(slot_{R,next}, v)`; `s' = ci_next ⊕ HMAC(w, mat)`; compare `HMAC(s', 0) == t`.
4. Wrong → attempts left = `rounds − next − 1`. Right → `M&D(u')` on every slot of
   R, then record with `next 0` (both copies), then `k` out.

**Attempt bound.** A usable guess needs an intact slot. A slot stops being intact
when an M&D call with a wrong `v` runs on it; only a correct PIN (which yields s,
hence u) re-keys slots. So the number of wrong guesses that can be *evaluated* is at
most the number of intact slots, whatever the record says. A reservation lost to a
fault is either a slot that was then consumed (any verify through it fails) or one
that was never used (that attempt never happened).

**Last slot.** With `next = rounds − 1`, step 2 commits `next = rounds`. A cut or a
lost reply anywhere between that commit and the `next 0` record leaves the PIN
BLOCKED: before the M&D call the slot is intact but the record is spent; after a
correct PIN's M&D call and before the re-key every slot is consumed and s existed
only in RAM, so no copy of any record can bring it back (PIN §3.5 steps 3–12); after
the re-key the slots are fine but the record still says blocked. Conservative in
every case. The PIN recovers the documented way: FIDO
authenticatorReset, OpenPGP RESET RETRY COUNTER (RC or PW3) for PW1, TERMINATE without
PW3 for PW3 (§7.2.16). Fail-closed, no extra guess, and inherent to M&D; the same holds
for the verify inside a change. With more than one slot left, the same fault only
counts the attempt: the next correct PIN goes through an intact slot and restores all.

**change(old, new)**: verify(old) with s' kept on the stack → setup(new, s') →
wipe. A fault after the verify leaves the old PIN working (restored); after the
setup commit, the new PIN (except the last-slot case above).

**clear**: retire every range of the PIN (checked; a failure stops), then clear the
pair (§2.3).

### 3.4 settle

Runs at the start of every kernel call: if the record has `retire_pending = 1`,
retire the other range and rewrite the record with 0. Idempotent; a failed or lost
M&D reply leaves `retire_pending = 1` — never marked done on a guess. Repeating
retirement of an identified obsolete range is safe; it is never a replay of a
verify (rule 5).

Why retire at all: s is kept across a change, so `u` is the same for both ranges. An
attacker who copied the old record (L3 access, the dev pairing key is public) and
knows the **old** PIN could otherwise recover s through the old range. After
`M&D(slot, random)` the old range no longer answers the old binding; putting it back
needs `M&D(u)`, and u needs s [J2a]. This is a **logical** retirement: the PIN app
note assumes physical slot readout may be possible (Appendix B), and s/k survive in
the new binding by design.

### 3.5 Timing

M&D takes 28.2 ms per call (DS §9.3, typical) [J2d]. FIDO PIN change ≈ 1 + 8 + 24 + 8
= 41 calls ≈ 1.2 s plus ~4 pair writes; first setPin ≈ 24 calls ≈ 0.7 s; a verify
≈ 9 calls ≈ 0.25 s plus 2 pair writes. Expected to stay inside client timeouts;
measured on hardware in the M4 validation (KEEPALIVE stays BACKLOG 6.7).

---

## 4. FIDO

- **O1** keeps the bitmap, alwaysUv and the `pin_bound` guard; PIN fields leave
  slot 0 (F1). O1 is written by allocation, erase, alwaysUv, first setPin and reset —
  never by a PIN attempt.
- **O2** = kernel binding (8 rounds). PIN set = binding present (ABSENT with
  `pin_bound` = ERROR, §2.5); retries = `status().attempts`; no PIN hash (D6).
  getRetries, getPinToken, 0x09, setPin and changePin go through
  `status/verify/setup/change`. The RAM `s_consec_fails`/`pinAuthBlocked` rule stays.
- **setPin**: only when O2 is ABSENT and `pin_bound` = 0; kernel setup (fresh s);
  then one O1 write: `pin_bound` = 1 and, on this first PIN, alwaysUv auto-enable
  (Phase 6). A fault between leaves the PIN set, guard 0, alwaysUv off (= "the site
  decides", Vaios's current choice); boot sets the guard.
- **changePin**: pinAuth check first (D10), then `kernel_change`.
- **authenticatorReset** (D8, hard barriers in this order): erase each credential's
  key (checked), then its metadata; O1 → bitmap 0, alwaysUv 0 (guard still 1);
  `kernel_clear` on O2; O1 → `pin_bound` 0. A stop before `kernel_clear` leaves the
  old PIN guarding whatever is left; a stop after it is an ERROR that the next Reset
  completes. Never credentials without the PIN.
- **Boot (`slots_init`)**:
  - repair every pair (§2.2);
  - O1 OK → orphan scrub: a bit is cleared only when its metadata slot reads
    `SLOT_EMPTY` (an unlisted credential is the safe side; its key is erased before
    the slot is reused, M3); a read error keeps the bit and lookups of that slot fail;
  - O1 ABSENT (first boot, an interrupted migration or reset, or both copies damaged)
    → checked wipe of what FIDO owns (keys 0–28, metadata 1–29, `kernel_clear` O2),
    then init O1. Only a completed checked wipe authorises initialising the signature
    counter (replaces the M3 `slots_take_fresh_store` EMPTY inference);
  - an old-layout marker of either application → the global migration (§2.6) runs
    first; FIDO serves nothing until both markers are gone;
  - ERROR / CORRUPT / uncertain → FIDO refuses everything except
    authenticatorReset (the documented way out; it erases blindly and inits).

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
- **PUT DATA D3** (PW3 verified): RC set/clear as in §3.3.
- **Flags cleared** (D9): IccPowerOff/On (`usb_ccid.c:225-229`), USB reset, SELECT of
  another AID, TERMINATE, ACTIVATE, any change/reset of that PIN.

**Lifecycle (D8, D11).** One routine, `pgp_wipe`, with hard barriers in this order:
erase ECC 29, 30, 31 (checked) → checked erase of both O3 copies (the DEC key is in
them) → `kernel_clear` PW1, PW3, RC. Any failure stops it.

| Event | Sequence | A fault leaves |
|---|---|---|
| Bootstrap (O3 ABSENT) | `pgp_wipe` → bind PW1 `123456`, PW3 `12345678` (fresh s) → init O3 OPERATIONAL | ABSENT → bootstrap again |
| TERMINATE (PW3 verified; or without PW3 when PW3 is blocked or the state is unreadable, §7.2.16) | `pgp_wipe` → init O3 TERMINATED | ABSENT → bootstrap, or TERMINATED |
| ACTIVATE (only when O3 reads OK and TERMINATED) | bind factory PINs → write O3 OPERATIONAL | TERMINATED (send ACTIVATE again) |
| Old layout of either application | global migration (§2.6) → bootstrap | migration repeats from step 1 |
| O3 ERROR / CORRUPT | refuse all but SELECT, VERIFY 83, TERMINATE | — |

Bootstrap and ACTIVATE bind factory PINs only after `pgp_wipe` has completed with
every erase checked; in ACTIVATE that happened in the TERMINATE that produced the
TERMINATED state, which O3 read cleanly.

---

## 6. Fail-closed summary

| State | FIDO | OpenPGP |
|---|---|---|
| copies differ | repair at boot, continue | repair at boot, continue |
| global/state ABSENT | checked wipe, then fresh | `pgp_wipe`, then bootstrap |
| PIN ABSENT, guard says set | ERROR | ERROR |
| `retire_pending` | settle, continue | settle, continue |
| ERROR (read error) / CORRUPT | refuse all but Reset | refuse; TERMINATE without PW3 recovers |
| uncertain write | refuse until reboot | refuse until reboot |
| old layout (either app) | both refuse; global migration (§2.6) | both refuse; global migration |
| last-slot fault (§3.3) | PIN BLOCKED → Reset | PIN BLOCKED → RC/PW3 reset, TERMINATE |
| any wipe step fails | stop, report, retry next time | stop, report, retry next time |

Never: init on a read error, a software PIN check, a default value for a counter
that could not be read, factory PINs before a checked wipe.

---

## 7. Validation

**Host (mock chip, ASan/UBSan):**
- R-mem mock with empty / error / torn-erase / torn-write / damaged-at-rest
  injection; a torn or damaged slot reads `BAD` or `SLOT_EMPTY` (both, [J1a, J1b]);
  a lost reply after a completed write.
- M&D mock that models the chip: each call replaces the slot value with
  `F1(data ‖ slot)` and returns `F2(old, new, slot)` (PIN app note §3.2, App. A), so
  retirement and re-keying behave as on silicon and a consumed slot answers OK with a
  wrong value [J2a, J2b].
- **Single-fault sweep**: for setup, verify (right/wrong), change, clear, FIDO reset,
  bootstrap, TERMINATE, ACTIVATE and migration, inject one fault at every chip call n
  (cut / lost reply / error), or damage one copy of one object at rest; reboot
  (repair + settle) and check:
  - I1 after a change: the old or the new PIN works, never both after settle — except
    the last-slot case (§3.3), where the PIN reads BLOCKED and its documented reset
    works;
  - I2 evaluated wrong guesses never exceed `rounds` without a correct PIN;
  - I3 no state with keys or a DEC key present under no PIN or a factory PIN;
  - I4 k unchanged by change, changed by RC/PW3 reset;
  - I5 a read error never causes init, migration or a write;
  - I6 no object reads older than its last acknowledged write; no guard, policy
    (alwaysUv, C4, UIF) or bitmap rolls back.
- A correct verification on the last remaining slot, and a fault at every restore
  boundary (before, between and after the re-key calls and the two record copies).
- Migration: a fault at every step of §2.6, with an attempted FIDO setPin and an
  OpenPGP VERIFY between boots — both refused until the migration completes; no
  new-layout binding is ever retired by a repeated step 1.
- Selected double faults from §10 (cut, then damage before repair) to show which
  fail closed.
- Pair rules (§2.2) row by row; generation compare and `UINT32_MAX`; checksum.
- OpenPGP: 81/82 separation, C4 `00`/`01`, flag clearing events, CHANGE split by
  stored length, ACTIVATE refused unless TERMINATED.

**Hardware (fixture PINs only; no fault injection):**
- First flash = the migration: FIDO and OpenPGP come up fresh; logged.
- `validate-pin-md.sh --destroy-my-pin` (FIDO lockout, then reset).
- FIDO setPin/changePin/getRetries; webauthn.io login after a change; timing of
  setPin / changePin / verify.
- OpenPGP: VERIFY 81 then CDS ✓, DEC ✗ until VERIFY 82; C4 `00` → second CDS ✗;
  card reset clears; CHANGE PW1/PW3; RC set + RESET RETRY COUNTER; PW3 reset of PW1;
  TERMINATE + ACTIVATE; ACTIVATE on an operational card is a no-op; `gpg
  --card-status` retries match.

---

## 8. Work plan (Fri 16 Oct)

1. `rec_pair` + host tests (rules table, read-back commit, repair, torn/damage injection).
2. Kernel v2 + M&D mock model + single-fault sweep.
3. FIDO: O1/O2 split, pin.c on `status/verify/setup/change`, reset order, boot rules,
   orphan scrub fix, counter authorisation, migration.
4. OpenPGP: O3 + O4–O6, 81/82/C4/flags, `pgp_wipe` + lifecycle table, migration.
5. Both builds, host tests, hardware (dongle at the end, one session), cpp-reviewer +
   Jan, STATUS/PROJECT/BACKLOG/PLAN + memory.

Not in M4: the DEC key wrap (M5), credProtect / FIDO_2_1 (BACKLOG 2.4), integrity
against a reflashed STM32 (Phase 10), moving the OpenPGP signature counter to a chip
monotonic counter (would remove one O3 write per signature; backlog).

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
  `LT_L3_R_MEM_DATA_READ_SLOT_EMPTY` (`libtropic_l3.c:847-867`). Not every masked
  failure is promised to be permanent.
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
  PIN §3.3, §4.2). 28.207 ms per call, typical (DS §9.3 p58) — not a worst-case
  bound. No per-second throttle documented.
- **J4** No official A/B R-mem recipe or prohibition. Two slots do not commit M&D,
  ECC and R-mem changes together — hence the explicit orders in §3–§5.

ES256 (M3b, same answer): any ECC slot 0–31 holds a P-256 key (API Table 28); the
chip signs a 32-byte digest, and SDK 3 `lt_ecc_ecdsa_sign` hashes the message with
SHA-256 **on the host** (`libtropic_l3.c:1205-1245`) — pass `authData ‖
clientDataHash`, not its digest. Output raw `r ‖ s` (64 B, API Table 32);
`ECC_Key_Read` returns curve, origin and 64-byte `x ‖ y`. Nonce: deterministic keyed
derivation inside SPECT (not RFC 6979). No P-256 erratum found; exhaustive absence
unverified.

---

## 10. Residuals (outside the one-fault model)

- **R1** Cut during the first FIDO setPin after copy A of O2 and before the guard,
  **then** copy A damaged before the next boot repairs it: O2 ABSENT, guard 0 → "PIN
  not set" with credentials present. Same shape for RC (`rc_set`). Closing it would
  need the guard written first, which turns a single cut into an ERROR that only a
  reset clears. Accepted: needs a cut inside a ~30 ms window of a one-time operation
  plus a damaged slot.
- **R2** Cut inside any write, then the newer copy damaged before repair: that object
  is one write older. For a PIN record this cannot add usable attempts (§3.3 bound);
  for O1/O3 it can undo one acknowledged-but-unrepaired change (the cut prevented
  acknowledgement, so the host saw an error).
- **R3** A reflashed STM32 with the public dev pairing key can read and write R-mem:
  records, guards and checksums do not stop it (Phase 10).

---

## 11. Review r1 → r2 (Jan, 2026-10-15, CHANGES REQUIRED)

| # | Finding | Change |
|---|---|---|
| 1 HIGH | ACTIVATE from unknown state binds factory PINs over surviving keys | D11; ACTIVATE only from a cleanly read TERMINATED; unknown state → TERMINATE without PW3 (§7.2.16) → `pgp_wipe` first (§5) |
| 2 HIGH | Generic fallback to the older record weakens policy / revives revoked credentials | D1 mirrored pairs: both copies equal at rest, acknowledge after both; no single fault rolls back (§2.2); I6 |
| 3 HIGH | Guard and binding-transition windows; reservation lost before M&D | guards set after both copies; retirement only after the new binding is in both copies; attempt bound restated (§3.3); fault model stated (§1.1), cut+damage = R1/R2 |
| 4 HIGH | Bootstrap must scrub the DEC key in both O3 copies before factory PINs | `pgp_wipe` erases both O3 copies, checked, before any factory binding; init always starts with a checked erase of both copies (D2) |
| 5 MED | EMPTY/BAD after a failed write is not proof of no commit; generation wrap | commit = exact read-back; otherwise uncertain until reboot (§2.3); `UINT32_MAX` refused |
| 6 MED | Random dongle pulls = hardware fault injection (rule 9) | removed; all faults on the host mock |
| Q5 | TERMINATE without PW3 when blocked? | yes (§7.2.16), used in D11 |
| D10 | changePin order | confirmed |
| other | M&D 32/33 cross a UAP group; orphan scrub on read errors; counter init by EMPTY; F2 wording; timing claim | layout inside 0–31 (§3.1); scrub fix and counter authorised by a checked wipe (§4); F2 "may"; timing "measured" (§3.5) |

## 12. Review r2 → r3 (Jan, 2026-10-15, CHANGES REQUIRED; r1 findings resolved)

| # | Finding | Change |
|---|---|---|
| 1 MED | A fault inside a correct verification on the last slot leaves neither PIN usable | inherent to M&D (s only in RAM, every slot consumed): stated as the one exception in §1.1, "Last slot" in §3.3, I1 qualified, §6 row, host tests at every restore boundary |
| 2 MED | Overlapping old/new M&D ranges need a global migration barrier | §2.6: one device-wide migration; while either old marker exists both applications refuse and the routine reruns from step 1; §4/§5/§6 point to it; migration fault tests |
| ES256 | J3 facts vs 8b43157 | no contradiction (Jan) |

r3: **APPROVE** (Jan). Nonblocking wording fix folded in: the last-slot lockout also
follows a fault before the M&D call or after the re-key (§3.3).

## 13. Implementation notes (step 1, `rec_pair`, 2026-10-16)

- **Interrupted init/clear → CORRUPT (Jan: keep, 2026-10-16).** An init or clear erases
  B, then A; an init then writes A first. A cut **inside** the erase of A, inside the
  first write of A, or inside an erase of an already-empty copy can leave one copy
  `BAD` and the other `EMPTY` = CORRUPT: neither the state before nor after. It fails
  closed (no access gained; FIDO refuses all but Reset, OpenPGP recovers by TERMINATE),
  so it is the second availability exception in §1.1. It stays CORRUPT, not ABSENT: a
  malformed record is evidence and must not be discarded. Init is destructive, not an
  atomic replacement: a cut after both erases leaves ABSENT.
- **Checked erase proves "reads empty", not physical erasure** [J1b]: erase OK, then a
  read answers `SLOT_EMPTY` (or length 0). A slot that is masked after an erase that
  answered OK passes, and if it ever decrypted again the cleared record would come
  back (one copy, older generation; outside the one-fault model). An erase error or
  lost reply is never turned into success by a later empty read. The sweep injects
  this case (`F_SILENT_MASK`) to keep the limit visible.
- Reads can write: a read whose copies differ repairs one. Callers keep one request at
  a time, and the legacy-layout check (§2.6) runs **before** any pair read.
- A record with generation 0 reads `BAD` (generations start at 1). Two valid copies
  whose generations differ by more than 1 read **ERROR**: no single fault explains a gap.
- Reviews: cpp-reviewer CHANGES REQUIRED on test strength only (raw state checked right
  after an acknowledged action; CORRUPT allowed only inside the window above; a failed
  write must leave the pair uncertain; silent-mask fault added) → fixed; Jan APPROVE.

**Step 2 (kernel v2, 2026-10-16):**
- `setup` returns OK once the record is committed (the new PIN is live); a failed
  retirement after that stays `retire_pending` and the next call's settle finishes it.
- `status` settles too, so it can write; `clear` does not settle and needs no readable
  record (retire every range, then clear the pair), so it also recovers a damaged one.
- A record whose fields are out of range (range, `retire_pending`, `next_slot`, length)
  is ERROR, never a binding. A one-range layout (RC) refuses `setup` unless ABSENT.
- Kernel v1 lives on as `pin_md_legacy` until FIDO (step 3) and OpenPGP (step 4) move.
- The host M&D mock now models §7: slot ← `F1(data ‖ slot)`, answer `F2(old, new, slot)`.
