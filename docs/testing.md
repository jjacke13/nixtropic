# Testing

Three layers, each catching what the others cannot: host tests against a simulated
chip, mutation testing of those tests, and hardware-in-the-loop runs on a real dongle
with real clients.

## Philosophy

1. **Test first.** A test is written and seen failing before the code that makes it
   pass.
2. **A test that never fails proves nothing.** Every new test is checked by planting a
   bug (a mutant) and confirming the test catches it.
3. **One fault at a time, everywhere.** Power cuts and lost replies are injected at
   every chip call of an operation; the device must end before or after the operation,
   never in between in a way that grants access or leaks a secret. Where the hardware
   makes a lockout unavoidable (an interrupted last PIN try), the test pins that down.
4. **Expected values come from outside.** Standard test vectors, an independent
   implementation (Python `cryptography`), and real clients (gpg, libfido2, browsers).
   A test that only compares the code with itself can agree with its own bug.
5. **Review before code and after.** Designs that touch the chip are reviewed against
   the vendor documentation before implementation; code is reviewed after.
6. **Hardware has the last word.** The simulator models only what is known. Real
   hardware found bugs the simulator could not show (USB timing between the host's
   `pcscd` and the device), so every milestone ends on the dongle.

## Host tests

The firmware's C code is compiled for the build machine and runs against
`tests/host/mock_tropic.c`, a simulated TROPIC01 with key slots, data slots,
MAC-and-Destroy, counters and **fault injection** (a cut before or after any call, a
lost reply, a damaged slot). AddressSanitizer and UndefinedBehaviorSanitizer are on.

```bash
nix build .#host-tests      # or: nix flake check
```

| Program | Covers |
|---|---|
| `test_cbor`, `test_ctap2_parse` | CTAP2 input validation and parsing, nesting limits, truncation |
| `test_cose` | COSE key and signature encodings, DER edge cases |
| `test_pin_token` | permission tokens: permissions, RP binding, lifetime |
| `test_fido_state`, `test_fido_pin_cmd` | FIDO state recovery, checked reset, PIN commands |
| `test_l3_result` | which chip results keep or drop the session |
| `test_trezor_rng` | TRNG failure stops the device, never returns a value |
| `test_rec_pair` | record pairs: every combination of copies, repair, uncertain writes |
| `test_pin_md_kernel` | the MAC-and-Destroy PIN binding: setup, verify, change, the last-try case, faults at every call |
| `test_openpgp_state`, `test_openpgp_applet` | OpenPGP storage and APDU behaviour, PIN rules, lifecycle, fault sweeps over generate and reset |
| `test_pgp_dec` | decryption-key seal: AES-GCM test vector, a golden record made outside the code, tamper on every field, nonce freshness, no key or PIN in any data slot |
| `test-dfu-flash.sh`, `test-lib-fixture.sh` | the flashing script's error handling, the PIN fixture loader |

## Mutation testing

For each milestone, bugs were planted by hand in the new code (a skipped check, a
wrong constant, a missing wipe) and the host tests run against each. A surviving
mutant means a missing test. In Phase 9 more than 150 mutants were planted; every one
was caught except those that change nothing by construction. A code reviewer then
planted further mutants against the tests themselves; the survivors became new tests.

## Hardware in the loop

The suites run against a real dongle. They change its state (they generate keys and
reset the applications), so they use a dedicated test dongle and the PINs in
`tools/fixture.env` (copied from `tools/fixture.env.example`, never committed).

| Command | What it does |
|---|---|
| `nix run .#validate` | FIDO2 (`validate-fido`) and OpenPGP (`validate-openpgp`) basic suites |
| `tools/validate_fido_m3.py` | 60 FIDO2 checks: tokens, RP binding, discoverable credentials, alwaysUv, credMgmt, cancel, reset at plug-in |
| `tools/validate-openpgp-m4.sh` | 42 OpenPGP APDU checks: PIN separation, C4, change, Reset Code, decryption-key lifecycle |
| `tools/validate-pin-md.sh --destroy-my-pin` | spends real PIN tries to show the chip-enforced limit |
| gpg in a throwaway `GNUPGHOME` | key generation on a fresh card, sign, decrypt, PIN change and reset |

The runs go through a shared terminal so the owner sees every prompt and presses SW1
when asked. Results per milestone are in the
[milestone log](https://github.com/jjacke13/nixtropic/blob/main/docs/history/STATUS-log.md).

## Review

Each Phase 9 milestone had:

- a design document reviewed **before** code by a reviewer checking every chip
  statement against the official TROPIC01 datasheet, API reference and application
  notes;
- a C code review after implementation, which also probed the tests' blind spots;
- a final hardware run on both builds.

## Limits

- The simulated chip encodes what the vendor documents say; it cannot prove the real
  chip's behaviour under power loss.
- No fault injection on hardware (deliberately: one dongle, irreversible risks).
- No fuzzing campaign yet; the CTAP2 parser has bounded-input tests.
- No independent audit or certification test suite.
