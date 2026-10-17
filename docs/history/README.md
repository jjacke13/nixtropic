# History

The frozen record of how nixtropic was built: phase plans, design documents with their
reviews, the milestone log and early research. Kept for the reasoning and the test
evidence; **not** a description of the current firmware, and not instructions to
follow. Each file carries a banner; known wrong statements are corrected inline where
they could mislead.

Current documentation: <https://jjacke13.github.io/nixtropic/> (source in `docs/`).

| File | Content |
|---|---|
| `PHASE-1-PLAN.md` | TROPIC01 round-trip from the STM32 (no USB) |
| `PHASE-2-PLAN.md` | USB serial ↔ SPI passthrough (removed in v0.3.0) |
| `PHASE-3-PLAN.md` | composite USB device, lt-rpc over HID |
| `PHASE-4-PLAN.md` | FIDO2 stack with a stub backend |
| `PHASE-5-PLAN.md`, `PHASE-5-M4-DESIGN.md` | FIDO2 on the chip, ClientPIN, the first MAC-and-Destroy PIN counter |
| `PHASE-6-PLAN.md` | SW1 user presence, Force-UV, credential management |
| `PHASE-7-PLAN.md` | CCID transport and the OpenPGP card applet |
| `PHASE-8-PLAN.md` | v0.2: OpenPGP PIN counters, RP compatibility |
| `PHASE-9-PLAN.md` | v0.3.0 hardening plan (the contract, guard rails, Phase 10 notes) |
| `PHASE-9-M3-WORKPLAN.md` | FIDO2 fixes, permission tokens, authenticatorConfig |
| `PHASE-9-M4-DESIGN.md` | record pairs, MAC-and-Destroy kernel v2, reviews |
| `PHASE-9-M5-DESIGN.md` | the sealed OpenPGP decryption key, reviews |
| `STATUS-log.md` | milestone log with hardware results, up to v0.3.0 |
| `PROJECT.md` | the project document up to v0.3.0 |
| `TROPIC01-primer.md` | first notes on the chip (May 2026) |
| `research/` | TROPIC01 and STM32U535 inventories, prior-art search (May 2026) |

The day-by-day log of phases 1–7, including deleted per-milestone scripts, is on the
`archive/phases-1-7` branch.
