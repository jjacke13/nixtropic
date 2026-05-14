# Historical design documents

These are the per-phase planning + design docs from the incremental
build of nixtropic.  They captured decisions and HW-validation
checkpoints as each surface came online:

- `PHASE-1-PLAN.md` — TROPIC01 round-trip on STM32 (no USB)
- `PHASE-2-PLAN.md` — USB CDC-ACM passthrough (stock-protocol-compatible)
- `PHASE-3-PLAN.md` — Composite USB device + lt-rpc over HID
- `PHASE-4-PLAN.md` — FIDO2 stack port (stub backend)
- `PHASE-5-PLAN.md` — Wire FIDO2 to TROPIC01 chip + ClientPIN + M&D
- `PHASE-5-M4-DESIGN.md` — MAC-and-Destroy PIN counter detailed design
- `PHASE-6-PLAN.md` — Production-grade UX (SW1 button + Force-UV + credMgmt)
- `PHASE-7-PLAN.md` — CCID transport + OpenPGP card applet

Kept for historical reference — the design rationale captured here
goes deeper than the final code comments do.  For the *current* state
of the codebase see `README.md`, `PROJECT.md`, and the firmware-source
file headers.

For the full incremental development history (including the per-
milestone validate scripts deleted from main), check out the
`archive/phases-1-7` branch.
