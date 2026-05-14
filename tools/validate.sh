#!/usr/bin/env bash
# Full nixtropic validation — runs FIDO2 + OpenPGP card surface checks.
#
# Two sub-suites, both non-interactive (no SW1 press needed):
#   1. validate-fido.sh     — FIDO2 surface via fido2-token CLI
#   2. validate-openpgp.sh  — OpenPGP card surface via opensc-tool + gpg
#
# For interactive deep checks (real touch consent, register/authenticate
# round-trips), use `tools/fido2_test.py` or webauthn.io in a browser.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "═══════════════════════════════════════════════════════════════"
echo "  nixtropic — full validation (FIDO2 + OpenPGP card)"
echo "═══════════════════════════════════════════════════════════════"

overall_rc=0

echo ""
echo "─── Sub-suite 1/2: FIDO2 surface ───"
bash "$SCRIPT_DIR/validate-fido.sh" || overall_rc=$?

echo ""
echo "─── Sub-suite 2/2: OpenPGP card surface ───"
bash "$SCRIPT_DIR/validate-openpgp.sh" || overall_rc=$?

echo ""
echo "═══════════════════════════════════════════════════════════════"
if [ $overall_rc -eq 0 ]; then
  echo "  ✓ FULL VALIDATION PASS"
else
  echo "  ✗ FULL VALIDATION FAIL  (rc=$overall_rc)"
fi
echo "═══════════════════════════════════════════════════════════════"
exit $overall_rc
