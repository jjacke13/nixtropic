# shellcheck shell=bash
# Sourced by the validate scripts.  Loads the PIN fixture (see
# tools/fixture.env.example) and provides APDU encodings of the PINs.

fixture_load() {
  local f="${NIXTROPIC_FIXTURE:-$PWD/tools/fixture.env}"
  if [ ! -f "$f" ]; then
    echo "✗ No test fixture at $f" >&2
    echo "  The scripts never guess a PIN.  Tell them the card's PINs:" >&2
    echo "    cp tools/fixture.env.example tools/fixture.env   # then edit" >&2
    exit 2
  fi
  # shellcheck source=/dev/null
  . "$f"
  fixture_check_pin NIXTROPIC_PW1 6
  fixture_check_pin NIXTROPIC_PW3 8
  if [ -n "${NIXTROPIC_PW1_MD_TEST:-}" ]; then
    fixture_check_pin NIXTROPIC_PW1_MD_TEST 6
    if [ "$NIXTROPIC_PW1_MD_TEST" = "$NIXTROPIC_PW1" ]; then
      echo "✗ fixture: NIXTROPIC_PW1_MD_TEST must differ from NIXTROPIC_PW1" >&2
      exit 2
    fi
  fi
}

# fixture_check_pin <var name> <min length>: printable ASCII, min..127 bytes.
fixture_check_pin() {
  local name="$1" min="$2" val
  val="${!1:-}"
  if [ -z "$val" ]; then
    echo "✗ fixture: $name is not set" >&2; exit 2
  fi
  if ! LC_ALL=C grep -qE '^[[:print:]]+$' <<<"$val" \
     || [ "$(LC_ALL=C; echo "${#val}")" -lt "$min" ] \
     || [ "$(LC_ALL=C; echo "${#val}")" -gt 127 ]; then
    echo "✗ fixture: $name must be $min..127 printable ASCII characters" >&2
    exit 2
  fi
}

# pin_hex <pin> [sep]: "123" → "31:32:33" (sep defaults to ':').
pin_hex() {
  printf '%s' "$1" | od -An -v -tx1 | tr -s ' \n' ' ' \
    | sed -e 's/^ //' -e 's/ $//' -e "s/ /${2:-:}/g"
}

# pin_lc <pin>: APDU Lc byte for the PIN, two hex digits.
pin_lc() { printf '%02X' "$(LC_ALL=C; printf '%s' "$1" | wc -c)"; }
