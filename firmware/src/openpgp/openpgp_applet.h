/*
 * Phase 7 M2 — OpenPGP card applet — SELECT + GET DATA (read-only).
 *
 * Per OpenPGP Card v3.4.1 spec §7.2.  M2 scope:
 *
 *   - SELECT (00 A4 04 00 ...) for the OpenPGP AID — returns SW=9000.
 *     No FCI template emitted (some cards do; gpg --card-status works
 *     fine without it).
 *
 *   - GET DATA (00 CA P1 P2) for read-only DOs:
 *       0x004F  AID (16 B raw)
 *       0x005E  Login data — returns 0x6A88 (not found) until M3
 *       0x5F50  URL — returns 0x6A88 until M3
 *       0x5F52  Historical bytes
 *       0x0065  Cardholder Related Data (composite: 5B + 5F2D + 5F35)
 *       0x006E  Application Related Data (composite: 4F + 5F52 + 73)
 *       0x007A  Security Support Template (composite: 93)
 *       0x00C0  Extended capabilities
 *       0x00C1  Algorithm attributes — sig key (Ed25519 OID)
 *       0x00C2  Algorithm attributes — dec key (Cv25519 OID)
 *       0x00C3  Algorithm attributes — aut key (Ed25519 OID)
 *       0x00C4  PW status (7 B: force_verify, max_lens, retry counters)
 *       0x00C5  Fingerprints (60 B sig||dec||aut — all-zero until M4)
 *       0x00C6  CA fingerprints (60 B — all-zero in our impl)
 *       0x00C7..C9  Individual fingerprints (20 B each)
 *       0x00CD  Generation timestamps (12 B sig||dec||aut)
 *       0x00CE..D0  Individual generation timestamps (4 B each)
 *       0x0093  Signature counter (3 B BCD)
 *       0x005B  Cardholder name
 *       0x5F2D  Language
 *       0x5F35  Sex
 *       0x00D6..D8  UIF (touch policy) — all alias the global flag
 *
 *   - Any other INS / unknown tag → SW=0x6A88 / 0x6D00 / 0x6A86 as
 *     appropriate.
 *
 * M3 adds VERIFY / CHANGE / RESET-RC + PUT DATA + TERMINATE/ACTIVATE.
 * M4 adds GENERATE + PSO:CDS.  M5 adds PSO:DEC + INT_AUT.
 */

#ifndef NIXTROPIC_OPENPGP_APPLET_H
#define NIXTROPIC_OPENPGP_APPLET_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Dispatch one ISO 7816 APDU to the OpenPGP applet.
 *
 * @param in        Pointer to APDU bytes (CLA INS P1 P2 [Lc data] [Le]).
 * @param in_len    Number of bytes pointed to by `in` (≥4).
 * @param out       Response buffer.
 * @param out_max   Capacity of `out`.
 * @param out_len   Bytes written (response_data ‖ SW1 SW2).
 * @return 0 on dispatched-OK (out_len populated with SW present in last
 *         2 B);  -1 if out_max < 2 (can't even emit SW).
 */
int openpgp_applet_dispatch(const uint8_t *in, size_t in_len,
                             uint8_t *out, size_t out_max, size_t *out_len);

#endif /* NIXTROPIC_OPENPGP_APPLET_H */
