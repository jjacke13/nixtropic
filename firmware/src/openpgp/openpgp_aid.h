/*
 * OpenPGP card Application Identifier — compile-time constant.
 *
 * AID layout per OpenPGP Card v3.4.1 §4.2.1:
 *
 *   D2 76 00 01 24 01   RID (FSFE-allocated for OpenPGP application)
 *   03 04               Version 3.4
 *   4E 58               Manufacturer "NX" — self-allocated for nixtropic
 *                       (gnupg's hardcoded manufacturer table doesn't
 *                       recognise this value → "Manufacturer: unknown"
 *                       in `gpg --card-status`.  Cosmetic-only.  Phase 8
 *                       may swap to 0xFF00..0xFFFE for the spec-defined
 *                       "unmanaged S/N range" label.  See
 *                       docs/PHASE-8-BACKLOG.md §4.2.)
 *   00 00 00 01         Serial number (placeholder)
 *   00 00               RFU
 *
 * Total: 16 bytes.  Returned in response to SELECT for the OpenPGP AID
 * and in GET DATA for DO 0x4F (raw AID) + as a sub-DO of DO 0x6E
 * (Application Related Data template).
 *
 * NOTE: scdaemon parses bytes 6-7 as application version.  Values
 * < 0x0100 trigger a fallback parser path that may fail to extract
 * fields like PW status from DO 6E — see
 * phase7_m6_d_display_anomalies.md.
 */

#ifndef NIXTROPIC_OPENPGP_AID_H
#define NIXTROPIC_OPENPGP_AID_H

#include <stdint.h>
#include <stddef.h>

#define OPENPGP_AID_LEN  16u

/* The SELECT match prefix — first 6 bytes (RID).  SELECT with these
 * 6 bytes alone OR with the full 16 bytes both match (CCID readers
 * tolerate partial AID match on SELECT per ISO 7816-4 §6.3). */
#define OPENPGP_AID_PREFIX_LEN  6u

extern const uint8_t OPENPGP_AID[OPENPGP_AID_LEN];
extern const uint8_t OPENPGP_AID_PREFIX[OPENPGP_AID_PREFIX_LEN];

#endif /* NIXTROPIC_OPENPGP_AID_H */
