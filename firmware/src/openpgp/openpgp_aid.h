/*
 * Phase 7 M2 — OpenPGP card application identifier.
 *
 * AID layout per OpenPGP Card v3.4.1 §4.2.1:
 *
 *   D2 76 00 01 24 01   RID (FSFE-allocated for OpenPGP application)
 *   03 04               Version 3.4
 *   4E 58               Manufacturer "NX" — self-allocated for nixtropic
 *                       (Reserved range per spec §Appendix A; not a
 *                       conflict with the FSFE-allocated commercial
 *                       manufacturer IDs.)
 *   00 00 00 01         Serial number (placeholder; M5+ may derive from
 *                       lower 32 bits of TROPIC01 chip ID for uniqueness)
 *   00 00               RFU
 *
 * Total: 16 bytes.  Returned in response to SELECT for the OpenPGP AID
 * and in GET DATA for DO 0x4F (raw AID) + DO 0x6E child (Application
 * Related Data template).
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
