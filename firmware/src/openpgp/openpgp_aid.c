/*
 * OpenPGP card AID constant definition.  See openpgp_aid.h for the
 * byte-by-byte breakdown + manufacturer-ID notes.
 */

#include "openpgp_aid.h"

const uint8_t OPENPGP_AID[OPENPGP_AID_LEN] = {
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,   /* RID (OpenPGP) */
    0x03, 0x04,                            /* v3.4 */
    0x4E, 0x58,                            /* Manufacturer "NX" */
    0x00, 0x00, 0x00, 0x01,                /* Serial number */
    0x00, 0x00                             /* RFU */
};

const uint8_t OPENPGP_AID_PREFIX[OPENPGP_AID_PREFIX_LEN] = {
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01
};
