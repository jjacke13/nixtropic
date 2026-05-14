/*
 * ISO 7816-4 APDU dispatcher — see apdu_dispatch.h for the public
 * API + spec references.
 *
 * Hard-coded to forward to the OpenPGP applet.  AID-based routing for
 * multiple applets (e.g. PIV) lands when the second applet does — see
 * docs/BACKLOG.md §4.4.
 */

#include "apdu_dispatch.h"
#include "ccid_proto.h"
#include "openpgp/openpgp_applet.h"

#include <string.h>

int apdu_dispatch_process(const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_max, size_t *out_len)
{
    if (out == NULL || out_len == NULL) return -1;
    *out_len = 0;

    if (in == NULL || in_len < 4u || in_len > APDU_MAX_LEN) {
        if (out_max < 2u) return -1;
        out[0] = (uint8_t)((SW_WRONG_LENGTH >> 8) & 0xFFu);
        out[1] = (uint8_t)( SW_WRONG_LENGTH       & 0xFFu);
        *out_len = 2u;
        return 0;
    }

    return openpgp_applet_dispatch(in, in_len, out, out_max, out_len);
}
