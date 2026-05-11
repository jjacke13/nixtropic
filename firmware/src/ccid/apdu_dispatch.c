/*
 * Phase 7 M1 — ISO 7816 APDU dispatcher (echo).  See apdu_dispatch.h.
 *
 * For M1, every well-formed APDU returns SW=0x9000 with no response
 * data.  M2 grows the INS table for the OpenPGP applet.
 */

#include "apdu_dispatch.h"
#include "ccid_proto.h"

#include <string.h>

/* Helper: emit 2-byte SW into out + out_len. */
static int emit_sw(uint16_t sw, uint8_t *out, size_t out_max, size_t *out_len)
{
    if (out_max < 2u) {
        return -1;
    }
    out[0] = (uint8_t)((sw >> 8) & 0xFFu);
    out[1] = (uint8_t)( sw       & 0xFFu);
    *out_len = 2u;
    return 0;
}

int apdu_dispatch_process(const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_max, size_t *out_len)
{
    if (out == NULL || out_len == NULL) {
        return -1;
    }
    *out_len = 0;

    /* Minimum APDU is 4 bytes: CLA INS P1 P2.  Anything shorter is
     * a transport error we can't even respond to in-band. */
    if (in == NULL || in_len < 4u) {
        return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
    }
    if (in_len > APDU_MAX_LEN) {
        return emit_sw(SW_WRONG_LENGTH, out, out_max, out_len);
    }

    const uint8_t cla = in[0];
    /* const uint8_t ins = in[1]; — unused in M1 echo path */

    /* CLA: per ISO 7816-4 + OpenPGP card spec, accept 0x00 (standard)
     * and 0x10 (chaining flag set).  M1 doesn't actually implement
     * chaining — M2/M3 will when they need long PUT DATA payloads.
     * For now anything other than 0x00 is rejected so we don't
     * silently accept malformed inputs. */
    if (cla != 0x00u && cla != 0x10u) {
        return emit_sw(SW_CLA_NOT_SUPPORTED, out, out_max, out_len);
    }

    /* M1: echo SW=OK with no response data.  Unknown INS would
     * normally land here too with SW_INS_NOT_SUPPORTED, but M1's
     * scope is "transport works"; the applet dispatcher arrives
     * in M2 to recognise OpenPGP card INS codes specifically. */
    return emit_sw(SW_OK, out, out_max, out_len);
}
