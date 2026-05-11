/*
 * Phase 7 M1 — ISO 7816 APDU dispatcher (minimal echo).
 *
 * M1 scope: receive APDU bytes, parse CLA/INS/P1/P2/Lc/Le with bounds
 * checks, return SW = 0x9000 (OK) with no response data.  Unknown
 * CLA → 0x6E00.  No actual command handling — that's M2 (OpenPGP
 * applet SELECT + GET DATA).
 *
 * The dispatcher takes a flat APDU byte string (header + body) and
 * writes a response byte string (data + SW1 SW2) to the caller's
 * buffer.  Sizes are sanity-checked; extended-length APDUs supported
 * up to 4096 B body.
 */

#ifndef NIXTROPIC_CCID_APDU_DISPATCH_H
#define NIXTROPIC_CCID_APDU_DISPATCH_H

#include <stdint.h>
#include <stddef.h>

#define APDU_MAX_LEN  4106u   /* 4096 body + 4 header (case 4 extended) + 2 SW */

/**
 * @brief Dispatch a single APDU.
 *
 * @param in        Pointer to APDU bytes (CLA INS P1 P2 [Lc data Le]).
 * @param in_len    Number of bytes pointed to by `in` (4..4106).
 * @param out       Caller's response buffer.
 * @param out_max   Capacity of `out`.
 * @param out_len   Set to bytes written (response_data || SW1 || SW2).
 * @return 0 on dispatched-OK (out_len populated, SW present in last 2 B);
 *         -1 if the input was malformed beyond what we can put in SW
 *            (e.g., out_max < 2).
 *
 * Even for "unknown command" responses we still return 0 — the SW
 * bytes in `out` convey the error.  Return -1 is for transport-layer
 * problems (no room to even emit a 2-byte SW).
 */
int apdu_dispatch_process(const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_max, size_t *out_len);

#endif /* NIXTROPIC_CCID_APDU_DISPATCH_H */
