/*
 * Host test for the debug lt-rpc dispatch gate: no chip command while a
 * FIDO request runs (v0.3.1: its progress points pump USB between chip
 * calls) or while anything waits for touch.  Built with NIXTROPIC_DEBUG.
 */
#include <string.h>

#include "check.h"
#include "tusb.h"
#include "hid_rpc/rpc.h"
#include "hid_rpc/lt_rpc_proto.h"
#include "fido_hid/ctaphid.h"
#include "fido_hid/user_presence.h"

static bool s_fido_running, s_awaiting;
static int  s_handled;

bool fido_hid_is_running(void)       { return s_fido_running; }
bool user_presence_is_awaiting(void) { return s_awaiting; }

static int handler(const uint8_t *req, size_t req_len, uint8_t *resp, size_t resp_max)
{
    (void) req;
    (void) req_len;
    (void) resp_max;
    s_handled++;
    resp[0] = 0x00;
    return 1;
}

rpc_handler_fn hid_rpc_lookup(uint8_t cmd)
{
    (void) cmd;
    return handler;
}

/* One request; returns the first payload byte of the answer, or -1. */
static int request(void)
{
    uint8_t pkt[LT_RPC_HID_REPORT_LEN] = {0};
    pkt[0] = 0xCA; pkt[1] = 0xFE; pkt[2] = 0x00; pkt[3] = 0x01;
    pkt[4] = (uint8_t)(LT_RPC_CMD_INIT_FLAG | 0x01u);
    mock_tusb_reset();
    hid_rpc_handle_packet(pkt, sizeof pkt);
    hid_rpc_task();
    return mock_hid_nsent > 0 ? (int) mock_hid_sent[0][7] : -1;
}

int main(void)
{
    hid_rpc_init();

    s_fido_running = true;
    CHECK(request() == LT_RPC_ERR_BUSY);
    CHECK(s_handled == 0);

    s_fido_running = false;
    s_awaiting = true;
    CHECK(request() == LT_RPC_ERR_BUSY);
    CHECK(s_handled == 0);

    s_awaiting = false;
    CHECK(request() == 0x00);
    CHECK(s_handled == 1);

    return check_done("test_rpc_gate");
}
