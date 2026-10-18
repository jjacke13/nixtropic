/*
 * Host tests for the touch wait together with the real CTAPHID framing
 * (v0.3.1): KEEPALIVE UPNEEDED during the wait, the request-owned CANCEL
 * latch (a CANCEL before the wait used to be lost: Jan, v0.3.1 review), and
 * that an OpenPGP wait (no FIDO request) sees neither.
 */
#include <string.h>

#include "check.h"
#include "tusb.h"
#include "fido_hid/ctaphid.h"
#include "fido_hid/proto.h"
#include "fido_hid/user_presence.h"
#include "platform/led.h"
#include "stm32u5xx_hal.h"

uint32_t mock_tick;
static bool s_button;                /* SW1 held */

GPIO_PinState HAL_GPIO_ReadPin(void *port, uint16_t pin)
{
    (void) port;
    (void) pin;
    return s_button ? GPIO_PIN_SET : GPIO_PIN_RESET;
}

void HAL_Delay(uint32_t ms)
{
    while (ms-- > 0u) {
        mock_tick++;
        user_presence_systick_tick();
    }
}

void led_set_state(led_state_t s) { (void) s; }

/* ----- scripted CBOR request ----- */

static void (*s_before_wait)(void);
static uint32_t s_timeout = 200u;
static up_result_t s_up;
static uint32_t s_wait_ms;

int fido_hid_cbor_dispatch(const uint8_t *req, size_t req_len,
                           uint8_t *resp, size_t resp_max)
{
    (void) req;
    (void) req_len;
    (void) resp_max;
    fido_hid_progress();                 /* a chip call before the touch */
    if (s_before_wait != NULL) s_before_wait();
    uint32_t t0 = mock_tick;
    s_up = user_presence_check(s_timeout);
    s_wait_ms = mock_tick - t0;
    resp[0] = (s_up == UP_OK) ? 0x00 : (s_up == UP_CANCEL) ? 0x2D : 0x27;
    return 1;
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t) v;
}

static void host_send(uint32_t cid, uint8_t cmd, const uint8_t *data, uint16_t len)
{
    uint8_t pkt[64] = {0};
    put_be32(pkt, cid);
    pkt[4] = (uint8_t)(FIDO_HID_CMD_INIT_FLAG | cmd);
    pkt[6] = (uint8_t) len;
    if (len > 0u) memcpy(&pkt[7], data, len);
    fido_hid_handle_packet(pkt, sizeof pkt);
}

#define CID 0x00000001u

static void cancel_now(void)
{
    host_send(CID, FIDO_HID_CMD_CANCEL, NULL, 0);
    mock_tud_task_hook = NULL;
}

static void reset_all(void)
{
    fido_hid_init();
    mock_tusb_reset();
    user_presence_clear_cancel();
    mock_tick = 5000u;
    s_button = false;
    s_before_wait = NULL;
    s_timeout = 200u;
    s_up = 0;
    s_wait_ms = 0;
    HAL_Delay(30);                       /* debouncer settles: released */
}

static void run_request(void)
{
    const uint8_t mc = 0x01;
    host_send(CID, FIDO_HID_CMD_CBOR, &mc, 1);
    fido_hid_task();
}

static int count_ka(uint8_t status)
{
    int n = 0;
    for (int i = 0; i < mock_hid_nsent; i++) {
        const uint8_t *p = mock_hid_sent[i];
        if (p[4] == (FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_KEEPALIVE) && p[7] == status) n++;
    }
    return n;
}

static void test_upneeded_during_wait(void)
{
    reset_all();
    run_request();
    CHECK(s_up == UP_FAIL && s_wait_ms == 200u);
    CHECK(count_ka(1) == 1);             /* PROCESSING before the wait */
    CHECK(count_ka(2) >= 4);             /* UPNEEDED every 50 ms of it */
}

static void cancel_before_wait(void)
{
    mock_tud_task_hook = cancel_now;
    fido_hid_progress();                 /* CANCEL arrives through this pump */
}

static void test_cancel_before_wait(void)
{
    reset_all();
    s_before_wait = cancel_before_wait;
    run_request();
    CHECK(s_up == UP_CANCEL);
    CHECK(s_wait_ms == 0u);              /* no wait at all */
    CHECK(count_ka(2) == 0);
}

static void cancel_in_wait(void)
{
    mock_tud_task_hook = cancel_now;     /* first pump inside the wait */
}

static void test_cancel_in_wait(void)
{
    reset_all();
    s_before_wait = cancel_in_wait;
    run_request();
    CHECK(s_up == UP_CANCEL);
    CHECK(s_wait_ms <= 1u);
}

static void test_latch_does_not_reach_next_request(void)
{
    reset_all();
    s_before_wait = cancel_before_wait;
    run_request();
    CHECK(s_up == UP_CANCEL);
    /* an OpenPGP wait right after it (no FIDO request in between, Jan):
     * no latch, no KEEPALIVE */
    int sent = mock_hid_nsent;
    uint32_t t0 = mock_tick;
    up_result_t up = user_presence_check(30u);
    CHECK(up == UP_FAIL && mock_tick - t0 == 30u);
    CHECK(mock_hid_nsent == sent);
    /* and the next FIDO request */
    s_before_wait = NULL;
    s_timeout = 50u;
    run_request();
    CHECK(s_up == UP_FAIL && s_wait_ms == 50u);
}

static void resync_queued(void)
{
    const uint8_t nonce[8] = {1, 1, 1, 1, 1, 1, 1, 1};
    host_send(CID, FIDO_HID_CMD_INIT, nonce, 8);
    mock_tud_task_hook = NULL;
}

/* A FIDO request queued before an OpenPGP touch wait, resynced during it:
 * the OpenPGP wait keeps its consent (Jan). */
static void test_queued_resync_keeps_openpgp_wait(void)
{
    reset_all();
    const uint8_t mc = 0x01;
    host_send(CID, FIDO_HID_CMD_CBOR, &mc, 1);           /* queued, not run */
    mock_tud_task_hook = resync_queued;
    uint32_t t0 = mock_tick;
    up_result_t up = user_presence_check(40u);           /* OpenPGP */
    CHECK(up == UP_FAIL && mock_tick - t0 == 40u);       /* not cancelled */
    fido_hid_task();
    CHECK(s_up == 0);                                     /* FIDO request never ran */
    CHECK(mock_hid_nsent == 1 &&
          mock_hid_sent[0][4] == (FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_INIT));
}

static void press_soon(void)
{
    static int calls;
    if (++calls == 20) s_button = true;
}

static void test_press_ok(void)
{
    reset_all();
    mock_tud_task_hook = press_soon;
    run_request();
    CHECK(s_up == UP_OK);
    CHECK(mock_hid_sent[mock_hid_nsent - 1][4] == (FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_CBOR));
    CHECK(mock_hid_sent[mock_hid_nsent - 1][7] == 0x00);
}

int main(void)
{
    test_upneeded_during_wait();
    test_cancel_before_wait();
    test_cancel_in_wait();
    test_latch_does_not_reach_next_request();
    test_queued_resync_keeps_openpgp_wait();
    test_press_ok();
    return check_done("test_user_presence");
}
