/*
 * Host tests for the CTAPHID framing (ctaphid.c) against a TinyUSB stub:
 * channel allocation, a CBOR request run from fido_hid_task(), and what the
 * host gets while that request runs (v0.3.1: KEEPALIVE).
 */
#include <string.h>

#include "check.h"
#include "tusb.h"
#include "fido_hid/ctaphid.h"
#include "fido_hid/proto.h"
#include "fido_hid/user_presence.h"

uint32_t mock_tick;

/* ----- user presence stub (test_user_presence.c links the real one) ----- */

static bool s_awaiting;
static int  s_cancels;
static int  s_cancel_clears;

bool user_presence_is_awaiting(void) { return s_awaiting; }
void user_presence_cancel(void)      { s_cancels++; }
void user_presence_clear_cancel(void) { s_cancel_clears++; }

/* ----- CBOR dispatch stub: the test scripts what a request does ----- */

static void (*s_during)(void);
static int s_dispatched;
static int s_resp_len = 2;         /* > 57 → a fragmented answer */

int fido_hid_cbor_dispatch(const uint8_t *req, size_t req_len,
                           uint8_t *resp, size_t resp_max)
{
    (void) req;
    (void) req_len;
    s_dispatched++;
    if (s_during != NULL) s_during();
    resp[0] = 0x00;            /* CTAP2_OK */
    resp[1] = 0xA0;            /* empty map */
    for (int i = 2; i < s_resp_len && (size_t) i < resp_max; i++) resp[i] = (uint8_t) i;
    return s_resp_len;
}

/* ----- helpers ----- */

static void reset_all(void)
{
    fido_hid_init();
    mock_tusb_reset();
    mock_tick = 1000u;
    s_awaiting = false;
    s_cancels = 0;
    s_cancel_clears = 0;
    s_during = NULL;
    s_dispatched = 0;
    s_resp_len = 2;
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t) v;
}

static uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) |
           ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}

/* One INIT packet carrying the whole (short) payload. */
static void host_send(uint32_t cid, uint8_t cmd, const uint8_t *data, uint16_t len)
{
    uint8_t pkt[64] = {0};
    put_be32(pkt, cid);
    pkt[4] = (uint8_t)(FIDO_HID_CMD_INIT_FLAG | cmd);
    pkt[5] = (uint8_t)(len >> 8);
    pkt[6] = (uint8_t) len;
    if (len > 0u) memcpy(&pkt[7], data, len);
    fido_hid_handle_packet(pkt, sizeof pkt);
}

static uint32_t open_channel(void)
{
    const uint8_t nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    host_send(FIDO_HID_CID_BROADCAST, FIDO_HID_CMD_INIT, nonce, 8);
    fido_hid_task();
    uint32_t cid = get_be32(&mock_hid_sent[mock_hid_nsent - 1][15]);
    mock_hid_nsent = 0;
    return cid;
}

static const uint8_t *last_sent(void)
{
    return mock_hid_nsent > 0 ? mock_hid_sent[mock_hid_nsent - 1] : NULL;
}

/* ----- tests: today's behaviour ----- */

static void test_init_allocates_channel(void)
{
    reset_all();
    const uint8_t nonce[8] = {9, 9, 9, 9, 9, 9, 9, 9};
    host_send(FIDO_HID_CID_BROADCAST, FIDO_HID_CMD_INIT, nonce, 8);
    fido_hid_task();
    CHECK(mock_hid_nsent == 1);
    const uint8_t *p = last_sent();
    CHECK(get_be32(p) == FIDO_HID_CID_BROADCAST);
    CHECK(p[4] == (FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_INIT));
    CHECK(memcmp(&p[7], nonce, 8) == 0);
    CHECK(get_be32(&p[15]) == 1u);
}

static void test_cbor_request_runs_from_task(void)
{
    reset_all();
    uint32_t cid = open_channel();
    const uint8_t getinfo = 0x04;
    host_send(cid, FIDO_HID_CMD_CBOR, &getinfo, 1);
    CHECK(s_dispatched == 0);            /* not inside the USB callback */
    fido_hid_task();
    CHECK(s_dispatched == 1);
    CHECK(mock_hid_nsent == 1);
    const uint8_t *p = last_sent();
    CHECK(get_be32(p) == cid);
    CHECK(p[4] == (FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_CBOR));
    CHECK(p[6] == 2 && p[7] == 0x00 && p[8] == 0xA0);
}

static uint32_t s_cid_a, s_cid_b;

static void during_other_request(void)
{
    const uint8_t getinfo = 0x04;
    host_send(s_cid_b, FIDO_HID_CMD_CBOR, &getinfo, 1);
}

static void test_other_request_while_running_is_busy(void)
{
    reset_all();
    s_cid_a = open_channel();
    s_cid_b = open_channel();
    const uint8_t getinfo = 0x04;
    host_send(s_cid_a, FIDO_HID_CMD_CBOR, &getinfo, 1);
    s_during = during_other_request;
    fido_hid_task();
    CHECK(s_dispatched == 1);
    CHECK(mock_hid_nsent == 2);
    const uint8_t *busy = mock_hid_sent[0];
    CHECK(get_be32(busy) == s_cid_b);
    CHECK(busy[4] == (FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_ERROR));
    CHECK(busy[7] == FIDO_HID_ERR_CHANNEL_BUSY);
    CHECK(get_be32(mock_hid_sent[1]) == s_cid_a);   /* A's answer after */
}

/* ----- tests: KEEPALIVE (v0.3.1, CTAP 2.2 §11.2.9.1.7) ----- */

static bool is_keepalive(const uint8_t *p, uint32_t cid, uint8_t status)
{
    return get_be32(p) == cid &&
           p[4] == (FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_KEEPALIVE) &&
           p[5] == 0 && p[6] == 1 && p[7] == status;
}

static int count_keepalives(void)
{
    int n = 0;
    for (int i = 0; i < mock_hid_nsent; i++) {
        if (mock_hid_sent[i][4] == (FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_KEEPALIVE)) n++;
    }
    return n;
}

/* Start a CBOR request on a fresh channel; fido_hid_task() runs s_during. */
static uint32_t start_request(void (*during)(void))
{
    uint32_t cid = open_channel();
    const uint8_t cmd = 0x06;            /* ClientPIN, any CBOR will do */
    host_send(cid, FIDO_HID_CMD_CBOR, &cmd, 1);
    s_during = during;
    s_cid_a = cid;
    return cid;
}

static void test_progress_idle_is_noop(void)
{
    reset_all();
    fido_hid_progress();
    CHECK(mock_hid_nsent == 0);
    CHECK(mock_tud_task_calls == 0);
}

static int s_sent_at[8];

static void during_schedule(void)
{
    /* chip calls at t = 0, 40, 60, 90, 200 ms; KEEPALIVE due after 50 ms */
    static const uint32_t at[5] = {0, 40, 60, 90, 200};
    for (int i = 0; i < 5; i++) {
        mock_tick = 1000u + at[i];
        fido_hid_progress();
        s_sent_at[i] = mock_hid_nsent;
    }
}

static void test_processing_cadence(void)
{
    reset_all();
    uint32_t cid = start_request(during_schedule);
    fido_hid_task();
    CHECK(s_sent_at[0] == 1);            /* first call: send at once */
    CHECK(is_keepalive(mock_hid_sent[0], cid, 1));
    CHECK(s_sent_at[1] == 1);            /* 40 ms: not yet */
    CHECK(s_sent_at[2] == 2);            /* 60 ms: due */
    CHECK(s_sent_at[3] == 2);            /* 30 ms after the last: not yet */
    CHECK(s_sent_at[4] == 3);            /* 140 ms after the last */
    CHECK(is_keepalive(mock_hid_sent[2], cid, 1));
    CHECK(mock_tud_task_calls >= 5);     /* every call pumps USB */
    /* the final answer comes last, untouched */
    CHECK(mock_hid_nsent == 4);
    CHECK(mock_hid_sent[3][4] == (FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_CBOR));
    CHECK(mock_hid_sent[3][7] == 0x00 && mock_hid_sent[3][8] == 0xA0);
}

static void during_touch(void)
{
    mock_tick = 1000u; fido_hid_progress();          /* PROCESSING */
    s_awaiting = true;
    mock_tick = 1010u; fido_hid_progress();          /* UPNEEDED at once */
    mock_tick = 1020u; fido_hid_progress();          /* nothing new */
    s_awaiting = false;
    mock_tick = 1030u; fido_hid_progress();          /* PROCESSING at once */
}

static void test_status_change_sends_at_once(void)
{
    reset_all();
    uint32_t cid = start_request(during_touch);
    fido_hid_task();
    CHECK(count_keepalives() == 3);
    CHECK(is_keepalive(mock_hid_sent[0], cid, 1));
    CHECK(is_keepalive(mock_hid_sent[1], cid, 2));
    CHECK(is_keepalive(mock_hid_sent[2], cid, 1));
}

static void test_no_keepalive_after_answer(void)
{
    reset_all();
    start_request(during_schedule);
    fido_hid_task();
    int n = mock_hid_nsent;
    mock_tick += 1000u;
    fido_hid_progress();
    fido_hid_task();
    CHECK(mock_hid_nsent == n);
}

static void during_busy_endpoint(void)
{
    mock_hid_ready = false;
    mock_tick = 1000u; fido_hid_progress();          /* endpoint busy: skip */
    s_sent_at[0] = mock_hid_nsent;
    mock_hid_ready = true;
    mock_tick = 1010u; fido_hid_progress();          /* still due: send */
    s_sent_at[1] = mock_hid_nsent;
}

static void test_busy_endpoint_defers(void)
{
    reset_all();
    uint32_t cid = start_request(during_busy_endpoint);
    fido_hid_task();
    CHECK(s_sent_at[0] == 0);
    CHECK(s_sent_at[1] == 1);
    CHECK(is_keepalive(mock_hid_sent[0], cid, 1));
}

static void inject_init_b(void)
{
    const uint8_t nonce[8] = {7, 7, 7, 7, 7, 7, 7, 7};
    mock_hid_ready = false;          /* the endpoint is busy as INIT arrives */
    host_send(s_cid_b, FIDO_HID_CMD_INIT, nonce, 8);  /* channel sync on B */
    mock_tud_task_hook = NULL;
}

static void during_init_from_other_channel(void)
{
    mock_tick = 1000u; fido_hid_progress();          /* KEEPALIVE */
    mock_tud_task_hook = inject_init_b;
    mock_tick = 1010u; fido_hid_progress();          /* pump delivers INIT on B: held */
    mock_hid_ready = false;
    mock_tick = 1020u; fido_hid_progress();          /* still busy: nothing */
    mock_tick = 1130u; fido_hid_progress();          /* INIT answer first, KEEPALIVE waits */
    mock_tick = 1140u; fido_hid_progress();          /* now the KEEPALIVE */
}

static void test_init_reply_not_lost(void)
{
    reset_all();
    s_cid_b = open_channel();
    mock_hid_autobusy = true;
    uint32_t cid = start_request(during_init_from_other_channel);
    fido_hid_task();
    int init_at = -1, ka2_at = -1;
    for (int i = 0; i < mock_hid_nsent; i++) {
        const uint8_t *p = mock_hid_sent[i];
        if (get_be32(p) == s_cid_b && p[4] == (FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_INIT)) init_at = i;
        if (i > 0 && is_keepalive(p, cid, 1)) ka2_at = i;
    }
    CHECK(init_at > 0);                  /* answered, not dropped */
    CHECK(ka2_at > init_at);             /* before the next KEEPALIVE */
}

static void during_other_request_via_pump(void)
{
    mock_tud_task_hook = during_other_request;
    mock_tick = 1000u; fido_hid_progress();
    mock_tud_task_hook = NULL;
}

static void test_new_request_during_progress_is_busy(void)
{
    reset_all();
    s_cid_b = open_channel();
    start_request(during_other_request_via_pump);
    fido_hid_task();
    CHECK(s_dispatched == 1);
    bool busy = false;
    for (int i = 0; i < mock_hid_nsent; i++) {
        const uint8_t *p = mock_hid_sent[i];
        if (get_be32(p) == s_cid_b && p[4] == (FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_ERROR) &&
            p[7] == FIDO_HID_ERR_CHANNEL_BUSY) busy = true;
    }
    CHECK(busy);
    fido_hid_task();
    CHECK(s_dispatched == 1);            /* never run later either */
}

static void cancel_a(void)
{
    host_send(s_cid_a, FIDO_HID_CMD_CANCEL, NULL, 0);
    mock_tud_task_hook = NULL;
}

static void during_cancel_while_processing(void)
{
    mock_tud_task_hook = cancel_a;
    mock_tick = 1000u; fido_hid_progress();
}

static void test_cancel_while_processing_completes(void)
{
    reset_all();
    uint32_t cid = start_request(during_cancel_while_processing);
    fido_hid_task();
    const uint8_t *p = last_sent();
    CHECK(get_be32(p) == cid);
    CHECK(p[4] == (FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_CBOR));
    CHECK(p[7] == 0x00);                 /* normal answer */
}

static int s_nested_calls;

static void nested_progress(void)
{
    s_nested_calls++;
    if (s_nested_calls < 3) {
        mock_tick += 200u;
        fido_hid_progress();
    }
}

static void during_nested(void)
{
    mock_tud_task_hook = nested_progress;
    mock_tick = 1000u; fido_hid_progress();
    mock_tud_task_hook = NULL;
}

static void test_nested_progress_is_noop(void)
{
    reset_all();
    s_nested_calls = 0;
    start_request(during_nested);
    fido_hid_task();
    CHECK(s_nested_calls == 1);          /* inner call did not pump again */
    CHECK(count_keepalives() == 1);
}

static bool s_running_seen[2];

static void during_running_flag(void)
{
    s_running_seen[0] = fido_hid_is_running();
}

static void test_is_running(void)
{
    reset_all();
    CHECK(!fido_hid_is_running());
    start_request(during_running_flag);
    fido_hid_task();
    s_running_seen[1] = fido_hid_is_running();
    CHECK(s_running_seen[0]);
    CHECK(!s_running_seen[1]);
}

/* ----- Jan's review of the design (v0.3.1) ----- */

static uint32_t s_max_gap;

static void during_jitter(void)
{
    uint32_t last = 0;
    int seen = 0;
    for (uint32_t t = 0; t <= 1000u; t += 40u) {
        mock_tick = 1000u + t;
        fido_hid_progress();
        if (mock_hid_nsent > seen) {
            if (seen > 0 && t - last > s_max_gap) s_max_gap = t - last;
            last = t;
            seen = mock_hid_nsent;
        }
    }
}

static void test_jitter_keeps_gap_under_100ms(void)
{
    reset_all();
    s_max_gap = 0;
    start_request(during_jitter);
    fido_hid_task();
    CHECK(count_keepalives() >= 10);
    CHECK(s_max_gap <= 100u);
}

static void during_refused(void)
{
    mock_hid_refuse = 1;
    mock_tick = 1000u; fido_hid_progress();          /* ready, but refused */
    mock_tick = 1005u; fido_hid_progress();          /* nothing was recorded: send now */
    s_sent_at[0] = mock_hid_nsent;
}

static void during_boundary(void)
{
    mock_tick = 1000u; fido_hid_progress();
    mock_tick = 1049u; fido_hid_progress();          /* 49 ms: not yet */
    s_sent_at[0] = mock_hid_nsent;
    mock_tick = 1050u; fido_hid_progress();          /* 50 ms: due */
    s_sent_at[1] = mock_hid_nsent;
}

static void test_interval_boundary(void)
{
    reset_all();
    start_request(during_boundary);
    fido_hid_task();
    CHECK(s_sent_at[0] == 1);
    CHECK(s_sent_at[1] == 2);
}

static void test_refused_report_changes_nothing(void)
{
    reset_all();
    uint32_t cid = start_request(during_refused);
    fido_hid_task();
    CHECK(s_sent_at[0] == 1);
    CHECK(is_keepalive(mock_hid_sent[0], cid, 1));
}

static void during_wrap(void)
{
    mock_tick = 0xFFFFFFF0u; fido_hid_progress();
    mock_tick = 0xFFFFFFFFu; fido_hid_progress();    /* 15 ms: not yet */
    s_sent_at[0] = mock_hid_nsent;
    mock_tick = 0x00000030u; fido_hid_progress();    /* 64 ms across the wrap */
    s_sent_at[1] = mock_hid_nsent;
}

static void test_tick_wrap(void)
{
    reset_all();
    start_request(during_wrap);
    fido_hid_task();
    CHECK(s_sent_at[0] == 1);
    CHECK(s_sent_at[1] == 2);
}

static uint32_t s_cid_c;

static void inject_two_inits(void)
{
    const uint8_t nb[8] = {0xB, 0xB, 0xB, 0xB, 0xB, 0xB, 0xB, 0xB};
    const uint8_t nc[8] = {0xC, 0xC, 0xC, 0xC, 0xC, 0xC, 0xC, 0xC};
    mock_hid_ready = false;
    host_send(s_cid_b, FIDO_HID_CMD_INIT, nb, 8);    /* kept in the slot */
    host_send(s_cid_c, FIDO_HID_CMD_INIT, nc, 8);    /* slot full: dropped */
    mock_tud_task_hook = NULL;
}

static void during_slot_overflow(void)
{
    mock_tud_task_hook = inject_two_inits;
    mock_tick = 1000u; fido_hid_progress();
    mock_tick = 1010u; fido_hid_progress();
}

static void test_short_slot_keeps_first(void)
{
    reset_all();
    s_cid_b = open_channel();
    s_cid_c = open_channel();
    mock_hid_autobusy = true;
    start_request(during_slot_overflow);
    fido_hid_task();
    fido_hid_task();
    int b = 0, c = 0;
    for (int i = 0; i < mock_hid_nsent; i++) {
        const uint8_t *p = mock_hid_sent[i];
        if (p[4] != (FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_INIT)) continue;
        if (get_be32(p) == s_cid_b) b++;
        if (get_be32(p) == s_cid_c) c++;
    }
    CHECK(b == 1);
    CHECK(c == 0);
}

static void test_fragmented_answer_intact(void)
{
    reset_all();
    s_resp_len = 150;                    /* 57 + 59 + 34 */
    mock_hid_autobusy = true;
    uint32_t cid = start_request(during_schedule);
    for (int i = 0; i < 6; i++) { fido_hid_task(); tud_task(); }
    int first = -1;
    for (int i = 0; i < mock_hid_nsent; i++) {
        if (mock_hid_sent[i][4] == (FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_CBOR)) first = i;
    }
    CHECK(first >= 0 && first + 3 == mock_hid_nsent);
    if (first >= 0 && first + 3 == mock_hid_nsent) {
        const uint8_t *p0 = mock_hid_sent[first];
        const uint8_t *p1 = mock_hid_sent[first + 1];
        const uint8_t *p2 = mock_hid_sent[first + 2];
        CHECK(get_be32(p0) == cid && p0[5] == 0 && p0[6] == 150);
        CHECK(p0[7] == 0x00 && p0[8] == 0xA0 && p0[9] == 2 && p0[63] == 56);
        CHECK(get_be32(p1) == cid && p1[4] == 0 && p1[5] == 57 && p1[63] == 115);
        CHECK(get_be32(p2) == cid && p2[4] == 1 && p2[5] == 116 && p2[38] == 149);
    }
}

static const uint8_t RESYNC_NONCE[8] = {0x5, 0x4, 0x3, 0x2, 0x1, 0x0, 0x9, 0x8};

static void resync_a(void)
{
    host_send(s_cid_a, FIDO_HID_CMD_INIT, RESYNC_NONCE, 8);
    mock_tud_task_hook = NULL;
}

static void during_resync(void)
{
    mock_tick = 1000u; fido_hid_progress();          /* KEEPALIVE */
    mock_tud_task_hook = resync_a;
    mock_tick = 1020u; fido_hid_progress();          /* INIT on our own CID arrives */
    s_sent_at[0] = mock_hid_nsent;
    mock_tick = 1200u; fido_hid_progress();          /* abandoned: no KEEPALIVE */
    mock_tick = 1300u; fido_hid_progress();
    s_sent_at[1] = mock_hid_nsent;
}

static bool is_resync_answer(const uint8_t *p, uint32_t cid)
{
    return get_be32(p) == cid && p[4] == (FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_INIT) &&
           memcmp(&p[7], RESYNC_NONCE, 8) == 0 && get_be32(&p[15]) == cid;
}

static bool any_cbor_on(uint32_t cid)
{
    for (int i = 0; i < mock_hid_nsent; i++) {
        if (get_be32(mock_hid_sent[i]) == cid &&
            mock_hid_sent[i][4] == (FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_CBOR)) return true;
    }
    return false;
}

static void test_resync_during_processing(void)
{
    reset_all();
    uint32_t cid = start_request(during_resync);
    fido_hid_task();
    fido_hid_task();
    CHECK(s_dispatched == 1);
    CHECK(s_cancels >= 1);               /* ends a touch wait, if any */
    CHECK(s_sent_at[0] == 1);            /* INIT answer held, not sent at once */
    CHECK(s_sent_at[1] == 1);            /* and no KEEPALIVE after the resync */
    CHECK(!any_cbor_on(cid));            /* the stale answer never goes out */
    CHECK(mock_hid_nsent == 2 && is_resync_answer(mock_hid_sent[1], cid));
}

static void test_resync_of_queued_request(void)
{
    reset_all();
    uint32_t cid = start_request(NULL);
    host_send(cid, FIDO_HID_CMD_INIT, RESYNC_NONCE, 8);
    fido_hid_task();
    fido_hid_task();
    CHECK(s_dispatched == 0);            /* never runs */
    CHECK(s_cancels == 0);               /* a queued request owns no touch wait */
    CHECK(!any_cbor_on(cid));
    CHECK(mock_hid_nsent == 1 && is_resync_answer(mock_hid_sent[0], cid));
}

static void test_resync_during_fragmented_answer(void)
{
    reset_all();
    s_resp_len = 150;
    uint32_t cid = start_request(NULL);
    mock_hid_autobusy = true;
    fido_hid_task();                     /* first fragment out, endpoint busy */
    CHECK(mock_hid_nsent == 1);
    tud_task();
    host_send(cid, FIDO_HID_CMD_INIT, RESYNC_NONCE, 8);
    for (int i = 0; i < 4; i++) { fido_hid_task(); tud_task(); }
    CHECK(mock_hid_nsent == 2);          /* no further fragment */
    CHECK(is_resync_answer(mock_hid_sent[1], cid));
}

static void during_resync_then_error(void)
{
    mock_tud_task_hook = resync_a;
    mock_tick = 1000u; fido_hid_progress();
    s_resp_len = -1;                     /* the request then fails: CTAPHID_ERROR */
}

static void test_resync_drops_error_answer(void)
{
    reset_all();
    uint32_t cid = start_request(during_resync_then_error);
    fido_hid_task();
    fido_hid_task();
    for (int i = 0; i < mock_hid_nsent; i++) {
        CHECK(!(get_be32(mock_hid_sent[i]) == cid &&
                mock_hid_sent[i][4] == (FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_ERROR)));
    }
    CHECK(is_resync_answer(mock_hid_sent[mock_hid_nsent - 1], cid));
}

/* Jan, code review 1: INIT(n1) on the running CID, its held answer cannot go
 * out, the host retries INIT(n2): only n2 is ever acknowledged. */
static const uint8_t NONCE2[8] = {0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22};

static void during_resync_then_busy(void)
{
    mock_tud_task_hook = resync_a;
    mock_tick = 1000u; fido_hid_progress();
    mock_hid_ready = false;              /* the held answer cannot go out */
}

static void test_repeated_resync_no_stale_ack(void)
{
    reset_all();
    uint32_t cid = start_request(during_resync_then_busy);
    fido_hid_task();
    host_send(cid, FIDO_HID_CMD_INIT, NONCE2, 8);       /* retry */
    mock_hid_ready = true;
    fido_hid_task();
    fido_hid_task();
    int n1 = 0, n2 = 0;
    for (int i = 0; i < mock_hid_nsent; i++) {
        const uint8_t *p = mock_hid_sent[i];
        if (get_be32(p) != cid || p[4] != (FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_INIT)) continue;
        if (memcmp(&p[7], RESYNC_NONCE, 8) == 0) n1++;
        if (memcmp(&p[7], NONCE2, 8) == 0) n2++;
    }
    CHECK(n1 == 0);
    CHECK(n2 == 1);
}

/* A refused submission of a held packet does not let the answer overtake it. */
static void inject_init_b_busy(void)
{
    const uint8_t nb[8] = {0xB, 0xB, 0xB, 0xB, 0xB, 0xB, 0xB, 0xB};
    mock_hid_ready = false;
    host_send(s_cid_b, FIDO_HID_CMD_INIT, nb, 8);        /* into the short slot */
    mock_tud_task_hook = NULL;
}

static void during_hold_b(void)
{
    mock_tud_task_hook = inject_init_b_busy;
    mock_tick = 1000u; fido_hid_progress();
}

static void test_held_packet_not_overtaken(void)
{
    reset_all();
    s_cid_b = open_channel();
    start_request(during_hold_b);
    fido_hid_task();                     /* B's answer held, endpoint busy */
    CHECK(!any_cbor_on(s_cid_a));
    mock_hid_ready = true;
    mock_hid_refuse = 1;                 /* the held packet is refused once */
    fido_hid_task();
    CHECK(!any_cbor_on(s_cid_a));        /* nothing overtook it */
    int before = mock_hid_nsent;
    fido_hid_task();
    CHECK(mock_hid_nsent == before + 2);
    if (mock_hid_nsent == before + 2) {
        CHECK(get_be32(mock_hid_sent[before]) == s_cid_b);          /* held one first */
        CHECK(get_be32(mock_hid_sent[before + 1]) == s_cid_a);      /* then the answer */
    }
}

/* A short answer arriving while an older one is held goes out after it. */
static void hold_b_then_error_c(void)
{
    const uint8_t nb[8] = {0xB, 0xB, 0xB, 0xB, 0xB, 0xB, 0xB, 0xB};
    mock_hid_ready = false;
    host_send(s_cid_b, FIDO_HID_CMD_INIT, nb, 8);        /* held */
    mock_hid_ready = true;
    const uint8_t x = 0x04;
    host_send(s_cid_c, FIDO_HID_CMD_CBOR, &x, 1);         /* BUSY for C */
    mock_tud_task_hook = NULL;
}

static void during_hold_then_error(void)
{
    mock_tud_task_hook = hold_b_then_error_c;
    mock_tick = 1000u; fido_hid_progress();
    mock_tick = 1010u; fido_hid_progress();
}

static void test_short_answers_keep_order(void)
{
    reset_all();
    s_cid_b = open_channel();
    s_cid_c = open_channel();
    start_request(during_hold_then_error);
    fido_hid_task();
    fido_hid_task();
    int b = -1, c = -1;
    for (int i = 0; i < mock_hid_nsent; i++) {
        if (get_be32(mock_hid_sent[i]) == s_cid_b && b < 0) b = i;
        if (get_be32(mock_hid_sent[i]) == s_cid_c && c < 0) c = i;
    }
    CHECK(b >= 0);
    CHECK(c < 0 || c > b);               /* C never before B */
}

/* INIT(n1) on an idle channel is held, INIT(n2) follows: only n2 answered. */
static void two_inits_on_b(void)
{
    mock_hid_ready = false;
    host_send(s_cid_b, FIDO_HID_CMD_INIT, RESYNC_NONCE, 8);   /* held */
    host_send(s_cid_b, FIDO_HID_CMD_INIT, NONCE2, 8);         /* supersedes */
    mock_tud_task_hook = NULL;
}

static void during_two_inits(void)
{
    mock_tud_task_hook = two_inits_on_b;
    mock_tick = 1000u; fido_hid_progress();
}

static void test_held_init_superseded(void)
{
    reset_all();
    s_cid_b = open_channel();
    start_request(during_two_inits);
    fido_hid_task();                     /* n2's answer held, endpoint busy */
    mock_hid_ready = true;
    fido_hid_task();
    fido_hid_task();
    int n1 = 0, n2 = 0;
    for (int i = 0; i < mock_hid_nsent; i++) {
        const uint8_t *p = mock_hid_sent[i];
        if (get_be32(p) != s_cid_b || p[4] != (FIDO_HID_CMD_INIT_FLAG | FIDO_HID_CMD_INIT)) continue;
        if (memcmp(&p[7], RESYNC_NONCE, 8) == 0) n1++;
        if (memcmp(&p[7], NONCE2, 8) == 0) n2++;
    }
    CHECK(n1 == 0);
    CHECK(n2 == 1);
}

#if NIXTROPIC_DEBUG
/* Jan, code review 2: the tail gap ends when the answer is accepted, not when
 * the handler returns. */
static void during_one_keepalive(void)
{
    mock_tick = 1000u; fido_hid_progress();
    mock_hid_ready = false;              /* the answer will wait 1 s */
}

static void test_dbg_tail_to_answer(void)
{
    reset_all();
    start_request(during_one_keepalive);
    fido_hid_task();
    CHECK(fido_hid_dbg_max_ka_gap() == 0u);    /* answer still queued */
    mock_tick = 2000u;
    mock_hid_ready = true;
    fido_hid_task();
    CHECK(fido_hid_dbg_max_ka_gap() >= 1000u);
}
#endif

static void test_cancel_latch_cleared_per_request(void)
{
    reset_all();
    start_request(NULL);
    fido_hid_task();
    CHECK(s_cancel_clears >= 2);         /* before and after the request */
}

int main(void)
{
    test_jitter_keeps_gap_under_100ms();
    test_interval_boundary();
    test_refused_report_changes_nothing();
    test_tick_wrap();
    test_short_slot_keeps_first();
    test_fragmented_answer_intact();
    test_resync_during_processing();
    test_resync_of_queued_request();
    test_resync_during_fragmented_answer();
    test_resync_drops_error_answer();
    test_repeated_resync_no_stale_ack();
    test_held_packet_not_overtaken();
    test_short_answers_keep_order();
    test_held_init_superseded();
#if NIXTROPIC_DEBUG
    test_dbg_tail_to_answer();
#endif
    test_cancel_latch_cleared_per_request();
    test_init_allocates_channel();
    test_cbor_request_runs_from_task();
    test_other_request_while_running_is_busy();
    test_progress_idle_is_noop();
    test_processing_cadence();
    test_status_change_sends_at_once();
    test_no_keepalive_after_answer();
    test_busy_endpoint_defers();
    test_init_reply_not_lost();
    test_new_request_during_progress_is_busy();
    test_cancel_while_processing_completes();
    test_nested_progress_is_noop();
    test_is_running();
    return check_done("test_ctaphid");
}
