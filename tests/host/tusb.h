/* Host-test stand-in for TinyUSB (mock_tusb.c): the HID IN endpoint as a list
 * of sent reports, a ready flag the test controls, and tud_task() as a hook. */
#ifndef NIXTROPIC_TESTS_TUSB_H
#define NIXTROPIC_TESTS_TUSB_H
#include <stdbool.h>
#include <stdint.h>

#define MOCK_HID_MAX_SENT 64

extern bool     mock_hid_ready;                 /* IN endpoint free */
/* Like the hardware: a sent report keeps the endpoint busy until the next
 * tud_task() completes the transfer.  Off = always free after a send. */
extern bool     mock_hid_autobusy;
extern int      mock_hid_refuse;                /* refuse the next N reports while ready */
extern int      mock_hid_nsent;
extern uint8_t  mock_hid_sent[MOCK_HID_MAX_SENT][64];
extern int      mock_tud_task_calls;
extern void   (*mock_tud_task_hook)(void);      /* runs inside tud_task() */

void mock_tusb_reset(void);

bool tud_hid_n_ready(uint8_t instance);
bool tud_hid_n_report(uint8_t instance, uint8_t report_id, void const *report, uint16_t len);
void tud_task(void);
#endif
