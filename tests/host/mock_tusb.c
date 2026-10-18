/* TinyUSB stand-in for the host tests, see tusb.h. */
#include <string.h>

#include "tusb.h"

bool     mock_hid_ready = true;
bool     mock_hid_autobusy;
int      mock_hid_refuse;
int      mock_hid_nsent;
uint8_t  mock_hid_sent[MOCK_HID_MAX_SENT][64];
int      mock_tud_task_calls;
void   (*mock_tud_task_hook)(void);

void mock_tusb_reset(void)
{
    mock_hid_ready = true;
    mock_hid_autobusy = false;
    mock_hid_refuse = 0;
    mock_hid_nsent = 0;
    mock_tud_task_calls = 0;
    mock_tud_task_hook = NULL;
}

bool tud_hid_n_ready(uint8_t instance)
{
    (void) instance;
    return mock_hid_ready;
}

bool tud_hid_n_report(uint8_t instance, uint8_t report_id, void const *report, uint16_t len)
{
    (void) instance;
    (void) report_id;
    if (mock_hid_ready && mock_hid_refuse > 0) {   /* ready, but refused */
        mock_hid_refuse--;
        return false;
    }
    if (!mock_hid_ready || len != 64u ||
        mock_hid_nsent >= MOCK_HID_MAX_SENT) {
        return false;
    }
    memcpy(mock_hid_sent[mock_hid_nsent++], report, 64);
    if (mock_hid_autobusy) mock_hid_ready = false;
    return true;
}

void tud_task(void)
{
    mock_tud_task_calls++;
    if (mock_hid_autobusy) mock_hid_ready = true;     /* transfer complete */
    if (mock_tud_task_hook != NULL) mock_tud_task_hook();
}
