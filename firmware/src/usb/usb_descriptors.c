/*
 * USB descriptors for nixtropic Phase 1 — CDC-ACM only.
 *
 * Per plan decision P1.15: VID/PID = TinyUSB demo defaults `0xCAFE:0x4001`.
 * Real allocation under pid.codes deferred to ship-prep.
 *
 * Phase 7 adds HID + CCID interfaces; the descriptor structure here will
 * grow to a composite. Naming kept future-friendly.
 */

#include "tusb.h"

/* ===== Device Descriptor ===== */

#define USB_VID   0xCAFE
#define USB_PID   0x4001
#define USB_BCD   0x0200    /* USB 2.0 */

tusb_desc_device_t const desc_device = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = USB_BCD,

    /* Interface Association Descriptor (IAD) for CDC composite-friendly */
    .bDeviceClass       = TUSB_CLASS_MISC,
    .bDeviceSubClass    = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol    = MISC_PROTOCOL_IAD,

    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,

    .idVendor           = USB_VID,
    .idProduct          = USB_PID,
    .bcdDevice          = 0x0100,

    .iManufacturer      = 0x01,
    .iProduct           = 0x02,
    .iSerialNumber      = 0x03,

    .bNumConfigurations = 0x01,
};

uint8_t const *tud_descriptor_device_cb(void)
{
    return (uint8_t const *) &desc_device;
}

/* ===== Configuration Descriptor ===== */

enum {
    ITF_NUM_CDC_NOTIF = 0,
    ITF_NUM_CDC_DATA,
    ITF_NUM_TOTAL
};

#define EPNUM_CDC_NOTIF   0x81  /* IN  EP1 — control/notif */
#define EPNUM_CDC_OUT     0x02  /* OUT EP2 — host → device */
#define EPNUM_CDC_IN      0x82  /* IN  EP2 — device → host */

#define CONFIG_TOTAL_LEN  (TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN)

uint8_t const desc_fs_configuration[] = {
    /* Config descriptor: 1 config, ITF_NUM_TOTAL interfaces, 100 mA bus-powered */
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN, 0x00, 100),

    /* CDC interface (notification + data) */
    TUD_CDC_DESCRIPTOR(ITF_NUM_CDC_NOTIF, 4, EPNUM_CDC_NOTIF, 8,
                       EPNUM_CDC_OUT, EPNUM_CDC_IN, 64),
};

uint8_t const *tud_descriptor_configuration_cb(uint8_t index)
{
    (void) index;
    return desc_fs_configuration;
}

/* ===== String Descriptors ===== */

enum {
    STR_LANGID = 0,
    STR_MANUFACTURER,
    STR_PRODUCT,
    STR_SERIAL,
    STR_CDC_INTERFACE,
};

static char const *string_desc_arr[] = {
    [STR_LANGID]        = (const char[]){0x09, 0x04},  /* en-US: 0x0409 LE */
    [STR_MANUFACTURER]  = "nixtropic",
    [STR_PRODUCT]       = "nixtropic Phase 1",
    [STR_SERIAL]        = "0001",
    [STR_CDC_INTERFACE] = "nixtropic CDC console",
};

static uint16_t _desc_str[32 + 1];  /* +1 for header word */

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid)
{
    (void) langid;

    size_t chr_count = 0;

    if (index == STR_LANGID) {
        memcpy(&_desc_str[1], string_desc_arr[0], 2);
        chr_count = 1;
    } else if (index < (sizeof(string_desc_arr) / sizeof(string_desc_arr[0]))) {
        const char *str = string_desc_arr[index];
        chr_count = strlen(str);
        if (chr_count > 32) chr_count = 32;

        for (size_t i = 0; i < chr_count; i++) {
            _desc_str[1 + i] = (uint16_t) str[i];
        }
    } else {
        return NULL;
    }

    /* Header: bDescriptorType=STRING(0x03), bLength = 2 + 2*chr_count */
    _desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (uint8_t)(2u + chr_count * 2u));
    return _desc_str;
}
