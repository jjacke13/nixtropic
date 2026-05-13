/*
 * USB descriptors for nixtropic — composite device exposing four
 * functions to the host on a single USB connection:
 *
 *   IF 0  CDC control (notification EP IN)             — console / log
 *   IF 1  CDC data    (bulk EP OUT/IN)                 — printf retarget
 *   IF 2  HID #0      vendor usage page 0xFF00         — lt-rpc framing
 *   IF 3  HID #1      FIDO2 usage page 0xF1D0          — CTAP2 transport
 *   IF 4  CCID        class 0x0B, bulk IN/OUT          — OpenPGP card
 *
 * VID/PID = 0xCAFE:0x4001 (TinyUSB demo range).  A pid.codes
 * allocation is a Phase 8 publishing task — see
 * docs/PHASE-8-BACKLOG.md §5.2.
 *
 * Two SEPARATE HID interfaces (rather than dual-collection) so each
 * surfaces as its own /dev/hidraw* and so libfido2's enumeration sees
 * exactly one FIDO interface (matching usage page 0xF1D0 per the
 * FIDO U2F HID 1.0 spec).
 *
 * CCID interface follows USB CCID 1.1 spec §5.  Class 0x0B
 * identifies us as a smart card reader to pcsc-lite for plug-and-play
 * enumeration.  Functional descriptor (54 B, type 0x21) advertises
 * T=1 protocol + short + extended APDU level exchange.  Bulk endpoints
 * carry PC_to_RDR_* / RDR_to_PC_* messages (firmware/src/usb/
 * usb_ccid.c).
 *
 * Reference specs: USB 2.0 (device, config, interface, endpoint
 * descriptors), USB CDC 1.2, USB HID 1.11, USB CCID 1.1.
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

    /* IAD-friendly miscellaneous class so composite descriptor works on
     * Windows without extra .inf. Linux is permissive either way. */
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

/* ===== HID Report Descriptors =====
 *
 * Two instances:
 *   #0  lt-rpc       usage page 0xFF00 (vendor), 64 B IN/OUT
 *   #1  FIDO2 (CTAP) usage page 0xF1D0 (FIDO Alliance), 64 B IN/OUT
 *
 * Both are vendor-style raw report descriptors — host treats payloads as
 * opaque byte arrays. The FIDO usage page is what libfido2 / browsers /
 * fido2-token grep for during enumeration.
 */

uint8_t const desc_hid_report_ltrpc[] = {
    0x06, 0x00, 0xFF,        /* Usage Page (Vendor Defined 0xFF00) */
    0x09, 0x01,              /* Usage (Vendor Usage 1) */
    0xA1, 0x01,              /* Collection (Application) */

    0x09, 0x02,              /*   Usage (Vendor Usage 2: input report) */
    0x15, 0x00,              /*   Logical Minimum (0)   */
    0x26, 0xFF, 0x00,        /*   Logical Maximum (255) */
    0x75, 0x08,              /*   Report Size (8 bits) */
    0x95, 0x40,              /*   Report Count (64)    */
    0x81, 0x02,              /*   Input (Data, Var, Abs) */

    0x09, 0x03,              /*   Usage (Vendor Usage 3: output report) */
    0x15, 0x00,              /*   Logical Minimum (0)   */
    0x26, 0xFF, 0x00,        /*   Logical Maximum (255) */
    0x75, 0x08,              /*   Report Size (8 bits) */
    0x95, 0x40,              /*   Report Count (64)    */
    0x91, 0x02,              /*   Output (Data, Var, Abs) */

    0xC0                     /* End Collection */
};

/* FIDO Alliance — U2F HID Protocol Specification, §3.3 ("HID Report
 * Descriptor"). The exact descriptor every YubiKey / SoloKey / Nitrokey
 * ships, copied verbatim. usage page 0xF1D0 + usage 0x01 (U2F HID) is
 * what libfido2's hid_linux.c matches when enumerating /dev/hidraw*. */
uint8_t const desc_hid_report_fido[] = {
    0x06, 0xD0, 0xF1,        /* Usage Page (FIDO Alliance 0xF1D0) */
    0x09, 0x01,              /* Usage (U2F Authenticator Device) */
    0xA1, 0x01,              /* Collection (Application) */

    0x09, 0x20,              /*   Usage (Input Report Data 0x20) */
    0x15, 0x00,              /*   Logical Minimum (0)   */
    0x26, 0xFF, 0x00,        /*   Logical Maximum (255) */
    0x75, 0x08,              /*   Report Size (8 bits) */
    0x95, 0x40,              /*   Report Count (64)    */
    0x81, 0x02,              /*   Input (Data, Var, Abs) */

    0x09, 0x21,              /*   Usage (Output Report Data 0x21) */
    0x15, 0x00,              /*   Logical Minimum (0)   */
    0x26, 0xFF, 0x00,        /*   Logical Maximum (255) */
    0x75, 0x08,              /*   Report Size (8 bits) */
    0x95, 0x40,              /*   Report Count (64)    */
    0x91, 0x02,              /*   Output (Data, Var, Abs) */

    0xC0                     /* End Collection */
};

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance)
{
    if (instance == 0) return desc_hid_report_ltrpc;
    return desc_hid_report_fido;
}

/* ===== Configuration Descriptor ===== */

enum {
    ITF_NUM_CDC_NOTIF = 0,
    ITF_NUM_CDC_DATA,
    ITF_NUM_HID_LTRPC,
    ITF_NUM_HID_FIDO,
    ITF_NUM_CCID,
    ITF_NUM_TOTAL
};

#define EPNUM_CDC_NOTIF      0x81  /* IN  EP1 — CDC notification */
#define EPNUM_CDC_OUT        0x02  /* OUT EP2 — host → device CDC bulk */
#define EPNUM_CDC_IN         0x82  /* IN  EP2 — device → host CDC bulk */
#define EPNUM_HID_LTRPC_OUT  0x03  /* OUT EP3 — host → device HID lt-rpc */
#define EPNUM_HID_LTRPC_IN   0x83  /* IN  EP3 — device → host HID lt-rpc */
#define EPNUM_HID_FIDO_OUT   0x04  /* OUT EP4 — host → device HID FIDO */
#define EPNUM_HID_FIDO_IN    0x84  /* IN  EP4 — device → host HID FIDO */
#define EPNUM_CCID_OUT       0x05  /* OUT EP5 — host → device CCID bulk */
#define EPNUM_CCID_IN        0x85  /* IN  EP5 — device → host CCID bulk */

/* Exposed for usb_ccid.c via extern in usb_ccid.h — single source of
 * truth so the descriptor and the driver agree on EP addresses. */
const uint8_t USB_CCID_EP_OUT = EPNUM_CCID_OUT;
const uint8_t USB_CCID_EP_IN  = EPNUM_CCID_IN;

/* Lengths used by CONFIG_TOTAL_LEN.  CCID interface descriptor block
 * is hand-crafted (TinyUSB has no CCID macro): 9 B interface desc +
 * 54 B class-specific CCID functional desc + 7 B bulk OUT EP desc +
 * 7 B bulk IN EP desc = 77 B total. */
#define TUD_CCID_DESC_LEN    (9u + 54u + 7u + 7u)

#define CONFIG_TOTAL_LEN  (TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN \
                           + 2 * TUD_HID_INOUT_DESC_LEN + TUD_CCID_DESC_LEN)

uint8_t const desc_fs_configuration[] = {
    /* Config descriptor: 1 config, ITF_NUM_TOTAL interfaces, 100 mA bus-powered */
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN, 0x00, 100),

    /* CDC: notif + data interfaces (IAD prefixed by macro) */
    TUD_CDC_DESCRIPTOR(ITF_NUM_CDC_NOTIF, 4, EPNUM_CDC_NOTIF, 8,
                       EPNUM_CDC_OUT, EPNUM_CDC_IN, 64),

    /* HID #0 lt-rpc: raw 64-byte IN + OUT, 1 ms polling */
    TUD_HID_INOUT_DESCRIPTOR(ITF_NUM_HID_LTRPC, 5, HID_ITF_PROTOCOL_NONE,
                             sizeof(desc_hid_report_ltrpc),
                             EPNUM_HID_LTRPC_OUT, EPNUM_HID_LTRPC_IN, 64, 1),

    /* HID #1 FIDO2: raw 64-byte IN + OUT, 5 ms polling
     * (5 ms matches FIDO U2F spec recommended bInterval; 1 ms also legal) */
    TUD_HID_INOUT_DESCRIPTOR(ITF_NUM_HID_FIDO, 6, HID_ITF_PROTOCOL_NONE,
                             sizeof(desc_hid_report_fido),
                             EPNUM_HID_FIDO_OUT, EPNUM_HID_FIDO_IN, 64, 5),

    /* CCID interface — Phase 7 M1.  Hand-crafted because TinyUSB has
     * no CCID descriptor macro.  Class 0x0B + functional descriptor +
     * 2 bulk endpoints.  See CCID spec rev 1.1 §5. */

    /* Interface descriptor (9 bytes) */
    9,                              /* bLength */
    TUSB_DESC_INTERFACE,            /* bDescriptorType */
    ITF_NUM_CCID,                   /* bInterfaceNumber */
    0,                              /* bAlternateSetting */
    2,                              /* bNumEndpoints — bulk OUT + bulk IN */
    TUSB_CLASS_SMART_CARD,          /* bInterfaceClass = 0x0B */
    0,                              /* bInterfaceSubClass */
    0,                              /* bInterfaceProtocol (0=CCID-no-ICC, OK for ICCD) */
    7,                              /* iInterface — STR_CCID_INTERFACE */

    /* CCID class-specific functional descriptor (54 bytes, type 0x21) */
    54,                             /* bLength */
    0x21,                           /* bDescriptorType — CCID functional */
    0x10, 0x01,                     /* bcdCCID = 1.10 LE */
    0x00,                           /* bMaxSlotIndex = 0 (single slot) */
    0x07,                           /* bVoltageSupport = 5V|3V|1.8V */
    0x03, 0x00, 0x00, 0x00,         /* dwProtocols = T=0 | T=1 (LE) */
    0xA0, 0x0F, 0x00, 0x00,         /* dwDefaultClock = 4000 kHz */
    0xA0, 0x0F, 0x00, 0x00,         /* dwMaximumClock = 4000 kHz */
    0x00,                           /* bNumClockSupported = 0 (default only) */
    0x80, 0x25, 0x00, 0x00,         /* dwDataRate = 9600 bps */
    0x80, 0x25, 0x00, 0x00,         /* dwMaxDataRate = 9600 bps */
    0x00,                           /* bNumDataRatesSupported = 0 */
    0xFE, 0x00, 0x00, 0x00,         /* dwMaxIFSD = 254 (T=1 max) */
    0x00, 0x00, 0x00, 0x00,         /* dwSynchProtocols = 0 */
    0x00, 0x00, 0x00, 0x00,         /* dwMechanical = 0 (no mechanical) */
    0x40, 0x08, 0x04, 0x00,         /* dwFeatures = 0x00040840 LE:
                                       0x00000040 auto param neg
                                     | 0x00000800 auto IFSD exchange
                                     | 0x00040000 short + extended APDU level */
    0x10, 0x10, 0x00, 0x00,         /* dwMaxCCIDMessageLength = 4112 LE */
    0xFF,                           /* bClassGetResponse — echo CLA */
    0xFF,                           /* bClassEnvelope — echo CLA */
    0x00, 0x00,                     /* wLcdLayout = 0 (no LCD) */
    0x00,                           /* bPINSupport = 0 */
    0x01,                           /* bMaxCCIDBusySlots = 1 */

    /* Bulk OUT endpoint (7 bytes) */
    7,                              /* bLength */
    TUSB_DESC_ENDPOINT,             /* bDescriptorType */
    EPNUM_CCID_OUT,                 /* bEndpointAddress */
    TUSB_XFER_BULK,                 /* bmAttributes */
    U16_TO_U8S_LE(64),              /* wMaxPacketSize = 64 */
    0,                              /* bInterval (unused for bulk) */

    /* Bulk IN endpoint (7 bytes) */
    7,                              /* bLength */
    TUSB_DESC_ENDPOINT,             /* bDescriptorType */
    EPNUM_CCID_IN,                  /* bEndpointAddress */
    TUSB_XFER_BULK,                 /* bmAttributes */
    U16_TO_U8S_LE(64),              /* wMaxPacketSize = 64 */
    0,                              /* bInterval */
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
    STR_HID_LTRPC_INTERFACE,
    STR_HID_FIDO_INTERFACE,
    STR_CCID_INTERFACE,
};

static char const *string_desc_arr[] = {
    [STR_LANGID]              = (const char[]){0x09, 0x04},  /* en-US: 0x0409 LE */
    [STR_MANUFACTURER]        = "nixtropic",
    [STR_PRODUCT]             = "nixtropic Phase 7",
    [STR_SERIAL]              = "0001",
    [STR_CDC_INTERFACE]       = "nixtropic CDC console",
    [STR_HID_LTRPC_INTERFACE] = "nixtropic HID lt-rpc",
    [STR_HID_FIDO_INTERFACE]  = "nixtropic FIDO2",
    [STR_CCID_INTERFACE]      = "nixtropic CCID Reader",
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
