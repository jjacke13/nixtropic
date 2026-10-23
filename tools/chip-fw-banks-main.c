/*
 * tools/chip-fw-banks-main.c
 *
 * Read-only check of a TROPIC01 after a chip firmware update (Tropic Square
 * app note ODN_TR01_app_007 v1.5 §3, p12 step 10 / p13 step 11):
 *   step 10: all four bank headers — App FW bank 1 and 2 hold the same image,
 *            SPECT bank 1 and 2 the same image, at the expected versions;
 *   step 11: back in Application mode, the running App and SPECT versions.
 * `chip-fw-version` alone shows only what the chip booted from.
 *
 * Flow: lt_init → maintenance reboot (Get_Info FW_BANK is a Start-up-mode
 * request, user API 1.4.0 §3 Table 1) → four Get_Info(FW_BANK) reads →
 * regular reboot, attempted on every path once the maintenance reboot was
 * tried → running-version reads → lt_deinit.  lt_reboot itself checks the
 * resulting mode.  Sends no update, erase, configuration or provisioning
 * command (the chip's own boot may still do internal recovery writes).
 *
 * Needs the stock firmware on the dongle (CDC SPI passthrough), like
 * chip-fw-version.  Exit 0 only when every check passes.
 */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "libtropic.h"
#include "libtropic_common.h"
#include "libtropic_port_posix_usb_dongle.h"
#include "libtropic_openssl.h"   /* lt_ctx_openssl_t */

/* ponytail: the versions nixtropic v0.3.2 requires; edit here when that changes. */
#define EXPECT_CPU_VER   0x02000000u   /* App FW 2.0.0 */
#define EXPECT_SPECT_VER 0x01000000u   /* SPECT FW 1.0.0 */

typedef struct {
    lt_bank_id_t id;
    const char *name;
    int ok;                 /* header read and parsed */
    lt_header_boot_v2_t hdr;
} bank_t;

static void ver_str(uint32_t v, char out[16])
{
    snprintf(out, 16, "%u.%u.%u", (unsigned) (v >> 24) & 0xFF,
             (unsigned) (v >> 16) & 0xFF, (unsigned) (v >> 8) & 0xFF);
}

static int read_bank(lt_handle_t *h, bank_t *b)
{
    uint8_t buf[TR01_L2_GET_INFO_FW_HEADER_SIZE] = {0};
    uint16_t len = 0;
    lt_ret_t r = lt_get_info_fw_bank(h, b->id, buf, sizeof buf, &len);
    if (r != LT_OK) {
        printf("  %-7s read failed: %s\n", b->name, lt_ret_verbose(r));
        return 0;
    }
    if (len == TR01_L2_GET_INFO_FW_HEADER_SIZE_BOOT_V2_EMPTY_BANK) {
        printf("  %-7s EMPTY bank\n", b->name);
        return 0;
    }
    if (len != sizeof b->hdr) {
        printf("  %-7s unexpected header size %u (bootloader v2 header is %zu)\n",
               b->name, len, sizeof b->hdr);
        return 0;
    }
    memcpy(&b->hdr, buf, sizeof b->hdr);

    char v[16], pv[16], hash[65];
    ver_str(b->hdr.ver, v);
    ver_str(b->hdr.pair_version, pv);
    for (int i = 0; i < 32; i++) snprintf(hash + 2 * i, 3, "%02x", b->hdr.hash[i]);
    printf("  %-7s type %u  version %-7s size %6" PRIu32 "  git %08" PRIx32
           "  pair %s\n          sha256 %s\n",
           b->name, b->hdr.type, v, b->hdr.size, b->hdr.git_hash,
           b->hdr.pair_version ? pv : "any", hash);
    return 1;
}

static int same_image(const bank_t *a, const bank_t *b)
{
    return a->hdr.ver == b->hdr.ver && a->hdr.size == b->hdr.size
        && memcmp(a->hdr.hash, b->hdr.hash, sizeof a->hdr.hash) == 0;
}

static int check(int cond, const char *what)
{
    printf("  %s %s\n", cond ? "✓" : "✗", what);
    return cond;
}

/* Step 11: running versions, Application mode. */
static int check_running(lt_handle_t *h)
{
    uint8_t cpu[TR01_L2_GET_INFO_RISCV_FW_SIZE] = {0};
    uint8_t spect[TR01_L2_GET_INFO_SPECT_FW_SIZE] = {0};
    lt_ret_t r = lt_get_info_riscv_fw_ver(h, cpu);
    if (r == LT_OK) r = lt_get_info_spect_fw_ver(h, spect);
    if (r != LT_OK) {
        printf("  ✗ running-version read failed: %s\n", lt_ret_verbose(r));
        return 0;
    }
    uint32_t c = (uint32_t) cpu[3] << 24 | (uint32_t) cpu[2] << 16 | (uint32_t) cpu[1] << 8;
    uint32_t s = (uint32_t) spect[3] << 24 | (uint32_t) spect[2] << 16 | (uint32_t) spect[1] << 8;
    char cv[16], sv[16], what[96];
    ver_str(c, cv);
    ver_str(s, sv);
    snprintf(what, sizeof what, "running App FW %s, SPECT FW %s (Application mode)", cv, sv);
    return check(c == EXPECT_CPU_VER && s == EXPECT_SPECT_VER, what);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    const char *dev_path = LT_USB_DEVKIT_PATH;
    if (argc > 1) dev_path = argv[1];

    lt_handle_t handle = {0};
    lt_dev_posix_usb_dongle_t device = {0};
    lt_ctx_openssl_t crypto_ctx;

    int n = snprintf(device.dev_path, sizeof device.dev_path, "%s", dev_path);
    if (n < 0 || (size_t) n >= sizeof device.dev_path) {
        fprintf(stderr, "ERROR: device path too long for libtropic buffer.\n");
        return 1;
    }
    device.baud_rate = 115200;
    handle.l2.device = &device;
    handle.l3.crypto_ctx = &crypto_ctx;

    lt_ret_t r = lt_init(&handle);
    if (r != LT_OK) {
        fprintf(stderr, "ERROR: lt_init: %s\n", lt_ret_verbose(r));
        return 1;
    }

    bank_t banks[4] = {
        { TR01_FW_BANK_FW1,    "FW1",    0, {0} },
        { TR01_FW_BANK_FW2,    "FW2",    0, {0} },
        { TR01_FW_BANK_SPECT1, "SPECT1", 0, {0} },
        { TR01_FW_BANK_SPECT2, "SPECT2", 0, {0} },
    };

    printf("Maintenance reboot (read-only bank inspection) ...\n");
    lt_ret_t rm = lt_reboot(&handle, TR01_MAINTENANCE_REBOOT);
    if (rm != LT_OK) {
        printf("  ✗ lt_reboot(TR01_MAINTENANCE_REBOOT): %s\n", lt_ret_verbose(rm));
    } else {
        for (int i = 0; i < 4; i++) banks[i].ok = read_bank(&handle, &banks[i]);
    }

    /* Every path past the maintenance attempt: try to return to Application
     * mode (a lost reply may have left the chip in maintenance anyway). */
    printf("Reboot back to Application mode ...\n");
    lt_ret_t rb = lt_reboot(&handle, TR01_REBOOT);
    int pass = rm == LT_OK;
    printf("\nChecks:\n");
    if (rb != LT_OK) {
        printf("  ✗ lt_reboot(TR01_REBOOT): %s — power-cycle the dongle.\n", lt_ret_verbose(rb));
        pass = 0;
    } else {
        pass &= check_running(&handle);
    }
    lt_deinit(&handle);

    for (int i = 0; i < 4; i++) {
        char what[64];
        snprintf(what, sizeof what, "%s header present", banks[i].name);
        pass &= check(banks[i].ok, what);
    }
    if (banks[0].ok && banks[1].ok && banks[2].ok && banks[3].ok) {
        char e[16], what[96];
        pass &= check(banks[0].hdr.type == 1 && banks[1].hdr.type == 1
                      && banks[2].hdr.type == 2 && banks[3].hdr.type == 2,
                      "bank types (App = 1, SPECT = 2)");
        ver_str(EXPECT_CPU_VER, e);
        snprintf(what, sizeof what, "FW1 == FW2 (version, size, hash) at App FW %s", e);
        pass &= check(same_image(&banks[0], &banks[1]) && banks[0].hdr.ver == EXPECT_CPU_VER, what);
        ver_str(EXPECT_SPECT_VER, e);
        snprintf(what, sizeof what, "SPECT1 == SPECT2 (version, size, hash) at SPECT FW %s", e);
        pass &= check(same_image(&banks[2], &banks[3]) && banks[2].hdr.ver == EXPECT_SPECT_VER, what);
    }
    printf("\n%s\n", pass ? "✓ ALL FOUR BANKS AND RUNNING FW OK" : "✗ CHECK FAILED");
    return pass ? 0 : 1;
}
