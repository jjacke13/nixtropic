/*
 * tools/chip-fw-version-main.c
 *
 * TROPIC01 chip-firmware version reporter.
 *
 * Reports the currently-running App FW + SPECT FW versions on the
 * TROPIC01 chip.  Companion to `fw-update-chip` which can UPDATE these
 * (one-way: chip rejects downgrade after success).
 *
 * Not a pure read: it runs lt_init, then a regular chip reboot into
 * Application mode (lt_reboot TR01_REBOOT, needed because the version
 * queries are Application-mode requests), then the two version
 * queries.  The reboot ends any open secure session.  The tool sends no
 * persistent-write, update or provisioning command, but the chip's own
 * boot may repair internal state in its flash (app 2.0.0 restores a
 * damaged monotonic-counter record from its shadow copy).
 *
 * Requires the dongle to be running the stock TS1302 firmware (the one
 * with the CDC USB↔SPI passthrough that libtropic's
 * libtropic_port_posix_usb_dongle expects).  Our open firmware doesn't
 * expose the L1 SPI passthrough since it's running its own L3 session
 * for FIDO + OpenPGP — re-flash stock first via `nix run .#flash-stock`
 * if you need to inspect the chip directly.
 *
 * The chip's identity (chip_id, silicon rev, serial, etc.) is a
 * separate query — use `nix run .#identify` for that.
 */

#include <stdio.h>
#include <string.h>

#include "libtropic.h"
#include "libtropic_common.h"
#include "libtropic_port_posix_usb_dongle.h"
#include "libtropic_openssl.h"   /* lt_ctx_openssl_t */

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

    /* Regular reboot into Application mode (a real reboot even when the
     * chip is already there; it ends any open session).  Required because
     * lt_get_info_riscv_fw_ver / lt_get_info_spect_fw_ver are App-Mode
     * queries (Maintenance Mode would refuse them). */
    r = lt_reboot(&handle, TR01_REBOOT);
    if (r != LT_OK) {
        fprintf(stderr, "ERROR: lt_reboot(TR01_REBOOT): %s\n", lt_ret_verbose(r));
        lt_deinit(&handle);
        return 1;
    }

    uint8_t cpu_ver[TR01_L2_GET_INFO_RISCV_FW_SIZE]  = {0};
    uint8_t spct_ver[TR01_L2_GET_INFO_SPECT_FW_SIZE] = {0};

    r = lt_get_info_riscv_fw_ver(&handle, cpu_ver);
    if (r != LT_OK) {
        fprintf(stderr, "ERROR: lt_get_info_riscv_fw_ver: %s\n", lt_ret_verbose(r));
        lt_deinit(&handle);
        return 1;
    }
    r = lt_get_info_spect_fw_ver(&handle, spct_ver);
    if (r != LT_OK) {
        fprintf(stderr, "ERROR: lt_get_info_spect_fw_ver: %s\n", lt_ret_verbose(r));
        lt_deinit(&handle);
        return 1;
    }

    printf("App FW    = %u.%u.%u\n",
           cpu_ver[3],  cpu_ver[2],  cpu_ver[1]);
    printf("SPECT FW  = %u.%u.%u\n",
           spct_ver[3], spct_ver[2], spct_ver[1]);

    lt_deinit(&handle);
    return 0;
}
