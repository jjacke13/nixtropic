/*
 * tools/fw-update-chip-main.c
 *
 * One-shot TROPIC01 application-firmware updater.  Adapted from libtropic
 * v3.2.1's examples/linux/usb_devkit/fw_update/main.c, but built against
 * the OpenSSL CAL (universally available in nixpkgs) instead of mbedtls v4
 * (which uses PSA crypto and an internet FetchContent we can't use in a
 * Nix sandbox).
 *
 * Flow (ACAB silicon — confirmed for our TR01-C2P-T101 dongle):
 *
 *   1. Read current App + SPECT FW versions (from running App Mode).
 *   2. Prompt user to confirm (y/Y).
 *   3. Maintenance-reboot → update FW_BANK_FW1 + FW_BANK_SPECT1.
 *   4. Maintenance-reboot AGAIN — required on ACAB so the second bank
 *      pair is also written (libtropic 3.2.1 changelog headline fix;
 *      without this the chip would retain old FW in the standby bank
 *      and be vulnerable to a downgrade).
 *   5. Update FW_BANK_FW2 + FW_BANK_SPECT2.
 *   6. Reboot to App Mode, print new versions.
 *
 * Risk: very low brick.  Mid-flight interrupt leaves chip in Maintenance
 * Mode; just re-run.  No JTAG/recovery hardware needed.  Factory data
 * (pairing keys, chip ID, certs, R-config, I-config) is untouched.
 *
 * IRREVERSIBLE: chip rejects FW downgrade after a successful update.
 * Once we go to 2.0.0 we can't go back to the original 0.3.1.
 */

#include <stdio.h>
#include <string.h>

#include "libtropic.h"
#include "libtropic_common.h"
#include "libtropic_port_posix_usb_dongle.h"
#include "libtropic_openssl.h"   /* lt_ctx_openssl_t */

/* CMake includes these via the bundled TROPIC01_fw_update_files/.
 * The pinned libtropic source provides 1.0.0 / 1.0.1 / 2.0.0 binaries
 * for ACAB silicon — selected at configure-time via -DLT_CPU_FW_UPDATE_DATA_VER. */
#include "fw_CPU.h"
#include "fw_SPECT.h"

static lt_ret_t print_fw_versions(lt_handle_t *h, const char *label)
{
    uint8_t cpu_ver[TR01_L2_GET_INFO_RISCV_FW_SIZE]  = {0};
    uint8_t spct_ver[TR01_L2_GET_INFO_SPECT_FW_SIZE] = {0};

    lt_ret_t r = lt_get_info_riscv_fw_ver(h, cpu_ver);
    if (r != LT_OK) {
        fprintf(stderr, "  ! lt_get_info_riscv_fw_ver: %s\n", lt_ret_verbose(r));
        return r;
    }
    r = lt_get_info_spect_fw_ver(h, spct_ver);
    if (r != LT_OK) {
        fprintf(stderr, "  ! lt_get_info_spect_fw_ver: %s\n", lt_ret_verbose(r));
        return r;
    }
    printf("  %s App FW = %u.%u.%u   SPECT FW = %u.%u.%u\n",
           label,
           cpu_ver[3],  cpu_ver[2],  cpu_ver[1],
           spct_ver[3], spct_ver[2], spct_ver[1]);
    return LT_OK;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  TROPIC01 application-firmware updater (nixtropic)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    const char *dev_path = LT_USB_DEVKIT_PATH;
    if (argc > 1) dev_path = argv[1];

    printf("Reader device:   %s\n", dev_path);
    printf("Target App FW:   "  LT_TARGET_VERSION_CPU   "\n");
    printf("Target SPECT FW: " LT_TARGET_VERSION_SPECT "\n\n");

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

    printf("Initializing handle ...\n");
    lt_ret_t r = lt_init(&handle);
    if (r != LT_OK) {
        fprintf(stderr, "  ! lt_init: %s\n", lt_ret_verbose(r));
        return 1;
    }

    printf("Rebooting to App Mode to read current FW versions ...\n");
    r = lt_reboot(&handle, TR01_REBOOT);
    if (r != LT_OK) {
        fprintf(stderr, "  ! lt_reboot(TR01_REBOOT): %s\n", lt_ret_verbose(r));
        lt_deinit(&handle);
        return 1;
    }
    if (print_fw_versions(&handle, "Current:") != LT_OK) {
        lt_deinit(&handle);
        return 1;
    }

    printf("\nProceed with update?  This is IRREVERSIBLE — the chip rejects\n"
           "FW downgrade after a successful update.  Type 'y' or 'Y' to proceed,\n"
           "anything else to abort: ");
    int c = getchar();
    if (c != 'y' && c != 'Y') {
        printf("\nAborted by user.  No changes made.\n");
        lt_deinit(&handle);
        return 0;
    }
    printf("\n");

    /* ------ Bank pair 1 ------ */
    printf("Step 1/4: Maintenance reboot ...\n");
    r = lt_reboot(&handle, TR01_MAINTENANCE_REBOOT);
    if (r != LT_OK) { fprintf(stderr, "  ! %s\n", lt_ret_verbose(r)); goto fail; }

    printf("Step 2/4: Writing FW_BANK_FW1 (App FW, %zu B) ...\n", sizeof fw_CPU);
    r = lt_do_mutable_fw_update(&handle, fw_CPU, sizeof fw_CPU, TR01_FW_BANK_FW1);
    if (r != LT_OK) { fprintf(stderr, "  ! %s\n", lt_ret_verbose(r)); goto fail; }

    printf("Step 2/4: Writing FW_BANK_SPECT1 (SPECT FW, %zu B) ...\n", sizeof fw_SPECT);
    r = lt_do_mutable_fw_update(&handle, fw_SPECT, sizeof fw_SPECT, TR01_FW_BANK_SPECT1);
    if (r != LT_OK) { fprintf(stderr, "  ! %s\n", lt_ret_verbose(r)); goto fail; }

    /* ------ Bank pair 2 (CRITICAL — without this, downgrade vulnerability) ------ */
    printf("Step 3/4: Maintenance reboot (required for second bank pair) ...\n");
    r = lt_reboot(&handle, TR01_MAINTENANCE_REBOOT);
    if (r != LT_OK) { fprintf(stderr, "  ! %s\n", lt_ret_verbose(r)); goto fail; }

    printf("Step 4/4: Writing FW_BANK_FW2 + FW_BANK_SPECT2 ...\n");
    r = lt_do_mutable_fw_update(&handle, fw_CPU,   sizeof fw_CPU,   TR01_FW_BANK_FW2);
    if (r != LT_OK) { fprintf(stderr, "  ! %s\n", lt_ret_verbose(r)); goto fail; }
    r = lt_do_mutable_fw_update(&handle, fw_SPECT, sizeof fw_SPECT, TR01_FW_BANK_SPECT2);
    if (r != LT_OK) { fprintf(stderr, "  ! %s\n", lt_ret_verbose(r)); goto fail; }

    printf("\nAll four banks updated successfully.  Rebooting to App Mode ...\n");
    r = lt_reboot(&handle, TR01_REBOOT);
    if (r != LT_OK) { fprintf(stderr, "  ! %s\n", lt_ret_verbose(r)); goto fail; }

    if (print_fw_versions(&handle, "New:    ") != LT_OK) goto fail;

    printf("\n✓ TROPIC01 firmware updated.\n");
    lt_deinit(&handle);
    return 0;

fail:
    fprintf(stderr,
            "\n✗ Update FAILED partway through.  The chip should be in\n"
            "  Maintenance Mode.  Re-run this tool to retry; chip is NOT bricked\n"
            "  unless this message persists across multiple full re-runs.\n");
    lt_deinit(&handle);
    return 1;
}
