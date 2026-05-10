{ config, lib, pkgs, ... }:

# NixOS module for TS1302 TROPIC01 USB devkit access.
#
# Enable with:
#
#   {
#     imports = [ inputs.nixtropic.nixosModules.tropic ];
#     services.tropic.enable = true;
#     services.tropic.users = [ "jacke" ];
#   }
#
# What it does:
#   - Creates a `tropic` group
#   - Adds udev rules for TS1302 in app mode (0483:5740) and DFU mode
#     (0483:df11), giving the `tropic` group read+write access without sudo
#   - Optionally adds specified users to the `tropic` group
#
# What it does NOT do (yet — Phase 8):
#   - Run any service
#   - Configure system-wide PKCS#11 module path
#   - Set up firmware auto-update
#
# These follow when the firmware project gets to Phase 8.

let
  cfg = config.services.tropic;
in
{
  options.services.tropic = {
    enable = lib.mkEnableOption "Tropic Square TROPIC01 dongle (TS1302) udev support";

    users = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        Users to add to the `tropic` group, granting them USB access to the
        TS1302 dongle in both app mode (`/dev/ttyACM*`) and DFU mode (DFU-class
        device). Without group membership, users would need sudo to access
        the dongle.
      '';
      example = [ "jacke" ];
    };

    groupName = lib.mkOption {
      type = lib.types.str;
      default = "tropic";
      description = "Name of the group granting access to the TS1302 dongle.";
    };
  };

  config = lib.mkIf cfg.enable {
    users.groups.${cfg.groupName} = { };

    users.users = lib.genAttrs cfg.users (user: {
      extraGroups = [ cfg.groupName ];
    });

    services.udev.extraRules = ''
      # Tropic Square TROPIC01 TS1302 USB devkit — udev rules
      #
      # Stock firmware: VID 0483 (STMicroelectronics), PID 5740 (CDC-ACM,
      #   labeled "TropicSquare SPI interface")
      # DFU mode: VID 0483, PID df11 (STM32 factory bootloader)
      #
      # Both modes get the same group + permissions so that Nix-flake apps
      # like `nix run .#flash-stock` and `nix run .#identify` work without
      # sudo for users in the `${cfg.groupName}` group.

      # TS1302 in app mode (CDC-ACM serial)
      SUBSYSTEM=="tty", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="5740", \
        GROUP="${cfg.groupName}", MODE="0660", \
        SYMLINK+="tropic01", \
        TAG+="uaccess"

      # TS1302 in app mode — also expose the bare USB device for diagnostic tools
      SUBSYSTEM=="usb", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="5740", \
        GROUP="${cfg.groupName}", MODE="0660", \
        TAG+="uaccess"

      # TS1302 in DFU mode (STM32 factory bootloader, accessed via dfu-util)
      SUBSYSTEM=="usb", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="df11", \
        GROUP="${cfg.groupName}", MODE="0660", \
        TAG+="uaccess"
    '';
  };

  meta = {
    maintainers = [ ];
  };
}
