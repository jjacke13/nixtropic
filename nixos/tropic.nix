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
      # Three USB identities the dongle can show up as:
      #   1. Stock firmware app mode: VID 0483 PID 5740 (ST CDC-ACM,
      #      labeled "TropicSquare SPI interface")
      #   2. Custom Phase 1 firmware: VID cafe PID 4001 (TinyUSB demo
      #      defaults — real allocation deferred to Phase 8 ship-prep)
      #   3. STM32 DFU bootloader: VID 0483 PID df11
      #
      # All three get group/permission + ID_MM_DEVICE_IGNORE so:
      #   - Nix-flake apps work without sudo for `${cfg.groupName}` members
      #   - ModemManager (NixOS default) does NOT auto-probe the dongle and
      #     hold /dev/ttyACM* hostage from picocom

      # ----- Stock firmware in app mode -----
      SUBSYSTEM=="tty", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="5740", \
        GROUP="${cfg.groupName}", MODE="0660", \
        SYMLINK+="tropic01", \
        ENV{ID_MM_DEVICE_IGNORE}="1", \
        TAG+="uaccess"
      SUBSYSTEM=="usb", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="5740", \
        GROUP="${cfg.groupName}", MODE="0660", \
        ENV{ID_MM_DEVICE_IGNORE}="1", \
        TAG+="uaccess"

      # ----- Custom Phase 1 firmware in app mode -----
      SUBSYSTEM=="tty", ATTRS{idVendor}=="cafe", ATTRS{idProduct}=="4001", \
        GROUP="${cfg.groupName}", MODE="0660", \
        SYMLINK+="tropic01-phase1", \
        ENV{ID_MM_DEVICE_IGNORE}="1", \
        TAG+="uaccess"
      SUBSYSTEM=="usb", ATTRS{idVendor}=="cafe", ATTRS{idProduct}=="4001", \
        GROUP="${cfg.groupName}", MODE="0660", \
        ENV{ID_MM_DEVICE_IGNORE}="1", \
        TAG+="uaccess"

      # ----- DFU bootloader (any TS1302 firmware can drop into DFU) -----
      SUBSYSTEM=="usb", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="df11", \
        GROUP="${cfg.groupName}", MODE="0660", \
        ENV{ID_MM_DEVICE_IGNORE}="1", \
        TAG+="uaccess"
    '';
  };

  meta = {
    maintainers = [ ];
  };
}
