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
#   - Adds udev rules for TS1302 in app mode (0483:5740 stock fw,
#     cafe:4001 nixtropic open fw) and DFU mode (0483:df11), giving
#     the `tropic` group r/w access without sudo
#   - Configures pcsc-lite + a patched libccid that recognises our CCID
#     interface (VID 0xCAFE PID 0x4001).  Without this patch, libccid
#     silently refuses to drive cafe:4001 even though the device
#     correctly advertises USB class 0x0B (smart card reader).
#   - Optionally adds specified users to the `tropic` group
#
# What it does NOT do (yet):
#   - Run any service
#   - Configure system-wide PKCS#11 module path
#   - Set up firmware auto-update

let
  cfg = config.services.tropic;

  # libccid (the pcsc-lite USB CCID driver) ships with a hardcoded
  # Info.plist listing 607 supported VID:PID pairs.  Our TinyUSB demo
  # VID:PID `0xCAFE:0x4001` is NOT in that list — libccid silently
  # refuses to drive any device whose ID isn't in the list, even when
  # the device correctly advertises USB class 0x0B (Smart Card).
  #
  # The override below appends a single nixtropic entry to each of the
  # three parallel arrays (ifdVendorID, ifdProductID, ifdFriendlyName)
  # in Info.plist via awk.  Existing 607 readers are untouched.
  #
  # Real fix (tracked in docs/BACKLOG.md §5.2): pid.codes-allocated
  # VID:PID + upstream PR to libccid.  For now this patch keeps the
  # test surface clean.
  ccidWithNixtropic = pkgs.ccid.overrideAttrs (old: {
    postFixup = (old.postFixup or "") + ''
      INFO="$out/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist"
      if [ ! -f "$INFO" ]; then
        echo "ERROR: ccid Info.plist not found at $INFO"
        exit 1
      fi

      ${pkgs.gawk}/bin/awk '
        /<key>ifdVendorID<\/key>/      { stage="vid";  print; next }
        /<key>ifdProductID<\/key>/     { stage="pid";  print; next }
        /<key>ifdFriendlyName<\/key>/  { stage="name"; print; next }
        /<\/array>/ {
          if (stage == "vid")  { print "\t\t<string>0xCAFE</string>" }
          if (stage == "pid")  { print "\t\t<string>0x4001</string>" }
          if (stage == "name") { print "\t\t<string>nixtropic CCID Reader</string>" }
          stage = ""
          print
          next
        }
        { print }
      ' "$INFO" > "$INFO.new"
      mv "$INFO.new" "$INFO"

      # Sanity-check the patch landed.
      if ! grep -q "0xCAFE" "$INFO"; then
        echo "ERROR: 0xCAFE not present in patched Info.plist"
        exit 1
      fi
    '';
  });
in
{
  options.services.tropic = {
    enable = lib.mkEnableOption "Tropic Square TROPIC01 dongle (TS1302) udev support";

    enableCcid = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Enable pcsc-lite with a libccid override that recognises the
        nixtropic CCID interface (VID 0xCAFE PID 0x4001).  Required for
        OpenPGP card functionality (`gpg --card-status`, `git commit -S`,
        SSH via gpg-agent).  Set to false if you only use the dongle as
        a FIDO2 key (HID transport).
      '';
    };

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

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
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
        #   2. nixtropic open firmware: VID cafe PID 4001 (TinyUSB demo
        #      defaults — pid.codes allocation tracked in
        #      docs/BACKLOG.md §5.2)
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

        # ----- nixtropic open firmware in app mode -----
        SUBSYSTEM=="tty", ATTRS{idVendor}=="cafe", ATTRS{idProduct}=="4001", \
          GROUP="${cfg.groupName}", MODE="0660", \
          SYMLINK+="tropic01-open", \
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
    }

    # pcsc-lite + patched libccid for CCID OpenPGP card transport.
    # Guarded by enableCcid so FIDO-only users aren't forced to install
    # pcscd.
    (lib.mkIf cfg.enableCcid {
      services.pcscd.enable = true;
      services.pcscd.plugins = lib.mkForce [ ccidWithNixtropic ];
    })
  ]);

  meta = {
    maintainers = [ ];
  };
}
