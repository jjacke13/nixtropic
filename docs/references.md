# References

The documents the implementation and these pages rely on, at the versions used.

## TROPIC01

All from [tropicsquare/tropic01](https://github.com/tropicsquare/tropic01/tree/90747cac7c0261408c0ca767d272894f481f2cf2/doc)
at commit `90747ca`.

| Short name | Document |
|---|---|
| Datasheet | [ODD_TR01 datasheet A.11](https://github.com/tropicsquare/tropic01/blob/90747cac7c0261408c0ca767d272894f481f2cf2/doc/datasheet/ODD_TR01_datasheet_vA_11.pdf) (2025-11-11) |
| User API | [ODU_TR01 User API 1.4.0](https://github.com/tropicsquare/tropic01/blob/90747cac7c0261408c0ca767d272894f481f2cf2/doc/api/ODU_TR01_user_api_v1_4_0.pdf) |
| PIN verification | [ODN_TR01_app_002 PIN Verification 1.2](https://github.com/tropicsquare/tropic01/blob/90747cac7c0261408c0ca767d272894f481f2cf2/doc/application_notes/ODN_TR01_app_002_pin_verif_1v2.pdf) |
| PKI | [ODN_TR01_app_003 PKI 1.3](https://github.com/tropicsquare/tropic01/blob/90747cac7c0261408c0ca767d272894f481f2cf2/doc/application_notes/ODN_TR01_app_003_pki_1v3.pdf) |
| First pairing key | [ODN_TR01_app_005 1.3](https://github.com/tropicsquare/tropic01/blob/90747cac7c0261408c0ca767d272894f481f2cf2/doc/application_notes/ODN_TR01_app_005_first_pairing_key_1v3.pdf) |
| Configuration objects | [ODN_TR01_app_006 1.3](https://github.com/tropicsquare/tropic01/blob/90747cac7c0261408c0ca767d272894f481f2cf2/doc/application_notes/ODN_TR01_app_006_config_obj_1v3.pdf) |
| Firmware update | [ODN_TR01_app_007 1.5](https://github.com/tropicsquare/tropic01/blob/90747cac7c0261408c0ca767d272894f481f2cf2/doc/application_notes/ODN_TR01_app_007_fw_update_1v5.pdf) |
| Security architecture | [ODN_TR01_app_008 1.1](https://github.com/tropicsquare/tropic01/blob/90747cac7c0261408c0ca767d272894f481f2cf2/doc/application_notes/ODN_TR01_app_008_sec_arch_1v1.pdf) |
| Catalog list | [OD_TR01 Catalog List 2.0](https://github.com/tropicsquare/tropic01/blob/90747cac7c0261408c0ca767d272894f481f2cf2/doc/catalog_list/OD_TR01_catalog_list_2v0.pdf) |
| Part page and errata | [TR01-C2P-T101](https://github.com/tropicsquare/tropic01/blob/90747cac7c0261408c0ca767d272894f481f2cf2/doc/pages/parts/TR01-C2P-T101.md) |
| LFI advisory | [ODR_TR01_SA_2026012900 1.0](https://github.com/tropicsquare/tropic01/blob/90747cac7c0261408c0ca767d272894f481f2cf2/doc/security_advisories/ODR_TR01_SA_2026012900_1v0.pdf) (disclosed 2026-06-03) |
| SDK | [libtropic v3.2.1](https://github.com/tropicsquare/libtropic/tree/51044cdc2e0aabff42305130b344c5db3136f158) |
| Board | [TS1302 stock firmware and schematic](https://github.com/tropicsquare/tropic01-stm32u5-usb-devkit-fw/tree/36a40baa802cf226e07296604afea24780fd09d1) |

## STM32U535

| Document | |
|---|---|
| [DS14217](https://www.st.com/resource/en/datasheet/stm32u535cb.pdf) | STM32U535xx datasheet, Rev 5 |
| [RM0456](https://www.st.com/resource/en/reference_manual/rm0456-stm32u575585-armbased-32bit-mcus-stmicroelectronics.pdf) | STM32U5 reference manual |
| [ES0587](https://www.st.com/content/st_com/en/technical-documents/es0587-stm32u535xx-and-stm32u545xx-device-errata-stmicroelectronics.html) | STM32U535/545 errata sheet |
| [AN5347](https://www.st.com/content/st_com/en/technical-documents/an5347-introduction-to-arm-trustzone-features-on-stm32l5-stm32u5-and-stm32u3-mcus-stmicroelectronics_asset/chunk-003-topic-an5347-rdp.html) | TrustZone and RDP on STM32U5 |
| [AN4759](https://www.st.com/content/st_com/en/technical-documents/an4759-introduction-to-using-the-hardware-realtime-clock-rtc-and-the-tamper-management-unit-tamp-for-stm32-mcus-stmicroelectronics_asset/chunk-007-topic-an4759-backup-registers.html) | RTC and TAMP (backup registers, boot hardware key) |

## Protocols

Which specification each USB interface of the dongle follows:

| USB interface | Follows | Key sections |
|---|---|---|
| FIDO2 (HID, usage page `0xF1D0`) | **CTAP 2.2** for the USB HID transport; **CTAP 2.1** for the authenticator commands (GetInfo reports `FIDO_2_0`, see [status](status.md)) | transport: [§11.2 USB](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#usb), [KEEPALIVE](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#usb-hid-keepalive), [CANCEL](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#usb-hid-cancel), [INIT](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#usb-hid-init); commands: [§6 Authenticator API](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticator-api), [§8 Message encoding](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#message-encoding) |
| Smart card (CCID) | **USB CCID 1.1** for the transport, **ISO/IEC 7816-4** for the APDUs, **OpenPGP card 3.4.1** for the application | Ed25519 / Cv25519 keys, PINs, touch policy (UIF): see [card setup](card-setup.md) |
| Debug build only: CDC console, lt-rpc HID | project-specific | [architecture](architecture.md) |

| Specification | Version |
|---|---|
| [FIDO CTAP 2.2](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html) | Proposed Standard, 2025-07-14 (USB HID transport) |
| [FIDO CTAP 2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html) | Proposed Standard, 2021-06-15 (the command level implemented) |
| [W3C WebAuthn](https://www.w3.org/TR/webauthn-2/) | Level 2 |
| [OpenPGP smart card application](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf) | 3.4.1 |
| [USB-IF Smart Card CCID class](https://www.usb.org/sites/default/files/DWG_Smart-Card_CCID_Rev110.pdf) | 1.1 |
| [ISO/IEC 7816-4](https://www.iso.org/standard/77180.html) | 2020 (commands and responses; paywalled) |
| [Noise Protocol Framework](https://noiseprotocol.org/noise.html) | revision 34 |

## Related projects

- [SoloKeys](https://github.com/solokeys/solo) and [CanoKey](https://github.com/canokeys/canokey-core):
  open FIDO2 / OpenPGP firmware, used as cross-references.
- [trezor-crypto](https://github.com/trezor/trezor-firmware/tree/main/crypto): the software
  cryptography library, shipped with libtropic.
