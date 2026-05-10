# Prior-Art Verification: TROPIC01-backed FIDO2 + OpenPGP-card USB Security Device

_Researched 2026-05-09 by exhaustive search of GitHub, GitLab, Codeberg, Hacker News, Tropic Square's site, 39C3 / FOSDEM programs, and the open web._

---

## 1. TL;DR conclusion

**The niche is open. Confidence: HIGH.** Across every search vector — GitHub repo + code searches, GitLab/Codeberg, conferences (39C3, FOSDEM), Hacker News, Tropic Square's own announcements and roadmap signals — **no project, commercial or open-source, has shipped (or is publicly developing) custom STM32U5/TS1302 firmware that implements USB HID-FIDO2 and/or USB CCID smartcard with TROPIC01 as the cryptographic backend.** The closest near-misses (`nexusclaw`, `cdc-badge-os`, `nitrokey-3-firmware`) each fail one or more of the three required criteria (right MCU + right secure element + right USB persona). Tropic Square explicitly invites custom firmware on the TS1302 ("Users are encouraged to develop custom firmware to leverage these features") and lists their target verticals as crypto wallets, IoT, and decentralized infrastructure — **not** authenticators. The project is greenfield.

---

## 2. Adjacent work

### 2.1 `avp-protocol/nexusclaw` — closest miss, but different category
- **URL:** [github.com/avp-protocol/nexusclaw](https://github.com/avp-protocol/nexusclaw)
- **Last activity:** 2026-02-19 (active, "Coming Soon" branding)
- **Status:** Working firmware, beta / pre-launch
- **What it is:** Custom STM32U535 + TROPIC01 firmware (forked from `tropic01-stm32u5-usb-devkit-fw`) that exposes a **USB CDC-ACM serial** interface implementing the proprietary "AVP" (Agent Vault Protocol) — a credential vault for AI agents (API keys, tokens). License: Apache 2.0.
- **Why it is NOT the same project:** Confirmed by reading [`usb/ux_device_descriptors.c`](https://github.com/avp-protocol/nexusclaw/blob/master/usb/ux_device_descriptors.c) (only `CLASS_TYPE_CDC_ACM` is registered — no HID, no CCID interface descriptors). The host-facing protocol is custom serial, not standards-based FIDO2 (CTAP-HID) or ISO 7816 OpenPGP-card-over-CCID. Browsers, `gpg`/`scdaemon`, and OpenSSH FIDO transports cannot see this device. Different problem (AI credential storage), different protocol shape, different audience.
- **Useful precedent:** It demonstrates that custom STM32U5 firmware on top of `libtropic` is feasible and has been done — the build/flash flow works.

### 2.2 `krim404/cdc-badge-os` — wrong MCU
- **URL:** [github.com/krim404/cdc-badge-os](https://github.com/krim404/cdc-badge-os) (pair to [riatlabs/cdc-badge](https://github.com/riatlabs/cdc-badge))
- **Last activity:** Active (2026-04-24 audit artifacts present)
- **What it is:** Full FIDO2 + OpenPGP + SSH + TOTP + password-manager firmware on the **CDC Badge** (39C3 hardware). Includes `mod_fido2/u2f.cpp`, full FIDO2 PIN logic, sign-counter rate-limiting code, etc. — the "real thing", protocol-wise.
- **Why it is NOT the same project:** Runs on **ESP32-S3**, not STM32U5/TS1302. Different MCU family, different USB stack, different toolchain, different RAM/flash budget. The codebase is C++/ESP-IDF, not C/STM32CubeMX. Source-level reuse to STM32U5 is non-trivial (bring-up of TinyUSB or USBX, rewrite of all boot/peripheral init).
- **Useful precedent:** Confirms TROPIC01 has enough ECC slots + crypto coverage for FIDO2 + OpenPGP card simultaneously. Source code can be studied for protocol layering, but cannot be ported wholesale.

### 2.3 `tropicsquare/libtropic-pkcs11` (and forks `hruboson/tropikey`, `rddl-network/tropic01_pkcs11`) — host-side, not firmware
- **URLs:** [libtropic-pkcs11](https://github.com/tropicsquare/libtropic-pkcs11), [tropikey](https://github.com/hruboson/tropikey), [tropic01_pkcs11](https://github.com/rddl-network/tropic01_pkcs11)
- **Last activity:** 2026-03-27 / 2026-05-08 / 2025-10-28 (all active)
- **What they are:** PKCS#11 modules running on the host PC, talking to a stock-firmware TS1302 over CDC-ACM serial.
- **Why NOT the same:** Don't change the dongle's USB persona. The dongle still appears as `/dev/ttyACM0`, not as a FIDO2 authenticator or smartcard reader. They solve a different problem (give existing tools hardware-backed signing) by putting the protocol stack on the host.
- **Useful precedent:** Maps PKCS#11 mechanisms onto libtropic primitives — directly informs how to implement an OpenPGP card or PIV on top of TROPIC01.

### 2.4 `markusbug/tropic01-base-account` — host-side blockchain wallet
- **URL:** [github.com/markusbug/tropic01-base-account](https://github.com/markusbug/tropic01-base-account)
- **What:** Coinbase ERC-4337 client driving `lt-util` over CDC-ACM. Not firmware.

### 2.5 `tropicsquare/openwrt` — router integration
- **URL:** [github.com/tropicsquare/openwrt](https://github.com/tropicsquare/openwrt)
- **What:** Host-side packaging for OpenWRT routers. Not firmware on the dongle.

### 2.6 Codeberg / GitLab smaller projects — wrong hardware
- [`telliandev/xmr-cdc-badge`](https://codeberg.org/telliandev/xmr-cdc-badge) — Monero on the CDC Badge (ESP32-S3). Wrong MCU.
- `roosemberth/rugart` (gitlab) — PIV smartcard in Rust, but on the CDC Badge. Wrong MCU. (Mentioned in the brief; site-restricted GitLab search didn't surface it directly, but it's known to be CDC-Badge-targeted.)

### 2.7 Trezor Safe 7 — uses TROPIC01, but a wallet
- **URL:** [tropicsquare.com news 2025-10-21](https://www.tropicsquare.com/news-and-events/tropic01-the-future-proof-secure-element-now-in-full-production-and-available-worldwide)
- **What:** Crypto hardware wallet with proprietary firmware and Trezor's protocol over USB. Not a FIDO2 authenticator, not an OpenPGP card. Closed firmware.

### 2.8 `8zppQr/trustzone_tropic01_test` — TrustZone academic demo
- **URL:** [github.com/8zppQr/trustzone_tropic01_test](https://github.com/8zppQr/trustzone_tropic01_test)
- **What:** Japanese academic demo — STM32L5 Nucleo + TROPIC01 + W5500 Ethernet running an HTTP server with TrustZone separation. Not USB, not FIDO2, not CCID. Different category.

### 2.9 `aneemesh-bot/OpenClaw-SPIRE-NHP` — host-side identity service
- **URL:** [github.com/aneemesh-bot/OpenClaw-SPIRE-NHP](https://github.com/aneemesh-bot/OpenClaw-SPIRE-NHP)
- **What:** Single-server SPIRE deployment on Linux, issues SPIFFE X.509 identities. Uses TROPIC01 as backend, but everything runs on the host. Different category.

### 2.10 `libtropic-stm32` forks — all stale tracking forks
The 7 forks of `tropicsquare/libtropic-stm32` are all `Merge pull request from tropicsquare/develop` — passive tracking, no custom feature work. The upstream itself was **archived 2026-02-06**, signaling that Tropic Square considers the STM32 *example* phase done and is not building a flagship STM32 product.

### 2.11 Open-source FIDO2 on STM32 (different SE) — useful precedent
[Nitrokey FIDO2](https://github.com/Nitrokey/nitrokey-fido2-firmware) (STM32L432, no SE — keys in MCU flash), [SoloKey / Solo2](https://github.com/solokeys/solo2) (STM32L432 + Trussed, Rust), [Somu](https://www.crowdsupply.com/solokeys/somu), [LionKey](https://www.hackster.io/news/lionkey-offers-an-open-source-take-on-fido2-compliant-two-factor-and-passwordless-authentication-bd350f4bb47e) (STM32H533, January 2026), various [DIY STM32L432 projects](https://www.hackster.io/emresensoy/diy-fido2-security-key-with-stm32l4-fa292d). **Nitrokey 3** is the closest — it has both FIDO2 and OpenPGP card on STM32 — but uses a Microchip ATECC608 secure element (or no SE in earlier variants), **not TROPIC01**. None of these projects have been ported or forked to use TROPIC01.

---

## 3. Tropic Square's own roadmap signals

Tropic Square is **not signaling** an upcoming first-party FIDO2 / smartcard firmware:

- **Official applications listed on [tropicsquare.com/tropic01](https://tropicsquare.com/tropic01):** "hardware crypto wallets, IoT devices, decentralized infrastructure and more." No mention of FIDO2, security keys, authenticators, OpenPGP card, PIV, or smartcards.
- **News & events page** ([tropicsquare.com/news-and-events](https://www.tropicsquare.com/news-and-events)): zero announcements about any authenticator or smartcard product. Only customer wins mentioned are Trezor Safe 7 (wallet) and ContentWise (OpenWRT router-class systems).
- **Official TS1302 firmware [README](https://github.com/tropicsquare/tropic01-stm32u5-usb-devkit-fw)** literally says: _"This firmware only facilitates raw data transfer between the TROPIC01 and a host-side application... Although this firmware is minimalistic by design, the STM32U535 MCU offers significantly more capabilities (e.g., secure key storage). **Users are encouraged to develop custom firmware to leverage these features for enhanced functionality.**"_ — explicit invitation, not a "we'll do it" reservation.
- **`libtropic-stm32` archived** on 2026-02-06: STM32 examples deemed complete; effort is moving toward `libtropic-rs` / `libtropic-go` / Linux. No "STM32 flagship product" parking-lot signal.
- **39C3 (Dec 2025) talks** ([_The CDC Badge_](https://pretalx.riat.at/39c3/talk/UKSKJF/), [_Programming the TROPIC01_](https://events.ccc.de/congress/2025/hub/en/event/detail/programming-the-tropic01-open-source-secure-e_1f9x) by Pavel Polach): both about programmability and the badge form factor, not about a forthcoming first-party USB authenticator.
- **Hacker News:** only two TROPIC01 stories surfaced ([2025-06-18, 2025-10-21](https://hn.algolia.com/?q=TROPIC01)) — both link to `tropicsquare.com/tropic01` itself; no community discussion about a FIDO2 product.

**Read:** Tropic Square is positioning itself as the silicon vendor whose ecosystem partners (e.g., Trezor for wallets) build end-products. They explicitly want third parties to ship firmware. There is no public signal of an in-house FIDO2 program that would render this work redundant.

---

## 4. Search trail

### GitHub repository searches (all via `gh api`)
| Query | Result |
|---|---|
| `TROPIC01+FIDO2` | 0 |
| `TROPIC01+OpenPGP` | 0 |
| `libtropic+FIDO2` | 0 |
| `TS1302+firmware` | 0 |
| `STM32U5+TROPIC01+FIDO2` | 0 |
| `TROPIC01+security+key` | 0 |
| `TROPIC01+CCID` | 0 |
| `TROPIC01+PIV` | 0 |
| `TROPIC01+ed25519-sk` | 0 |
| `tropic+CTAP` | 0 |
| `tropic+OpenPGP` | 0 |
| `tropic+CCID` | 0 |
| `tropic+SoloKey` | 0 |
| `tropic+nitrokey` | 0 |
| `tropic+yubikey` | 0 |
| `TROPIC01+passkey` | 0 |
| `TROPIC01+WebAuthn` | 0 |
| `TROPIC01+u2f` | 0 |
| `tropic+authenticator` | 1 (unrelated ASP.NET app) |
| `TROPIC01` (sorted updated) | 39 repos — all reviewed; none match (see §2) |
| `libtropic` | 13 repos — all reviewed; none match |

### GitHub code searches
| Query | Result |
|---|---|
| `TROPIC01+FIDO2` | 147 hits — 100% in `krim404/cdc-badge-os` (ESP32) + Trezor translation files |
| `libtropic+ctap` | 3 hits — all `cdc-badge-os` audit artifacts |
| `libtropic+OpenPGP` | 1 hit — `cdc-badge-os` audit artifact |
| `TROPIC01+CCID` filename:CMakeLists.txt | 0 |
| `TROPIC01+HID` filename:CMakeLists.txt | 0 |
| `libtropic+ux_device` | 0 (no STM32 USB-class integrations beyond CDC) |
| `lt_ecc_eddsa_sign+CCID` | 0 |
| `lt_ecc_ecdsa_sign+ctaphid` | 0 |

### Fork inspection
- `tropicsquare/tropic01-stm32u5-usb-devkit-fw` — **1 fork** (`avp-protocol/nexusclaw`) — analyzed, CDC-only.
- `tropicsquare/libtropic-stm32` — 7 forks, all stale tracking forks; upstream archived.
- `tropicsquare/ts13-usb-dev-kit-fw` — 0 forks.
- `tropicsquare/libtropic` — 23 forks; sampled actives (`avp-protocol/avp-tropic`, `vpilat/`, `nishant-ghosh/`, `markusbug/`) — all are tracking branches or wallet/AI-vault host-side experiments, none add CTAP/CCID.

### WebSearch queries
| Query | Findings |
|---|---|
| `"TROPIC01" "FIDO2" firmware open source security key` | Only generic FIDO2 results (Nitrokey, SoloKeys, OpenSK); no TROPIC01 hit |
| `"TROPIC01" "OpenPGP card" smartcard CCID firmware` | Only generic OpenPGP-card results (pico-openpgp, GnuPG wiki); no TROPIC01 hit |
| `"TROPIC01" "STM32U5" custom firmware yubikey alternative` | Only the official Tropic Square repos surfaced |
| `"TROPIC01" "ed25519-sk" SSH hardware security key` | Generic Yubico/SSH FIDO results; no TROPIC01 hit |
| `tropicsquare ts1302 reflash custom firmware FIDO2` | Tropic Square repos only; no FIDO firmware results |
| `site:gitlab.com TROPIC01 OR libtropic` | No matches |
| `site:codeberg.org TROPIC01 OR libtropic` | One result: `xmr-cdc-badge` (CDC Badge / Monero, wrong MCU) |
| `"TROPIC01" Hacker News OR "lobste.rs"` | No matches |
| `"TROPIC01" 38C3 OR 39C3 OR FOSDEM talk` | Two 39C3 talks (CDC Badge, Programming TROPIC01); neither announces a FIDO product |
| `"tropic square" FIDO2 plans roadmap 2026 product` | No Tropic Square FIDO2 announcement |
| `"libtropic" CTAP OR "smart card" OR "HID" firmware` | No libtropic-CTAP results |
| `"TROPIC01" "WebAuthn" OR "passkey" OR "U2F"` | No matches |
| `"TROPIC01" "Trussed" OR "Solo2" OR "Nitrokey 3"` | No matches |
| `"TROPIC01" thesis academic paper masters bachelor` | No matches |
| `tropic square discord community "FIDO" OR "yubikey" OR "openpgp"` | No matches |
| `"open source FIDO2" "secure element" "STM32" 2025 OR 2026` | LionKey, SoloKey, Nitrokey 3 — all use ATECC608 or no SE; none use TROPIC01 |

### WebFetch verification
- [Tropic Square TROPIC01 page](https://tropicsquare.com/tropic01) — applications listed are wallets / IoT / decentralized infra; no FIDO2 / smartcard.
- [Tropic Square news page](https://www.tropicsquare.com/news-and-events) — no security-key or smartcard product announcements.
- [Official `tropic01-stm32u5-usb-devkit-fw` README](https://github.com/tropicsquare/tropic01-stm32u5-usb-devkit-fw) — explicit invitation to build custom firmware.
- [`avp-protocol/nexusclaw/usb/ux_device_descriptors.c`](https://github.com/avp-protocol/nexusclaw/blob/master/usb/ux_device_descriptors.c) — `CLASS_TYPE_CDC_ACM` only; no HID/CCID class registered.

---

## 5. Risk assessment

**Probability that someone is silently working on this and will publish before us: LOW (~10-15%).**

Strongest signals supporting "low":
- **Zero traces** in three independent surfaces (code search, repo search, conference programs). Anyone serious about this would have left at least a personal repo, a GitHub gist, a forum post, or a conference abstract. The TROPIC01 community is small enough (~40 repos total) that we've enumerated all of it.
- The closest concrete "custom STM32U5 + TROPIC01 firmware" effort (`nexusclaw`) chose CDC-ACM + a brand-new proprietary protocol *instead of* FIDO2/CCID — strong evidence that no team has yet reached for the standards-based persona.
- Tropic Square's archival of `libtropic-stm32` (Feb 2026) and silence on FIDO2 in their public communications are consistent with "we want partners to do this."
- Substantial engineering moat: implementing FIDO2 + CCID on a fresh STM32U5 USB stack with no `libtropic-stm32` USB device-class HAL (the USB transport currently lives only as a Linux example, not a clean reusable STM32 HAL) takes weeks of work even for an experienced firmware developer. Few people have both the skills and the niche interest.

Signals nudging "low" toward "medium":
- **STM32 + open FIDO2 is a known, well-trodden track** (Nitrokey, SoloKey, Trussed, LionKey). The recipe is public; only the SE swap is novel. A motivated Trussed contributor could plausibly do an SE-backend port in 2-3 months. We have no evidence anyone has started, but the idea is obvious enough that a "race to publish" is conceivable.
- The TS1302 hardware is **commercially shipping at scale** since Feb 2025; usage is growing. The probability that "someone curious is hacking on this" rises every month. Time-to-publish matters.
- Trezor's TROPIC01 deployment legitimizes the chip, attracts security-key vendors. Possible that Nitrokey or another vendor is privately evaluating TROPIC01 for a future product — that would be the biggest "could publish first" scenario, and it would not be visible in any open search until they ship.

**Worth-flagging: the "no one has succeeded" framing.** TROPIC01 has documented **awkwardness** for a FIDO2 use case: no exposed AES, no exposed hash/HMAC, and an erratum (`OI_TR01_ERR_2026010800`) where a botched R-config write bricks the chip permanently. The reason no one has shipped this yet *might* be partly that it's tedious, not just that nobody's tried. Plan for: doing all hashing/HMAC on the STM32U535 (it has hardware AES + SHA), using TROPIC01 only for ECDSA P-256 (FIDO2) and EdDSA Ed25519 (OpenPGP card / SSH-sk) signing + TRNG + slot storage, and being **extremely** cautious with R-config / I-config writes (test against the simulator first; do not lock the I-config until the design is final).

---

## 6. Recommendations

**Proceed.** The niche is genuinely open: no commercial product, no public open-source effort, and no announced Tropic Square first-party plan to do it themselves. Their official invitation in the TS1302 firmware README — _"Users are encouraged to develop custom firmware"_ — combined with the lack of FIDO2 in their listed verticals makes this a deliberate gap, not a closed-off lane.

**Move with appropriate urgency** but not panic: a 6-12 month publish window before a credible competitor (Nitrokey-class vendor, motivated hobbyist, Trussed/SoloKey port) is realistic. Publish early — even a working FIDO2-only MVP (no OpenPGP card yet) is enough to plant the flag in the public record (announcement on Hacker News, lobste.rs, and a 40C3 talk submission). Adding CCID/OpenPGP-card later as a second composite interface is incremental, not a different project. Mitigate the chip-bricking risk by doing all R-config/I-config bring-up against the [TVL simulator](https://github.com/tropicsquare/ts-tvl) before touching real silicon.
