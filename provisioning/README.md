# WiFi provisioning over BLE, encrypted to the iroh endpoint id

Give a fresh ESP32 your WiFi credentials from a web page over Bluetooth. No
captive portal, no hardcoded `WIFI_CONFIG`, no app to install.

The credentials never cross the air in the clear. The device generates its iroh
identity (an ed25519 key) on first boot and exposes the public half over BLE. The
page seals the credentials to that key with [HPKE] (RFC 9180), so only that device
can open them. It's the same key that later authenticates every iroh connection
to the device.

Provisioning is also how the page learns the device's endpoint id, read over
BLE from the key that opens the credentials. But the endpoint id is public, so
knowing it can't be what authorizes control. The page therefore also sends a
fresh pairing secret (and a name for the device), and combines the endpoint id
and the secret into a single-use **pairing ticket** (`pair…`). Whoever redeems
it over iroh first becomes an owner, authenticated from then on by their own
endpoint id. The ticket can be handed to another client; the page that
provisions doesn't have to be the one that controls the device.

The page's workflow: enter the networks once, then provision any number of
devices with them, each with its own name (a trailing number counts up:
`lamp-1`, `lamp-2`, …) and its own ticket.

This example stops once WiFi is up. Binding the iroh endpoint with the stored key
is the next step.

## Layout

Three separate Cargo projects, like the rest of this repo:

- [`proto/`](proto/src/lib.rs): GATT UUIDs, the status encoding, and `seal` /
  `open`. Used by both sides, so the protocol has one implementation.
- [`esp32-c61-psram/`](esp32-c61-psram/src/main.rs): the firmware, based on
  [`server-esp32-c61-psram`](../server-esp32-c61-psram/README.md).
- [`web/`](web/public/main.js): the page. Web Bluetooth in plain JS, sealing in
  Rust compiled to wasm.
- `vendor/esp32-nimble/`: [esp32-nimble] 0.13 with a one-line fix, see
  [below](#vendored-esp32-nimble).

## How it works

On boot the device:

1. Loads its secret key from NVS, or generates and stores one. The key survives
   reprovisioning, so the endpoint id never changes.
2. If networks are stored, scans and tries the known networks in range, strongest
   first. Networks not seen in the scan are only tried if a hidden network is
   around, since every failed attempt costs a 20 s connect timeout. After 3
   rounds it falls back to provisioning mode.
3. In provisioning mode, advertises over BLE as `iroh-<short endpoint id>`
   (iroh's `fmt_short`, 10 hex chars) and waits for a list of networks. It joins
   one of them the same way, stores the whole list, reports which network and
   IP, and shuts BLE down.

Holding BOOT for 5 seconds wipes the networks, name and pairing secret (not the
identity) and restarts into provisioning mode.

GATT service `08c6b3c5-8a57-40af-8eec-45a746f70d3f`:

| Characteristic | UUID | Access | Value |
|---|---|---|---|
| identity | `18969798-…` | read | 32 byte ed25519 public key (the endpoint id) |
| credentials | `bca33919-…` | write | `0x01 \| enc (32) \| ciphertext \| tag (16)` |
| status | `2484ca31-…` | read, notify | state byte + network index and IPv4, or failure code |

Sealing is HPKE base mode, DHKEM(X25519, HKDF-SHA256) + ChaCha20Poly1305, to the
X25519 form of the ed25519 key, with the endpoint id as associated data. Reusing
an ed25519 key for X25519 key exchange is analyzed in [this paper].

The plaintext is `op | count | (len | ssid | len | password)* | len | name |
pairing secret (32)`, with up to 4 networks and a name of up to 32 bytes. `op`
is `0`, "replace the stored state". The pairing secret comes from the page's
RNG, the same one the HPKE ephemeral key (and so the password's protection)
already depends on. It's there so a list can later
be spread over several messages (appending, or chunks) without breaking existing
devices, which answer an unknown op with a distinct `Unsupported` failure.

A BLE characteristic value is at most 512 bytes. 4 networks at the maximum SSID
(32) and password (64) lengths, plus a 32 byte name, seal to 508 bytes, so a
message always fits in one write.

A pairing ticket is `pair` + lowercase base32 of `version (0) | endpoint id |
secret`. The device stores the secret until it's redeemed; a new provisioning
replaces an unredeemed one. Redeeming (an iroh protocol, `pair/0`) needs the
endpoint on the device, so it's not implemented yet.

Failures the status can report: the message didn't open, unsupported op, no
network in range, could not join (usually a wrong password), joined but no IP.

## Security

- **Passive sniffing**: defeated. A recorded provisioning session reveals nothing
  without the device's secret key.
- **Impersonating the device during provisioning**: not prevented by the protocol
  alone. An attacker could advertise as the device and hand out their own key.
  The page shows the endpoint id; compare it with the one the device prints on
  its serial console. After provisioning, every iroh connection is authenticated
  by the same key, so a man in the middle would have to proxy forever and is
  exposed by a single comparison.
- **Someone else provisioning your unprovisioned device**: possible while it
  advertises. A button-press confirmation would close this.
- **Replay**: a recorded message only re-sends the same credentials to the same
  device.

## Build and flash the firmware

Same toolchain as [`server-esp32-c61-psram`](../server-esp32-c61-psram/README.md#toolchain-requirements)
(ESP-IDF v5.5.2+, espflash 4.4+), with esp-idf-svc 0.53 because esp32-nimble
0.13 requires it.

```sh
cd esp32-c61-psram
cargo run --release
```

Flashing this image onto another chip (e.g. a C6) fails before `main` with an
"Illegal instruction" panic; `espflash board-info` tells you what's connected.
The cargo runner flashes with `--after no-reset`, so only the monitor resets the
chip. With espflash's default, the reset after flashing and the monitor's reset
land within milliseconds, and the C61 ends up in a ROM watchdog loop
(`rst:0x7 (TG0_WDT_HPSYS)` over and over) that only unplugging fixes.

The first build downloads ESP-IDF. If you already built `server-esp32-c61-psram`,
`ln -s ../../server-esp32-c61-psram/.embuild .embuild` reuses its copy.

The serial log shows `Endpoint ID: …` and then `Advertising as iroh-…`.

The BOOT button pin is set in `main.rs`: GPIO9 on the ESP32-C61 DevKit. Other
boards differ; the XIAO ESP32-C5 uses GPIO28.

## Build and serve the page

Needs the `wasm32-unknown-unknown` target and the `wasm-bindgen` CLI at the
version pinned in [`web/Cargo.toml`](web/Cargo.toml).

```sh
cd web
npm run build
npm run serve   # http://localhost:8080
```

Web Bluetooth needs a secure context; `localhost` counts. It works in Chrome and
Edge on desktop and Android. It doesn't work in Firefox, or in any browser on iOS.

Click **find device**, pick `iroh-…`, check the endpoint id, then enter one or
more networks.

## Vendored esp32-nimble

esp32-nimble 0.13 doesn't compile against ESP-IDF v5.5 on chips with Espressif's
own NimBLE controller (C5, C6, C61, H2): `os_mempool_init` became
`r_os_mempool_init` there, like the `os_mbuf_*` functions esp32-nimble already
maps. The fix is in `vendor/esp32-nimble/src/l2cap/mod.rs`, wired in with
`[patch.crates-io]`. Drop both once it's fixed upstream.

A second bug is worked around in the firmware instead: `BLEDevice::deinit_full`
resets the advertising state after shutting down the NimBLE host, which reads
freed memory (load access fault). The firmware calls `deinit` instead; the extra
reset only matters for restarting BLE, which it never does.

## Status

Tested with a native BLE test client doing what the page does (on an ESP32-C6
build of the same code): discovery, reading the identity, sealed writes up to
the 443 byte maximum, status notifications, the not-in-range, wrong-network and
tampered-message failures, and the identity surviving a reflash. The C61 build
boots with PSRAM and advertises.

Tested on the C61 from the page: joining a real network, storing it, rejoining
after a reboot, BLE shutting down after success, and BOOT wiping the stored
state, names and pairing tickets. Not implemented yet: redeeming a ticket.

[HPKE]: https://www.rfc-editor.org/rfc/rfc9180
[esp32-nimble]: https://docs.rs/esp32-nimble
[this paper]: https://eprint.iacr.org/2021/509
