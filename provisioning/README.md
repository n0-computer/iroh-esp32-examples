# WiFi provisioning over BLE, encrypted to the iroh endpoint id

Give fresh ESP32s your WiFi credentials over Bluetooth, from a web page or the
command line. No captive portal, no hardcoded `WIFI_CONFIG`, no app to install.
The credentials are sealed with [HPKE] to the device's iroh endpoint id, so only
that device can open them, and you get back a single-use **pairing ticket** for
each device.

The workflow, formats and security notes are in
[`iroh-provision/README.md`](iroh-provision/README.md).

This example stops once WiFi is up. Binding the iroh endpoint with the stored key,
and redeeming tickets over it, is the next step.

## Layout

Separate Cargo projects, like the rest of this repo:

| Directory | What |
|---|---|
| [`iroh-provision/`](iroh-provision/) | the library: formats, sealing, client `Session`, device logic; platform independent, tested without hardware |
| [`iroh-provision-ble/`](iroh-provision-ble/) | client transports: btleplug (`native`) and Web Bluetooth (`web`); plus the CLI example |
| [`iroh-provision-esp-idf/`](iroh-provision-esp-idf/) | device side on ESP-IDF: NimBLE GATT service, NVS, WiFi, reset button |
| [`esp32-c61-psram/`](esp32-c61-psram/src/main.rs) | the firmware: about 40 lines on top of the above |
| [`web/`](web/) | the page: wasm binding over the client `Session`, JS only for the UI |
| `vendor/esp32-nimble/` | [esp32-nimble] 0.13 with a fix, see [below](#vendored-esp32-nimble) |

## The device

On boot it loads or creates its identity. With stored networks it joins the
strongest one in range, retrying until one works, and later rejoins whichever
is available when the connection drops; it never goes back to provisioning
mode by itself. Without networks (first boot, or after holding BOOT for 5
seconds, which forgets networks, name and pairing secret but not the identity)
it advertises over BLE as `iroh-<short endpoint id>` until a working set
arrives, then turns BLE off.

The RGB LED shows the state: blinking yellow while waiting for provisioning,
yellow and green alternating while joining WiFi, solid green once joined.

Same toolchain as [`server-esp32-c61-psram`](../server-esp32-c61-psram/README.md#toolchain-requirements)
(ESP-IDF v5.5.2+, espflash 4.4+), with esp-idf-svc 0.53 because esp32-nimble
0.13 requires it.

```sh
cd esp32-c61-psram
cargo run --release
```

The serial log shows `Endpoint ID: …` and then `Advertising as iroh-…`.

- The first build downloads ESP-IDF. If you already built `server-esp32-c61-psram`,
  `ln -s ../../server-esp32-c61-psram/.embuild .embuild` reuses its copy.
- The cargo runner flashes with `--after no-reset`, so only the monitor resets the
  chip. With espflash's default, the reset after flashing and the monitor's reset
  land within milliseconds, and the C61 ends up in a ROM watchdog loop
  (`rst:0x7 (TG0_WDT_HPSYS)` over and over) that only unplugging fixes.
- Flashing this image onto another chip (e.g. a C6) fails before `main` with an
  "Illegal instruction" panic; `espflash board-info` tells you what's connected.
- The BOOT pin is set in `main.rs`: GPIO9 on the ESP32-C61 DevKit. Other boards
  differ; the XIAO ESP32-C5 uses GPIO28.
- The LED is board specific too. The C61 DevKit only has an RGB LED (WS2812 on
  GPIO8), driven over SPI because the C61 has no RMT ([`rgb_led.rs`](esp32-c61-psram/src/rgb_led.rs),
  from iroh-co2-monitor). Boards with a plain LED use `BlinkingLed` from
  `iroh-provision-esp-idf`; the XIAO ESP32-C5's user LED is GPIO27, active low.

## The page

```sh
cd web
npm run build   # needs the wasm32-unknown-unknown target and wasm-bindgen 0.2.126
npm run serve   # http://localhost:8080
```

Enter the networks once, then press **provision a device** for each board. A
number after `-` or `_` in the name counts up (`lamp-1`, `lamp-2`, …); `co2`
stays `co2`. Each device
shows its ticket; the page remembers name and ticket per endpoint id, so
provisioning a known device again only changes its networks and keeps its
ticket valid.

Web Bluetooth needs a secure context (`localhost` counts) and works in Chrome
and Edge on desktop and Android, not in Firefox or on iOS.

## The command line

```sh
cd iroh-provision-ble
cargo run --example provision --features native -- \
    --network home:secret [--network office:other] [--name lamp-1]
```

Provisions every device in range, one after another, and prints each endpoint
id and ticket. `--ticket NAME=pair…` reprovisions a known device, keeping its
name and ticket.

## Vendored esp32-nimble

esp32-nimble 0.13 doesn't compile against ESP-IDF v5.5 on chips with Espressif's
own NimBLE controller (C5, C6, C61, H2): `os_mempool_init` became
`r_os_mempool_init` there, like the `os_mbuf_*` functions esp32-nimble already
maps. The fix is in `vendor/esp32-nimble/src/l2cap/mod.rs`, wired in with
`[patch.crates-io]` in the firmware. Drop both once it's fixed upstream.

A second bug is worked around in `iroh-provision-esp-idf` instead:
`BLEDevice::deinit_full` resets the advertising state after shutting down the
NimBLE host, which reads freed memory (load access fault). It calls `deinit`;
the extra reset only matters for restarting BLE, which it never does.

[HPKE]: https://www.rfc-editor.org/rfc/rfc9180
[esp32-nimble]: https://docs.rs/esp32-nimble
