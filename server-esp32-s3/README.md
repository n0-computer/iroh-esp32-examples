# iroh on ESP32-S3 (without PSRAM)

![A bare ESP32-S3 development board](../images/esp32-s3.jpg)

An iroh endpoint running on an ESP32-S3 **without** PSRAM. It is tuned to keep the
memory footprint low — smaller buffers and avoiding allocations — so that it
fits in the on-chip RAM.

It targets `xtensa-esp32s3-espidf` and uses published iroh 1.2.0, without
an iroh Git dependency or patch. It remains LAN-direct (relay disabled) to limit
RAM usage. The system DNS adapter and allocation-profiling helper are retained.
Hickory is no longer in the dependency graph.

See the [release size measurements](../RELEASE-SIZES.md) for flash requirements.

## Build / run

An ESP32 device must be connected over USB-C while running the server. Flashing
and the serial monitor are handled by `espflash` (configured as the cargo
runner in `.cargo/config.toml`).

```bash
WIFI_CONFIG='SSID:PASSWORD' cargo run --release
```

`WIFI_CONFIG` is read at build time and embedded into the firmware; it is the
SSID and password of the WiFi network the device should join, separated by a
colon.

On startup the device prints an endpoint ticket to the serial monitor. Pass
that ticket to the [`client`](../client/README.md) to dial it.

## Targeting a plain ESP32 (LX6) without PSRAM

For a plain ESP32 (LX6) without PSRAM, use the dedicated
[`server-esp32`](../server-esp32/README.md) project — it is this same
code already retargeted (`target = "xtensa-esp32-espidf"`, `MCU = "esp32"`).
