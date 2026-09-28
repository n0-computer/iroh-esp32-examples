# iroh on an ESP32-C6 (RISC-V, no PSRAM)

An iroh endpoint running on an ESP32-C6 — a single-core 32-bit **RISC-V**
(RV32IMAC) chip with WiFi 6, **no PSRAM**. This is the bare
[`server-esp32`](../server-esp32/README.md) echo server ported
from Xtensa to RISC-V: the application code is identical (it's chip-agnostic —
just NVS + WiFi + iroh), so the port is **config only**.

It targets `riscv32imac-esp-espidf` and uses published iroh 1.2.0. Like the bare
ESP32, the whole iroh heap and every task stack must fit in
internal SRAM (the C6 has ~512 KB), so it keeps the no-psram memory tuning.

> ⚠️ Same caveat as the bare ESP32: this runs near the memory floor and is
> **LAN-direct only** (relay + discovery are removed — dial via the long ticket).
> For headroom and relay/discovery/NAT-traversal, use the
> [`server-esp32-psram`](../server-esp32-psram/README.md) (PSRAM) target.

## What changed from the bare ESP32 (the whole port)

- **`.cargo/config.toml`** — `target = "riscv32imac-esp-espidf"` and `MCU=esp32c6`
  (was `xtensa-esp32-espidf` / `esp32`). The C6's main core is RV32IMAC, which has
  the `a` atomics extension — unlike the C3 (`imc`), so no extra atomics shims are
  needed beyond what the no-psram graph already does for 64-bit atomics.
- **`sdkconfig.defaults`** — dropped the PSRAM toggle block. The
  `CONFIG_ESP32_SPIRAM_*` symbols are ESP32-only and don't exist for the C6 (no
  PSRAM interface). Everything else (WiFi/lwIP/stack cuts) is chip-independent and
  carries over unchanged.
- **`Cargo.toml`** — package/bin renamed to `server-esp32-c6`. Dependencies and
  features match the bare ESP32, including published iroh 1.2.0.
- **`rust-toolchain.toml`** — unchanged (`channel = "esp"`). The espup `esp`
  toolchain builds the RISC-V esp target too; stock `nightly` + `rust-src` also
  works if you prefer.
- **`src/`** — unchanged.

## Build / run

Unlike the bare ESP32 (which needs an external USB-to-UART bridge), the C6 has a
**built-in USB Serial/JTAG** peripheral — connect it directly over USB. `espflash`
(the cargo runner) auto-detects the chip and port.

```bash
WIFI_CONFIG='SSID:PASSWORD' cargo run --release
```

`WIFI_CONFIG` is read at build time and embedded into the firmware (SSID and
password separated by a colon). Over the native USB CDC the flash baud isn't the
bottleneck, so `ESPFLASH_BAUD` is usually unnecessary; add it if you flash through
an external UART bridge instead.

On startup the device prints an endpoint ticket to the serial monitor. Pass that
ticket to the [`client`](../client/README.md) to dial it (use the **long** ticket
— LAN-direct, no relay).

## Memory tuning

The knobs are identical to the bare ESP32 and the rationale carries over verbatim
— see [`server-esp32`](../server-esp32/README.md#memory-tuning)
for the full writeup. In short: shrunk QUIC windows, relay/discovery removed, no
TLS resumption cache, a 1 KiB stack echo buffer, a 40 KiB main task stack, WiFi
static buffers cut to 4/4 with AMPDU off, trimmed lwIP pools, IPv6 off, and
`NEWLIB_NANO_FORMAT`. The C6 is single-core, so there's no core-pinning to
consider; WiFi and the tokio current-thread runtime share the one core.

> The exact byte figures in the bare-ESP32 writeup were measured on the LX6. The
> C6's RISC-V codegen and SRAM map differ, so re-measure on hardware — the accept
> handler logs free heap, largest contiguous block, and main-task stack high-water
> per connection.

### Profiling the heap

Same [`src/alloc_log.rs`](src/alloc_log.rs) logging allocator as the baseline.
Decode backtraces with the **RISC-V** toolchain addr2line:

```
riscv32-esp-elf-addr2line -e target/riscv32imac-esp-espidf/release/server-esp32-c6 <pc>…
```
