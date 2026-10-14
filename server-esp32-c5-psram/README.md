# iroh on an ESP32-C5 (RISC-V, PSRAM, relay + discovery)

An iroh endpoint running on an ESP32-C5 — a single-core 32-bit **RISC-V**
(RV32IMAC) chip with **dual-band WiFi 6** (2.4 and 5 GHz) and an SPI PSRAM
interface. Tested on the [Seeed Studio XIAO ESP32-C5]: 8 MB flash, **8 MB PSRAM**.
It targets `riscv32imac-esp-espidf` like the
[`server-esp32-c61-psram`](../server-esp32-c61-psram/README.md), and uses the
PSRAM to run the **full relay + pkarr discovery** stack.

That makes it reachable **across networks**: it publishes to pkarr and falls back
to a relay for NAT traversal, so a peer dials the **short ticket** (bare endpoint
ID) from anywhere — no need to share a WiFi.

## Toolchain requirements

Same as the C61:

- **ESP-IDF v5.5** — the first release with the C5 as a stable target. Pinned to
  `v5.5.4` in [`.cargo/config.toml`](.cargo/config.toml).
- **`esp-idf-svc` 0.52+** (→ `esp-idf-sys` 0.37) — the first release whose chip
  table contains an `ESP32C5` variant.
- **A recent `espflash`** that knows the C5. Upgrade with
  `cargo install espflash --locked` before flashing.

## What changed from the C61

- **`.cargo/config.toml`** — `MCU=esp32c5` (was `esp32c61`), and the runner
  flashes with `--no-reset` (see [Build / run](#build--run)). The rust target
  `riscv32imac-esp-espidf` and ESP-IDF `v5.5.4` are unchanged.
- **`Cargo.toml`** — package/bin renamed. Same dependencies.
- **`src/main.rs`** — unchanged, apart from a comment.
- **`sdkconfig.defaults`** — unchanged, apart from comments: PSRAM on (QUAD), a
  96 KB main-task stack, small WiFi/lwIP buffers, flash pinned to 4 MB.
- **`rust-toolchain.toml`** — unchanged (`channel = "esp"`).

The C61's memory recipe carries over as is: the C5 has more internal SRAM
(384 KB vs ~320 KB) and four times the PSRAM, so the C61 settings leave headroom
here. See the C61's
[Making relay fit on the C61](../server-esp32-c61-psram/README.md#making-relay-fit-on-the-c61)
for why the buffers stay small and the stack is 96 KB.

## Build / run

The XIAO's USB-C port is the C5's built-in USB Serial/JTAG, so there's no baud
rate to tune:

```bash
WIFI_CONFIG='SSID:PASSWORD' cargo run --release
```

`WIFI_CONFIG` is read at build time and embedded into the firmware. The C5 joins
2.4 GHz and 5 GHz networks alike.

The cargo runner flashes with `--no-reset --non-interactive`: only the flasher
resets the chip. With espflash's default, the monitor resets it again right
after, and the C5 lands in download mode (`waiting for download`) instead of
running the app. The price is that the monitor has no CTRL+R; press the board's
reset button instead.

The XIAO's antenna is external, on a U.FL connector. Plug it in, or WiFi will
barely work.

On startup the device prints two tickets. Pass either to the
[`client`](../client/README.md):

- **Short ticket** — bare endpoint ID, resolved via pkarr/relay. Works from any
  network. Use this one.
- **Long ticket** — includes the WiFi IP, for a same-LAN direct fast path.

## Memory tuning

The accept handler logs, per connection: free heap, largest contiguous 8-bit
block, and **main-task stack high-water** (`[stack] … bytes free of <configured>` —
read straight from `CONFIG_ESP_MAIN_TASK_STACK_SIZE`, so it tracks the real stack
size). Use the high-water to right-size the 96 KB stack. The log only fires after
a connection completes, so dial the board once to get a reading.

### Profiling the heap

The [`src/alloc_log.rs`](src/alloc_log.rs) logging allocator is present but not
hooked up by default. Decode backtraces with the **RISC-V** toolchain addr2line:

```
riscv32-esp-elf-addr2line -e target/riscv32imac-esp-espidf/release/server-esp32-c5-psram <pc>…
```

[Seeed Studio XIAO ESP32-C5]: https://www.seeedstudio.com/Seeed-Studio-XIAO-ESP32C5-p-6609.html
