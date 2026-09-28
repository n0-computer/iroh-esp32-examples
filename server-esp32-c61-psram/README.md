# iroh on an ESP32-C61 (RISC-V, PSRAM, relay + discovery)

An iroh endpoint running on an ESP32-C61 — a single-core 32-bit **RISC-V**
(RV32IMAC) chip with WiFi 6 and a **2 MB SPI PSRAM** (module marking `…N8R2`:
8 MB flash, 2 MB PSRAM). It targets `riscv32imac-esp-espidf` like the
[`server-esp32-c6`](../server-esp32-c6/README.md), and uses the PSRAM to run the
**full relay + pkarr discovery** stack, as on the S3/ESP32 PSRAM targets.

That makes it reachable **across networks**: it publishes to pkarr and falls back
to a relay for NAT traversal, so a peer dials the **short ticket** (bare endpoint
ID) from anywhere — no need to share a WiFi.

> This is the first *single-core, tight-internal-SRAM* chip in this repo to run the
> full relay build, and getting there took a specific config recipe — see
> [Making relay fit on the C61](#making-relay-fit-on-the-c61). The short version:
> keep the internal-SRAM buffers **small** and give the main task a **96 KB** stack.

## Toolchain requirements

The C61 is newer silicon than the rest of this repo, so it needs more recent tools:

- **ESP-IDF v5.5.2+** — the C61 became a stable ESP-IDF target in v5.5.2. Pinned to
  `v5.5.4` in [`.cargo/config.toml`](.cargo/config.toml) (the C6 targets stay on
  v5.3.3, which predates the C61).
- **`esp-idf-svc` 0.52+** (→ `esp-idf-sys` 0.37) — the first release whose chip
  table contains an `ESP32C61` variant. 0.51 / esp-idf-sys 0.36 fails chip
  detection for `MCU=esp32c61`.
- **`espflash` 4.4.0+** — earlier versions don't recognize the C61's chip ID
  (`espflash board-info` reports `unrecognized chip ID: 20` on 4.3.x). Upgrade with
  `cargo install espflash --locked` before flashing.

## What changed from the C6

- **`.cargo/config.toml`** — `MCU=esp32c61` (was `esp32c6`) and
  `ESP_IDF_VERSION=v5.5.4` (was `v5.3.3`). The rust target
  `riscv32imac-esp-espidf` is unchanged — the C61 is RV32IMAC like the C6/C5/H2.
- **`Cargo.toml`** — package/bin renamed; `esp-idf-svc` bumped `0.51 → 0.52`.
- **`src/main.rs`** — `relay_mode(Default)` + two `address_lookup(Pkarr…)` calls,
  and it prints the **short ticket** too. Otherwise unchanged from the C6.
- **`sdkconfig.defaults`** — PSRAM on (chip-independent `CONFIG_SPIRAM`, **QUAD** —
  no `MODE_OCT`), a **96 KB** main-task stack, `CONFIG_LOG_COLORS` restored, and
  deliberately **small** WiFi/lwIP buffers (see below). Flash stays 4 MB.
- **`rust-toolchain.toml`** — unchanged (`channel = "esp"`).

## Making relay fit on the C61

The relay code is identical to the S3/ESP32 PSRAM targets, but the C61 is harder in
two ways, and the fix for each pulls in opposite directions on the same scarce
resource — **internal SRAM** (~320 KB on the C61 vs 512 KB on the S3/ESP32, leaving
~188 KB of heap). PSRAM is plentiful (2 MB) but can't back everything.

- **Keep WiFi/lwIP buffers small; leave `SPIRAM_MALLOC_RESERVE_INTERNAL` alone.**
  The iroh *heap* lives happily in PSRAM, but FreeRTOS objects — every
  `std::sync::Mutex` lazily creates a semaphore — plus DMA descriptors are
  **internal-only**; PSRAM can't hold them. Loosening the WiFi/lwIP buffers to the
  "PSRAM profile" the other targets use eats that internal SRAM, and under the
  relay path's concurrent probing the next `pthread_mutex_lock` fails with ENOMEM →
  "failed to lock mutex" panic → double-panic → abort. So the buffers stay at the
  slim C6 values; that's a feature here, not laziness.
- **96 KB main-task stack.** tokio's `current_thread` runtime runs the whole async
  tree on the main task's stack, and the deepest path — `RelayActor` + the pkarr
  reqwest/rustls DoH clients — overflowed 49 KB (a stack-protection fault in
  `RelayActor::active_relay_handle`, SP ~8.7 KB past the floor). 96 KB clears it.
  Note the S3/ESP32 use 114 KB, but that was sized for `hickory-resolver`, which
  iroh no longer depends on — so we don't need the extra.

The tension: that 96 KB stack is **internal** SRAM (the RISC-V main task stack
isn't eligible for PSRAM), so it competes with the very FreeRTOS/DMA allocations
above. The small buffers are what keep both satisfiable at once.

> **Escape hatch if a future path wants more stack.** `CONFIG_SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY=y`
> is already set, so a stack we allocate ourselves *can* live in PSRAM — the main
> task's can't. Running the tokio runtime inside a
> `std::thread::Builder::new().stack_size(256 * 1024).spawn(…)` puts the whole deep
> async tree on a PSRAM stack and frees ~90 KB of internal SRAM. The one rule: that
> thread must **never** run cache-disabling flash ops (NVS/flash writes, OTA) — the
> cache is off during those and a PSRAM stack becomes unreachable → hard fault. NVS
> + WiFi init already happen on the main task, so it's viable; we just didn't need
> it (96 KB was enough).

## Build / run

The C61 has a **built-in USB Serial/JTAG** peripheral (on this devkit it's the
**bottom** USB port — the top one is the CP210x UART bridge). Flash over the bottom
port and `espflash` runs at USB speed:

```bash
WIFI_CONFIG='SSID:PASSWORD' cargo run --release
```

If you use the **UART bridge** port instead, the default 115200 baud is slow — set
`ESPFLASH_BAUD=921600` (a CP2102 sweet spot; a CP2102N can often do `1500000`).
This only affects flashing, not the serial monitor.

`WIFI_CONFIG` is read at build time and embedded into the firmware.

On startup the device prints two tickets. Pass either to the
[`client`](../client/README.md):

- **Short ticket** — bare endpoint ID, resolved via pkarr/relay. Works from any
  network. Use this one.
- **Long ticket** — includes the WiFi IP, for a same-LAN direct fast path.

## Memory tuning

The accept handler logs, per connection: free heap, largest contiguous 8-bit
block, and **main-task stack high-water** (`[stack] … bytes free of <configured>` —
read straight from `CONFIG_ESP_MAIN_TASK_STACK_SIZE`, so it tracks the real stack
size). Use the high-water to right-size: if a connection leaves a comfortable
margin, the 96 KB stack can be trimmed and the difference returned to the
internal-SRAM heap (or, conversely, bumped if a deeper path shows up). The log only
fires after a connection completes, so dial the board once to get a reading.

> Hardware note: on the C61 rev v1.0 the boot log warns that PSRAM contents aren't
> encrypted (an errata). It only matters with flash encryption enabled (it isn't
> here), but rustls buffers do live in PSRAM — keep it in mind before shipping.

### Profiling the heap

The [`src/alloc_log.rs`](src/alloc_log.rs) logging allocator is present but not
hooked up by default. Decode backtraces with the **RISC-V** toolchain addr2line:

```
riscv32-esp-elf-addr2line -e target/riscv32imac-esp-espidf/release/server-esp32-c61-psram <pc>…
```
