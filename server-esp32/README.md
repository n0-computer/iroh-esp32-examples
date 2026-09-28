# iroh on a bare ESP32 (LX6, without PSRAM)

![A bare ESP32 (LX6) development board](../images/esp32.jpg)

An iroh endpoint running on a plain ESP32 (LX6) **without** PSRAM. It is tuned
to keep the memory footprint low — smaller buffers and avoiding allocations —
so that it fits in the on-chip RAM.

It targets `xtensa-esp32-espidf` (ESP32 / LX6). The `alloc_log` module helps
track allocations while keeping the footprint down.

> ⚠️ **This variant runs right at the memory limit.** It is the "look, we can
> make this work" target, not a production one. The whole iroh heap and every
> task stack must fit in the LX6's internal SRAM (no PSRAM), and that internal
> RAM is both smaller and more fragmented than the S3's. The settings below are
> cut to the *functional floor*; before any of it, the post-handshake heap was
> down to ~4 KB free with a ~2.3 KB largest contiguous block, which OOM'd as
> soon as anything needed a slightly bigger allocation. If you want real
> headroom or features (relay, discovery, NAT traversal), use the
> [`server-esp32-psram`](../server-esp32-psram/README.md) (PSRAM) target instead.

## Build / run

A bare ESP32 has no native USB; it connects through an external USB-to-UART
bridge (CP2102 / CH340 / CH9102). Connect it over USB while running the server.
Flashing and the serial monitor are handled by `espflash` (configured as the
cargo runner in `.cargo/config.toml`).

```bash
ESPFLASH_BAUD=230400 WIFI_CONFIG='SSID:PASSWORD' cargo run --release
```

`WIFI_CONFIG` is read at build time and embedded into the firmware; it is the
SSID and password of the WiFi network the device should join, separated by a
colon. `ESPFLASH_BAUD=230400` keeps flashing reliable over the UART bridge
(cheap CH340 bridges often can't sustain the higher default rates).

On startup the device prints an endpoint ticket to the serial monitor. Pass
that ticket to the [`client`](../client/README.md) to dial it.

## Memory tuning

Getting iroh to run in internal SRAM took cutting every buffer to the point
where one more allocation tips it over. These are the knobs, what they buy, and
why they are safe *here* but not defaults you should copy blindly.

**Application / iroh ([`src/main.rs`](src/main.rs))**

- **QUIC flow-control windows** shrunk to the echo's working set:
  `stream_receive_window` 4 KiB, `receive_window` 8 KiB, `send_window` 8 KiB
  (down from the 64 KiB-scale internet defaults). The echo moves 1 KiB chunks
  over a single stream, so nothing is ever near these limits — and smaller
  windows mean smaller *contiguous* buffers, which is what the fragmented heap
  can actually place. One bidi stream, no uni streams, no datagrams.
- **Relay + discovery removed** (`RelayMode::Disabled`, no pkarr). These were
  the big heap hogs (relay reportgen/QAD probing, pkarr reqwest clients). The
  cost: **LAN-direct only** — dial via the long ticket (IP + port), no NAT
  traversal, no discovery.
- **TLS session-resumption cache disabled** (`max_tls_tickets(0)`) — saves the
  ~9–150 KiB hashbrown table; we never resume on an embedded server.
- **1 KiB stack echo buffer** instead of `tokio::io::copy` (whose 8 KiB heap
  buffer OOM'd once the heap fragmented). Zero heap on the data path.

**ESP-IDF / FreeRTOS ([`sdkconfig.defaults`](sdkconfig.defaults))**

- **Main task stack** `CONFIG_ESP_MAIN_TASK_STACK_SIZE=40960` — measured
  high-water was ~34.5 KiB used, so 40 KiB leaves ~6.4 KiB margin and returns
  ~8 KiB to the heap. The stack-overflow watchpoint
  (`CONFIG_FREERTOS_WATCHPOINT_END_OF_STACK`) traps a deeper path cleanly.
- **Static WiFi buffers cut to the floor** — `STATIC_RX_BUFFER_NUM=4` (from 10)
  and `STATIC_TX_BUFFER_NUM=4` (from 8). These are *pre-allocated*, so they hit
  the idle baseline directly: ~16 KiB reclaimed. This was the single biggest
  baseline win. AMPDU disabled to drop the RX reorder buffers.
- **lwIP pools trimmed** — `MAX_SOCKETS`/`MAX_UDP_PCBS` 8→6 (only QUIC + SNTP +
  DNS are ever live), smaller mboxes, floored TCP windows (all traffic is UDP).
- **`NEWLIB_NANO_FORMAT=y`** — smaller printf, and a lower stack footprint on
  the format path.
- **No PSRAM, no Bluetooth, no coredump** — BT and coredump are already off by
  default; there is no further subsystem to disable. WiFi is the transport and
  cannot be removed, so its ~50 KiB is the hard floor.

The PSRAM and S3 targets deliberately keep **more conservative** buffer
settings — they have the RAM, so there is no reason to run them this close to
the edge.

### If it doesn't boot or drops connections

The cuts are at the functional floor, so if the deterministic ESP silicon
doesn't like a value on your board, back the relevant one off — small,
isolated changes:

- WiFi won't associate, or `no buffer` RX errors → `STATIC_RX_BUFFER_NUM` 4 → 6.
- TX stalls under load, or warnings like
  `noq_udp: sendmsg error: Os { code: 12, kind: OutOfMemory }` → the WiFi TX
  buffer pool is exhausting under a QUIC send burst (errno 12 / `ENOMEM` is
  lwIP failing to get a TX buffer, **not** a Rust-heap OOM — the heap stays at
  ~31 KB). It's only a warning (QUIC retransmits), so the floor build leaves it;
  bump `STATIC_TX_BUFFER_NUM` 4 → 8 to clear it, or switch to dynamic TX buffers.
- DNS/SNTP failures at boot → `LWIP_MAX_SOCKETS` / `MAX_UDP_PCBS` 6 → 8.
- A heap OOM with a *small* failing size → it's fragmentation; the smaller QUIC
  windows above are the main lever.

### Profiling the heap

[`src/alloc_log.rs`](src/alloc_log.rs) is a size-filtered logging global
allocator (enabled here) that prints every allocation/free at or above
`THRESHOLD` with a backtrace. The accept handler also logs free heap, the
largest contiguous block, and the main-task stack high-water per connection.
Pair an `[alloc]` with its `[free]` by pointer to tell held memory from
transient, and decode backtraces with
`xtensa-esp32-elf-addr2line -e target/xtensa-esp32-espidf/release/server-esp32 <pc>…`.
Raise `THRESHOLD` (or comment out the `#[global_allocator]` in `main.rs`) once
you are done — it is noisy.
