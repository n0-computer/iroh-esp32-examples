# Published iroh release sizes

All seven ESP32 server examples build with unmodified **iroh 1.2.0 from
crates.io**, the latest release checked on 2026-09-28. Their lockfiles contain
no Hickory packages or Git-sourced iroh packages. The existing rustls-rustcrypto
Git dependency remains necessary and unchanged.

Every release application fits **4 MiB flash with espflash's default single-app
layout**: app offset `0x10000`, app capacity **4,128,768 bytes**. This is stricter
than comparing only against the raw 4,194,304-byte flash-chip capacity.

| Example | App bytes | MiB | App-partition headroom |
| --- | ---: | ---: | ---: |
| `server-esp32` | 3,876,464 | 3.697 | 252,304 bytes |
| `server-esp32-c6` | 3,957,456 | 3.774 | 171,312 bytes |
| `server-esp32-c61-psram` | 4,020,832 | 3.835 | 107,936 bytes |
| `server-esp32-p4` | 3,838,896 | 3.661 | 289,872 bytes |
| `server-esp32-psram` | 4,033,824 | 3.847 | 94,944 bytes |
| `server-esp32-s3` | 3,890,608 | 3.710 | 238,160 bytes |
| `server-esp32-s3-psram` | 4,001,424 | 3.816 | 127,344 bytes |

These are generated **application image** sizes, not ELF file sizes. The
comparison reserves the first 64 KiB for the bootloader/partition area; it does
not provide two OTA app slots or reserve an additional filesystem partition.
It uses espflash's generated layout, not ESP-IDF's build-time partition table.

**Flash settings and partition configuration are unchanged**, including the S3
examples' existing 8 MiB settings. The `--flash-size 4mb` below is only an image
size check, not a change to any project's flash configuration. RAM settings,
relay/discovery behavior, crypto-provider features, and release profiles also
remain unchanged. No hardware was flashed or runtime memory revalidated.

## Reproduce

Build each server from its own directory after activating the espup environment
(usually `. "$HOME/export-esp.sh"`):

```sh
cd server-esp32
WIFI_CONFIG='size-test:unused' cargo +esp build --locked --release
```

The measurements used placeholder Wi-Fi credentials, the committed release
profiles (`opt-level = "s"`, LTO, one codegen unit, `panic = "abort"`), and the
existing size-optimized build of `std`. Toolchain:
`rustc +esp 1.92.0-nightly (1e93cde56 2025-12-10)`.
ESP-IDF remains v5.3.3 for ESP32/S3/C6 and v5.5.4 for C61/P4.

After building all seven examples, run from the repository root (Python 3.11+):

```sh
python3 scripts/measure-release-sizes.py
```

This verifies each lockfile's iroh source/version and absence of Hickory, then
uses `espflash save-image --chip <chip> --flash-size 4mb` to generate and validate
the images. It writes the images and `sizes.json` under `target/release-sizes/`.
Individual examples can be selected with positional arguments.

For example, the underlying measurement for the original ESP32 is:

```sh
espflash save-image --skip-update-check --chip esp32 --flash-size 4mb \
  server-esp32/target/xtensa-esp32-espidf/release/server-esp32 /tmp/server-esp32.bin
wc -c /tmp/server-esp32.bin
```

`gethostname` linker stubs formerly required by Hickory's `resolv_conf`
dependency have been removed. The application-level `StdDnsResolver` adapters
remain, as do the existing runtime and memory configurations.
