# noq interop: a bare QUIC server that iroh can dial

An echo server on an **ESP32-C6** (RISC-V, no PSRAM) that runs plain [noq] QUIC.
It has no iroh endpoint, relay, discovery, DNS or SNTP. A stock iroh endpoint
can still dial it with a long ticket, because the device speaks iroh's TLS
profile:

- TLS 1.3 with **raw public keys** ([RFC 7250]) on both sides. The server presents
  its ed25519 key, which is its iroh endpoint ID. It also requests the client's key,
  so it learns who dialed.
- No SNI. iroh doesn't send it, so the server doesn't need it.
- noq's **multipath** extension is negotiated, the same as between two iroh
  endpoints. iroh's n0 NAT-traversal extension is not: this is a LAN-direct device
  with no address candidates to offer.

All of that lives in [`tls.rs`][tls]. The QUIC side is [`echo.rs`][echo]: a noq
`Endpoint` with small flow-control windows, plus the two endpoint keys
([`keys.rs`][keys]) noq normally gets from ring.

The firmware uses [`iroh-base`] and [`iroh-tickets`] only for types: `SecretKey`
and `PublicKey` for the identity, and `EndpointAddr` and `EndpointTicket` for the
ticket it prints. They add about 2.5 KB.

## Layout

- [`noq-esp32-c6/`][fw] is the firmware.
- [`interop-test/`][test] is a host crate. It compiles the firmware's `echo`,
  `tls`, `keys` and crypto-provider modules unchanged, with the same
  rustls-rustcrypto provider, and dials them from a real iroh endpoint via a
  long ticket. It is meant to move into iroh's own test suite eventually.

## Binary size

| build | app image |
| --- | ---: |
| `noq-esp32-c6` (this) | 1,772,608 bytes (1.69 MiB) |
| [`server-esp32-c6`][iroh-c6] (full iroh 1.2, LAN-direct) | 3,898,800 bytes (3.72 MiB) |

Both use the same release profile: LTO, `codegen-units = 1`, `opt-level = "s"`,
`panic = "abort"`, std rebuilt with `optimize_for_size`. The biggest pieces are
noq-proto (~240 KB of symbols), rustls (~140 KB) and curve25519/ed25519 (~64 KB).
The P-256 code in rustls-rustcrypto is off; iroh only uses ed25519 and X25519.

The shipping-build options in `Cargo.toml` shrink it further:

| profile | app image |
| --- | ---: |
| default | 1,772,608 bytes (1.69 MiB) |
| + `opt-level = "z"` | 1,641,296 bytes (1.57 MiB) |
| + `panic = "immediate-abort"` | 1,535,472 bytes (1.46 MiB) |

## Build and flash

Tested on an ESP32-C6 (revision v0.2, 4 MB flash).

Same tooling as [`server-esp32-c6`][iroh-c6] (`esp` toolchain, ESP-IDF v5.3.3,
espflash):

```sh
cd noq-esp32-c6
WIFI_CONFIG='SSID:PASSWORD' cargo run --release   # flashes and opens the monitor
```

The serial log prints the long ticket:

```text
noq endpoint bound
  Listening on: 192.168.1.42:11204
  Endpoint ID: 6b1f…
  Long ticket:  endpoint…
```

The secret is generated at build time and baked in (set `IROH_SECRET=<64 hex>` to
choose one). The UDP port is fixed, so the ticket survives reboots as long as the
DHCP lease does.

## Dial it from iroh

From the same LAN, with the desktop [client]:

```sh
cd ../client
cargo run -- --no-relay --no-mdns <long-ticket>
```

## Host interop test

No board needed:

```sh
cd interop-test
cargo test
```

[noq]: https://docs.rs/noq
[RFC 7250]: https://datatracker.ietf.org/doc/html/rfc7250
[`iroh-base`]: https://docs.rs/iroh-base
[`iroh-tickets`]: https://docs.rs/iroh-tickets
[tls]: noq-esp32-c6/src/tls.rs
[echo]: noq-esp32-c6/src/echo.rs
[keys]: noq-esp32-c6/src/keys.rs
[fw]: noq-esp32-c6/
[test]: interop-test/
[iroh-c6]: ../server-esp32-c6/README.md
[client]: ../client/README.md
