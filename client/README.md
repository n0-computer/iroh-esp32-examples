# Desktop client

A client for desktop computers to go with the ESP32 servers in this repository.

It can dial both long tickets (containing IP addresses and relays) and short
tickets (containing just the endpoint id).

## Build / run

```bash
cargo run <endpoint-ticket>
```

Use the endpoint ticket printed by the server on its serial monitor. A long
ticket (with IP address) enables direct dialing.
