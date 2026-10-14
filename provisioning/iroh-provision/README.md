# iroh-provision

Get WiFi credentials onto an iroh device, encrypted to its endpoint id, and
get back a ticket that lets you pair with it.

## Workflow

1. **First boot.** The device generates its ed25519 key, its iroh endpoint id,
   and keeps it forever. With no networks stored, it goes into provisioning
   mode and offers its public key and its kind (e.g. `co2`) over a transport
   (BLE, in practice).
2. **Connect.** The client (a web page, a CLI) connects and reads the endpoint
   id and kind. Compare the endpoint id with the one the device prints, to
   rule out someone impersonating it. The kind gives new devices a default
   name: `co2-1`, `co2-2`, …
3. **Provision.** The client sends one message, sealed with HPKE to the
   endpoint id, so only that device can open it. The message holds:
   - up to 4 WiFi networks,
   - a name for the device,
   - a fresh random pairing secret.
4. **Join.** The device scans and joins the strongest network it knows,
   reporting progress (`Connecting`, then `Connected` or a reason for
   failing). On failure the client can fix the networks and send again over
   the same connection.
5. **Ticket.** On success the device stores everything and turns off BLE. The
   client now holds a **pairing ticket**: endpoint id + pairing secret. The
   endpoint id alone is public; the ticket is what proves you're allowed in.
6. **Pair** (not implemented yet). Whoever redeems the ticket first over iroh
   becomes an owner, and is recognized by their own endpoint id from then on.
   The secret is used up.

Later:

- **Losing WiFi**: the device keeps trying all its stored networks, strongest
  in range first, with growing pauses (5 s up to 60 s), at boot as well as
  when the connection drops. It never goes back to provisioning mode on its
  own: a router rebooting after a power cut usually comes back, and devices
  stuck waiting for their tickets would be worse.
- **Reset**: a long button press makes the device forget networks, name and
  pairing secret, and go back to provisioning mode. The endpoint id stays.
  This is the only way into provisioning mode for a provisioned device.
- **Reprovisioning** (new networks, e.g. after moving the device): reset it,
  then send its existing name and ticket again with the new networks. Only
  the networks change; the ticket stays valid.

The device shows its state (`Provisioning`, `Connecting`, `Connected`) on an
`Indicator`, in whatever way its hardware allows: blink patterns on a plain
LED, colors on an RGB LED.

## Using it

The crate is platform independent; transports and platform glue are separate:

| Crate | Side | Contents |
|---|---|---|
| `iroh-provision` | both | formats, sealing, the client `Session`, the device logic |
| `iroh-provision-ble` | client | BLE transports: btleplug (`native`), Web Bluetooth (`web`) |
| `iroh-provision-esp-idf` | device | NimBLE GATT service, NVS storage, WiFi |

Client, with feature `client`:

```rust
let mut session = Session::connect(transport).await?;
println!("compare with the device: {}", session.endpoint());
let provisioned = session.provision(&networks, "lamp-1").await?;
println!("joined {}, ticket {}", provisioned.ssid, provisioned.ticket);
// later, keeping name and ticket:
session.reprovision(&new_networks, "lamp-1", &provisioned.ticket).await?;
```

Device, with feature `device`, over your own `Storage`, `Wifi` and
`Transport` (or the ESP-IDF ones):

```rust
let secret = device::load_or_create_identity(&mut storage, fill_random)?;
let joined = match device::load_credentials(&mut storage) {
    // Stored networks: keep trying them, never provisioning mode.
    Some(creds) => device::connect(&mut wifi, &creds, &mut indicator, sleep),
    None => device::provision(&mut storage, &mut wifi, &secret, &mut transport)?,
};
// Later, on a thread: rejoin whatever stored network is around.
device::stay_connected(&mut wifi, &creds, &mut indicator, sleep);
```

## Security

- Passive sniffing reveals nothing: the password and the pairing secret only
  travel sealed to the device's key.
- An attacker impersonating the device during provisioning isn't stopped by
  the protocol alone; comparing the endpoint id is. After that, every iroh
  connection is authenticated by the same key, so a man in the middle would
  have to proxy forever.
- While unprovisioned, anyone in range can provision the device.

## Formats

All postcard. A sealed message is `version (1) | HPKE enc (32) | ciphertext |
tag (16)`, HPKE base mode with DHKEM(X25519, HKDF-SHA256) and
ChaCha20Poly1305, to the X25519 form of the ed25519 key, with the endpoint id
as associated data. The worst case (4 networks, maximum lengths) is 508 bytes,
so it fits a single BLE characteristic write (512). A ticket is `pair` +
base32 of a versioned postcard payload.
