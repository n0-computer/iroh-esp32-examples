use core::convert::TryInto;

use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::wifi::{BlockingWifi, ClientConfiguration, Configuration, EspWifi};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::SecretKey;
use iroh::tls::CaTlsConfig;
use iroh_tickets::endpoint::EndpointTicket;
use log::{info, warn};

// Allocation-profiling allocator. Kept in-repo but NOT hooked up by default — it
// logs a backtrace per allocation via blocking ROM printf, which starves the app
// under load (throughput craters, the client times out). To profile, uncomment
// the `#[global_allocator]` below (and tune `alloc_log::THRESHOLD`), and run
// without `--monitor` so the serial console doesn't throttle it.
#[allow(dead_code)]
mod alloc_log;
mod std_dns_resolver;
mod quic_crypto_provider;
mod insecure_verifier;

// #[global_allocator]
// static GLOBAL_ALLOC: alloc_log::LoggingAlloc = alloc_log::LoggingAlloc;

/// The ALPN for the echo protocol
const ECHO_ALPN: &[u8] = b"echo/0";

/// Stack for the thread running tokio + the whole iroh stack. Allocated in
/// PSRAM (see the ThreadSpawnConfiguration in main) — internal SRAM is too
/// tight for it once esp_hosted + esp_wifi_remote are linked in.
const TOKIO_STACK_SIZE: usize = 96 * 1024;

/// Optional: bake in a fixed secret key so the node ID is stable across reboots.
/// Set via: IROH_SECRET=<64 hex chars or base32> cargo build
const IROH_SECRET: Option<&str> = option_env!("IROH_SECRET");

/// The P4 itself has no radio: WiFi comes from the board's ESP32-C6-MINI-1
/// companion module over SDIO (ESP-Hosted slave firmware on the C6, the
/// esp_wifi_remote + esp_hosted components on our side). The esp_wifi_* API —
/// and therefore this whole file — looks exactly like a native-WiFi chip.
const WIFI_CONFIG: &str = match option_env!("WIFI_CONFIG") {
    Some(value) => value,
    None => panic!("WIFI_CONFIG is not set. Build with WIFI_CONFIG='SSID:PASSWORD' cargo build"),
};

fn parse_secret_key() -> Option<SecretKey> {
    let s = IROH_SECRET?;
    Some(
        s.parse()
            .expect("IROH_SECRET must be valid hex (64 chars) or base32"),
    )
}

fn connect_wifi() -> (BlockingWifi<EspWifi<'static>>, std::net::Ipv4Addr) {
    let (ssid, password) = WIFI_CONFIG
        .split_once(':')
        .expect("WIFI_CONFIG must be in the format SSID:PASSWORD");

    info!("Connecting to WiFi network: {ssid} (via the ESP32-C6 companion over SDIO)");

    let peripherals = Peripherals::take().expect("Failed to take peripherals");
    let sys_loop = EspSystemEventLoop::take().expect("Failed to take event loop");
    let nvs = EspDefaultNvsPartition::take().expect("Failed to take NVS partition");

    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(peripherals.modem, sys_loop.clone(), Some(nvs))
            .expect("Failed to create EspWifi"),
        sys_loop,
    )
    .expect("Failed to create BlockingWifi");

    let config = Configuration::Client(ClientConfiguration {
        ssid: ssid.try_into().expect("SSID too long"),
        password: password.try_into().expect("Password too long"),
        ..Default::default()
    });

    wifi.set_configuration(&config)
        .expect("Failed to set WiFi configuration");
    wifi.start().expect("Failed to start WiFi");
    info!("WiFi started");

    wifi.connect().expect("Failed to connect to WiFi");
    info!("WiFi connected");

    wifi.wait_netif_up().expect("Failed to wait for netif up");
    let ip_info = wifi
        .wifi()
        .sta_netif()
        .get_ip_info()
        .expect("Failed to get IP info");
    info!("WiFi DHCP info: {ip_info:?}");

    let ip = ip_info.ip;
    (
        wifi,
        std::net::Ipv4Addr::new(
            ip.octets()[0],
            ip.octets()[1],
            ip.octets()[2],
            ip.octets()[3],
        ),
    )
}

fn sync_time_sntp() -> esp_idf_svc::sntp::EspSntp<'static> {
    info!("Starting SNTP time sync...");
    let sntp = esp_idf_svc::sntp::EspSntp::new_default().expect("Failed to start SNTP");
    let mut retries = 0;
    while sntp.get_sync_status() != esp_idf_svc::sntp::SyncStatus::Completed {
        retries += 1;
        if retries > 30 {
            warn!("SNTP sync timed out after 30s, continuing anyway");
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    if sntp.get_sync_status() == esp_idf_svc::sntp::SyncStatus::Completed {
        info!("SNTP synced");
    }
    sntp
}

/// Echo protocol handler
#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let endpoint_id = connection.remote_id();
        // Per-connection heap probe: a leak shows as `free` dropping each
        // connection; fragmentation shows as `free` ~steady but `largest_8bit`
        // shrinking (no contiguous block left).
        info!(
            "Accepted connection from {endpoint_id} [heap free={} largest_8bit={}]",
            unsafe { esp_idf_svc::sys::esp_get_free_heap_size() },
            unsafe {
                esp_idf_svc::sys::heap_caps_get_largest_free_block(
                    esp_idf_svc::sys::MALLOC_CAP_8BIT,
                )
            },
        );

        let (mut send, mut recv) = connection.accept_bi().await?;
        info!("Got bidi stream");

        // Echo with a 1 KiB STACK buffer instead of tokio::io::copy, whose 8 KiB
        // heap buffer OOM'd on the 2nd connection on the bare-LX6 boards. A stack
        // buffer puts zero pressure on the heap on the data path.
        let mut buf = [0u8; 1024];
        let mut total: u64 = 0;
        loop {
            let n = AsyncReadExt::read(&mut recv, &mut buf).await?;
            if n == 0 {
                break;
            }
            AsyncWriteExt::write_all(&mut send, &buf[..n]).await?;
            total += n as u64;
        }
        info!("Copied over {total} byte(s)");

        send.finish()?;

        connection.closed().await;
        info!("Connection closed");

        // Stack high-water: minimum free bytes ever seen on this (the tokio)
        // thread's PSRAM stack. tokio current_thread runs every async task here,
        // so this is the deepest the whole async tree ever got. Whatever's left
        // is headroom that could be trimmed from TOKIO_STACK_SIZE.
        let stack_total = TOKIO_STACK_SIZE;
        let stack_free = unsafe {
            esp_idf_svc::sys::uxTaskGetStackHighWaterMark(core::ptr::null_mut())
        };
        info!("[stack] tokio thread high-water: {stack_free} bytes free of {stack_total}");

        Ok(())
    }
}

fn main() {
    // It is necessary to call this function once. Otherwise, some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_svc::sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    // Register eventfd VFS — needed by mio's poll implementation which powers tokio I/O
    let eventfd_config = esp_idf_svc::sys::esp_vfs_eventfd_config_t {
        max_fds: 5,
        ..Default::default()
    };
    unsafe { esp_idf_svc::sys::esp_vfs_eventfd_register(&eventfd_config) };

    // Pure-Rust crypto provider with minimal QUIC support
    let provider = std::sync::Arc::new(quic_crypto_provider::provider());

    let (_wifi, wifi_ip) = connect_wifi();

    // Sync system clock via SNTP — needed for TLS certificate validation
    // Keep _sntp alive so the periodic re-sync continues
    let _sntp = sync_time_sntp();

    // Run tokio + iroh on a separate thread whose stack lives in PSRAM
    // (stack_alloc_caps below; CONFIG_SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY=y
    // makes it legal). Internal SRAM can't hold a 96 KB stack anymore with the
    // esp_hosted/esp_wifi_remote components linked in — and with 32 MB of
    // PSRAM there's no reason it should. One rule for PSRAM stacks: this
    // thread must never run cache-disabling flash ops (NVS/flash writes, OTA).
    // NVS + WiFi init already happened above on the main task, and the iroh
    // path does no flash writes.
    use esp_idf_svc::hal::task::thread::{MallocCap, ThreadSpawnConfiguration};
    ThreadSpawnConfiguration {
        stack_alloc_caps: MallocCap::Spiram | MallocCap::Cap8bit,
        ..Default::default()
    }
    .set()
    .expect("failed to set thread spawn configuration");

    let tokio_thread = std::thread::Builder::new()
        .name("tokio".into())
        .stack_size(TOKIO_STACK_SIZE)
        .spawn(move || tokio_main(provider, wifi_ip))
        .expect("failed to spawn tokio thread");
    tokio_thread.join().expect("tokio thread panicked");
}

fn tokio_main(provider: std::sync::Arc<rustls::crypto::CryptoProvider>, wifi_ip: std::net::Ipv4Addr) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .thread_stack_size(4096)
        .build()
        .expect("Failed to create tokio runtime");

    rt.block_on(async {
        let dns_resolver = iroh::dns::DnsResolver::custom(std_dns_resolver::StdDnsResolver);

        // QUIC transport config. The defaults size flow-control windows for
        // internet throughput (MB-scale per connection) — shrink hard: one bidi
        // stream (echo only), tiny windows, no datagrams. With 32 MB PSRAM this
        // is hygiene rather than survival — it only caps throughput, which an
        // echo doesn't need.
        let transport_config = {
            use iroh::endpoint::{QuicTransportConfig, VarInt};
            QuicTransportConfig::builder()
                .max_concurrent_bidi_streams(VarInt::from_u32(1))
                .max_concurrent_uni_streams(VarInt::from_u32(0))
                .stream_receive_window(VarInt::from_u32(4 * 1024))
                .receive_window(VarInt::from_u32(8 * 1024))
                .send_window(8 * 1024)
                .datagram_receive_buffer_size(None)
                .build()
        };

        info!("[heap] before endpoint setup: free={} largest_8bit={}", unsafe {
            esp_idf_svc::sys::esp_get_free_heap_size()
        }, unsafe {
            esp_idf_svc::sys::heap_caps_get_largest_free_block(esp_idf_svc::sys::MALLOC_CAP_8BIT)
        });

        let mut builder = iroh::Endpoint::builder(iroh::endpoint::presets::Empty)
            .crypto_provider(provider)
            .ca_tls_config(CaTlsConfig::custom_server_cert_verifier(
                insecure_verifier::skip_verify(),
            ))
            .dns_resolver(dns_resolver)
            .transport_config(transport_config)
            // Kill the TLS client session-resumption cache (see the C61 variant
            // for the full story) — we never resume on this embedded server.
            .max_tls_tickets(0)
            // Full relay + pkarr discovery: with 32 MB of in-package PSRAM the
            // P4 is the roomiest chip in this repo. Reachable across networks
            // via the short ticket.
            .relay_mode(iroh::RelayMode::Default)
            .address_lookup(iroh::address_lookup::PkarrPublisher::n0_dns())
            .address_lookup(iroh::address_lookup::PkarrResolver::n0_dns())
            // Disable HTTPS latency probes and captive-portal detection: both make
            // real-cert TLS connections, which our minimal crypto provider (no RSA,
            // AES-128-GCM + X25519 only) cannot verify. QAD (UDP) probes still
            // measure relay latency.
            .net_report_config({
                let mut c = iroh::NetReportConfig::default();
                c.https_probes = false;
                c.captive_portal_check = false;
                c
            });

        if let Some(key) = parse_secret_key() {
            builder = builder.secret_key(key);
        }

        let endpoint = builder.bind().await.expect("unable to bind endpoint");

        info!(
            "[heap] after bind: free={} largest_8bit={}",
            unsafe { esp_idf_svc::sys::esp_get_free_heap_size() },
            unsafe {
                esp_idf_svc::sys::heap_caps_get_largest_free_block(
                    esp_idf_svc::sys::MALLOC_CAP_8BIT,
                )
            },
        );

        let endpoint_id = endpoint.addr().id;
        let port = endpoint
            .bound_sockets()
            .first()
            .map(|s| s.port())
            .expect("no bound socket");

        // Short ticket: bare endpoint ID, resolved via pkarr/relay — the ticket to
        // dial from another network.
        let short_ticket = EndpointTicket::new(iroh::EndpointAddr::new(endpoint_id));

        // Long ticket: includes WiFi IP + bound port (same-LAN direct fast path).
        let mut addr_with_ip = endpoint.addr();
        addr_with_ip
            .addrs
            .insert(iroh::TransportAddr::Ip(std::net::SocketAddr::new(
                wifi_ip.into(),
                port,
            )));
        let long_ticket = EndpointTicket::new(addr_with_ip);

        let _router = Router::builder(endpoint).accept(ECHO_ALPN, Echo).spawn();

        info!("Iroh endpoint bound");
        info!("  Listening on: {wifi_ip}:{port}");
        info!("  Endpoint ID: {endpoint_id}");
        info!("  Short ticket: {short_ticket}");
        info!("  Long ticket:  {long_ticket}");

        info!("Router started, accepting connections");

        // Keep the router running indefinitely
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        }
    });
}
