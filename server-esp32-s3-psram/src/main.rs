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

mod std_dns_resolver;
mod quic_crypto_provider;
mod insecure_verifier;

/// The ALPN for the echo protocol
const ECHO_ALPN: &[u8] = b"echo/0";

/// Optional: bake in a fixed secret key so the node ID is stable across reboots.
/// Set via: IROH_SECRET=<64 hex chars or base32> cargo build
const IROH_SECRET: Option<&str> = option_env!("IROH_SECRET");

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

    info!("Connecting to WiFi network: {ssid}");

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
        let endpoint_id = connection.remote_id();
        info!("Accepted connection from {endpoint_id}");

        let (mut send, mut recv) = connection.accept_bi().await?;
        info!("Got bidi stream");

        // Echo bytes back
        let bytes_sent = tokio::io::copy(&mut recv, &mut send).await?;
        info!("Copied over {bytes_sent} byte(s)");

        send.finish()?;

        connection.closed().await;
        info!("Connection closed");

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

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .thread_stack_size(4096)
        .build()
        .expect("Failed to create tokio runtime");

    rt.block_on(async {
        let dns_resolver = iroh::dns::DnsResolver::custom(std_dns_resolver::StdDnsResolver);

        let mut builder = iroh::Endpoint::builder(iroh::endpoint::presets::Empty)
            .crypto_provider(provider)
            .ca_tls_config(CaTlsConfig::custom_server_cert_verifier(
                insecure_verifier::skip_verify(),
            ))
            .dns_resolver(dns_resolver)
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

        let endpoint_id = endpoint.addr().id;
        let port = endpoint
            .bound_sockets()
            .first()
            .map(|s| s.port())
            .expect("no bound socket");

        // Short ticket: just the endpoint ID (no addresses)
        let short_ticket = EndpointTicket::new(iroh::EndpointAddr::new(endpoint_id));

        // Long ticket: includes WiFi IP + bound port
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
