//! An echo server on an ESP32-C6 that speaks bare noq (QUIC) — no iroh endpoint, no
//! relay, no discovery — yet is dialable from any iroh endpoint via a long ticket.
//!
//! What makes that work is entirely in the TLS setup ([`tls`]): iroh authenticates
//! peers with raw ed25519 public keys in TLS 1.3, and a plain noq server can do the
//! same with a rustls config. iroh sends ordinary QUIC packets on direct IP paths.

use core::convert::TryInto;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::wifi::{BlockingWifi, ClientConfiguration, Configuration, EspWifi};
use iroh_base::{EndpointAddr, SecretKey, TransportAddr};
use iroh_tickets::endpoint::EndpointTicket;
use log::info;

mod echo;
mod keys;
mod quic_crypto_provider;
mod tls;

/// The endpoint secret, baked in at build time by build.rs (or set explicitly via
/// IROH_SECRET=<64 hex chars>), so the endpoint ID is stable across reboots.
const IROH_SECRET: &str = env!("IROH_SECRET");

const WIFI_CONFIG: &str = match option_env!("WIFI_CONFIG") {
    Some(value) => value,
    None => panic!("WIFI_CONFIG is not set. Build with WIFI_CONFIG='SSID:PASSWORD' cargo build"),
};

/// Fixed UDP port: together with the fixed secret (and a DHCP lease that usually
/// sticks) the ticket stays the same across reboots.
const PORT: u16 = 11204;

fn connect_wifi() -> (BlockingWifi<EspWifi<'static>>, Ipv4Addr) {
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
    wifi.connect().expect("Failed to connect to WiFi");
    wifi.wait_netif_up().expect("Failed to wait for netif up");
    let ip_info = wifi
        .wifi()
        .sta_netif()
        .get_ip_info()
        .expect("Failed to get IP info");
    info!("WiFi DHCP info: {ip_info:?}");

    let ip = ip_info.ip.octets();
    (wifi, Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))
}

fn main() {
    // It is necessary to call this function once. Otherwise, some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    // Register eventfd VFS — needed by mio's poll implementation which powers tokio I/O
    let eventfd_config = esp_idf_svc::sys::esp_vfs_eventfd_config_t {
        max_fds: 5,
        ..Default::default()
    };
    unsafe { esp_idf_svc::sys::esp_vfs_eventfd_register(&eventfd_config) };

    let secret: SecretKey = IROH_SECRET.parse().expect("IROH_SECRET must be 64 hex chars");
    // Pure-Rust crypto provider with minimal QUIC support (AES-128-GCM + X25519).
    let provider = Arc::new(quic_crypto_provider::provider());

    let (_wifi, wifi_ip) = connect_wifi();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .thread_stack_size(4096)
        .build()
        .expect("Failed to create tokio runtime");

    rt.block_on(async {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, PORT)).expect("bind UDP socket");
        let endpoint = echo::bind(&secret, provider, socket).expect("create noq endpoint");

        info!(
            "[heap] after bind: free={} largest_8bit={}",
            unsafe { esp_idf_svc::sys::esp_get_free_heap_size() },
            unsafe {
                esp_idf_svc::sys::heap_caps_get_largest_free_block(
                    esp_idf_svc::sys::MALLOC_CAP_8BIT,
                )
            },
        );

        // LAN-direct only, so only the long ticket (endpoint ID + IP:port) is useful.
        let addr = EndpointAddr::from_parts(
            secret.public(),
            [TransportAddr::Ip(SocketAddr::new(wifi_ip.into(), PORT))],
        );
        info!("noq endpoint bound");
        info!("  Listening on: {wifi_ip}:{PORT}");
        info!("  Endpoint ID: {}", secret.public());
        info!("  Long ticket:  {}", EndpointTicket::new(addr));

        echo::serve(endpoint).await;
    });
}
