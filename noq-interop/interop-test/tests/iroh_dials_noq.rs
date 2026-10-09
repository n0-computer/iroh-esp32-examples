//! An iroh endpoint dials the bare noq echo server via a long ticket.

use std::{
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    sync::Arc,
};

use iroh::{endpoint::presets, Endpoint, RelayMode};
use iroh_base::{EndpointAddr, SecretKey, TransportAddr};
use iroh_tickets::endpoint::EndpointTicket;
use noq_interop_test::{echo, quic_crypto_provider};

#[tokio::test]
async fn iroh_dials_noq_echo() {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).try_init().ok();

    // Server side: exactly what the firmware does after WiFi is up.
    let secret = SecretKey::from_bytes(&rand_bytes());
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = socket.local_addr().unwrap().port();
    let server = echo::bind(
        &secret,
        Arc::new(quic_crypto_provider::provider()),
        socket,
    )
    .unwrap();
    let addr = EndpointAddr::from_parts(
        secret.public(),
        [TransportAddr::Ip(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port))],
    );
    let ticket = EndpointTicket::new(addr).to_string();
    tokio::spawn(echo::serve(server.clone()));

    // Client side: a stock iroh endpoint, given nothing but the ticket string.
    let addr: iroh::EndpointAddr = ticket.parse::<EndpointTicket>().unwrap().into();
    let client = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    for round in 0..3 {
        let conn = client.connect(addr.clone(), echo::ECHO_ALPN).await.unwrap();
        assert_eq!(conn.remote_id(), secret.public());

        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        // Bigger than the 4 KiB stream window, so flow control has to work.
        let msg: Vec<u8> = (0..20_000u32).map(|i| (i ^ round) as u8).collect();
        send.write_all(&msg).await.unwrap();
        send.finish().unwrap();
        let echoed = recv.read_to_end(usize::MAX).await.unwrap();
        assert_eq!(echoed, msg);
        conn.close(0u32.into(), b"done");
    }
    client.close().await;
}

fn rand_bytes() -> [u8; 32] {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).unwrap();
    buf
}
