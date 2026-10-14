//! A bare noq echo server that iroh endpoints can dial. Nothing in here is
//! ESP-specific; the host interop test runs this exact module.

use std::{io, net::UdpSocket, sync::Arc};

use iroh_base::SecretKey;
use log::{info, warn};
use noq::{EndpointConfig, ServerConfig, TransportConfig, VarInt};
use rustls::crypto::CryptoProvider;

use crate::{keys, tls};

/// The ALPN for the echo protocol, same as the iroh servers in this repo.
pub const ECHO_ALPN: &[u8] = b"echo/0";

/// Multipath paths we allow. iroh negotiates noq's multipath extension; one direct IP
/// path is all a LAN-only device uses, plus headroom for iroh migrating to a new one.
const MAX_PATHS: u32 = 4;

/// Creates a noq server endpoint on `socket` with iroh-compatible TLS for `secret`.
pub fn bind(
    secret: &SecretKey,
    provider: Arc<CryptoProvider>,
    socket: UdpSocket,
) -> io::Result<noq::Endpoint> {
    let crypto = tls::server_config(secret, provider, &[ECHO_ALPN]).map_err(io::Error::other)?;
    let mut server = ServerConfig::new(Arc::new(crypto), Arc::new(keys::TokenKey::random()));
    server
        .transport_config(Arc::new(transport_config()))
        // Default is 64Ki pending handshakes and 100 MiB of buffered Initial data;
        // a ~512 KB-SRAM chip has to cap that hard.
        .max_incoming(4)
        .incoming_buffer_size(16 * 1024)
        .incoming_buffer_size_total(32 * 1024);
    noq::Endpoint::new(
        EndpointConfig::new(Arc::new(keys::ResetKey::random())),
        Some(server),
        socket,
        Arc::new(noq::TokioRuntime),
    )
}

/// QUIC flow-control windows sized for the echo's working set rather than internet
/// throughput (MB-scale defaults would OOM the first stream). Same numbers as the
/// iroh C6 server.
fn transport_config() -> TransportConfig {
    let mut config = TransportConfig::default();
    config
        .max_concurrent_bidi_streams(VarInt::from_u32(1))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u32(4 * 1024))
        .receive_window(VarInt::from_u32(8 * 1024))
        .send_window(8 * 1024)
        .datagram_receive_buffer_size(None)
        .max_concurrent_multipath_paths(MAX_PATHS);
    config
}

/// Accepts connections forever, echoing the first bidi stream of each.
pub async fn serve(endpoint: noq::Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            if let Err(err) = echo(incoming).await {
                warn!("connection failed: {err}");
            }
        });
    }
}

async fn echo(incoming: noq::Incoming) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let from = incoming.remote_address();
    let conn = incoming.await?;
    let remote = tls::remote_id(&conn).ok_or("peer did not present an ed25519 key")?;
    info!("Accepted connection from {remote} at {from}{}", mem_info());

    let (mut send, mut recv) = conn.accept_bi().await?;
    // 1 KiB stack buffer: no heap pressure on the data path.
    let mut buf = [0u8; 1024];
    let mut total = 0u64;
    while let Some(n) = recv.read(&mut buf).await? {
        send.write_all(&buf[..n]).await?;
        total += n as u64;
    }
    send.finish()?;
    info!("Copied over {total} byte(s)");

    let reason = conn.closed().await;
    info!("Connection closed: {reason}{}", mem_info());
    Ok(())
}

/// Memory probe for the device logs. Heap: a leak shows as `free` dropping per
/// connection, fragmentation as `largest_8bit` shrinking. Stack: the minimum free
/// bytes ever seen on the main task, which runs every tokio task (current_thread),
/// so this is the deepest the QUIC/TLS handshake + echo ever got.
fn mem_info() -> String {
    #[cfg(target_os = "espidf")]
    {
        use esp_idf_svc::sys;
        unsafe {
            format!(
                " [heap free={} largest_8bit={}] [stack free min={}]",
                sys::esp_get_free_heap_size(),
                sys::heap_caps_get_largest_free_block(sys::MALLOC_CAP_8BIT),
                sys::uxTaskGetStackHighWaterMark(core::ptr::null_mut()),
            )
        }
    }
    #[cfg(not(target_os = "espidf"))]
    String::new()
}
