//! Lightweight DNS resolver using the system's getaddrinfo (via std::net::ToSocketAddrs).
//!
//! This avoids pulling in hickory-resolver's deeply nested async stack,
//! which requires ~111KB of stack space with opt-level "z".
//!
//! The blocking getaddrinfo call is run via `spawn_blocking` so it doesn't
//! stall the tokio event loop. Configure the runtime with a small
//! `thread_stack_size` and `max_blocking_threads(1)` to keep RAM usage low.

use std::net::{Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use iroh::dns::{BoxIter, DnsError, Resolver, TxtRecordData};
use log::{debug, warn};
use n0_error::e;
use n0_future::boxed::BoxFuture;

/// DNS resolver backed by the system's getaddrinfo (via `std::net::ToSocketAddrs`).
///
/// This is a lightweight alternative to hickory-resolver that delegates to the
/// OS DNS resolver. It supports A and AAAA lookups but not TXT records.
#[derive(Debug, Clone)]
pub struct StdDnsResolver;

/// Strip trailing dot from FQDN — some getaddrinfo implementations don't handle it.
fn strip_fqdn_dot(host: &str) -> &str {
    host.strip_suffix('.').unwrap_or(host)
}

impl Resolver for StdDnsResolver {
    fn lookup_ipv4(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
        Box::pin(async move {
            let h = strip_fqdn_dot(&host).to_string();
            debug!("[std-dns] lookup_ipv4: {h}");
            let addrs = tokio::task::spawn_blocking(move || {
                format!("{h}:0").to_socket_addrs()
            })
            .await
            .map_err(|e| {
                warn!("[std-dns] lookup_ipv4 {host}: spawn failed: {e}");
                e!(DnsError::NoResponse)
            })?
            .map_err(|e| {
                warn!("[std-dns] lookup_ipv4 {host}: getaddrinfo failed: {e}");
                e!(DnsError::NoResponse)
            })?;

            let v4: Vec<Ipv4Addr> = addrs
                .filter_map(|a| match a.ip() {
                    std::net::IpAddr::V4(ip) => Some(ip),
                    _ => None,
                })
                .collect();

            if v4.is_empty() {
                debug!("[std-dns] lookup_ipv4 {host}: no IPv4 results");
                Err(e!(DnsError::NoResponse))
            } else {
                debug!("[std-dns] lookup_ipv4 {host}: resolved to {v4:?}");
                Ok(Box::new(v4.into_iter()) as BoxIter<Ipv4Addr>)
            }
        })
    }

    fn lookup_ipv6(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
        Box::pin(async move {
            let h = strip_fqdn_dot(&host).to_string();
            debug!("[std-dns] lookup_ipv6: {h}");
            let addrs = tokio::task::spawn_blocking(move || {
                format!("{h}:0").to_socket_addrs()
            })
            .await
            .map_err(|e| {
                warn!("[std-dns] lookup_ipv6 {host}: spawn failed: {e}");
                e!(DnsError::NoResponse)
            })?
            .map_err(|e| {
                warn!("[std-dns] lookup_ipv6 {host}: getaddrinfo failed: {e}");
                e!(DnsError::NoResponse)
            })?;

            let v6: Vec<Ipv6Addr> = addrs
                .filter_map(|a| match a.ip() {
                    std::net::IpAddr::V6(ip) => Some(ip),
                    _ => None,
                })
                .collect();

            if v6.is_empty() {
                debug!("[std-dns] lookup_ipv6 {host}: no IPv6 results");
                Err(e!(DnsError::NoResponse))
            } else {
                debug!("[std-dns] lookup_ipv6 {host}: resolved to {v6:?}");
                Ok(Box::new(v6.into_iter()) as BoxIter<Ipv6Addr>)
            }
        })
    }

    fn lookup_txt(&self, host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
        // getaddrinfo doesn't support TXT records.
        // TXT lookups are used for iroh DNS endpoint discovery — not needed
        // when using pkarr or direct connections.
        Box::pin(async move {
            debug!("[std-dns] lookup_txt {host}: not supported");
            Err(e!(DnsError::NoResponse))
        })
    }

    fn clear_cache(&self) {}

    fn reset(&self) -> Box<dyn Resolver> {
        // StdDnsResolver is stateless (delegates to the OS resolver), so a fresh
        // clone is a valid replacement after a network change.
        Box::new(self.clone())
    }
}
