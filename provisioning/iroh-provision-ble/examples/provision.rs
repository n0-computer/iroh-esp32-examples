//! Provision every iroh device in BLE range with the same networks.
//!
//! ```sh
//! cargo run --example provision --features native -- \
//!     --network home:secret [--network office:other] [--name lamp-1] \
//!     [--ticket lamp-0=pair...] [--scan 5]
//! ```
//!
//! A trailing number in `--name` counts up per device (`lamp-1`, `lamp-2`, ...).
//! Prints each device's endpoint id (compare with its console) and its
//! single-use pairing ticket.
//!
//! A device with a `--ticket` is reprovisioned: it only gets the new networks,
//! and keeps the given name and the ticket's secret, so the ticket stays valid.

use std::time::Duration;

use iroh_provision::client::Session;
use iroh_provision::{Network, PairingTicket};
use iroh_provision_ble::native;
use n0_error::{anyerr, Result, StackResultExt, StdResultExt};

struct Args {
    networks: Vec<Network>,
    name: Option<String>,
    /// Devices to reprovision: name and existing ticket.
    tickets: Vec<(String, PairingTicket)>,
    scan: Duration,
}

fn parse_args() -> Result<Args> {
    let mut args = Args {
        networks: Vec::new(),
        name: None,
        tickets: Vec::new(),
        scan: Duration::from_secs(5),
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = || it.next().ok_or_else(|| anyerr!("{arg} needs a value"));
        match arg.as_str() {
            "--network" => {
                let value = value()?;
                let (ssid, password) = value.split_once(':').unwrap_or((&value, ""));
                args.networks.push(Network {
                    ssid: ssid.into(),
                    password: password.into(),
                });
            }
            "--name" => args.name = Some(value()?),
            "--ticket" => {
                let value = value()?;
                let (name, ticket) = value
                    .split_once('=')
                    .ok_or_else(|| anyerr!("--ticket wants NAME=TICKET"))?;
                args.tickets.push((name.into(), ticket.parse()?));
            }
            "--scan" => args.scan = Duration::from_secs(value()?.parse().std_context("--scan")?),
            other => return Err(anyerr!("unknown argument {other}")),
        }
    }
    if args.networks.is_empty() {
        return Err(anyerr!("give at least one --network ssid:password"));
    }
    Ok(args)
}

/// "lamp-1" -> "lamp-2"; names without a trailing number stay.
fn next_name(name: &str) -> String {
    let digits = name.len() - name.trim_end_matches(|c: char| c.is_ascii_digit()).len();
    if digits == 0 {
        return name.to_owned();
    }
    let (prefix, number) = name.split_at(name.len() - digits);
    let next = number.parse::<u64>().unwrap_or(0) + 1;
    format!("{prefix}{next:0digits$}")
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;
    println!("scanning for {:?}...", args.scan);
    let devices = native::discover(args.scan).await.context("scan failed")?;
    if devices.is_empty() {
        println!("no device in provisioning mode found");
        return Ok(());
    }
    let mut name = args.name.clone();
    for device in devices {
        let ble_name = device.name.clone().unwrap_or_else(|| "?".into());
        println!("\n{ble_name} ({} dBm)", device.rssi.unwrap_or_default());
        let transport = match device.connect().await {
            Ok(transport) => transport,
            Err(err) => {
                println!("  could not connect: {err:#}");
                continue;
            }
        };
        let mut session = Session::connect(transport).await?;
        println!("  endpoint id {}", session.endpoint());
        let known = args
            .tickets
            .iter()
            .find(|(_, ticket)| ticket.endpoint == session.endpoint());
        let (this_name, ticket) = match known {
            Some((known_name, ticket)) => {
                println!("  reprovisioning {known_name:?}, keeping its ticket...");
                (known_name.clone(), Some(ticket))
            }
            None => {
                let this_name = name.clone().unwrap_or_else(|| ble_name.clone());
                println!("  provisioning as {this_name:?}...");
                (this_name, None)
            }
        };
        let result = session
            .provision_with(&args.networks, &this_name, ticket, |status| {
                println!("  status {status:?}")
            })
            .await;
        match result {
            Ok(provisioned) => {
                println!("  joined {}, IP {}", provisioned.ssid, provisioned.ip);
                println!("  ticket {}", provisioned.ticket);
                if ticket.is_none() {
                    name = name.as_deref().map(next_name);
                }
            }
            Err(err) => println!("  failed: {err:#}"),
        }
        // After success the device turns BLE off itself; this is for failures.
        let _ = session.into_transport().disconnect().await;
    }
    Ok(())
}
