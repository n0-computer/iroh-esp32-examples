use std::net::Ipv4Addr;

use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::modem::WifiModemPeripheral;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::sys::{
    esp, esp_coex_prefer_t_ESP_COEX_PREFER_WIFI, esp_coex_preference_set, EspError,
};
use esp_idf_svc::wifi::config::ScanConfig;
use esp_idf_svc::wifi::{AuthMethod, BlockingWifi, ClientConfiguration, Configuration, EspWifi};
use iroh_provision::device::{AccessPoint, Wifi};
use iroh_provision::{Failure, Network};
use log::warn;

/// How long to wait for the access point, and then for an address.
const JOIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// The WiFi driver in station mode, started.
pub struct StationWifi(BlockingWifi<EspWifi<'static>>);

impl StationWifi {
    /// Create the driver and start it in station mode, without joining
    /// anything yet. Starting it also makes the hardware RNG a true RNG.
    pub fn start(
        modem: impl WifiModemPeripheral + 'static,
        sys_loop: EspSystemEventLoop,
        nvs: EspDefaultNvsPartition,
    ) -> Result<Self, EspError> {
        let mut wifi =
            BlockingWifi::wrap(EspWifi::new(modem, sys_loop.clone(), Some(nvs))?, sys_loop)?;
        // The driver needs a mode before start(); the real config comes in
        // join(). Auth threshold None, or the driver warns about the empty
        // password.
        wifi.set_configuration(&Configuration::Client(ClientConfiguration {
            auth_method: AuthMethod::None,
            ..Default::default()
        }))?;
        wifi.start()?;
        // With Bluetooth compiled in, the coexistence arbiter keeps radio time
        // for it even when it isn't running, and WiFi then misses much of
        // what other devices on the LAN send: no ping, no direct connection,
        // only traffic the device asked for. Give WiFi the radio. BLE still
        // works, it's only used while provisioning.
        esp!(unsafe { esp_coex_preference_set(esp_coex_prefer_t_ESP_COEX_PREFER_WIFI) })?;
        Ok(Self(wifi))
    }
}

impl Wifi for StationWifi {
    fn scan(&mut self) -> Vec<AccessPoint> {
        // A previous failed attempt can leave the driver mid-connect, which
        // makes the scan fail.
        let _ = self.0.disconnect();
        let config = ScanConfig {
            show_hidden: true,
            ..Default::default()
        };
        let result = self
            .0
            .wifi_mut()
            .start_scan(&config, true)
            .and_then(|_| self.0.wifi_mut().get_scan_result());
        match result {
            Ok(aps) => aps
                .into_iter()
                .map(|ap| AccessPoint {
                    ssid: ap.ssid.as_str().to_owned(),
                    rssi: ap.signal_strength,
                })
                .collect(),
            Err(e) => {
                warn!("Scan failed: {e}");
                Vec::new()
            }
        }
    }

    fn join(&mut self, network: &Network) -> Result<Ipv4Addr, Failure> {
        let config = Configuration::Client(ClientConfiguration {
            // Lengths are checked by the protocol, so these can't fail.
            ssid: network
                .ssid
                .as_str()
                .try_into()
                .map_err(|_| Failure::BadMessage)?,
            password: network
                .password
                .as_str()
                .try_into()
                .map_err(|_| Failure::BadMessage)?,
            auth_method: if network.password.is_empty() {
                AuthMethod::None
            } else {
                AuthMethod::WPA2Personal
            },
            ..Default::default()
        });
        let _ = self.0.disconnect();
        self.0
            .set_configuration(&config)
            .map_err(|_| Failure::WifiConnect)?;
        // Not BlockingWifi::connect(): its 15 s timeout is too short when
        // BLE shares the radio, and on dual-band chips the scan alone takes
        // a while.
        self.0
            .wifi_mut()
            .connect()
            .map_err(|_| Failure::WifiConnect)?;
        let wifi = &self.0;
        if wifi
            .wifi_wait_while(|| wifi.is_connected().map(|c| !c), Some(JOIN_TIMEOUT))
            .is_err()
        {
            let _ = self.0.disconnect();
            return Err(Failure::WifiConnect);
        }
        if wifi
            .ip_wait_while(|| wifi.is_up().map(|up| !up), Some(JOIN_TIMEOUT))
            .is_err()
        {
            let _ = self.0.disconnect();
            return Err(Failure::NoIp);
        }
        let ip = self
            .0
            .wifi()
            .sta_netif()
            .get_ip_info()
            .map_err(|_| Failure::NoIp)?
            .ip;
        Ok(ip)
    }

    fn is_connected(&mut self) -> bool {
        self.0.is_connected().unwrap_or(false)
    }
}
