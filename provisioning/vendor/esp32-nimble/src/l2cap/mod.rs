#[cfg(not(esp_idf_soc_esp_nimble_controller))]
use esp_idf_svc::sys::{os_mbuf_free, os_mbuf_get_pkthdr, os_mbuf_pool_init, os_mempool_init};
#[cfg(esp_idf_soc_esp_nimble_controller)]
use esp_idf_svc::sys::{
    r_os_mbuf_free as os_mbuf_free, r_os_mbuf_get_pkthdr as os_mbuf_get_pkthdr,
    r_os_mbuf_pool_init as os_mbuf_pool_init,
};
// ESP-IDF v5.5 renamed os_mempool_init to r_os_mempool_init on chips with the
// ESP NimBLE controller (C5/C6/C61/H2), like the os_mbuf functions above.
#[cfg(all(
    esp_idf_soc_esp_nimble_controller,
    not(any(
        esp_idf_version_major = "6",
        all(esp_idf_version_major = "5", esp_idf_version_minor = "5")
    ))
))]
use esp_idf_svc::sys::os_mempool_init;
#[cfg(all(
    esp_idf_soc_esp_nimble_controller,
    any(
        esp_idf_version_major = "6",
        all(esp_idf_version_major = "5", esp_idf_version_minor = "5")
    )
))]
use esp_idf_svc::sys::r_os_mempool_init as os_mempool_init;

mod l2cap_channel;
pub use l2cap_channel::L2capChannel;

mod l2cap_client;
pub use l2cap_client::L2capClient;

mod l2cap_server;
pub use l2cap_server::L2capServer;

mod l2cap_core;
use l2cap_core::L2cap;

mod utilities;
pub use utilities::ReceivedData;
