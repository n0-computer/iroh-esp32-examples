use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};
use esp_idf_svc::sys::EspError;
use iroh_provision::device::Storage;

/// The NVS namespace everything is stored in.
const NVS_NAMESPACE: &str = "prov";

/// [`Storage`] in the `prov` namespace of the default NVS partition.
pub struct NvsStorage(EspNvs<NvsDefault>);

impl NvsStorage {
    pub fn new(partition: EspDefaultNvsPartition) -> Result<Self, EspError> {
        Ok(Self(EspNvs::new(partition, NVS_NAMESPACE, true)?))
    }
}

impl Storage for NvsStorage {
    type Error = EspError;

    fn get<'a>(&mut self, key: &str, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, EspError> {
        self.0.get_blob(key, buf)
    }

    fn set(&mut self, key: &str, value: &[u8]) -> Result<(), EspError> {
        self.0.set_blob(key, value)
    }

    fn remove(&mut self, key: &str) -> Result<(), EspError> {
        self.0.remove(key).map(|_| ())
    }
}
