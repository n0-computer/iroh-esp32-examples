fn main() {
    // Makes the ESP-IDF config visible as cfgs, e.g. esp_idf_bt_nimble_enabled.
    embuild::espidf::sysenv::output();
    println!("cargo::rustc-check-cfg=cfg(esp_idf_bt_nimble_enabled)");
}
