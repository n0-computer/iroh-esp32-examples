use std::io::Read;

fn main() {
    // iroh node identity. An explicit IROH_SECRET env var wins; otherwise bake in a
    // random secret generated at build time and cached in OUT_DIR. Either way the
    // secret is embedded in the firmware, so the endpoint ID (and thus the ticket) is
    // STABLE across reboots — unlike generating a fresh key on every startup, which
    // changed the ticket each boot. Regenerated on `cargo clean` or if IROH_SECRET
    // changes. (main.rs reads it via `option_env!("IROH_SECRET")`.)
    println!("cargo:rerun-if-env-changed=IROH_SECRET");
    let secret = std::env::var("IROH_SECRET").unwrap_or_else(|_| {
        let cache =
            std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("iroh_secret.hex");
        if let Ok(existing) = std::fs::read_to_string(&cache) {
            return existing;
        }
        let mut bytes = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut bytes))
            .expect("generating IROH_SECRET: read /dev/urandom");
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(&cache, &hex).expect("caching IROH_SECRET");
        hex
    });
    println!("cargo:rustc-env=IROH_SECRET={secret}");

    embuild::espidf::sysenv::output();
}
