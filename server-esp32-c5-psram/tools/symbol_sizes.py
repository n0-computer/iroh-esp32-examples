import re
import shutil
import subprocess
from collections import defaultdict

bin_path = "target/xtensa-esp32-espidf/release/server-esp32"

nm = None
for candidate in ("xtensa-esp32-elf-nm", "llvm-nm", "nm"):
    if shutil.which(candidate):
        nm = candidate
        break

if nm is None:
    raise SystemExit("no nm tool found")

out = subprocess.check_output([nm, "-S", "-C", bin_path], text=True, errors="ignore")

sym_re = re.compile(r"^[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+[A-Za-z]\s+(.+)$")

crate_markers = [
    "server_esp32_no_spiram",
    "iroh_relay",
    "iroh",
    "noq_proto",
    "noq",
    "hickory_resolver",
    "hickory_proto",
    "rustls",
    "webpki",
    "reqwest",
    "hyper_util",
    "hyper",
    "tokio",
    "tracing",
    "futures_util",
    "futures_lite",
    "curve25519_dalek",
    "sha2",
    "pkarr",
    "simple_dns",
    "data_encoding",
    "http",
    "idna",
    "netwatch",
    "esp_idf_svc",
    "esp_idf_hal",
    "esp_idf_sys",
    "core::",
    "std::",
    "alloc::",
]

totals = defaultdict(int)
other = 0

for line in out.splitlines():
    m = sym_re.match(line)
    if not m:
        continue
    size = int(m.group(1), 16)
    symbol = m.group(2)

    marker = None
    for candidate in crate_markers:
        if candidate in symbol:
            marker = candidate
            break

    if marker is None:
        other += size
    else:
        totals[marker] += size

print(f"nm tool: {nm}")
print("Approx linked symbol bytes by crate marker:")
for name, size in sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:40]:
    print(f"{size / 1024:10.1f} KiB  {name}")
print(f"{other / 1024:10.1f} KiB  <unattributed/other>")
