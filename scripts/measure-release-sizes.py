#!/usr/bin/env python3
"""Measure built release applications against espflash's 4 MiB single-app layout."""
import argparse
import json
from pathlib import Path
import subprocess
import tomllib

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
parser.add_argument('--output', type=Path)
parser.add_argument('examples', nargs='*')
args = parser.parse_args()
root = args.root.resolve()
output = args.output or root / 'target/release-sizes'
output.mkdir(parents=True, exist_ok=True)
rows = []
for name in args.examples or sorted(p.name for p in root.glob('server-esp32*')):
    project = root / name
    config = tomllib.loads((project / '.cargo/config.toml').read_text())
    target = config['build']['target']
    chip = config['env']['MCU']
    packages = tomllib.loads((project / 'Cargo.lock').read_text())['package']
    iroh = next(p for p in packages if p['name'] == 'iroh')
    assert iroh['version'] == '1.2.0' and iroh['source'].startswith('registry+'), iroh
    assert not any(p['name'].startswith('hickory-') for p in packages)
    assert not any('github.com/n0-computer/iroh?' in p.get('source', '') for p in packages)
    elf = project / 'target' / target / 'release' / name
    image = output / (name + '.bin')
    command = ['espflash', 'save-image', '--skip-update-check', '--chip', chip,
               '--flash-size', '4mb', str(elf), str(image)]
    result = subprocess.run(command, capture_output=True, text=True)
    print(result.stdout, end='')
    if result.returncode:
        print(result.stderr, end='')
        raise SystemExit(result.returncode)
    size = image.stat().st_size
    # espflash's default non-OTA layout: app starts at 0x10000.
    capacity = 4 * 1024 * 1024 - 0x10000
    row = dict(example=name, chip=chip, target=target, iroh=iroh['version'],
               app_bytes=size, app_mib=round(size / 2**20, 3),
               app_capacity_bytes=capacity, headroom_bytes=capacity-size,
               fits=size <= capacity)
    rows.append(row)
    print(json.dumps(row))
(output / 'sizes.json').write_text(json.dumps(rows, indent=2) + '\n')
