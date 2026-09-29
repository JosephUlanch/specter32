"""Create a first-install image and checksums from a successful PlatformIO build."""
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--esptool', help='Optional path to PlatformIO esptool.py')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
build = root / '.pio/build/esp32dev'
out = root / 'downloads'
out.mkdir(exist_ok=True)
for name in ('bootloader.bin', 'partitions.bin', 'firmware.bin'):
    shutil.copy2(build / name, out / name)
command = [sys.executable, args.esptool] if args.esptool else [sys.executable, '-m', 'esptool']
subprocess.run(command + ['--chip', 'esp32', 'merge_bin', '-o', str(out / 'specter32-merged.bin'),
                         '--flash_mode', 'dio', '--flash_freq', '40m', '--flash_size', '4MB',
                         '0x1000', str(out / 'bootloader.bin'), '0x8000', str(out / 'partitions.bin'),
                         '0x10000', str(out / 'firmware.bin')], check=True)
(out / 'SHA256SUMS').write_text(''.join(
    f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in sorted(out.glob('*.bin'))
))
