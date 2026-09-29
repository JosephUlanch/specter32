# Firmware downloads

- **specter32-merged.bin** — initial installation, flash at **0x0**. This image replaces the partition layout and clears NVS, regenerating the hotspot password.
- **firmware.bin** — app-only update for an existing SPECTER32 installation, flash at **0x10000**.
- **bootloader.bin** / **partitions.bin** — individual build components, offsets **0x1000** / **0x8000**.
- **SHA256SUMS** — checksums of all binaries.
- **dashboard-*.png** — browser-test screenshots with simulated network data.

Target: classic ESP32 ESP-WROOM-32 / ESP-32S development board, 4 MB flash. See the root README for flashing and first connection. These binaries were compiled successfully but still require validation on a physical board.

To rebuild the bundle after `pio run`, install `esptool==4.11.0` into your Python environment and run `python tools/package_firmware.py`. Alternatively pass `--esptool /path/to/platformio/packages/tool-esptoolpy/esptool.py`.
