# SPDClient

**SPDClient** is an advanced Python tool for accessing and manipulating Spreadtrum/Unisoc (SPD) BootROM devices via serial connection. It is designed for both enthusiasts and engineers, providing user-friendly partition-based operations and support for common device flashing tasks.

## Features

- **Partition Name Support**: Interact with device partitions by name (e.g., `system`, `userdata`, `boot`, etc.) for easier and safer operations.
- **Serial Communication**: Connects to devices over serial ports (e.g., `/dev/ttyUSB0`, `COM3`).
- **BootROM Commands**: Supports protocol commands for handshake, FDL loading, reading, writing, erasing, and device info.
- **Partition Table Fallback**: Uses a built-in list of common SPD partitions if device-specific info is unavailable.
- **Backup & Restore**: Easily backup and restore partitions or the entire device.
- **PAC Extraction**: Extract FDL loaders from `.pac` firmware packages.
- **Logging**: Informative logging for all steps and error handling.
- **Cross-platform**: Runs on Linux, Windows, and macOS.

## Supported Commands

- `handshake`: Establish connection with the device BootROM.
- `loadfdl1`, `loadfdl2`: Load FDL1 or FDL2 bootloader files.
- `read`, `write`, `erase`: Low-level raw address-based flash operations.
- `readpart`, `writepart`, `erasepart`: Partition-based read/write/erase operations by name.
- `backup`: Backup partitions with automatic timestamped filenames.
- `listparts`: List all available partitions (either from device or built-in fallback).
- `info`: Get device information and print raw details.
- `extractpac`: Extract FDL loaders from `.pac` firmware archives.

## Example Usage

```bash
# List available partitions (no device required)
python spd.py listparts

# Connect to device and read a full partition
python spd.py /dev/ttyUSB0 readpart system system_backup.bin --fdl1 FDL1.bin --fdl2 FDL2.bin

# Write a backup image to userdata partition
python spd.py /dev/ttyUSB0 writepart userdata userdata_backup.bin --fdl1 FDL1.bin --fdl2 FDL2.bin

# Erase the cache partition
python spd.py /dev/ttyUSB0 erasepart cache --fdl1 FDL1.bin --fdl2 FDL2.bin

# Backup the modem partition
python spd.py /dev/ttyUSB0 backup modem

# Extract FDL loaders from a .pac file
python spd.py extractpac firmware.pac
```

## Requirements

- Python 3.7+
- `pyserial`
- Other dependencies: `argparse`, `struct`, `logging`, `os`, `sys`, `zipfile`, `json`, `time`

Install dependencies:
```bash
pip install pyserial
```

## Notes

- Always use correct FDL loaders for your device (consult vendor or firmware sources).
- The tool falls back to common SPD partition layout if device-specific information cannot be read.
- Use partition operations for safer device flashing and backup.
- For advanced usage or troubleshooting, refer to detailed logs and error messages.

## License

MIT License.

## Authors

- @ABDO10DZ

---

For questions or contributions, open an issue or pull request!