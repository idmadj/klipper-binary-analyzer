# klipper-binary-analyzer

A static analysis tool for [Klipper](https://github.com/Klipper3d/klipper) MCU firmware binaries. Inspects a `.bin` file and produces a self-contained HTML report covering the ARM Cortex-M vector table, bootloader offset, and the embedded Klipper config dictionary.

Requires Python 3.6+ and no third-party dependencies, only the standard library (`zlib`, `struct`, `json`, `argparse`).

## Features

- **Bootloader offset detection** - identifies the flash offset the firmware was linked against using a dictionary pointer cross-reference technique, reliable across GCC/binutils versions and binary layouts (application images and full flash images)
- **ARM vector table analysis** - validates the MSP and reset vector, flags invalid images
- **Klipper config dictionary extraction** - decodes the zlib-compressed JSON dictionary embedded in the firmware, surfacing MCU model, clock frequency, serial pins, baud rate, initial pins, firmware version, and build toolchain
- **`make menuconfig` summary** - translates findings into the settings needed to reproduce the build
- **Self-contained HTML report** - single file with no external dependencies, opens directly in any browser

## Usage

```sh
python3 klipper_analyzer.py firmware.bin
```

Generates `firmware_analysis.html` alongside the binary and opens it in the default browser.

```sh
# Write report to a specific path
python3 klipper_analyzer.py firmware.bin --output report.html

# Don't open the browser (useful on headless systems like the printer itself)
python3 klipper_analyzer.py firmware.bin --no-browser

# Analyze multiple binaries in one invocation
python3 klipper_analyzer.py noz0_*.bin mcu0_*.bin --no-browser
```

Run `python3 klipper_analyzer.py --help` for the full option reference.

## How bootloader offset detection works

Naively reading the reset handler address from the vector table and rounding to the nearest 4 KiB page is unreliable, the compiler can place the reset handler anywhere in the application, not necessarily near the link base. Scanning the binary for the lowest `0x08xxxxxx` address is similarly unreliable because coincidental bit patterns in data sections can produce false matches.

This tool uses a more robust approach: the Klipper firmware embeds a pointer to its config dictionary in the `identify` command handler. For each known bootloader offset, the tool computes what flash address the dictionary would have at that offset, then searches the binary for that address as a 4-byte little-endian value. Only the true link base produces a hit.

This works correctly regardless of:
- Toolchain version (tested with GCC 9.2.1/binutils 2.34 and GCC 12.2.1/binutils 2.40)
- Binary layout (application images starting at the bootloader offset, or full flash images starting at `0x08000000`)
- Reset handler placement within the application

## Known bootloader offsets

| Offset | Size | Typical use |
|--------|------|-------------|
| `0x0000` | 0 KiB | No bootloader (direct flash) |
| `0x1000` | 4 KiB | Minimal / custom bootloader |
| `0x2000` | 8 KiB | HID / stm32duino bootloader |
| `0x3000` | 12 KiB | Creality K1 / K1 SE / K1 Max (GD32F303) |
| `0x5000` | 20 KiB | DFU 20 KiB |
| `0x7000` | 28 KiB | Creality / Klipper custom 28 KiB bootloader |
| `0x8000` | 32 KiB | DFU 32 KiB standard |

## Background

Developed while updating Klipper MCU firmware on a Creality K1, which uses GD32F303 MCUs not supported by mainline Klipper. The GD32 support requires the [CrealityOfficial/K1_Series_Klipper](https://github.com/CrealityOfficial/K1_Series_Klipper) fork or a merge of its board support files. Building on the printer (MIPS host, GCC 12.2.1/binutils 2.40) produces binaries with a different layout than building on x86 (GCC 9.2.1/binutils 2.34), which is what motivated building a reliable cross-platform offset detection tool.

## License

MIT
