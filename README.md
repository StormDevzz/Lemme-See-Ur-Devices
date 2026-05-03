# Device Analyzer

A comprehensive Linux device discovery and analysis tool combining multiple programming languages for maximum capability.

## Architecture

| Component | Language | Purpose |
|-----------|----------|---------|
| Core UI & System Integration | C (ncurses) | Windowed menu interface, USB scanning, system integration |
| Low-level Hardware Access | x86_64 Assembly | CPUID, MSR access, serial numbers, deep hardware inspection |
| Network Analysis | Lua | Protocol analysis, network discovery, mDNS/SSDP |
| Data Analysis | Python | Advanced analytics, JSON export, vendor database |

## Features

### USB Device Analysis
- Enumerate all connected USB devices
- Read device descriptors and properties
- Port status and bandwidth information
- Power management details
- Device tree visualization

### Hardware Information
- CPUID detailed information
- CPU features and capabilities
- Memory layout and DIMM info
- DMI/SMBIOS data
- UEFI/Secure Boot status
- TPM information
- ACPI tables

### Network Discovery
- Local interface enumeration
- ARP table analysis
- mDNS/Bonjour service discovery
- Port scanning
- Protocol statistics
- Connection tracking

### Data Analysis
- USB vendor identification
- Device categorization
- JSON report generation
- System summary reports

## Building

### Dependencies

```bash
# Debian/Ubuntu
sudo apt-get install -y \
    build-essential \
    nasm \
    libncursesw5-dev \
    libudev-dev \
    liblua5.3-dev \
    python3-dev \
    libpython3-dev \
    pkg-config

# Fedora/RHEL
sudo dnf install -y \
    gcc \
    nasm \
    ncurses-devel \
    systemd-devel \
    lua-devel \
    python3-devel
```

### Compile

```bash
make
```

Or with debug symbols:
```bash
make debug
```

### Install Dependencies (convenience)

```bash
make install-deps
```

## Running

```bash
./bin/device_analyzer
```

**Note:** Some features require root access for:
- Reading kernel debug USB data
- DMI/ACPI table access
- Network raw socket operations

## Controls

| Key | Action |
|-----|--------|
| ↑/↓ or k/j | Navigate menu |
| Enter | Select item |
| F1 | Show help |
| Q | Quit |

## Project Structure

```
.
├── src/              # C source files
│   ├── main.c        # Entry point
│   ├── ui.c/h        # Ncurses windowed interface
│   ├── usb_scanner.c/h   # USB device enumeration
│   ├── hardware_info.c/h # Hardware inspection
│   ├── lua_bridge.c/h    # Lua integration
│   └── python_bridge.c/h # Python integration
├── asm/              # Assembly source
│   ├── cpuinfo.asm   # CPUID and MSR access
│   └── hardware.asm  # Additional hardware routines
├── lua/              # Lua scripts
│   ├── network_scan.lua    # Network discovery
│   └── protocol_analyzer.lua # Protocol decoding
├── python/           # Python modules
│   └── analyzer.py   # Data analysis module
├── Makefile          # Build system
└── README.md         # This file
```

## Implementation Details

### C Core
- Uses `libudev` for USB enumeration
- `ncursesw` for Unicode-aware UI
- Multi-window interface with menu, content, and status panels

### Assembly Module
- NASM syntax for x86_64 Linux
- CPUID for processor information
- MSR (Model Specific Register) reading
- TSC (Time Stamp Counter) access

### Lua Network Module
- Embedded in C via `liblua`
- Raw socket operations exposed from C
- Protocol analysis using /proc/net files
- ARP table parsing

### Python Analysis Module
- Embedded Python 3 interpreter
- Dataclass-based data structures
- JSON export capabilities
- Vendor ID database

## Security Notes

- Assembly module uses privileged instructions (CPUID, RDMSR)
- Network scanning requires appropriate permissions
- Some /sys and /proc files may need root access
- Tool is designed for authorized system analysis only

## License

MIT License - See individual source files for details.

## Troubleshooting

### "Terminal too small"
Resize terminal to at least 80x24 characters.

### "Permission denied" for USB devices
Run with sudo or add user to `plugdev` group.

### Lua/Python bridge errors
Ensure development libraries are installed:
- `liblua5.3-dev`
- `python3-dev`
- `libpython3-dev`

### Assembly compilation errors
Ensure NASM is installed: `sudo apt-get install nasm`
# Lemme-See-Ur-Devices
