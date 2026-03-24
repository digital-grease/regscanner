# regscanner

Windows registry scanner for installed program inventory and executable detection.

## Overview

`regscanner` is a Windows-only command-line tool that performs a comprehensive scan of your system's installed programs. It queries the Windows registry from multiple sources, detects .NET Framework versions, scans for Windows Optional Capabilities via DISM, locates executable files on disk, and generates a detailed inventory report.

The tool is designed for system administrators and IT professionals who need to audit installed software, verify executable presence, and detect version mismatches across a Windows system.

## Features

- **Multi-source registry scanning**: Queries HKLM and HKCU registry hives at both 64-bit and 32-bit views (4 registry sources total)
- **.NET Framework detection**: Automatically detects installed .NET Framework versions via the NDP registry key
- **Windows Optional Capabilities**: Scans for installed capabilities using DISM (Windows Optional Features)
- **Smart deduplication**: Merges duplicate entries across sources with priority-based selection (HKLM_64 > HKLM_32 > HKCU_64 > HKCU_32 > NDP_REGISTRY > DISM)
- **Executable discovery**: Locates `.exe` files on disk by checking:
  - Registry InstallLocation values
  - Parsed UninstallString paths
  - Heuristic matching against Program Files, AppData, and ProgramData directories
- **Version verification**: Reads FileVersion from executables using the Windows VersionInfo API (via ctypes—no external dependencies)
- **Status classification**: Assigns one of six status values to each entry (OK, Missing Executable, Version Mismatch, Partial Data, System Component, Windows Capability)
- **Detailed reporting**: Writes a formatted text report to disk with system metadata, summary statistics, and per-program details

## Requirements

- **OS**: Windows 10 or Windows 11
- **Python**: 3.9 or later
- **Dependencies**: None (stdlib only: `winreg`, `ctypes`, `subprocess`, `pathlib`, `argparse`, etc.)
- **Recommended**: Run as Administrator for full registry access and driver package detection

## Installation

1. Ensure you have Python 3.9+ installed on Windows.
2. Download or clone `regscanner.py` to your desired location.
3. No additional packages to install.

## Usage

Run the script from the command line. Basic usage:

```bash
python regscanner.py
```

### Command-line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--output-dir PATH` | Output directory for the report | Current working directory |
| `--no-dism` | Skip DISM Windows Optional Capabilities scan | (scan enabled) |
| `--no-dotnet` | Skip .NET Framework NDP registry detection | (scan enabled) |
| `--include-system-components` | Include driver packages and hotfixes in report | (filtered by default) |
| `--verbose`, `-v` | Enable DEBUG-level logging to stderr | (INFO level) |

### Examples

**Basic scan (current directory):**
```bash
python regscanner.py
```

**Scan with verbose output and custom output directory:**
```bash
python regscanner.py --verbose --output-dir C:\Reports
```

**Skip DISM scanning:**
```bash
python regscanner.py --no-dism
```

**Include system components (drivers, hotfixes):**
```bash
python regscanner.py --include-system-components
```

**Skip .NET Framework detection:**
```bash
python regscanner.py --no-dotnet
```

**All options combined:**
```bash
python regscanner.py --verbose --output-dir C:\Reports --include-system-components
```

## Output

### Report File

The tool generates a single text report file named:

```
Matthew_Flowers_1.txt
```

This file is written to the directory specified by `--output-dir` (default: current working directory).

### Report Contents

The report includes:

1. **System Information**: Hostname, OS version/build, architecture, Python version, admin status, scan timestamp
2. **Summary Statistics**: Counts by status (OK, Missing Executable, Version Mismatch, Partial Data, System Component, Windows Capability), total programs, frameworks detected
3. **Detailed Program Listing**: For each program:
   - Display name, version, publisher, install location, install date
   - Registry source and status
   - Framework classification (if applicable)
   - Found executable paths with version information
   - Merge notes (if deduped from multiple sources)

### Console Output

After the scan completes, a summary is printed to the console showing the same statistics as in the report header.

## Status Definitions

Each program entry is assigned one of the following status values:

| Status | Meaning |
|--------|---------|
| **OK** | Executable found on disk and version matches registry entry |
| **Missing Executable** | Install location known but no executable found on disk |
| **Version Mismatch** | Executable found but version doesn't match registry entry |
| **Partial Data** | Missing version information or install location; cannot verify |
| **System Component** | Driver package or hotfix; filtered by default (use `--include-system-components` to include) |
| **Windows Capability (DISM)** | Windows Optional Capability reported by DISM (not found in traditional registry) |

## Technical Details

### Registry Sources Scanned

1. `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` (64-bit view)
2. `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` (32-bit view)
3. `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` (64-bit view)
4. `HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` (32-bit view)

Additionally scanned when enabled:
- `HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP` (for .NET Framework detection)
- DISM (for Windows Optional Capabilities)

### Executable Discovery Logic

For each program, the tool searches for `.exe` files in the following order:

1. **InstallLocation**: If the registry specifies an install directory, it is searched first (up to 2 levels deep)
2. **UninstallString parsing**: Attempts to extract an executable path from the uninstall command
3. **Heuristic matching**: As a fallback, searches common install directories:
   - `C:\Program Files`
   - `C:\Program Files (x86)`
   - `C:\Users\<User>\AppData\Local`
   - `C:\Users\<User>\AppData\Roaming`
   - `C:\ProgramData`

Setup/uninstaller executables (e.g., `unins000.exe`, `setup.exe`, `installer.exe`) are filtered out.

### Version Comparison

Executable versions are read from the Windows VersionInfo structure (VERSIONINFO resource). Versions are considered to "match" if the first two components (major.minor) are identical to the registry entry. For example:
- Registry: `2.0.50727.0`
- Executable: `2.0.50727.5007`
- Result: **Match** (both are `2.0`)

### Deduplication

When the same program appears in multiple registry sources, the tool selects one authoritative entry based on source priority:

1. HKLM_64 (highest priority)
2. HKLM_32
3. HKCU_64
4. HKCU_32
5. NDP_REGISTRY
6. DISM (lowest priority)

Duplicate entries are merged and noted in the report.

## Notes

- **Administrator privileges**: Running as Administrator is strongly recommended to ensure full access to HKLM, HKCU (all users), and to detect driver packages and system components.
- **Admin detection**: The report indicates whether the scan was run with administrative privileges.
- **Performance**: The executable search can take several minutes on systems with many installed programs. Progress is logged during the scan.
- **Framework filtering**: The tool automatically categorizes .NET Framework, Visual C++ redistributables, Java Runtime, DirectX, Windows SDK, and other frameworks as "frameworks" for easier filtering.

## License

See the `LICENSE` file in the repository.
