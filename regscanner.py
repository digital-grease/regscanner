"""
windows_program_inventory.py

Scans a Windows 10/11 machine for installed programs using the registry,
verifies executables exist on disk, and writes a TXT report.

Requires Windows 10/11. Run as Administrator for best results.
Python 3.9+
"""

import argparse
import ctypes
import ctypes.wintypes
import logging
import os
import platform
import re
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# Check running on windows
if sys.platform != "win32":
    raise SystemExit(
        f"ERROR: This script only runs on Windows. Detected: {sys.platform}"
    )

import winreg  # Done after windows only check because only exists on windows

# Registry paths for installed programs
UNINSTALL_KEY     = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
WOW64_UNINSTALL_KEY = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
DOTNET_NDP_KEY    = r"SOFTWARE\Microsoft\NET Framework Setup\NDP"

# registry sources to scan
REGISTRY_SOURCES = [
    (winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY,       winreg.KEY_READ | winreg.KEY_WOW64_64KEY, "HKLM_64"),
    (winreg.HKEY_LOCAL_MACHINE, WOW64_UNINSTALL_KEY, winreg.KEY_READ | winreg.KEY_WOW64_32KEY, "HKLM_32"),
    (winreg.HKEY_CURRENT_USER,  UNINSTALL_KEY,       winreg.KEY_READ,                          "HKCU_64"),
    (winreg.HKEY_CURRENT_USER,  WOW64_UNINSTALL_KEY, winreg.KEY_READ,                          "HKCU_32"),
]

# Common install directories
COMMON_INSTALL_ROOTS = [
    Path(os.environ.get("ProgramFiles",      r"C:\Program Files")),
    Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
    Path(os.environ.get("LOCALAPPDATA",      r"C:\Users\Default\AppData\Local")),
    Path(os.environ.get("APPDATA",           r"C:\Users\Default\AppData\Roaming")),
    Path(os.environ.get("ProgramData",       r"C:\ProgramData")),
]

MAX_SEARCH_DEPTH = 2

# Filter out uninstaller/setup executables
SETUP_EXE_RE = re.compile(
    r"^(unins\d*|uninst\w*|setup|install(?:er)?|_setup|_install"
    r"|au3_\w+|is-[0-9a-f]+|uninstall)\.exe$",
    re.IGNORECASE,
)

# regexes to identify framework or actual app
FRAMEWORK_PATTERNS = [
    (re.compile(r"Microsoft \.NET Framework\s+\d",      re.I), ".NET Framework"),
    (re.compile(r"Microsoft \.NET\s+\d",                re.I), ".NET"),
    (re.compile(r"Microsoft \.NET (Core|Desktop) Runtime", re.I), ".NET Runtime"),
    (re.compile(r"Microsoft ASP\.NET",                  re.I), ".NET / ASP.NET"),
    (re.compile(r"Microsoft Visual C\+\+\s+\d{4}",     re.I), "VC++ Redistributable"),
    (re.compile(r"Visual C\+\+\s+\d{4}\s+(x86|x64)",   re.I), "VC++ Redistributable"),
    (re.compile(r"Windows SDK",                          re.I), "Windows SDK"),
    (re.compile(r"DirectX",                              re.I), "DirectX"),
    (re.compile(r"Java\s*(SE|Runtime|JDK|JRE)?\s*(Runtime|Environment)?", re.I), "Java Runtime"),
]

DISM_EXE = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "dism.exe"

# Source priority for deduplication (lower = higher priority)
SOURCE_PRIORITY = {
    "HKLM_64":      0,
    "HKLM_32":      1,
    "HKCU_64":      2,
    "HKCU_32":      3,
    "NDP_REGISTRY": 4,
    "DISM":         5,
}

STATUS_OK               = "OK"
STATUS_MISSING_EXE      = "Missing Executable"
STATUS_PARTIAL_DATA     = "Partial Data"
STATUS_VERSION_MISMATCH = "Version Mismatch"
STATUS_SYSTEM_COMPONENT = "System Component"
STATUS_DISM_CAPABILITY  = "Windows Capability (DISM)"


@dataclass
class ExecutableInfo:
    path: str
    version: Optional[str] = None
    version_matches_program: bool = False


@dataclass
class ProgramEntry:
    display_name:      str
    version:           Optional[str]
    install_location:  Optional[str]
    publisher:         Optional[str]
    install_date:      Optional[str]
    uninstall_string:  Optional[str]
    source:            str
    registry_key_name: Optional[str]

    normalized_name:    str           = field(default="")
    is_system_component: bool         = False
    is_framework:       bool          = False
    framework_category: Optional[str] = None
    executables:        list          = field(default_factory=list)
    status:             str           = "Unknown"
    notes:              list          = field(default_factory=list)


@dataclass
class SystemMetadata:
    hostname:           str
    os_name:            str
    os_version:         str
    os_build:           str
    architecture:       str
    python_version:     str
    python_executable:  str
    scan_timestamp_utc: str
    running_as_admin:   bool


def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  [%(funcName)s]  %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
        force=True,
    )
    return logging.getLogger(__name__)


log = logging.getLogger(__name__)


def _is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def collect_system_metadata():
    uname = platform.uname()
    return SystemMetadata(
        hostname=socket.gethostname(),
        os_name=uname.system,
        os_version=platform.release(),
        os_build=uname.version,
        architecture=platform.machine(),
        python_version=platform.python_version(),
        python_executable=sys.executable,
        scan_timestamp_utc=datetime.now(timezone.utc).isoformat(),
        running_as_admin=_is_admin(),
    )


def _read_reg_sz(key, value_name):
    """Read string from an open registry key, returns None if missing."""
    try:
        data, reg_type = winreg.QueryValueEx(key, value_name)
        if reg_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
            return None
        expanded = os.path.expandvars(str(data)).strip()
        return expanded if expanded else None
    except FileNotFoundError:
        return None
    except OSError as e:
        log.debug("Can't read registry value '%s': %s", value_name, e)
        return None


def _read_reg_dword(key, value_name):
    """Read DWORD value from an open registry key, returns None if missing."""
    try:
        data, reg_type = winreg.QueryValueEx(key, value_name)
        return int(data) if reg_type == winreg.REG_DWORD else None
    except OSError:
        return None


def _parse_uninstall_entry(parent_key, subkey_name, access_flags, source_label):
    """Read one Uninstall subkey and return a ProgramEntry, or None if it has no DisplayName."""
    try:
        with winreg.OpenKey(parent_key, subkey_name, access=access_flags) as key:
            display_name = _read_reg_sz(key, "DisplayName")
            if not display_name:
                return None

            sys_component = _read_reg_dword(key, "SystemComponent")

            return ProgramEntry(
                display_name=display_name,
                version=          _read_reg_sz(key, "DisplayVersion"),
                install_location= _read_reg_sz(key, "InstallLocation"),
                publisher=        _read_reg_sz(key, "Publisher"),
                install_date=     _read_reg_sz(key, "InstallDate"),
                uninstall_string= _read_reg_sz(key, "UninstallString"),
                source=source_label,
                registry_key_name=subkey_name,
                is_system_component=(sys_component == 1),
            )

    except PermissionError:
        log.debug("Permission denied: %s\\%s", source_label, subkey_name)
        return None
    except OSError as e:
        log.debug("Can't open subkey %s\\%s: %s", source_label, subkey_name, e)
        return None


def enumerate_registry_programs():
    """Enumerate programs from standard Uninstall registry locations."""
    all_entries = []

    for hive, subkey_path, access_flags, label in REGISTRY_SOURCES:
        log.info("Scanning registry: %s", label)
        try:
            with winreg.OpenKey(hive, subkey_path, access=access_flags) as uninstall_key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(uninstall_key, i)
                        i += 1
                    except OSError:
                        break

                    entry = _parse_uninstall_entry(uninstall_key, subkey_name, access_flags, label)
                    if entry is not None:
                        all_entries.append(entry)

        except FileNotFoundError:
            log.debug("Registry path not found: %s", subkey_path)
        except PermissionError:
            log.warning("Permission denied: %s [%s]", subkey_path, label)
        except OSError as e:
            log.warning("OS error in %s [%s]: %s", subkey_path, label, e)

    log.info("Registry scan done. Found %d raw entries.", len(all_entries))
    return all_entries


def enumerate_dotnet_frameworks():
    """Check NDP registry key for installed .NET Framework 2.x-4.x versions."""
    entries = []
    dotnet_root = (
        Path(os.environ.get("SystemRoot", r"C:\Windows"))
        / "Microsoft.NET"
        / "Framework64"
    )

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            DOTNET_NDP_KEY,
            access=winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as ndp_key:
            i = 0
            while True:
                try:
                    version_name = winreg.EnumKey(ndp_key, i)
                    i += 1
                except OSError:
                    break

                if not version_name.startswith("v"):
                    continue

                try:
                    with winreg.OpenKey(ndp_key, version_name,
                                        access=winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as ver_key:
                        _parse_ndp_version_key(ver_key, version_name, dotnet_root, entries)
                except (FileNotFoundError, OSError) as e:
                    log.debug("NDP subkey %s unreadable: %s", version_name, e)

    except (FileNotFoundError, PermissionError, OSError) as e:
        log.debug(".NET NDP key not accessible: %s", e)

    log.debug(".NET NDP found %d entries", len(entries))
    return entries


def _parse_ndp_version_key(ver_key, version_name, dotnet_root, results):
    # v4 is special — the real data lives in a "Full" subkey
    if version_name == "v4":
        try:
            with winreg.OpenKey(ver_key, "Full",
                                access=winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as v4_full:
                if _read_reg_dword(v4_full, "Install") != 1:
                    return
                version_str = _read_reg_sz(v4_full, "Version")
                if version_str:
                    results.append(_make_dotnet_entry(
                        f"Microsoft .NET Framework {version_str}", version_str, dotnet_root
                    ))
        except (FileNotFoundError, OSError):
            pass
        return

    if _read_reg_dword(ver_key, "Install") != 1:
        return

    version_str  = _read_reg_sz(ver_key, "Version") or version_name
    sp_level     = _read_reg_dword(ver_key, "SP")
    display_name = f"Microsoft .NET Framework {version_str}"
    if sp_level and sp_level > 0:
        display_name += f" SP{sp_level}"

    results.append(_make_dotnet_entry(display_name, version_str, dotnet_root))


def _make_dotnet_entry(display_name, version_str, install_root):
    return ProgramEntry(
        display_name=display_name,
        version=version_str,
        install_location=str(install_root),
        publisher="Microsoft Corporation",
        install_date=None,
        uninstall_string=None,
        source="NDP_REGISTRY",
        registry_key_name=None,
        is_framework=True,
        framework_category=".NET Framework",
    )


def _run_subprocess_safe(args, timeout_seconds=60):
    """Run a subprocess, return stdout as a string or None on failure."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        log.warning("Subprocess timed out: %s", args[0])
        return None
    except FileNotFoundError:
        log.debug("Executable not found: %s", args[0])
        return None
    except OSError as e:
        log.debug("Subprocess error (%s): %s", args[0], e)
        return None


def enumerate_dism_capabilities():
    """Run DISM to find installed Windows Optional Capabilities."""
    if not DISM_EXE.exists():
        log.debug("DISM not found at %s, skipping.", DISM_EXE)
        return []

    log.info("Running DISM to find installed capabilities (may take a few seconds)...")
    output = _run_subprocess_safe(
        [str(DISM_EXE), "/Online", "/Get-Capabilities"],
        timeout_seconds=90,
    )

    if not output:
        log.warning("DISM returned no output.")
        return []

    entries = []
    current_identity = None

    for raw_line in output.splitlines():
        line = raw_line.strip()

        if line.startswith("Capability Identity"):
            current_identity = line.split(":", 1)[1].strip()

        elif line.startswith("State") and current_identity:
            state = line.split(":", 1)[1].strip().lower()

            if state == "installed":
                entries.append(ProgramEntry(
                    display_name=f"[DISM] {current_identity}",
                    version=None,
                    install_location=None,
                    publisher="Microsoft Corporation",
                    install_date=None,
                    uninstall_string=None,
                    source="DISM",
                    registry_key_name=current_identity,
                    is_framework=True,
                    framework_category="Windows Capability",
                ))

            current_identity = None

    log.info("DISM found %d installed capabilities.", len(entries))
    return entries


def get_exe_file_version(exe_path):
    """
    Read the FileVersion from a Windows .exe using the VersionInfo API.
    Returns a version string or None.
    Uses ctypes so no extra packages are needed.
    """
    try:
        path_str = str(exe_path)

        dummy     = ctypes.c_uint(0)
        info_size = ctypes.windll.version.GetFileVersionInfoSizeW(path_str, ctypes.byref(dummy))
        if info_size == 0:
            return None

        buf = ctypes.create_string_buffer(info_size)
        if not ctypes.windll.version.GetFileVersionInfoW(path_str, 0, info_size, buf):
            return None

        p_info = ctypes.c_void_p()
        n_info = ctypes.c_uint(0)
        if not ctypes.windll.version.VerQueryValueW(buf, "\\", ctypes.byref(p_info), ctypes.byref(n_info)):
            return None

        class VS_FIXEDFILEINFO(ctypes.Structure):
            _fields_ = [
                ("dwSignature",        ctypes.c_uint32),
                ("dwStrucVersion",     ctypes.c_uint32),
                ("dwFileVersionMS",    ctypes.c_uint32),
                ("dwFileVersionLS",    ctypes.c_uint32),
                ("dwProductVersionMS", ctypes.c_uint32),
                ("dwProductVersionLS", ctypes.c_uint32),
                ("dwFileFlagsMask",    ctypes.c_uint32),
                ("dwFileFlags",        ctypes.c_uint32),
                ("dwFileOS",           ctypes.c_uint32),
                ("dwFileType",         ctypes.c_uint32),
                ("dwFileSubtype",      ctypes.c_uint32),
                ("dwFileDateMS",       ctypes.c_uint32),
                ("dwFileDateLS",       ctypes.c_uint32),
            ]

        ffi = ctypes.cast(p_info, ctypes.POINTER(VS_FIXEDFILEINFO)).contents

        if ffi.dwSignature != 0xFEEF04BD:
            log.debug("Invalid VersionInfo signature in %s", exe_path.name)
            return None

        major = ffi.dwFileVersionMS >> 16
        minor = ffi.dwFileVersionMS & 0xFFFF
        patch = ffi.dwFileVersionLS >> 16
        build = ffi.dwFileVersionLS & 0xFFFF

        return f"{major}.{minor}.{patch}.{build}"

    except (OSError, ctypes.ArgumentError, OverflowError) as e:
        log.debug("Couldn't read version from '%s': %s", exe_path.name, e)
        return None


def _versions_broadly_match(exe_version, program_version):
    """Compare the first two version components to see if they broadly match."""
    if not exe_version or not program_version:
        return False

    def split_ver(v):
        parts = []
        for seg in v.split(".")[:4]:
            try:
                parts.append(int(seg))
            except ValueError:
                break
        return tuple(parts)

    exe_parts  = split_ver(exe_version)
    prog_parts = split_ver(program_version)

    if not exe_parts or not prog_parts:
        return False

    depth = min(len(exe_parts), len(prog_parts), 2)
    return exe_parts[:depth] == prog_parts[:depth]


def _parse_uninstall_dir(uninstall_string):
    """Try to get an install directory from an UninstallString value."""
    if not uninstall_string:
        return None

    if "msiexec" in uninstall_string.lower():
        return None

    # Try quoted path first
    m = re.search(r'"([A-Za-z]:[^"]+\.exe)"', uninstall_string, re.IGNORECASE)
    if m:
        p = Path(m.group(1))
        if p.parent.is_dir():
            return p.parent

    # Fall back to unquoted path
    m = re.search(r'([A-Za-z]:\\[^\s"]+\.exe)', uninstall_string, re.IGNORECASE)
    if m:
        p = Path(m.group(1))
        if p.parent.is_dir():
            return p.parent

    return None


def _collect_exes_under(directory, max_depth=MAX_SEARCH_DEPTH):
    """Recursively collect exe files up to max_depth levels deep."""
    results = []

    def _recurse(current, depth):
        try:
            for item in current.iterdir():
                if item.is_file() and item.suffix.lower() == ".exe":
                    if not SETUP_EXE_RE.match(item.name):
                        results.append(item)
                elif item.is_dir() and depth < max_depth:
                    _recurse(item, depth + 1)
        except PermissionError:
            log.debug("Permission denied: %s", current)
        except OSError as e:
            log.debug("Error iterating %s: %s", current, e)

    _recurse(directory, 0)
    return results


def _guess_install_dirs(prog):
    """
    Try to guess where a program is installed based on its name and publisher.
    Only used as a fallback.
    """
    candidates = []

    name_slug = re.sub(r"[^a-z0-9]", "", prog.display_name.lower())[:24]
    pub_slug  = re.sub(r"[^a-z0-9]", "", (prog.publisher or "").lower())[:20]

    for root in COMMON_INSTALL_ROOTS:
        if not root.is_dir():
            continue
        try:
            for child in root.iterdir():
                if not child.is_dir():
                    continue
                child_slug = re.sub(r"[^a-z0-9]", "", child.name.lower())

                name_hit = name_slug and (name_slug in child_slug or child_slug in name_slug)
                pub_hit  = pub_slug and pub_slug in child_slug

                if name_hit or pub_hit:
                    candidates.append(child)
                    prog.notes.append(
                        f"Heuristic match: {child} (name_hit={name_hit}, pub_hit={pub_hit})"
                    )

                if len(candidates) >= 3:
                    return candidates

        except (PermissionError, OSError):
            continue

    return candidates


def find_executables_for_program(prog):
    """Find .exe files for a program. Checks InstallLocation first, then guesses."""
    candidate_dirs = []
    seen = set()

    def add_dir(path):
        if path and path.is_dir():
            k = str(path).lower()
            if k not in seen:
                seen.add(k)
                candidate_dirs.append(path)

    if prog.install_location:
        add_dir(Path(prog.install_location))

    add_dir(_parse_uninstall_dir(prog.uninstall_string))

    if not candidate_dirs:
        for d in _guess_install_dirs(prog):
            add_dir(d)

    found    = []
    seen_exe = set()

    for search_root in candidate_dirs:
        for exe_path in _collect_exes_under(search_root):
            k = str(exe_path).lower()
            if k in seen_exe:
                continue
            seen_exe.add(k)

            exe_ver = get_exe_file_version(exe_path)
            found.append(ExecutableInfo(
                path=str(exe_path),
                version=exe_ver,
                version_matches_program=_versions_broadly_match(exe_ver, prog.version),
            ))

    return found


def _normalise_name(name):
    """Clean up a display name for use as a dedup key."""
    result = name.lower()
    result = re.sub(r"[®©™]", "", result)
    result = re.sub(r"\(r\)|\(tm\)|\(c\)", "", result, flags=re.IGNORECASE)
    result = re.sub(r"\s+", " ", result).strip()
    result = re.sub(r"\s+(version|update|release|build|edition)$", "", result, flags=re.IGNORECASE)
    return result


def _detect_framework(display_name):
    for pattern, category in FRAMEWORK_PATTERNS:
        if pattern.search(display_name):
            return True, category
    return False, None


def deduplicate_programs(programs):
    """Merge duplicate entries."""
    # Pass 1: normalise names and detect frameworks
    for prog in programs:
        prog.normalized_name = _normalise_name(prog.display_name)
        is_fw, fw_cat = _detect_framework(prog.display_name)
        if is_fw:
            prog.is_framework       = True
            prog.framework_category = fw_cat

    # Pass 2: pick the best entry per (name, version) pair
    best        = {}
    all_sources = {}

    for prog in programs:
        key = f"{prog.normalized_name}|{(prog.version or '').strip().lower()}"

        if key not in best:
            best[key]        = prog
            all_sources[key] = [prog.source]
        else:
            all_sources[key].append(prog.source)
            cur_priority = SOURCE_PRIORITY.get(best[key].source, 99)
            new_priority = SOURCE_PRIORITY.get(prog.source, 99)
            if new_priority < cur_priority:
                best[key] = prog

    # Pass 3: annotate entries that appeared in multiple sources
    deduped = []
    for key, prog in best.items():
        sources = list(dict.fromkeys(all_sources[key]))
        if len(sources) > 1:
            merged_source = ", ".join(sources)
            prog.notes.append(f"Merged from: {merged_source}")
            prog.source = merged_source
        deduped.append(prog)

    deduped.sort(key=lambda p: p.normalized_name)
    log.info("Deduplication: %d raw → %d unique", len(programs), len(deduped))
    return deduped


def determine_status(prog):
    if "DISM" in prog.source:
        return STATUS_DISM_CAPABILITY

    if prog.is_system_component:
        return STATUS_SYSTEM_COMPONENT

    if not prog.executables:
        if not prog.install_location and not prog.uninstall_string:
            return STATUS_PARTIAL_DATA
        return STATUS_MISSING_EXE

    if prog.version is None:
        return STATUS_PARTIAL_DATA

    if any(e.version_matches_program for e in prog.executables):
        return STATUS_OK

    if any(e.version is not None for e in prog.executables):
        return STATUS_VERSION_MISMATCH

    return STATUS_PARTIAL_DATA



def _build_summary(programs):
    return {
        "total_programs":      len(programs),
        "status_ok":           sum(1 for p in programs if p.status == STATUS_OK),
        "missing_executable":  sum(1 for p in programs if p.status == STATUS_MISSING_EXE),
        "version_mismatch":    sum(1 for p in programs if p.status == STATUS_VERSION_MISMATCH),
        "partial_data":        sum(1 for p in programs if p.status == STATUS_PARTIAL_DATA),
        "system_components":   sum(1 for p in programs if p.status == STATUS_SYSTEM_COMPONENT),
        "dism_capabilities":   sum(1 for p in programs if p.status == STATUS_DISM_CAPABILITY),
        "frameworks_detected": sum(
            1 for p in programs if p.is_framework and p.status != STATUS_DISM_CAPABILITY
        ),
    }


def write_txt_report(metadata, summary, programs, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "Matthew_Flowers_1.txt"

    bar  = "=" * 62
    dash = "-" * 62

    with open(output_path, "w", encoding="utf-8") as f:
        # Host OS header
        f.write(f"{bar}\n")
        f.write("  Windows Program Inventory Report\n")
        f.write(f"{bar}\n\n")

        f.write("SYSTEM INFORMATION\n")
        f.write(f"{dash}\n")
        f.write(f"  Host OS        : {metadata.os_name} {metadata.os_version}\n")
        f.write(f"  OS Build       : {metadata.os_build}\n")
        f.write(f"  Hostname       : {metadata.hostname}\n")
        f.write(f"  Architecture   : {metadata.architecture}\n")
        f.write(f"  Python Version : {metadata.python_version}\n")
        f.write(f"  Running as Admin: {metadata.running_as_admin}\n")
        f.write(f"  Scan Timestamp : {metadata.scan_timestamp_utc}\n\n")

        f.write("SUMMARY\n")
        f.write(f"{dash}\n")
        f.write(f"  Total programs       : {summary['total_programs']}\n")
        f.write(f"  Status OK            : {summary['status_ok']}\n")
        f.write(f"  Missing executable   : {summary['missing_executable']}\n")
        f.write(f"  Version mismatch     : {summary['version_mismatch']}\n")
        f.write(f"  Partial data         : {summary['partial_data']}\n")
        f.write(f"  System components    : {summary['system_components']}\n")
        f.write(f"  DISM capabilities    : {summary['dism_capabilities']}\n")
        f.write(f"  Frameworks detected  : {summary['frameworks_detected']}\n\n")

        f.write("PROGRAMS\n")
        f.write(f"{dash}\n")
        for i, prog in enumerate(programs, 1):
            f.write(f"\n[{i}] {prog.display_name}\n")
            f.write(f"    Version          : {prog.version or 'N/A'}\n")
            f.write(f"    Publisher        : {prog.publisher or 'N/A'}\n")
            f.write(f"    Install Location : {prog.install_location or 'N/A'}\n")
            f.write(f"    Install Date     : {prog.install_date or 'N/A'}\n")
            f.write(f"    Source           : {prog.source}\n")
            f.write(f"    Status           : {prog.status}\n")
            f.write(f"    System Component : {prog.is_system_component}\n")
            f.write(f"    Framework        : {prog.is_framework}"
                    + (f" ({prog.framework_category})" if prog.framework_category else "") + "\n")
            if prog.executables:
                f.write(f"    Executables ({len(prog.executables)}):\n")
                for exe in prog.executables:
                    match_flag = "version match" if exe.version_matches_program else "no version match"
                    f.write(f"      - {exe.path}  [{exe.version or 'no version'}  {match_flag}]\n")
            if prog.notes:
                f.write(f"    Notes            : {'; '.join(prog.notes)}\n")

    log.info("TXT report written: %s", output_path)
    return output_path


def _print_summary(summary, txt_path):
    bar = "=" * 62
    print(f"\n{bar}")
    print("  Windows Program Inventory — Scan Complete")
    print(bar)
    print(f"  Total programs       : {summary['total_programs']}")
    print(f"  Status OK            : {summary['status_ok']}")
    print(f"  Missing executable   : {summary['missing_executable']}")
    print(f"  Version mismatch     : {summary['version_mismatch']}")
    print(f"  Partial data         : {summary['partial_data']}")
    print(f"  System components    : {summary['system_components']}")
    print(f"  DISM capabilities    : {summary['dism_capabilities']}")
    print(f"  Frameworks detected  : {summary['frameworks_detected']}")
    print("-" * 62)
    print(f"  TXT:  {txt_path}")
    print(f"{bar}\n")


def _parse_args():
    parser = argparse.ArgumentParser(
        prog="windows_program_inventory",
        description=(
            "Enumerate installed programs on Windows 10/11, verify executables "
            "exist on disk, and write a TXT report."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python windows_program_inventory.py
  python windows_program_inventory.py --verbose --output-dir C:\\Reports
  python windows_program_inventory.py --no-dism
  python windows_program_inventory.py --include-system-components
  python windows_program_inventory.py --no-dotnet
""",
    )
    parser.add_argument("--output-dir", type=Path, default=Path.cwd(), metavar="PATH",
                        help="Directory for reports (default: current directory).")
    parser.add_argument("--no-dism", action="store_true", default=False,
                        help="Skip DISM capability.")
    parser.add_argument("--no-dotnet", action="store_true", default=False,
                        help="Skip .NET NDP registry detection.")
    parser.add_argument("--include-system-components", action="store_true", default=False,
                        help="Include driver packages and hotfixes.")
    parser.add_argument("--verbose", "-v", action="store_true", default=False,
                        help="Enable DEBUG-level logging.")
    return parser.parse_args()


def main():
    args   = _parse_args()
    logger = setup_logging(args.verbose)

    logger.info("=" * 60)
    logger.info("Windows Program Inventory — starting scan")
    logger.info("Output directory: %s", args.output_dir)
    logger.info("=" * 60)

    metadata = collect_system_metadata()
    logger.info(
        "Host: %s | Windows %s (build %s) | %s | Admin: %s",
        metadata.hostname, metadata.os_version, metadata.os_build,
        metadata.architecture, metadata.running_as_admin,
    )
    if not metadata.running_as_admin:
        logger.warning("Not running as admin — other users' installs may be missing.")

    # Collect programs from all sources
    all_programs = []
    all_programs.extend(enumerate_registry_programs())

    if not args.no_dotnet:
        dotnet = enumerate_dotnet_frameworks()
        all_programs.extend(dotnet)
        logger.info("Added %d .NET Framework entries.", len(dotnet))
    else:
        logger.info(".NET NDP detection skipped.")

    if not args.no_dism:
        dism = enumerate_dism_capabilities()
        all_programs.extend(dism)
    else:
        logger.info("DISM skipped.")

    # Filter system components unless the user wants them
    if not args.include_system_components:
        before = len(all_programs)
        all_programs = [p for p in all_programs if not p.is_system_component]
        filtered = before - len(all_programs)
        if filtered:
            logger.info(
                "Filtered %d system component entries "
                "(use --include-system-components to keep them).",
                filtered,
            )

    unique_programs = deduplicate_programs(all_programs)

    # Find executables on disk for each program
    logger.info("Searching for executables (%d programs)...", len(unique_programs))
    for i, prog in enumerate(unique_programs, 1):
        if "DISM" in prog.source:
            continue
        prog.executables = find_executables_for_program(prog)
        if i % 50 == 0:
            logger.info("  %d / %d done", i, len(unique_programs))

    for prog in unique_programs:
        prog.status = determine_status(prog)

    summary = _build_summary(unique_programs)

    try:
        txt_path = write_txt_report(metadata, summary, unique_programs, args.output_dir)
    except OSError as e:
        logger.error("Failed to write report: %s", e)
        return 1

    _print_summary(summary, txt_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
