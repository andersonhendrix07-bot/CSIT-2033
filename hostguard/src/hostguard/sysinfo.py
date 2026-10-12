"""Basic facts about the host: OS, build, architecture, Python, elevation."""

from __future__ import annotations

import ctypes
import os
import platform
import sys
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class HostInfo:
    os_family: str  # "windows" | "linux" | "macos" | other
    os_name: str
    os_version: str
    os_build: str
    arch: str
    python: str
    elevated: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def os_family() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("linux"):
        return "linux"
    return sys.platform


def is_elevated() -> bool:
    """True when running as Administrator (Windows) or root (POSIX)."""
    if sys.platform == "win32":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0


# platform.win32_edition() returns the registry EditionID, not the marketing name.
_WINDOWS_EDITIONS = {
    "Core": "Home",
    "CoreN": "Home N",
    "CoreSingleLanguage": "Home Single Language",
    "CoreCountrySpecific": "Home China",
    "Professional": "Pro",
    "ProfessionalN": "Pro N",
    "ProfessionalWorkstation": "Pro for Workstations",
    "ProfessionalEducation": "Pro Education",
}


def windows_edition_name(edition_id: str) -> str:
    return _WINDOWS_EDITIONS.get(edition_id, edition_id)


# Server releases share NT 10.0 with client Windows; only the build tells them apart.
_SERVER_BUILDS = {"14393": "2016", "17763": "2019", "20348": "2022", "26100": "2025"}


def windows_product_name(release: str, build: str, edition_id: str) -> str:
    """E.g. ("10", "26200", "Core") -> "Windows 11 Home"."""
    if edition_id.startswith("Server"):
        year = _SERVER_BUILDS.get(build, "")
        edition = edition_id.removeprefix("Server")
        return " ".join(p for p in ("Windows Server", year, edition) if p)
    # platform reports "10" for Windows 11 on older Pythons; build >= 22000 is Windows 11.
    name = "Windows 11" if build.isdigit() and int(build) >= 22000 else f"Windows {release}"
    return f"{name} {windows_edition_name(edition_id)}".strip()


def _linux_pretty_name() -> str:
    try:
        info = platform.freedesktop_os_release()
    except OSError:
        return "Linux"
    return info.get("PRETTY_NAME", "Linux")


def collect() -> HostInfo:
    fam = os_family()
    if fam == "windows":
        release, version, _csd, _ptype = platform.win32_ver()
        build = version.rsplit(".", 1)[-1] if version else ""
        os_name = windows_product_name(release, build, platform.win32_edition() or "")
        os_version = version
    elif fam == "macos":
        os_name, os_version, build = "macOS", platform.mac_ver()[0], ""
    elif fam == "linux":
        os_name, os_version, build = _linux_pretty_name(), platform.release(), platform.version()
    else:
        os_name, os_version, build = platform.system(), platform.release(), platform.version()
    return HostInfo(
        os_family=fam,
        os_name=os_name,
        os_version=os_version,
        os_build=build,
        arch=platform.machine(),
        python=platform.python_version(),
        elevated=is_elevated(),
    )
