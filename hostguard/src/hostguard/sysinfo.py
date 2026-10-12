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
        # platform reports "10" for Windows 11 on older Pythons; build >= 22000 is Windows 11.
        name = "Windows 11" if build.isdigit() and int(build) >= 22000 else f"Windows {release}"
        edition = platform.win32_edition() or ""
        os_name = f"{name} {edition}".strip()
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
