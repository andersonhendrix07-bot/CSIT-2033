"""Read-only host inventory (OS, software, Python packages, listeners, persistence)."""

from __future__ import annotations

import platform
from dataclasses import dataclass, field
from pathlib import Path

from hostguard.inventory import linux, macos, ports, python_envs
from hostguard.inventory.models import Inventory, OsInfo, Skip
from hostguard.sysinfo import os_family
from hostguard.winsys import PowerShell, RealPowerShell, Registry, WinRegistry


@dataclass
class Collectors:
    """Injectable backends so tests can supply fakes."""

    registry: Registry = field(default_factory=WinRegistry)
    powershell: PowerShell = field(default_factory=RealPowerShell)
    root: Path = Path("/")


def collect(
    python_envs_paths: list[str] | None = None,
    *,
    family: str | None = None,
    backends: Collectors | None = None,
    software: bool = True,
    persistence: bool = True,
    listeners: bool = True,
) -> Inventory:
    fam = family or os_family()
    b = backends or Collectors()
    skipped: list[Skip] = []

    if fam == "windows":
        from hostguard.inventory import windows

        os_info = windows.collect_os(b.registry, b.powershell, skipped, platform.machine())
        inv = Inventory(os=os_info, skipped=skipped)
        if software:
            inv.software = windows.collect_software(b.registry, b.powershell, skipped)
        if persistence:
            inv.persistence = windows.collect_persistence(b.registry, b.powershell, skipped)
    elif fam == "linux":
        os_info = linux.collect_os(b.root)
        inv = Inventory(os=os_info, skipped=skipped)
        if software:
            eco = linux.osv_ecosystem(linux.read_os_release(b.root))
            if not eco:
                skipped.append(
                    Skip("Distro security data", f"OSV has no ecosystem for {os_info.name}")
                )
            inv.software, ev = linux.collect_software(eco, skipped)
            inv.evidence += ev
        if persistence:
            inv.persistence = linux.collect_persistence(skipped, b.root)
    elif fam == "macos":
        inv = Inventory(os=macos.collect_os(), skipped=skipped)
        if software:
            inv.software = macos.collect_software(skipped)
        if persistence:
            inv.persistence = macos.collect_persistence(skipped)
    else:
        inv = Inventory(os=OsInfo(fam, platform.system(), platform.release()), skipped=skipped)
        skipped.append(Skip("Software inventory", f"unsupported OS family {fam!r}"))

    inv.persistence_collected = persistence
    if python_envs_paths:
        inv.python_packages = python_envs.collect(python_envs_paths, skipped)
    if listeners:
        inv.listeners, ev2 = ports.collect(skipped)
        if ev2:
            inv.evidence.append(ev2)
            inv.listeners_collected = True
    return inv
