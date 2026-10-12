"""Windows inventory: OS build/patch level, installed apps, persistence entries.

All reads are unelevated-friendly: registry keys under HKLM\\SOFTWARE and the
Services key are readable by standard users, and the PowerShell cmdlets used
(Get-HotFix, Get-AppxPackage, Get-ScheduledTask) work without admin rights
(they may return fewer items, which is reported).

winget is NOT used by default: `winget export` contacts Microsoft's package
sources over the network, which is outside hostguard's approved data sources.
The registry Uninstall keys that winget itself reads are used instead.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from hostguard.inventory.models import Hotfix, OsInfo, PersistenceEntry, Skip, Software
from hostguard.logsetup import get_logger
from hostguard.models import Evidence
from hostguard.sysinfo import windows_product_name
from hostguard.winsys import (
    HKCU,
    HKLM,
    PowerShell,
    PowerShellError,
    Registry,
    RegistryError,
    iter_dicts,
    reg_evidence,
)

log = get_logger("inventory.windows")

CURRENT_VERSION = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
UNINSTALL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
RUN_KEYS = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
)
SERVICES = r"SYSTEM\CurrentControlSet\Services"

# Uninstall entries that describe updates rather than products.
_UPDATE_RELEASE_TYPES = {"update", "hotfix", "security update", "service pack"}

PS_HOTFIX = (
    "Get-HotFix | Select-Object HotFixID,Description,"
    "@{n='InstalledOn';e={if($_.InstalledOn){$_.InstalledOn.ToString('yyyy-MM-dd')}}}"
    " | ConvertTo-Json -Compress"
)
PS_APPX = (
    "Get-AppxPackage | Where-Object { -not $_.IsFramework } | "
    "Select-Object Name,Version,Publisher,InstallLocation,SignatureKind | ConvertTo-Json -Compress"
)
PS_TASKS = (
    "Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object { "
    "[pscustomobject]@{TaskPath=$_.TaskPath;TaskName=$_.TaskName;Author=$_.Author;"
    "Actions=@($_.Actions | ForEach-Object { ($_.Execute + ' ' + $_.Arguments).Trim() })} }"
    " | ConvertTo-Json -Compress -Depth 3"
)


def collect_os(reg: Registry, ps: PowerShell, skipped: list[Skip], arch: str) -> OsInfo:
    try:
        cv = reg.values(HKLM, CURRENT_VERSION) or {}
    except RegistryError as exc:
        skipped.append(Skip("Windows version details", str(exc)))
        cv = {}
    build = str(cv.get("CurrentBuildNumber") or cv.get("CurrentBuild") or "")
    ubr_raw = cv.get("UBR")
    ubr = int(ubr_raw) if isinstance(ubr_raw, int) else None
    edition_id = str(cv.get("EditionID", ""))
    display_version = str(cv.get("DisplayVersion", ""))
    # Note: ProductName still says "Windows 10" on Windows 11, so the name comes from the build.
    name = windows_product_name("10", build, edition_id)
    shown = {
        k: cv.get(k)
        for k in ("ProductName", "DisplayVersion", "CurrentBuildNumber", "UBR", "EditionID")
    }
    info = OsInfo(
        family="windows",
        name=name,
        version=f"10.0.{build}" + (f".{ubr}" if ubr is not None else ""),
        build=build,
        ubr=ubr,
        display_version=display_version,
        edition_id=edition_id,
        arch=arch,
        evidence=[reg_evidence(HKLM, CURRENT_VERSION, shown)],
    )
    try:
        data, ev = ps.run_json(PS_HOTFIX)
        info.hotfixes = [
            Hotfix(
                str(d.get("HotFixID", "")),
                str(d.get("Description") or ""),
                str(d.get("InstalledOn") or ""),
            )
            for d in iter_dicts(data)
        ]
        info.evidence.append(ev)
    except PowerShellError as exc:
        skipped.append(Skip("Installed Windows updates (Get-HotFix)", str(exc)))
    return info


def _uninstall_entries(
    reg: Registry, hive: str, view32: bool, label: str, skipped: list[Skip]
) -> Iterable[Software]:
    try:
        names = reg.subkeys(hive, UNINSTALL, view32=view32) or []
    except RegistryError as exc:
        skipped.append(Skip(f"Installed programs ({label})", str(exc)))
        return
    for sub in names:
        path = f"{UNINSTALL}\\{sub}"
        try:
            v = reg.values(hive, path, view32=view32) or {}
        except RegistryError:
            continue
        name = str(v.get("DisplayName") or "").strip()
        if not name or v.get("SystemComponent") == 1 or v.get("ParentKeyName"):
            continue
        if str(v.get("ReleaseType") or "").lower() in _UPDATE_RELEASE_TYPES:
            continue
        yield Software(
            name=name,
            version=str(v.get("DisplayVersion") or "").strip(),
            publisher=str(v.get("Publisher") or "").strip(),
            install_location=str(v.get("InstallLocation") or "").strip(),
            source=f"registry:{label}",
            origin=f"registry {hive}\\{path}" + (" (32-bit view)" if view32 else ""),
        )


def collect_software(reg: Registry, ps: PowerShell, skipped: list[Skip]) -> list[Software]:
    found: list[Software] = []
    found += _uninstall_entries(reg, HKLM, False, "HKLM", skipped)
    found += _uninstall_entries(reg, HKLM, True, "HKLM-WOW6432Node", skipped)
    found += _uninstall_entries(reg, HKCU, False, "HKCU", skipped)
    try:
        data, _ev = ps.run_json(PS_APPX)
        for d in iter_dicts(data):
            found.append(
                Software(
                    name=str(d.get("Name", "")),
                    version=str(d.get("Version", "")),
                    publisher=_appx_publisher(str(d.get("Publisher", ""))),
                    install_location=str(d.get("InstallLocation") or ""),
                    source="appx",
                    origin="powershell: Get-AppxPackage",
                )
            )
    except PowerShellError as exc:
        skipped.append(Skip("Microsoft Store / MSIX apps (Get-AppxPackage)", str(exc)))
    return dedupe(found)


def _appx_publisher(dn: str) -> str:
    m = re.search(r"(?:^|,\s*)O=([^,]+)", dn) or re.search(r"CN=([^,]+)", dn)
    return m.group(1).strip().strip('"') if m else dn


def dedupe(items: list[Software]) -> list[Software]:
    seen: set[tuple[str, str]] = set()
    out = []
    for s in items:
        k = (s.name.casefold(), s.version)
        if k not in seen:
            seen.add(k)
            out.append(s)
    return sorted(out, key=lambda s: s.name.casefold())


def collect_persistence(
    reg: Registry, ps: PowerShell, skipped: list[Skip], env: dict[str, str] | None = None
) -> list[PersistenceEntry]:
    env = dict(os.environ) if env is None else env
    out: list[PersistenceEntry] = []
    for hive, view32, label in (
        (HKLM, False, "HKLM"),
        (HKLM, True, "HKLM-WOW6432Node"),
        (HKCU, False, "HKCU"),
    ):
        for key in RUN_KEYS:
            try:
                vals = reg.values(hive, key, view32=view32)
            except RegistryError as exc:
                skipped.append(Skip(f"{label}\\{key}", str(exc)))
                continue
            for name, cmd in (vals or {}).items():
                out.append(
                    PersistenceEntry("run-key", name or "(default)", str(cmd), f"{label}\\{key}")
                )

    for folder in _startup_folders(env):
        try:
            entries = sorted(folder.iterdir()) if folder.is_dir() else []
        except OSError as exc:
            skipped.append(Skip(str(folder), str(exc)))
            continue
        for f in entries:
            if f.name.lower() != "desktop.ini":
                out.append(PersistenceEntry("startup-folder", f.name, str(f), str(folder)))

    out += _services(reg, skipped)

    try:
        data, _ev = ps.run_json(PS_TASKS, timeout=120)
        for d in iter_dicts(data):
            actions = d.get("Actions") or []
            out.append(
                PersistenceEntry(
                    "scheduled-task",
                    str(d.get("TaskName", "")),
                    "; ".join(
                        str(a) for a in (actions if isinstance(actions, list) else [actions])
                    ),
                    str(d.get("TaskPath", "")),
                    notes=f"author: {d.get('Author') or 'unknown'}",
                )
            )
    except PowerShellError as exc:
        skipped.append(Skip("Scheduled tasks (Get-ScheduledTask)", str(exc)))
    return out


def _startup_folders(env: dict[str, str]) -> list[Path]:
    folders = []
    if env.get("APPDATA"):
        folders.append(Path(env["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/Startup")
    if env.get("ProgramData"):
        folders.append(Path(env["ProgramData"]) / "Microsoft/Windows/Start Menu/Programs/StartUp")
    return folders


def _services(reg: Registry, skipped: list[Skip]) -> list[PersistenceEntry]:
    """Automatic-start Win32 services (Start = 2) with their ImagePath."""
    out: list[PersistenceEntry] = []
    try:
        names = reg.subkeys(HKLM, SERVICES) or []
    except RegistryError as exc:
        skipped.append(Skip("Services", str(exc)))
        return out
    for name in names:
        try:
            v: dict[str, Any] = reg.values(HKLM, f"{SERVICES}\\{name}") or {}
        except RegistryError:
            continue
        svc_type = v.get("Type")
        if not isinstance(svc_type, int) or not svc_type & 0x30:  # own/share process services
            continue
        if v.get("Start") != 2:
            continue
        out.append(
            PersistenceEntry(
                "service",
                name,
                str(v.get("ImagePath", "")),
                f"HKLM\\{SERVICES}\\{name}",
                notes=str(v.get("DisplayName", ""))[:200],
            )
        )
    return out


def persistence_evidence(entries: list[PersistenceEntry]) -> Evidence:
    return Evidence(
        source="registry Run/RunOnce keys, Startup folders, Services key, Get-ScheduledTask",
        output=f"{len(entries)} entries",
    )
