"""macOS inventory: apps in /Applications (Info.plist), Homebrew, launch agents/daemons.

Written against Apple's documented plist keys; not yet run on a real Mac
(no macOS test machine), which the README states.
"""

from __future__ import annotations

import platform
import plistlib
from pathlib import Path

from hostguard import proc
from hostguard.inventory.linux import Runner
from hostguard.inventory.models import OsInfo, PersistenceEntry, Skip, Software
from hostguard.models import Evidence


def collect_os() -> OsInfo:
    ver = platform.mac_ver()[0]
    return OsInfo(
        family="macos",
        name=f"macOS {ver}",
        version=ver,
        arch=platform.machine(),
        evidence=[Evidence("platform.mac_ver()", ver)],
    )


def _plist(p: Path) -> dict[str, object]:
    try:
        with p.open("rb") as fh:
            data = plistlib.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, plistlib.InvalidFileException, ValueError):
        return {}


def collect_software(
    skipped: list[Skip],
    run: Runner = proc.run,
    apps_dirs: tuple[Path, ...] = (Path("/Applications"),),
) -> list[Software]:
    out: list[Software] = []
    for d in apps_dirs:
        try:
            bundles = sorted(d.glob("*.app"))
        except OSError as exc:
            skipped.append(Skip(str(d), str(exc)))
            continue
        for app in bundles:
            info = _plist(app / "Contents" / "Info.plist")
            name = str(info.get("CFBundleName") or app.stem)
            ver = str(info.get("CFBundleShortVersionString") or info.get("CFBundleVersion") or "")
            out.append(Software(name, ver, "app-bundle", install_location=str(app)))
    try:
        r = run(["brew", "list", "--versions"])
        if r.ok:
            for line in r.stdout.splitlines():
                cols = line.split()
                if len(cols) >= 2:
                    out.append(Software(cols[0], cols[-1], "homebrew"))
    except proc.ToolNotFoundError:
        pass
    return out


def collect_persistence(skipped: list[Skip], home: Path | None = None) -> list[PersistenceEntry]:
    home = home or Path.home()
    out: list[PersistenceEntry] = []
    for base, kind in (
        (home / "Library/LaunchAgents", "launch-agent"),
        (Path("/Library/LaunchAgents"), "launch-agent"),
        (Path("/Library/LaunchDaemons"), "launch-daemon"),
    ):
        try:
            files = sorted(base.glob("*.plist")) if base.is_dir() else []
        except OSError as exc:
            skipped.append(Skip(str(base), str(exc)))
            continue
        for f in files:
            p = _plist(f)
            args = p.get("ProgramArguments")
            cmd = (
                " ".join(str(a) for a in args)
                if isinstance(args, list)
                else str(p.get("Program", ""))
            )
            out.append(
                PersistenceEntry(
                    kind,
                    str(p.get("Label", f.stem)),
                    cmd[:500],
                    str(base),
                    enabled=not p.get("Disabled", False),
                )
            )
    return out
