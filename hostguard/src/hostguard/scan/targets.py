"""What to scan: quick / full / custom targets, exclusions, and a safe directory walker.

The walker never follows symlinks or Windows reparse points (junctions,
mount points) unless configured, never crosses into /proc, /sys, /dev or /run,
and skips cloud placeholder files (e.g. OneDrive "online-only" files), because
reading them would download them.
"""

from __future__ import annotations

import fnmatch
import os
import re
import stat
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from hostguard.inventory.models import PersistenceEntry

# Windows file attributes (winnt.h); defined here so the code also runs elsewhere.
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000

POSIX_PSEUDO = ("/proc", "/sys", "/dev", "/run")
NETWORK_FS = {"nfs", "nfs4", "cifs", "smbfs", "smb3", "sshfs", "fuse.sshfs", "9p", "afs", "davfs"}
WINDOWS_SYSTEM_FILES = {"pagefile.sys", "hiberfil.sys", "swapfile.sys", "dumpstack.log.tmp"}


@dataclass
class WalkFile:
    path: Path
    size: int


@dataclass
class WalkSkip:
    path: Path
    reason: str


class Exclusions:
    def __init__(self, paths: Iterable[Path], globs: Iterable[str]) -> None:
        self.paths = [_norm(p) for p in paths]
        self.globs = [g.lower() if os.name == "nt" else g for g in globs]

    def excluded(self, path: Path) -> str | None:
        n = _norm(path)
        for p in self.paths:
            if n == p or n.startswith(p.rstrip(os.sep) + os.sep):
                return f"excluded folder {p}"
        name = path.name.lower() if os.name == "nt" else path.name
        full = str(path).lower() if os.name == "nt" else str(path)
        for g in self.globs:
            if fnmatch.fnmatchcase(name, g) or fnmatch.fnmatchcase(full, g):
                return f"excluded by pattern {g}"
        return None


def _norm(p: Path) -> str:
    s = os.path.normpath(os.path.abspath(str(p)))
    return s.lower() if os.name == "nt" else s


def long_path(p: Path) -> str:
    """Use the \\\\?\\ prefix for long Windows paths so open() works beyond MAX_PATH."""
    s = str(p)
    if os.name == "nt" and len(s) >= 240 and not s.startswith("\\\\?\\"):
        s = os.path.abspath(s)
        return "\\\\?\\UNC\\" + s[2:] if s.startswith("\\\\") else "\\\\?\\" + s
    return s


def _network_mounts() -> set[str]:
    mounts: set[str] = set()
    try:
        with open("/proc/mounts", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 3 and parts[2] in NETWORK_FS:
                    mounts.add(parts[1])
    except OSError:
        pass
    return mounts


def walk(
    roots: Iterable[Path], exclusions: Exclusions, *, follow_symlinks: bool = False
) -> Iterator[WalkFile | WalkSkip]:
    skip_dirs = set() if os.name == "nt" else {*POSIX_PSEUDO, *_network_mounts()}
    seen_dirs: set[tuple[int, int]] = set()
    for root in roots:
        root = Path(os.path.abspath(root))
        try:
            st = root.stat() if follow_symlinks else root.lstat()
        except OSError as exc:
            yield WalkSkip(root, f"cannot access: {exc.strerror or exc}")
            continue
        if stat.S_ISREG(st.st_mode):
            reason = exclusions.excluded(root)
            yield WalkSkip(root, reason) if reason else WalkFile(root, st.st_size)
            continue
        stack = [root]
        while stack:
            d = stack.pop()
            if str(d) in skip_dirs or exclusions.excluded(d):
                continue
            try:
                dst = d.stat()
                key = (dst.st_dev, dst.st_ino)
                if key in seen_dirs and key != (0, 0):
                    continue  # loop protection when following links
                seen_dirs.add(key)
                with os.scandir(long_path(d)) as it:
                    entries = list(it)
            except PermissionError:
                yield WalkSkip(d, "Skipped: permission denied (folder)")
                continue
            except OSError as exc:
                yield WalkSkip(d, f"cannot list folder: {exc.strerror or exc}")
                continue
            for e in entries:
                p = d / e.name
                try:
                    est = e.stat(follow_symlinks=False)
                except OSError as exc:
                    yield WalkSkip(p, f"cannot stat: {exc.strerror or exc}")
                    continue
                attrs = getattr(est, "st_file_attributes", 0)
                is_link = stat.S_ISLNK(est.st_mode) or bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)
                if attrs & (
                    FILE_ATTRIBUTE_OFFLINE
                    | FILE_ATTRIBUTE_RECALL_ON_OPEN
                    | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
                ):
                    yield WalkSkip(
                        p, "cloud placeholder / offline file (reading it would download it)"
                    )
                    continue
                if is_link and not follow_symlinks:
                    continue  # symlinks and junctions are not followed (config: follow_symlinks)
                if is_link:
                    try:
                        est = p.stat()
                    except OSError:
                        continue
                if stat.S_ISDIR(est.st_mode):
                    stack.append(p)
                elif stat.S_ISREG(est.st_mode):
                    if os.name == "nt" and e.name.lower() in WINDOWS_SYSTEM_FILES:
                        yield WalkSkip(p, "Windows system file (always locked)")
                        continue
                    reason = exclusions.excluded(p)
                    if reason:
                        continue
                    yield WalkFile(p, est.st_size)


# --- quick / full targets --------------------------------------------------------------


def quick_targets(
    env: dict[str, str] | None = None, persistence: Iterable[PersistenceEntry] = ()
) -> list[Path]:
    """Downloads, Desktop, temp folders, startup folders and files that start automatically."""
    env = dict(os.environ) if env is None else env
    home = Path(env.get("USERPROFILE") or env.get("HOME") or Path.home())
    out: list[Path] = [home / "Downloads", home / "Desktop"]
    if os.name == "nt":
        for var in ("TEMP", "TMP"):
            if env.get(var):
                out.append(Path(env[var]))
        if env.get("APPDATA"):
            out.append(Path(env["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/Startup")
        if env.get("ProgramData"):
            out.append(Path(env["ProgramData"]) / "Microsoft/Windows/Start Menu/Programs/StartUp")
    else:
        out += [Path("/tmp"), Path("/var/tmp"), Path("/dev/shm"), home / ".config/autostart"]  # noqa: S108 - scan targets
    for entry in persistence:
        out += [p for p in command_paths(entry.command, env) if p.is_file()]
    seen: set[str] = set()
    unique = []
    for p in out:
        k = _norm(p)
        if k not in seen and p.exists():
            seen.add(k)
            unique.append(p)
    return unique


def full_targets() -> list[Path]:
    if sys.platform == "win32":
        return _fixed_drives()
    return [Path("/")]


def _fixed_drives() -> list[Path]:
    if sys.platform != "win32":
        return []
    import ctypes

    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if bitmask & (1 << i):
            root = f"{chr(65 + i)}:\\"
            if ctypes.windll.kernel32.GetDriveTypeW(root) == 3:  # DRIVE_FIXED
                drives.append(Path(root))
    return drives


_EXE_EXT = r"(?:exe|dll|scr|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|msi|lnk|cpl|sys|jar|py|sh)"
_QUOTED = re.compile(r'"([^"]+\.' + _EXE_EXT + r')"', re.IGNORECASE)
_UNQUOTED = re.compile(
    r"((?:[A-Za-z]:\\|\\\\|/|%[A-Za-z_]+%)[^\s\",;]*\." + _EXE_EXT + r")\b", re.IGNORECASE
)


def command_paths(command: str, env: dict[str, str] | None = None) -> list[Path]:
    """Best-effort file paths referenced by a startup command line (for quick scans)."""
    env = dict(os.environ) if env is None else env

    def expand(s: str) -> str:
        return re.sub(r"%([A-Za-z_][A-Za-z0-9_()]*)%", lambda m: env.get(m.group(1), m.group(0)), s)

    found = [m.group(1) for m in _QUOTED.finditer(command)]
    rest = _QUOTED.sub(" ", command)
    found += [m.group(1) for m in _UNQUOTED.finditer(rest)]
    return [Path(expand(f)) for f in dict.fromkeys(found)]
