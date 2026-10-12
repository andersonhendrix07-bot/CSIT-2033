"""Linux inventory: distro, packages (dpkg/rpm/snap/flatpak), persistence entries.

Package versions are recorded together with the *distro's own* package name
and version (for Debian/Ubuntu, the source package), so vulnerability matching
uses distro security data and backported fixes are not reported as missing.
"""

from __future__ import annotations

import platform
from collections.abc import Callable, Sequence
from pathlib import Path

from hostguard import proc
from hostguard.inventory.models import OsInfo, PersistenceEntry, Skip, Software
from hostguard.models import Evidence

Runner = Callable[[Sequence[str]], proc.ProcResult]

DPKG_FORMAT = (
    "${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n"
)
RPM_FORMAT = "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{VENDOR}\n"


def read_os_release(root: Path = Path("/")) -> dict[str, str]:
    for rel in ("etc/os-release", "usr/lib/os-release"):
        p = root / rel
        try:
            text = p.read_text(encoding="utf-8")
        except OSError:
            continue
        out: dict[str, str] = {}
        for line in text.splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
        return out
    return {}


def osv_ecosystem(osr: dict[str, str]) -> str:
    """OSV ecosystem name for this distro, or "" if OSV has no data for it.

    Formats (checked against api.osv.dev 2026-10-12): "Ubuntu:24.04:LTS",
    "Ubuntu:25.04", "Debian:12", "AlmaLinux:9", "Rocky Linux:9".
    """
    distro, ver = osr.get("ID", ""), osr.get("VERSION_ID", "")
    if not ver:
        return ""
    if distro == "ubuntu":
        return f"Ubuntu:{ver}:LTS" if "LTS" in osr.get("VERSION", "") else f"Ubuntu:{ver}"
    if distro == "debian":
        return f"Debian:{ver.split('.')[0]}"
    if distro == "almalinux":
        return f"AlmaLinux:{ver.split('.')[0]}"
    if distro == "rocky":
        return f"Rocky Linux:{ver.split('.')[0]}"
    return ""


def collect_os(root: Path = Path("/")) -> OsInfo:
    osr = read_os_release(root)
    return OsInfo(
        family="linux",
        name=osr.get("PRETTY_NAME", "Linux"),
        version=platform.release(),
        build=platform.version(),
        arch=platform.machine(),
        distro_id=osr.get("ID", ""),
        distro_version=osr.get("VERSION_ID", ""),
        evidence=[Evidence("file /etc/os-release", "; ".join(f"{k}={v}" for k, v in osr.items()))],
    )


def _try(
    run: Runner, argv: Sequence[str], what: str, skipped: list[Skip]
) -> proc.ProcResult | None:
    try:
        r = run(argv)
    except proc.ToolNotFoundError:
        return None  # package manager not present: not a skip, just not applicable
    if not r.ok:
        skipped.append(Skip(what, f"`{r.cmdline}` failed: {(r.stderr or '').strip()[:200]}"))
        return None
    return r


def collect_software(
    ecosystem: str, skipped: list[Skip], run: Runner = proc.run
) -> tuple[list[Software], list[Evidence]]:
    found: list[Software] = []
    evidence: list[Evidence] = []

    r = _try(run, ["dpkg-query", "-W", "-f", DPKG_FORMAT], "dpkg packages", skipped)
    if r:
        n = 0
        for line in r.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) != 5 or not parts[0].startswith("ii"):
                continue
            _st, name, ver, src, srcver = parts
            found.append(
                Software(
                    name=name.split(":")[0],
                    version=ver,
                    source="dpkg",
                    ecosystem=ecosystem,
                    package=src or name.split(":")[0],
                    package_version=srcver or ver,
                    origin="dpkg-query -W",
                )
            )
            n += 1
        evidence.append(Evidence(r.cmdline, f"{n} installed packages"))

    r = _try(run, ["rpm", "-qa", "--qf", RPM_FORMAT], "rpm packages", skipped)
    if r:
        n = 0
        for line in r.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 2 or parts[0] == "gpg-pubkey":
                continue
            evr = parts[1][2:] if parts[1].startswith("0:") else parts[1]
            found.append(
                Software(
                    name=parts[0],
                    version=evr,
                    publisher=parts[2] if len(parts) > 2 else "",
                    source="rpm",
                    ecosystem=ecosystem,
                    package=parts[0],
                    package_version=evr,
                    origin="rpm -qa",
                )
            )
            n += 1
        evidence.append(Evidence(r.cmdline, f"{n} installed packages"))

    r = _try(run, ["snap", "list", "--unicode=never", "--color=never"], "snap packages", skipped)
    if r:
        for line in r.stdout.splitlines()[1:]:
            cols = line.split()
            if len(cols) >= 2:
                found.append(
                    Software(cols[0], cols[1], "snap", publisher=cols[4] if len(cols) > 4 else "")
                )
        evidence.append(Evidence(r.cmdline, f"{len(r.stdout.splitlines()) - 1} snaps"))

    r = _try(
        run,
        ["flatpak", "list", "--app", "--columns=application,version,origin"],
        "flatpak apps",
        skipped,
    )
    if r:
        for line in r.stdout.splitlines():
            cols = line.split("\t")
            if cols and cols[0]:
                found.append(Software(cols[0], cols[1] if len(cols) > 1 else "", "flatpak"))
        evidence.append(Evidence(r.cmdline, f"{len(r.stdout.splitlines())} flatpaks"))
    return found, evidence


def collect_persistence(
    skipped: list[Skip], root: Path = Path("/"), home: Path | None = None
) -> list[PersistenceEntry]:
    out: list[PersistenceEntry] = []
    home = home if home is not None else Path("~").expanduser()

    for f in [root / "etc/crontab", *_ls(root / "etc/cron.d", skipped)]:
        out += _cron_file(f, skipped)
    spool = root / "var/spool/cron/crontabs"
    if spool.exists():
        try:
            for f in sorted(spool.iterdir()):
                out += _cron_file(f, skipped)
        except PermissionError:
            skipped.append(Skip(str(spool), "Skipped: requires admin (per-user crontabs)"))

    for base in (root / "etc/systemd/system", home / ".config/systemd/user"):
        for wants in sorted(base.glob("*.wants")) if base.is_dir() else []:
            for unit in _ls(wants, skipped):
                out.append(PersistenceEntry("systemd", unit.name, _systemd_exec(unit), str(wants)))

    for base in (root / "etc/xdg/autostart", home / ".config/autostart"):
        for f in _ls(base, skipped):
            if f.suffix == ".desktop":
                out.append(PersistenceEntry("xdg-autostart", f.name, _desktop_exec(f), str(base)))
    return out


def _ls(d: Path, skipped: list[Skip]) -> list[Path]:
    try:
        return sorted(d.iterdir()) if d.is_dir() else []
    except PermissionError:
        skipped.append(Skip(str(d), "Skipped: requires admin"))
        return []


def _cron_file(f: Path, skipped: list[Skip]) -> list[PersistenceEntry]:
    try:
        text = f.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return []
    except PermissionError:
        skipped.append(Skip(str(f), "Skipped: requires admin"))
        return []
    except OSError:
        return []
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" in s.split()[0]:
            continue
        out.append(PersistenceEntry("cron", f.name, s[:500], str(f)))
    return out


def _systemd_exec(unit: Path) -> str:
    try:
        for line in unit.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("ExecStart="):
                return line.split("=", 1)[1].strip()[:500]
    except OSError:
        pass
    return ""


def _desktop_exec(f: Path) -> str:
    try:
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("Exec="):
                return line.split("=", 1)[1].strip()[:500]
    except OSError:
        pass
    return ""
