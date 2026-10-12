"""Linux configuration checks (read-only). Files are read under ctx.root for testability."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from pathlib import Path

from hostguard import proc
from hostguard.audit.base import (
    REQUIRES_ADMIN,
    AuditContext,
    Outcome,
    check,
    failed,
    not_applicable,
    passed,
    skipped,
)
from hostguard.models import Confidence, Evidence, Severity

CIS_UBUNTU = "https://www.cisecurity.org/benchmark/ubuntu_linux"
UBUNTU_DOCS = "https://documentation.ubuntu.com/server/how-to"

SYSTEM_DIRS = ("usr", "bin", "sbin", "lib", "lib64", "opt", "boot", "etc")
SUID_DIRS = ("usr", "bin", "sbin", "opt")
MAX_WALK_FILES = 500_000
MAX_LISTED = 25


def _read(ctx: AuditContext, rel: str) -> str | None:
    try:
        return (ctx.root / rel).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return None
    except IsADirectoryError:
        return None


def _try_run(ctx: AuditContext, argv: list[str]) -> proc.ProcResult | None:
    try:
        return ctx.run(argv)
    except proc.ToolNotFoundError:
        return None


# --- Firewall -------------------------------------------------------------------------------------


@check(
    "LNX-FW-001",
    "Host firewall active",
    family="linux",
    severity=Severity.MEDIUM,
    remediation="Enable a host firewall, e.g. on Ubuntu: `sudo ufw default deny incoming && sudo ufw allow ssh && "
    "sudo ufw enable` (allow any other services you need first).",
    references=(f"{UBUNTU_DOCS}/security/firewalls/", CIS_UBUNTU),
    retest="Run `hostguard audit`; LNX-FW-001 should pass (ufw ENABLED=yes, firewalld active, or an nftables ruleset).",
)
def firewall(ctx: AuditContext) -> Outcome:
    ufw = _read(ctx, "etc/ufw/ufw.conf")
    if ufw is not None:
        enabled = any(line.strip().lower() == "enabled=yes" for line in ufw.splitlines())
        ev = Evidence("file /etc/ufw/ufw.conf", "ENABLED=yes" if enabled else "ENABLED=no")
        if enabled:
            return passed("ufw is enabled", ev)
    r = _try_run(ctx, ["systemctl", "is-active", "firewalld"])
    if r is not None and r.stdout.strip() == "active":
        return passed("firewalld is active", Evidence(r.cmdline, r.stdout.strip()))
    if not ctx.elevated:
        return skipped(
            f"{REQUIRES_ADMIN} (reading the nftables ruleset needs root); ufw/firewalld not enabled"
        )
    r = _try_run(ctx, ["nft", "list", "ruleset"])
    if r is None:
        return failed("no ufw, firewalld or nft found", confidence=Confidence.LIKELY)
    ev = Evidence(r.cmdline, r.stdout[:1500] or "(empty ruleset)")
    if r.ok and "hook input" in r.stdout:
        return passed("an nftables input chain is configured", ev)
    return failed("no firewall rules filter incoming traffic", ev)


# --- SSH -----------------------------------------------------------------------------------------


def sshd_effective(ctx: AuditContext) -> tuple[dict[str, str], list[str]] | None:
    """First-match-wins sshd_config parsing (as sshd does), following Include; stops at Match."""
    main = ctx.root / "etc/ssh/sshd_config"
    if not main.exists():
        return None
    values: dict[str, str] = {}
    files: list[str] = []
    stop = False

    def parse(path: Path, depth: int) -> None:
        nonlocal stop
        if depth > 5 or stop:
            return
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        files.append(str(path))
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            key = parts[0].lower()
            val = parts[1].strip() if len(parts) > 1 else ""
            if key == "match":
                stop = True
                return
            if key == "include":
                for pattern in val.split():
                    base = pattern if pattern.startswith("/") else f"/etc/ssh/{pattern}"
                    for inc in sorted(ctx.root.glob(base.lstrip("/"))):
                        parse(inc, depth + 1)
                        if stop:
                            return
                continue
            values.setdefault(key, val.lower())

    parse(main, 0)
    return values, files


SSH_REFS = (f"{UBUNTU_DOCS}/security/openssh-server/", CIS_UBUNTU)


@check(
    "LNX-SSH-001",
    "SSH root login with a password disabled",
    family="linux",
    severity=Severity.HIGH,
    remediation="In /etc/ssh/sshd_config set `PermitRootLogin no` (or `prohibit-password`), then "
    "`sudo systemctl reload ssh`.",
    references=SSH_REFS,
    retest="Run `hostguard audit`; LNX-SSH-001 should pass (PermitRootLogin is not 'yes').",
)
def ssh_root(ctx: AuditContext) -> Outcome:
    eff = sshd_effective(ctx)
    if eff is None:
        return not_applicable("OpenSSH server is not installed (/etc/ssh/sshd_config not found)")
    values, files = eff
    val = values.get("permitrootlogin", "prohibit-password (default)")
    ev = Evidence("files " + ", ".join(files), f"PermitRootLogin {val}")
    if val == "yes":
        return failed("PermitRootLogin yes", ev)
    return passed(f"PermitRootLogin {val}", ev)


@check(
    "LNX-SSH-002",
    "SSH password authentication disabled",
    family="linux",
    severity=Severity.MEDIUM,
    remediation="Set up SSH keys first, then set `PasswordAuthentication no` in /etc/ssh/sshd_config and "
    "`sudo systemctl reload ssh`.",
    references=SSH_REFS,
    retest="Run `hostguard audit`; LNX-SSH-002 should pass (PasswordAuthentication no).",
)
def ssh_password(ctx: AuditContext) -> Outcome:
    eff = sshd_effective(ctx)
    if eff is None:
        return not_applicable("OpenSSH server is not installed (/etc/ssh/sshd_config not found)")
    values, files = eff
    val = values.get("passwordauthentication", "yes (default)")
    ev = Evidence("files " + ", ".join(files), f"PasswordAuthentication {val}")
    if val.startswith("yes"):
        return failed("password logins are allowed", ev)
    return passed(f"PasswordAuthentication {val}", ev)


# --- Updates, sudo ------------------------------------------------------------------------------------


@check(
    "LNX-UPD-001",
    "Automatic security updates enabled",
    family="linux",
    severity=Severity.MEDIUM,
    remediation="Debian/Ubuntu: `sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow "
    "unattended-upgrades`. RHEL family: install dnf-automatic and enable dnf-automatic.timer.",
    references=(f"{UBUNTU_DOCS}/software/automatic-updates/", CIS_UBUNTU),
    retest="Run `hostguard audit`; LNX-UPD-001 should pass.",
)
def auto_updates(ctx: AuditContext) -> Outcome:
    if (ctx.root / "var/lib/dpkg/status").exists():
        status = _read(ctx, "var/lib/dpkg/status") or ""
        installed = "Package: unattended-upgrades\nStatus: install ok installed" in status
        confs = []
        d = ctx.root / "etc/apt/apt.conf.d"
        for f in sorted(d.iterdir()) if d.is_dir() else []:
            try:
                for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                    if "APT::Periodic::Unattended-Upgrade" in line and not line.strip().startswith(
                        "//"
                    ):
                        confs.append(f"{f.name}: {line.strip()}")
            except OSError:
                continue
        ev = Evidence(
            "file /var/lib/dpkg/status, /etc/apt/apt.conf.d/*",
            f"unattended-upgrades installed={installed}; "
            + ("; ".join(confs) or "no Unattended-Upgrade setting"),
        )
        enabled = any('"1"' in c for c in confs[-1:])  # later files override earlier ones
        if installed and enabled:
            return passed("unattended-upgrades is installed and enabled", ev)
        return failed("automatic security updates are not enabled", ev)
    timers = list(
        (ctx.root / "etc/systemd/system/timers.target.wants").glob("dnf-automatic*.timer")
    )
    if (ctx.root / "usr/bin/dnf").exists():
        ev = Evidence(
            "dir /etc/systemd/system/timers.target.wants",
            ", ".join(t.name for t in timers) or "none",
        )
        if timers:
            return passed("dnf-automatic timer is enabled", ev)
        return failed("dnf-automatic is not enabled", ev)
    return not_applicable("no supported package manager (apt/dnf) found")


@check(
    "LNX-SUDO-001",
    "No passwordless sudo rules",
    family="linux",
    severity=Severity.MEDIUM,
    remediation="Edit sudoers with `sudo visudo` (and files in /etc/sudoers.d) and remove NOPASSWD from rules "
    "unless a service account genuinely needs it.",
    references=(CIS_UBUNTU,),
    retest="Run `sudo hostguard audit`; LNX-SUDO-001 should pass (no NOPASSWD rules).",
)
def sudo_nopasswd(ctx: AuditContext) -> Outcome:
    files = [ctx.root / "etc/sudoers"]
    d = ctx.root / "etc/sudoers.d"
    try:
        files += sorted(d.iterdir()) if d.is_dir() else []
    except PermissionError:
        return skipped(f"{REQUIRES_ADMIN} (/etc/sudoers.d is readable by root only)")
    hits, read = [], []
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            continue
        except PermissionError:
            return skipped(f"{REQUIRES_ADMIN} ({f} is readable by root only)")
        read.append(str(f))
        hits += [
            f"{f.name}: {ln.strip()}"
            for ln in text.splitlines()
            if "NOPASSWD" in ln and not ln.strip().startswith("#")
        ]
    if not read:
        return not_applicable("sudo is not configured on this system")
    ev = Evidence("files " + ", ".join(read), "\n".join(hits) or "no NOPASSWD rules")
    if hits:
        return failed(f"{len(hits)} passwordless sudo rule(s)", ev)
    return passed("no NOPASSWD rules", ev)


# --- File permissions ----------------------------------------------------------------------------------


def _walk(root: Path, dirs: tuple[str, ...]) -> Iterator[tuple[Path, os.stat_result]]:
    """lstat every entry under root/dirs without following symlinks or crossing filesystems."""
    count = 0
    for d in dirs:
        top = root / d
        try:
            top_dev = top.lstat().st_dev
        except OSError:
            continue
        if stat.S_ISLNK(top.lstat().st_mode):
            continue
        stack = [top]
        while stack:
            cur = stack.pop()
            try:
                with os.scandir(cur) as it:
                    for e in it:
                        try:
                            st = e.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        count += 1
                        if count > MAX_WALK_FILES:
                            return
                        p = Path(e.path)
                        if stat.S_ISDIR(st.st_mode) and st.st_dev == top_dev:
                            stack.append(p)
                        yield p, st
            except OSError:
                continue


def _dpkg_owned(ctx: AuditContext) -> set[str] | None:
    info = ctx.root / "var/lib/dpkg/info"
    if not info.is_dir():
        return None
    owned: set[str] = set()
    for lst in info.glob("*.list"):
        try:
            owned.update(
                line.strip()
                for line in lst.read_text(encoding="utf-8", errors="replace").splitlines()
            )
        except OSError:
            continue
    return owned


@check(
    "LNX-PERM-001",
    "No SUID/SGID programs outside the package manager's control",
    family="linux",
    severity=Severity.MEDIUM,
    remediation="For each listed file, find out what installed it. If it is not needed, remove the bit with "
    "`sudo chmod u-s,g-s <file>` or remove the file; never run unknown SUID programs.",
    references=(CIS_UBUNTU,),
    retest="Run `hostguard audit`; LNX-PERM-001 should list no unowned SUID/SGID files.",
)
def suid_unowned(ctx: AuditContext) -> Outcome:
    owned = _dpkg_owned(ctx)
    suid = [
        (p, st)
        for p, st in _walk(ctx.root, SUID_DIRS)
        if stat.S_ISREG(st.st_mode) and st.st_mode & (stat.S_ISUID | stat.S_ISGID)
    ]
    rel = ["/" + str(p.relative_to(ctx.root)) for p, _ in suid]
    if owned is None:
        r = _try_run(ctx, ["rpm", "--version"])
        if r is None:
            return skipped(
                f"no dpkg or rpm database to check ownership of {len(rel)} SUID/SGID files"
            )
        unowned = []
        for path in rel:
            q = _try_run(ctx, ["rpm", "-qf", path])
            if q is not None and not q.ok:
                unowned.append(path)
        source = "rpm -qf"
    else:
        unowned = [p for p in rel if p not in owned]
        source = "/var/lib/dpkg/info/*.list"
    ev = Evidence(
        f"filesystem walk of /{', /'.join(SUID_DIRS)} (no symlinks followed); ownership via {source}",
        f"{len(rel)} SUID/SGID files; not package-owned: "
        + (", ".join(unowned[:MAX_LISTED]) or "none"),
    )
    if unowned:
        return failed(
            f"{len(unowned)} SUID/SGID file(s) not owned by any package",
            ev,
            confidence=Confidence.LIKELY,
        )
    return passed(f"all {len(rel)} SUID/SGID files belong to installed packages", ev)


@check(
    "LNX-PERM-002",
    "No world-writable files in system directories",
    family="linux",
    severity=Severity.MEDIUM,
    remediation="Remove world write permission from each listed path with `sudo chmod o-w <path>` after checking "
    "which program needs it; for shared directories use the sticky bit (chmod +t).",
    references=(CIS_UBUNTU,),
    retest="Run `hostguard audit`; LNX-PERM-002 should list nothing.",
)
def world_writable(ctx: AuditContext) -> Outcome:
    hits = []
    for p, st in _walk(ctx.root, SYSTEM_DIRS):
        if stat.S_ISLNK(st.st_mode) or not st.st_mode & stat.S_IWOTH:
            continue
        if stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX:
            continue  # sticky shared directories (like /tmp) are expected
        if stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode):
            hits.append("/" + str(p.relative_to(ctx.root)))
    ev = Evidence(
        f"filesystem walk of /{', /'.join(SYSTEM_DIRS)} (no symlinks followed)",
        ", ".join(hits[:MAX_LISTED]) + (" …" if len(hits) > MAX_LISTED else "") if hits else "none",
    )
    if hits:
        return failed(f"{len(hits)} world-writable path(s) in system directories", ev)
    return passed("no world-writable files or non-sticky directories", ev)


@check(
    "LNX-MAC-001",
    "AppArmor or SELinux enforcing",
    family="linux",
    severity=Severity.LOW,
    remediation="Keep the distribution's mandatory access control on: AppArmor on Ubuntu/Debian/SUSE, SELinux in "
    "enforcing mode on RHEL/Fedora. Do not disable it to work around an application problem.",
    references=(f"{UBUNTU_DOCS}/security/apparmor/", CIS_UBUNTU),
    retest="Run `hostguard audit`; LNX-MAC-001 should pass.",
)
def mac(ctx: AuditContext) -> Outcome:
    aa = (_read(ctx, "sys/module/apparmor/parameters/enabled") or "").strip()
    se = (_read(ctx, "sys/fs/selinux/enforce") or "").strip()
    ev = Evidence(
        "files /sys/module/apparmor/parameters/enabled, /sys/fs/selinux/enforce",
        f"apparmor={aa or 'absent'}; selinux enforce={se or 'absent'}",
    )
    if aa == "Y":
        return passed("AppArmor is enabled", ev)
    if se == "1":
        return passed("SELinux is enforcing", ev)
    if se == "0":
        return failed("SELinux is in permissive mode", ev)
    return failed("neither AppArmor nor SELinux is active", ev, confidence=Confidence.LIKELY)
