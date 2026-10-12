"""Checks that use the inventory and apply to every OS."""

from __future__ import annotations

import re

from hostguard.audit.base import AuditContext, Outcome, check, failed, passed, skipped
from hostguard.models import Confidence, Evidence, Severity

ALL = ("windows", "linux", "macos")
MS_FW = "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules"
CIS_WIN = "https://www.cisecurity.org/benchmark/microsoft_windows_desktop"
CIS_UBUNTU = "https://www.cisecurity.org/benchmark/ubuntu_linux"

# Folders any local user (or a download) can write to. Programs that start automatically from
# here are a common persistence trick, but many legitimate per-user apps live here too.
_USER_WRITABLE = re.compile(
    r"\\appdata\\|%appdata%|%localappdata%|%temp%|\\temp\\|\\downloads\\|\\users\\public\\"
    r"|/tmp/|/var/tmp/|/dev/shm/|/downloads/",
    re.IGNORECASE,
)

MAX_LISTED = 30


@check(
    "EXP-001",
    "Services listening on network interfaces",
    family=ALL,
    severity=Severity.INFO,
    remediation="Review each listed program. Stop or uninstall services you do not use, configure the ones you "
    "need to listen on 127.0.0.1 only, and keep the host firewall on so they are not reachable from the network.",
    references=(MS_FW, CIS_WIN, CIS_UBUNTU),
    retest="Run `hostguard audit`; services you removed or restricted should no longer be listed in EXP-001.",
)
def exposed(ctx: AuditContext) -> Outcome:
    inv = ctx.inventory
    if inv is None or not inv.listeners_collected:
        return skipped("listening-port inventory not available")
    exposed = [x for x in inv.listeners if not x.loopback]
    lines = [
        f"{x.protocol}/{x.port} on {x.address} — {x.process}" + (f" ({x.exe})" if x.exe else "")
        for x in exposed
    ]
    ev = Evidence(
        "psutil.net_connections(kind='inet') (local socket table, no network scan)",
        "\n".join(lines[:MAX_LISTED]) + ("\n…" if len(lines) > MAX_LISTED else "")
        if lines
        else "none",
    )
    if exposed:
        return failed(f"{len(exposed)} socket(s) listening on non-loopback addresses", ev)
    return passed("only loopback listeners", ev)


@check(
    "PER-001",
    "Programs that start automatically from user-writable folders",
    family=ALL,
    severity=Severity.INFO,
    remediation="Check each listed entry: if you do not recognise it, look up the file's publisher and scan it "
    "(`hostguard scan <path>` from Phase 3, plus Microsoft Defender). Remove startup entries you do not need via "
    "Task Manager > Startup apps (Windows) or by deleting the unit/cron/autostart entry.",
    references=(CIS_WIN, CIS_UBUNTU),
    retest="Run `hostguard audit`; entries you removed should no longer appear in PER-001.",
)
def user_writable_persistence(ctx: AuditContext) -> Outcome:
    inv = ctx.inventory
    if inv is None or not inv.persistence_collected:
        return skipped("persistence inventory not available")
    hits = [p for p in inv.persistence if _USER_WRITABLE.search(p.command)]
    lines = [f"[{p.kind}] {p.name}: {p.command} ({p.location})" for p in hits]
    ev = Evidence(
        "registry Run keys, Startup folders, services, scheduled tasks / cron, systemd, autostart",
        "\n".join(lines[:MAX_LISTED]) + ("\n…" if len(lines) > MAX_LISTED else "")
        if lines
        else "none",
    )
    if hits:
        return failed(
            f"{len(hits)} startup entr{'y' if len(hits) == 1 else 'ies'} run from user-writable folders",
            ev,
            confidence=Confidence.NEEDS_VERIFICATION,
        )
    return passed(
        f"none of {len(inv.persistence)} startup entries run from user-writable folders", ev
    )
