"""macOS configuration checks (read-only).

Command outputs follow Apple's documented tools (fdesetup, spctl, csrutil,
socketfilterfw). Not yet run on a real Mac; the README states this.
"""

from __future__ import annotations

import plistlib

from hostguard import proc
from hostguard.audit.base import AuditContext, Outcome, check, failed, passed, skipped
from hostguard.models import Evidence, Severity

CIS_MAC = "https://www.cisecurity.org/benchmark/apple_os"


def _cmd(ctx: AuditContext, argv: list[str]) -> tuple[str, Evidence] | None:
    try:
        r = ctx.run(argv)
    except proc.ToolNotFoundError:
        return None
    out = (r.stdout + r.stderr).strip()
    return out, Evidence(r.cmdline, out[:500])


def _simple(ctx: AuditContext, argv: list[str], good: str, bad_detail: str) -> Outcome:
    res = _cmd(ctx, argv)
    if res is None:
        return skipped(f"{argv[0]} not found")
    out, ev = res
    if good.lower() in out.lower():
        return passed(out.splitlines()[0][:200], ev)
    return failed(bad_detail, ev)


@check(
    "MAC-FV-001",
    "FileVault disk encryption on",
    family="macos",
    severity=Severity.MEDIUM,
    remediation="Turn on FileVault in System Settings > Privacy & Security > FileVault.",
    references=(CIS_MAC,),
    retest="Run `hostguard audit`; MAC-FV-001 should pass ('FileVault is On').",
)
def filevault(ctx: AuditContext) -> Outcome:
    return _simple(ctx, ["/usr/bin/fdesetup", "status"], "FileVault is On", "FileVault is off")


@check(
    "MAC-GK-001",
    "Gatekeeper enabled",
    family="macos",
    severity=Severity.HIGH,
    remediation="Re-enable Gatekeeper: `sudo spctl --global-enable`, and allow apps from the App Store and "
    "identified developers only.",
    references=(CIS_MAC,),
    retest="Run `hostguard audit`; MAC-GK-001 should pass ('assessments enabled').",
)
def gatekeeper(ctx: AuditContext) -> Outcome:
    return _simple(
        ctx,
        ["/usr/sbin/spctl", "--status"],
        "assessments enabled",
        "Gatekeeper assessments are disabled",
    )


@check(
    "MAC-SIP-001",
    "System Integrity Protection enabled",
    family="macos",
    severity=Severity.HIGH,
    remediation="Re-enable SIP from macOS Recovery: run `csrutil enable` in Terminal there, then restart.",
    references=(CIS_MAC,),
    retest="Run `hostguard audit`; MAC-SIP-001 should pass ('status: enabled').",
)
def sip(ctx: AuditContext) -> Outcome:
    return _simple(
        ctx,
        ["/usr/bin/csrutil", "status"],
        "status: enabled",
        "System Integrity Protection is disabled",
    )


@check(
    "MAC-FW-001",
    "Application firewall enabled",
    family="macos",
    severity=Severity.MEDIUM,
    remediation="Turn on the firewall in System Settings > Network > Firewall.",
    references=(CIS_MAC,),
    retest="Run `hostguard audit`; MAC-FW-001 should pass ('Firewall is enabled').",
)
def app_firewall(ctx: AuditContext) -> Outcome:
    return _simple(
        ctx,
        ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
        "enabled",
        "the firewall is off",
    )


@check(
    "MAC-UPD-001",
    "Automatic security updates enabled",
    family="macos",
    severity=Severity.MEDIUM,
    remediation="In System Settings > General > Software Update > Automatic updates, turn on 'Install Security "
    "Responses and system files' and 'Download new updates when available'.",
    references=(CIS_MAC,),
    retest="Run `hostguard audit`; MAC-UPD-001 should pass.",
)
def auto_updates(ctx: AuditContext) -> Outcome:
    path = ctx.root / "Library/Preferences/com.apple.SoftwareUpdate.plist"
    try:
        with path.open("rb") as fh:
            prefs = plistlib.load(fh)
    except FileNotFoundError:
        return skipped("Software Update preferences file not found (defaults apply)")
    except (OSError, plistlib.InvalidFileException) as exc:
        return skipped(f"cannot read {path}: {exc}")
    keys = (
        "AutomaticCheckEnabled",
        "AutomaticDownload",
        "CriticalUpdateInstall",
        "ConfigDataInstall",
    )
    shown = {k: prefs.get(k) for k in keys}
    ev = Evidence(f"file {path}", str(shown))
    off = [k for k in keys if prefs.get(k) is False]
    if off:
        return failed(f"disabled: {', '.join(off)}", ev)
    return passed("automatic checks and security responses are not disabled", ev)
