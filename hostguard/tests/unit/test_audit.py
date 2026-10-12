from __future__ import annotations

import os
import stat
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from fakes import FakePowerShell, FakeRegistry
from hostguard import proc
from hostguard.audit import AuditContext, run_checks
from hostguard.audit import windows as aw
from hostguard.audit.base import CHECKS
from hostguard.inventory.models import Inventory, Listener, OsInfo, PersistenceEntry
from hostguard.models import CheckStatus, Confidence, Severity
from hostguard.winsys import HKLM, PowerShellError

# --- Windows ---------------------------------------------------------------------------------


def recon_registry() -> FakeRegistry:
    """Defaults of a current Windows 11 Home install like the user's PC."""
    reg = FakeRegistry()
    reg.set(
        HKLM, aw.UAC, {"EnableLUA": 1, "ConsentPromptBehaviorAdmin": 5, "PromptOnSecureDesktop": 1}
    )
    reg.set(HKLM, aw.SECUREBOOT, {"UEFISecureBootEnabled": 1})
    reg.set(HKLM, aw.DEVICEGUARD, {"Enabled": 1})
    reg.set(HKLM, aw.LSA, {"RunAsPPL": 2})
    reg.set(HKLM, aw.WINLOGON, {"AutoAdminLogon": "0", "Shell": "explorer.exe"})
    reg.set(HKLM, f"{aw.SERVICES}\\LanmanServer\\Parameters", {"EnableSecuritySignature": 1})
    reg.set(HKLM, aw.TS, {"fDenyTSConnections": 1})
    return reg


def recon_powershell(**overrides: Any) -> FakePowerShell:
    today = datetime.now(UTC).date()
    responses: dict[str, Any] = {
        # Matches the recon output the user pasted (firewall all on, Defender fully on).
        "Get-NetFirewallProfile": [
            {"Name": "Domain", "Enabled": True},
            {"Name": "Private", "Enabled": True},
            {"Name": "Public", "Enabled": True},
        ],
        "Get-MpComputerStatus": {
            "AMServiceEnabled": True,
            "AntivirusEnabled": True,
            "RealTimeProtectionEnabled": True,
            "IsTamperProtected": True,
            "AntivirusSignatureAge": 0,
            "AMRunningMode": "Normal",
            "AMProductVersion": "4.18.26080.4",
        },
        "SecurityCenter2": {"displayName": "Windows Defender", "productState": 397568},
        "Get-LocalUser": [
            {"Name": "Administrator", "Enabled": False, "SID": "S-1-5-21-1-2-3-500"},
            {"Name": "Guest", "Enabled": False, "SID": "S-1-5-21-1-2-3-501"},
            {"Name": "ander", "Enabled": True, "SID": "S-1-5-21-1-2-3-1001"},
        ],
        "GetCurrent()": {"User": "PC\\ander", "AdminGroupMember": True},
        "Get-HotFix": [{"HotFixID": "KB1", "InstalledOn": str(today - timedelta(days=5))}],
    }
    responses.update(overrides)
    return FakePowerShell(responses)


def win_ctx(
    reg: FakeRegistry | None = None, ps: FakePowerShell | None = None, **kw: Any
) -> AuditContext:
    return AuditContext(
        family="windows",
        elevated=kw.pop("elevated", False),
        registry=reg or recon_registry(),
        powershell=ps or recon_powershell(),
        edition_id=kw.pop("edition_id", "Core"),
        **kw,
    )


def results_by_id(ctx: AuditContext) -> dict[str, Any]:
    return {r.check.id: r for r in run_checks(ctx)}


def test_windows_recon_baseline() -> None:
    r = results_by_id(win_ctx())
    status = {k: v.status for k, v in r.items()}
    assert status["WIN-FW-001"] == CheckStatus.PASSED
    assert status["WIN-DEF-001"] == CheckStatus.PASSED
    assert status["WIN-DEF-002"] == CheckStatus.PASSED
    assert status["WIN-DEF-003"] == CheckStatus.PASSED
    assert status["WIN-SMB-001"] == CheckStatus.PASSED
    assert status["WIN-RDP-001"] == CheckStatus.NOT_APPLICABLE  # Home edition
    assert status["WIN-UAC-001"] == CheckStatus.PASSED
    assert status["WIN-ACC-001"] == CheckStatus.PASSED
    assert status["WIN-ACC-002"] == CheckStatus.PASSED
    assert status["WIN-ACC-003"] == CheckStatus.FAILED  # daily account is an admin (common default)
    assert status["WIN-ENC-001"] == CheckStatus.SKIPPED
    assert r["WIN-ENC-001"].outcome.detail.startswith("Skipped: requires admin")
    assert status["WIN-SB-001"] == CheckStatus.PASSED
    assert status["WIN-VBS-001"] == CheckStatus.PASSED
    assert status["WIN-LSA-001"] == CheckStatus.PASSED
    assert status["WIN-UPD-001"] == CheckStatus.PASSED
    assert status["WIN-UPD-002"] == CheckStatus.PASSED
    assert status["WIN-UPD-003"] == CheckStatus.PASSED
    # Common checks are skipped without an inventory, never silently passed.
    assert status["EXP-001"] == CheckStatus.SKIPPED and status["PER-001"] == CheckStatus.SKIPPED
    # Every non-skipped result carries evidence.
    for res in r.values():
        if res.status in (CheckStatus.PASSED, CheckStatus.FAILED):
            assert res.outcome.evidence, res.check.id


def test_every_check_has_reference_remediation_and_retest() -> None:
    run_checks(AuditContext(family="none", elevated=False))  # import all check modules
    assert len(CHECKS) >= 25
    for c in CHECKS:
        assert c.references and all(u.startswith("https://") for u in c.references), c.id
        assert c.remediation and c.retest, c.id


def test_windows_failures() -> None:
    reg = recon_registry()
    reg.set(HKLM, aw.UAC, {"EnableLUA": 0})
    reg.set(HKLM, aw.SECUREBOOT, {"UEFISecureBootEnabled": 0})
    reg.set(HKLM, f"{aw.SERVICES}\\mrxsmb10", {"Start": 2})
    reg.set(HKLM, aw.AU_POLICY, {"NoAutoUpdate": 1})
    reg.set(HKLM, aw.REBOOT_KEYS[0], {"x": 1})
    reg.set(HKLM, aw.TS, {"fDenyTSConnections": 0})
    reg.set(HKLM, f"{aw.TS}\\WinStations\\RDP-Tcp", {"UserAuthentication": 0})
    old = str(datetime.now(UTC).date() - timedelta(days=90))
    ps = recon_powershell(
        **{
            "Get-NetFirewallProfile": [
                {"Name": "Domain", "Enabled": 1},
                {"Name": "Public", "Enabled": 0},
            ],
            "Get-MpComputerStatus": {
                "AMServiceEnabled": True,
                "RealTimeProtectionEnabled": False,
                "IsTamperProtected": False,
                "AntivirusSignatureAge": 20,
                "AMRunningMode": "Normal",
            },
            "Get-LocalUser": [{"Name": "Guest", "Enabled": True, "SID": "S-1-5-21-9-501"}],
            "Get-HotFix": [{"HotFixID": "KB1", "InstalledOn": old}],
        }
    )
    r = results_by_id(win_ctx(reg, ps, edition_id="Professional"))
    assert (
        r["WIN-FW-001"].status == CheckStatus.FAILED and "Public" in r["WIN-FW-001"].outcome.detail
    )
    assert r["WIN-DEF-001"].status == CheckStatus.FAILED
    assert (
        r["WIN-DEF-002"].status == CheckStatus.FAILED and r["WIN-DEF-002"].severity == Severity.HIGH
    )
    assert r["WIN-DEF-003"].status == CheckStatus.FAILED
    assert (
        r["WIN-SMB-001"].status == CheckStatus.FAILED
        and r["WIN-SMB-001"].outcome.confidence == Confidence.LIKELY
    )
    assert r["WIN-RDP-001"].status == CheckStatus.FAILED
    assert r["WIN-UAC-001"].status == CheckStatus.FAILED
    assert r["WIN-ACC-001"].status == CheckStatus.FAILED
    assert r["WIN-SB-001"].status == CheckStatus.FAILED
    assert r["WIN-UPD-001"].status == CheckStatus.FAILED
    assert r["WIN-UPD-002"].status == CheckStatus.FAILED
    assert r["WIN-UPD-003"].status == CheckStatus.FAILED
    f = r["WIN-FW-001"].to_finding()
    assert f is not None and f.id == "HG-WIN-FW-001" and f.references and f.retest and f.evidence


def test_autologon_never_reads_the_stored_password() -> None:
    reg = recon_registry()
    reg.set(HKLM, aw.WINLOGON, {"AutoAdminLogon": "1", "DefaultPassword": "hunter2-secret"})
    r = results_by_id(win_ctx(reg))["WIN-ACC-002"]
    assert r.status == CheckStatus.FAILED and r.severity == Severity.HIGH
    blob = repr(r.to_dict())
    assert "hunter2-secret" not in blob
    assert "PRESENT (contents not read)" in blob
    assert ("HKLM", aw.WINLOGON.lower(), "DefaultPassword") not in reg.reads


def test_autologon_without_password_is_medium() -> None:
    reg = recon_registry()
    reg.set(HKLM, aw.WINLOGON, {"AutoAdminLogon": "1"})
    r = results_by_id(win_ctx(reg))["WIN-ACC-002"]
    assert r.status == CheckStatus.FAILED and r.severity == Severity.MEDIUM


def test_defender_passive_with_third_party_av_is_not_applicable() -> None:
    ps = recon_powershell(
        **{
            "Get-MpComputerStatus": {
                "AMServiceEnabled": True,
                "RealTimeProtectionEnabled": False,
                "AMRunningMode": "Passive Mode",
            },
            "SecurityCenter2": [{"displayName": "Windows Defender"}, {"displayName": "ACME AV"}],
        }
    )
    r = results_by_id(win_ctx(ps=ps))["WIN-DEF-001"]
    assert r.status == CheckStatus.NOT_APPLICABLE and "ACME AV" in r.outcome.detail


def test_powershell_failure_is_error_not_pass() -> None:
    ps = recon_powershell(**{"Get-NetFirewallProfile": PowerShellError("Access is denied.")})
    r = results_by_id(win_ctx(ps=ps))["WIN-FW-001"]
    assert r.status == CheckStatus.ERROR and "Access is denied" in r.outcome.detail


def test_bitlocker_when_elevated() -> None:
    ps = recon_powershell(
        **{"Get-BitLockerVolume": {"MountPoint": "C:", "ProtectionStatus": 1, "VolumeStatus": 1}}
    )
    r = results_by_id(win_ctx(ps=ps, elevated=True))["WIN-ENC-001"]
    assert r.status == CheckStatus.PASSED


def test_crashing_check_is_reported_as_error(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = recon_registry()

    def boom(*a: Any, **k: Any) -> Any:
        raise ValueError("unexpected data")

    monkeypatch.setattr(reg, "value", boom)
    r = results_by_id(win_ctx(reg))
    assert r["WIN-SB-001"].status == CheckStatus.ERROR
    assert r["WIN-FW-001"].status == CheckStatus.PASSED  # other checks still ran


# --- Common checks --------------------------------------------------------------------------


def test_exposure_and_persistence_checks() -> None:
    inv = Inventory(
        os=OsInfo("windows", "Windows 11 Home", "10.0.26200.6899"),
        listeners=[
            Listener("tcp", "0.0.0.0", 445, 4, "System"),
            Listener("tcp", "127.0.0.1", 9000, 100, "dev.exe"),
        ],
        persistence=[
            PersistenceEntry(
                "run-key", "Updater", r"C:\Users\me\AppData\Roaming\x\up.exe", "HKCU\\...\\Run"
            ),
            PersistenceEntry(
                "service", "Good", r"C:\Program Files\Good\svc.exe", "HKLM\\...\\Services\\Good"
            ),
        ],
        listeners_collected=True,
        persistence_collected=True,
    )
    r = results_by_id(win_ctx(inventory=inv))
    exp, per = r["EXP-001"], r["PER-001"]
    assert exp.status == CheckStatus.FAILED and exp.severity == Severity.INFO
    assert (
        "tcp/445 on 0.0.0.0" in exp.outcome.evidence[0].output
        and "9000" not in exp.outcome.evidence[0].output
    )
    assert (
        per.status == CheckStatus.FAILED and per.outcome.confidence == Confidence.NEEDS_VERIFICATION
    )
    assert (
        "Updater" in per.outcome.evidence[0].output and "Good" not in per.outcome.evidence[0].output
    )


# --- Linux ------------------------------------------------------------------------------------


def runner(outputs: dict[str, proc.ProcResult]):  # type: ignore[no-untyped-def]
    def run(argv: Sequence[str]) -> proc.ProcResult:
        key = " ".join(argv)
        for k, v in outputs.items():
            if key.startswith(k):
                return v
        raise proc.ToolNotFoundError(argv[0])

    return run


def lnx(root: Path, elevated: bool = False, **outs: proc.ProcResult) -> AuditContext:
    return AuditContext(family="linux", elevated=elevated, root=root, run=runner(outs))


def write(root: Path, rel: str, text: str, mode: int | None = None) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    if mode is not None:
        p.chmod(mode)
    return p


def test_sshd_first_match_wins_with_include(tmp_path: Path) -> None:
    write(
        tmp_path,
        "etc/ssh/sshd_config",
        "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nPasswordAuthentication yes\n",
    )
    write(tmp_path, "etc/ssh/sshd_config.d/50-cloud.conf", "PasswordAuthentication no\n")
    r = {x.check.id: x for x in run_checks(lnx(tmp_path))}
    assert r["LNX-SSH-001"].status == CheckStatus.FAILED  # PermitRootLogin yes
    assert r["LNX-SSH-002"].status == CheckStatus.PASSED  # the include came first and wins
    assert "50-cloud.conf" in r["LNX-SSH-002"].outcome.evidence[0].source


def test_sshd_match_block_stops_parsing(tmp_path: Path) -> None:
    write(tmp_path, "etc/ssh/sshd_config", "Match User bob\n  PasswordAuthentication no\n")
    r = {x.check.id: x for x in run_checks(lnx(tmp_path))}
    assert r["LNX-SSH-002"].status == CheckStatus.FAILED  # default "yes" applies globally
    assert r["LNX-SSH-001"].status == CheckStatus.PASSED  # default prohibit-password


def test_firewall_variants(tmp_path: Path) -> None:
    write(tmp_path, "etc/ufw/ufw.conf", "ENABLED=yes\n")
    assert {x.check.id: x for x in run_checks(lnx(tmp_path))}[
        "LNX-FW-001"
    ].status == CheckStatus.PASSED
    other = tmp_path / "other"
    other.mkdir()
    r = {x.check.id: x for x in run_checks(lnx(other))}["LNX-FW-001"]
    assert r.status == CheckStatus.SKIPPED and "requires admin" in r.outcome.detail
    nft = proc.ProcResult(
        ("nft", "list", "ruleset"),
        0,
        "table inet f {\n chain input { type filter hook input priority 0; policy drop; }\n}",
        "",
    )
    r = {x.check.id: x for x in run_checks(lnx(other, True, nft=nft))}["LNX-FW-001"]
    assert r.status == CheckStatus.PASSED


def test_unattended_upgrades(tmp_path: Path) -> None:
    write(
        tmp_path,
        "var/lib/dpkg/status",
        "Package: unattended-upgrades\nStatus: install ok installed\n",
    )
    write(
        tmp_path,
        "etc/apt/apt.conf.d/20auto-upgrades",
        'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n',
    )
    assert {x.check.id: x for x in run_checks(lnx(tmp_path))}[
        "LNX-UPD-001"
    ].status == CheckStatus.PASSED
    write(tmp_path, "etc/apt/apt.conf.d/99local", 'APT::Periodic::Unattended-Upgrade "0";\n')
    assert {x.check.id: x for x in run_checks(lnx(tmp_path))}[
        "LNX-UPD-001"
    ].status == CheckStatus.FAILED


def test_sudo_nopasswd(tmp_path: Path) -> None:
    write(tmp_path, "etc/sudoers", "root ALL=(ALL:ALL) ALL\n# %wheel ALL=(ALL) NOPASSWD: ALL\n")
    write(tmp_path, "etc/sudoers.d/ci", "ci ALL=(ALL) NOPASSWD: ALL\n")
    r = {x.check.id: x for x in run_checks(lnx(tmp_path))}["LNX-SUDO-001"]
    assert r.status == CheckStatus.FAILED and "1 passwordless" in r.outcome.detail


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_sudo_unreadable_is_skipped(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root can read everything")
    write(tmp_path, "etc/sudoers", "x", mode=0o000)
    r = {x.check.id: x for x in run_checks(lnx(tmp_path))}["LNX-SUDO-001"]
    assert r.status == CheckStatus.SKIPPED and "requires admin" in r.outcome.detail


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_suid_and_world_writable(tmp_path: Path) -> None:
    write(tmp_path, "usr/bin/passwd", "x", mode=0o4755)
    write(tmp_path, "usr/local/bin/backdoor", "x", mode=0o4755)
    write(tmp_path, "etc/insecure.conf", "x", mode=0o666)
    shared = tmp_path / "usr/share/dropbox"
    shared.mkdir(parents=True)
    shared.chmod(0o1777)  # sticky: allowed
    (tmp_path / "usr/bin/link").symlink_to("/etc/shadow")  # never followed
    write(tmp_path, "var/lib/dpkg/info/passwd.list", "/usr/bin/passwd\n")
    r = {x.check.id: x for x in run_checks(lnx(tmp_path))}
    suid, ww = r["LNX-PERM-001"], r["LNX-PERM-002"]
    assert suid.status == CheckStatus.FAILED
    assert "/usr/local/bin/backdoor" in suid.outcome.evidence[0].output
    assert "/usr/bin/passwd," not in suid.outcome.evidence[0].output.split("owned: ")[1]
    assert ww.status == CheckStatus.FAILED
    assert "/etc/insecure.conf" in ww.outcome.evidence[0].output
    assert "dropbox" not in ww.outcome.evidence[0].output
    assert stat.S_ISLNK((tmp_path / "usr/bin/link").lstat().st_mode)


def test_mac_status(tmp_path: Path) -> None:
    write(tmp_path, "sys/module/apparmor/parameters/enabled", "Y\n")
    assert {x.check.id: x for x in run_checks(lnx(tmp_path))}[
        "LNX-MAC-001"
    ].status == CheckStatus.PASSED
    other = tmp_path / "o"
    write(other, "sys/fs/selinux/enforce", "0")
    assert {x.check.id: x for x in run_checks(lnx(other))}[
        "LNX-MAC-001"
    ].status == CheckStatus.FAILED


# --- macOS ----------------------------------------------------------------------------------


def test_macos_checks(tmp_path: Path) -> None:
    outs = {
        "/usr/bin/fdesetup status": proc.ProcResult(("fdesetup",), 0, "FileVault is On.\n", ""),
        "/usr/sbin/spctl --status": proc.ProcResult(("spctl",), 0, "assessments disabled\n", ""),
        "/usr/bin/csrutil status": proc.ProcResult(
            ("csrutil",), 0, "System Integrity Protection status: enabled.\n", ""
        ),
    }
    ctx = AuditContext(family="macos", elevated=False, root=tmp_path, run=runner(outs))
    r = {x.check.id: x for x in run_checks(ctx)}
    assert r["MAC-FV-001"].status == CheckStatus.PASSED
    assert r["MAC-GK-001"].status == CheckStatus.FAILED
    assert r["MAC-SIP-001"].status == CheckStatus.PASSED
    assert r["MAC-FW-001"].status == CheckStatus.SKIPPED  # tool not found in this fake
    assert r["MAC-UPD-001"].status == CheckStatus.SKIPPED


def test_bitlocker_numeric_status_is_named() -> None:
    """Values as returned by Windows PowerShell 5.1 on a real (CI) Windows machine."""
    ps = recon_powershell(
        **{"Get-BitLockerVolume": {"MountPoint": "C:", "VolumeStatus": 0, "ProtectionStatus": 0}}
    )
    r = results_by_id(win_ctx(ps=ps, elevated=True))["WIN-ENC-001"]
    assert (
        r.status == CheckStatus.FAILED
        and r.outcome.detail == "C: is not protected (FullyDecrypted)"
    )
