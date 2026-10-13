from __future__ import annotations

from pathlib import Path

import pytest

from fakes import FakePowerShell, FakeRegistry
from hostguard.inventory import Collectors, collect, windows
from hostguard.inventory.models import Skip
from hostguard.winsys import HKCU, HKLM, PowerShellError

U = windows.UNINSTALL


def target_pc_registry() -> FakeRegistry:
    """Values modelled on the user's PC: Windows 11 Home 25H2, build 26200."""
    reg = FakeRegistry()
    reg.set(
        HKLM,
        windows.CURRENT_VERSION,
        {
            "ProductName": "Windows 10 Home",  # sic: Windows 11 still reports this
            "DisplayVersion": "25H2",
            "CurrentBuildNumber": "26200",
            "UBR": 6899,
            "EditionID": "Core",
        },
    )
    reg.set(
        HKLM,
        f"{U}\\7-zip",
        {"DisplayName": "7-Zip 23.01 (x64)", "DisplayVersion": "23.01", "Publisher": "Igor Pavlov"},
    )
    reg.set(HKLM, f"{U}\\hidden", {"DisplayName": "Hidden component", "SystemComponent": 1})
    reg.set(HKLM, f"{U}\\kb", {"DisplayName": "Update for X", "ReleaseType": "Security Update"})
    reg.set(HKLM, f"{U}\\child", {"DisplayName": "Child", "ParentKeyName": "Parent"})
    reg.set(HKLM, f"{U}\\noname", {"DisplayVersion": "1.0"})
    reg.set(
        HKLM,
        f"{U}\\vlc",
        {"DisplayName": "VLC media player", "DisplayVersion": "3.0.20", "Publisher": "VideoLAN"},
        view32=True,
    )
    reg.set(
        HKCU,
        f"{U}\\zoom",
        {"DisplayName": "Zoom Workplace", "DisplayVersion": "6.2.0", "Publisher": "Zoom"},
    )
    # Same product listed twice (64-bit view and HKCU) -> deduplicated.
    reg.set(HKCU, f"{U}\\7zip-dup", {"DisplayName": "7-Zip 23.01 (x64)", "DisplayVersion": "23.01"})
    return reg


def target_pc_powershell(**overrides: object) -> FakePowerShell:
    responses: dict[str, object] = {
        "Get-HotFix": [
            {
                "HotFixID": "KB5066835",
                "Description": "Security Update",
                "InstalledOn": "2026-10-01",
            },
            {"HotFixID": "KB5054156", "Description": "Update", "InstalledOn": None},
        ],
        # A single object (not a list) is what ConvertTo-Json emits for one item.
        "Get-AppxPackage": {
            "Name": "Microsoft.WindowsCalculator",
            "Version": "11.2502.2.0",
            "Publisher": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
            "InstallLocation": "C:\\Program Files\\WindowsApps\\calc",
        },
        "Get-ScheduledTask": [
            {
                "TaskPath": "\\",
                "TaskName": "Updater",
                "Author": "ACME",
                "Actions": ["C:\\Users\\me\\AppData\\Local\\acme\\up.exe --silent"],
            },
        ],
    }
    responses.update(overrides)
    return FakePowerShell(responses)


def test_os_info_target_pc() -> None:
    skipped: list[Skip] = []
    info = windows.collect_os(target_pc_registry(), target_pc_powershell(), skipped, "AMD64")
    assert info.name == "Windows 11 Home"
    assert info.display_version == "25H2"
    assert info.full_build == "26200.6899"
    assert info.version == "10.0.26200.6899"
    assert [h.id for h in info.hotfixes] == ["KB5066835", "KB5054156"]
    assert info.hotfixes[1].installed_on == ""
    assert "CurrentBuildNumber" in info.evidence[0].output
    assert skipped == []


def test_os_info_hotfix_failure_is_skip_not_crash() -> None:
    skipped: list[Skip] = []
    ps = target_pc_powershell(**{"Get-HotFix": PowerShellError("Access is denied")})
    info = windows.collect_os(target_pc_registry(), ps, skipped, "AMD64")
    assert info.hotfixes == []
    assert skipped[0].what.startswith("Installed Windows updates")
    assert "Access is denied" in skipped[0].reason


def test_software_filters_and_dedupes() -> None:
    skipped: list[Skip] = []
    sw = windows.collect_software(target_pc_registry(), target_pc_powershell(), skipped)
    names = [(s.name, s.version, s.source) for s in sw]
    assert ("7-Zip 23.01 (x64)", "23.01", "registry:HKLM") in names
    assert ("VLC media player", "3.0.20", "registry:HKLM-WOW6432Node") in names
    assert ("Zoom Workplace", "6.2.0", "registry:HKCU") in names
    assert ("Microsoft.WindowsCalculator", "11.2502.2.0", "appx") in names
    flat = " ".join(n for n, _, _ in names)
    for hidden in ("Hidden component", "Update for X", "Child"):
        assert hidden not in flat
    assert sum(1 for n, _, _ in names if n.startswith("7-Zip")) == 1
    calc = next(s for s in sw if s.source == "appx")
    assert calc.publisher == "Microsoft Corporation"


def test_software_appx_failure_recorded() -> None:
    skipped: list[Skip] = []
    ps = target_pc_powershell(**{"Get-AppxPackage": PowerShellError("not supported")})
    windows.collect_software(target_pc_registry(), ps, skipped)
    assert any("Get-AppxPackage" in s.what for s in skipped)


def test_persistence(tmp_path: Path) -> None:
    reg = target_pc_registry()
    reg.set(
        HKCU,
        windows.RUN_KEYS[0],
        {"OneDrive": '"C:\\Users\\me\\AppData\\Local\\OneDrive\\OneDrive.exe" /background'},
    )
    reg.set(
        HKLM,
        windows.RUN_KEYS[0],
        {"SecurityHealth": "%windir%\\system32\\SecurityHealthSystray.exe"},
    )
    reg.set(
        HKLM,
        f"{windows.SERVICES}\\goodsvc",
        {
            "Type": 16,
            "Start": 2,
            "ImagePath": "C:\\Program Files\\Good\\svc.exe",
            "DisplayName": "Good",
        },
    )
    reg.set(HKLM, f"{windows.SERVICES}\\manualsvc", {"Type": 16, "Start": 3, "ImagePath": "x.exe"})
    reg.set(HKLM, f"{windows.SERVICES}\\driver", {"Type": 1, "Start": 2, "ImagePath": "drv.sys"})
    startup = tmp_path / "AppData" / "Microsoft/Windows/Start Menu/Programs/Startup"
    startup.mkdir(parents=True)
    (startup / "evil.lnk").write_bytes(b"x")
    (startup / "desktop.ini").write_bytes(b"x")
    skipped: list[Skip] = []
    env = {"APPDATA": str(tmp_path / "AppData")}
    entries = windows.collect_persistence(reg, target_pc_powershell(), skipped, env)
    kinds = {(e.kind, e.name) for e in entries}
    assert ("run-key", "OneDrive") in kinds
    assert ("run-key", "SecurityHealth") in kinds
    assert ("startup-folder", "evil.lnk") in kinds
    assert ("startup-folder", "desktop.ini") not in kinds
    assert ("service", "goodsvc") in kinds
    assert ("service", "manualsvc") not in kinds and ("service", "driver") not in kinds
    task = next(e for e in entries if e.kind == "scheduled-task")
    assert "up.exe --silent" in task.command and task.notes == "author: ACME"


def test_registry_access_denied_is_skipped(tmp_path: Path) -> None:
    reg = target_pc_registry()
    reg.denied.add((HKLM, windows.SERVICES))
    skipped: list[Skip] = []
    windows.collect_persistence(reg, target_pc_powershell(), skipped, {})
    assert any(s.what == "Services" and "denied" in s.reason for s in skipped)


def test_collect_end_to_end_windows(monkeypatch: object) -> None:
    inv = collect(
        family="windows",
        backends=Collectors(registry=target_pc_registry(), powershell=target_pc_powershell()),
        listeners=False,
    )
    assert inv.os.name == "Windows 11 Home"
    assert inv.software and inv.persistence is not None
    d = inv.to_dict()
    assert d["os"]["full_build"] == "26200.6899"


def test_powershell_error_summary_finds_parser_message() -> None:
    from hostguard.winsys import _error_summary

    parser = (
        "At line:1 char:434\r\n+ ... SignatureType} } | ConvertTo-Json -Compress\r\n"
        "+                    ~\r\nAn empty pipe element is not allowed.\r\n"
        "    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException\r\n"
    )
    assert _error_summary(parser) == "An empty pipe element is not allowed. (At line:1 char:434)"
    runtime = "Get-Thing : Access is denied.\r\nAt line:1 char:5\r\n+ Get-Thing\r\n"
    assert _error_summary(runtime) == "Get-Thing : Access is denied."
    assert _error_summary("  \n") == ""


def test_powershell_env_drops_inherited_module_path(monkeypatch: pytest.MonkeyPatch) -> None:
    from hostguard.winsys import powershell_env

    monkeypatch.setenv("PSModulePath", r"C:\Program Files\PowerShell\7\Modules")
    monkeypatch.setenv("SYSTEMROOT", r"C:\Windows")
    env = powershell_env()
    assert not any(k.upper() == "PSMODULEPATH" for k in env)
    assert env["SYSTEMROOT"] == r"C:\Windows"


def test_signature_error_reason_is_kept() -> None:
    from hostguard.scan.allowlist import PS_SIGNATURES, windows_signatures

    ps = FakePowerShell(
        {
            PS_SIGNATURES: {
                "Path": r"C:\a.exe",
                "Status": "Error",
                "Error": "module could not be loaded",
            }
        }
    )
    out = windows_signatures([r"C:\a.exe"], ps, ["Microsoft Corporation"])
    assert not out[r"C:\a.exe"].trusted
    assert "module could not be loaded" in out[r"C:\a.exe"].detail
