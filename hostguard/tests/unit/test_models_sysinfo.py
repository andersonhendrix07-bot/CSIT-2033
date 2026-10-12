from __future__ import annotations

import sys

import pytest

from hostguard import sysinfo
from hostguard.models import Confidence, Evidence, ExitCode, Finding, Severity


def _finding(evidence: list[Evidence]) -> Finding:
    return Finding(
        id="HG-TEST-1",
        title="t",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        component="c",
        evidence=evidence,
        remediation="r",
        references=["https://example.invalid"],
        retest="x",
    )


def test_finding_requires_evidence() -> None:
    with pytest.raises(ValueError, match="no evidence"):
        _finding([])


def test_finding_to_dict() -> None:
    d = _finding([Evidence("cmd", "out")]).to_dict()
    assert d["severity"] == "high"
    assert d["confidence"] == "Confirmed"
    assert d["evidence"][0]["source"] == "cmd"


def test_exit_codes() -> None:
    assert (ExitCode.CLEAN, ExitCode.FINDINGS, ExitCode.ERROR) == (0, 1, 2)


def test_severity_rank_order() -> None:
    assert Severity.CRITICAL.rank < Severity.HIGH.rank < Severity.INFO.rank


def test_collect_runs_on_this_host() -> None:
    h = sysinfo.collect()
    assert h.os_family in {"windows", "linux", "macos", sys.platform}
    assert h.python
    assert isinstance(h.elevated, bool)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only check")
def test_elevation_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    assert sysinfo.is_elevated() is False
    monkeypatch.setattr("os.geteuid", lambda: 0)
    assert sysinfo.is_elevated() is True


def test_windows_11_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sysinfo, "os_family", lambda: "windows")
    monkeypatch.setattr(sysinfo, "is_elevated", lambda: False)
    monkeypatch.setattr(sysinfo.platform, "win32_ver", lambda: ("10", "10.0.26100", "", ""))
    monkeypatch.setattr(sysinfo.platform, "win32_edition", lambda: "Professional")
    h = sysinfo.collect()
    assert h.os_name == "Windows 11 Professional"
    assert h.os_build == "26100"
