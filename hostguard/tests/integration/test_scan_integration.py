"""End-to-end scan tests on real files in a temp folder.

EICAR is written to disk only inside a pytest temp folder and only when the OS
allows it; if real-time antivirus (e.g. Microsoft Defender) blocks or removes it,
the on-disk test is skipped and detection is covered by the in-memory tests.
"""

from __future__ import annotations

import io
import json
import os
import sys
import zipfile
from pathlib import Path

import pytest

from hostguard.cli import main
from hostguard.models import Confidence, Verdict
from hostguard.scan import archive, factory, selftest
from hostguard.scan.allowlist import DpkgVerifier
from hostguard.scan.engines.yara_engine import YaraEngine
from hostguard.scan.findings import item_to_finding
from hostguard.scan.hashdb import HashDB
from hostguard.scan.model import EngineHit
from hostguard.scan.scanner import Scanner, ScanSettings, combine
from hostguard.scan.targets import Exclusions

pytestmark = pytest.mark.integration

LIMITS = archive.Limits(10 * 2**20, 3, 64 * 2**20, 100)
MARKER = b"HOSTGUARD-TEST-ONLY-MARKER-7f3c9a1e"


def write_eicar(path: Path) -> bool:
    """Write EICAR; return False if antivirus prevented it (then the test is skipped)."""
    try:
        path.write_bytes(selftest.eicar_bytes())
        return path.read_bytes() == selftest.eicar_bytes()
    except OSError:
        return False


def make_scanner(tmp_path: Path, *, test_rules: bool = True, **kw: object) -> Scanner:
    settings = ScanSettings(LIMITS, workers=int(kw.pop("workers", 1)), **kw)  # type: ignore[arg-type]
    yara = YaraEngine(tmp_path / "rules", tmp_path / "cache", include_test_rules=test_rules)
    return Scanner(settings, hashdb=None, yara=yara, clamd=None)


def by_name(items: list, name: str):  # type: ignore[no-untyped-def]
    return next(i for i in items if i.path.endswith(name))


def test_eicar_on_disk_and_in_zip(tmp_path: Path) -> None:
    root = tmp_path / "target"
    root.mkdir()
    if not write_eicar(root / "eicar.com"):
        pytest.skip("antivirus blocked EICAR on disk; in-memory detection is tested separately")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("docs/readme.txt", "hello")
        zf.writestr("nested/eicar.com", selftest.eicar_bytes())
    (root / "bundle.zip").write_bytes(buf.getvalue())
    (root / "clean.txt").write_text("nothing to see", encoding="utf-8")

    res = make_scanner(tmp_path).scan_paths([root], Exclusions([], []))
    assert res.stats.files_scanned == 3 and res.stats.archive_members_scanned == 2
    paths = {i.path.replace(str(root), "") for i in res.flagged}
    sep = os.sep
    assert paths == {f"{sep}eicar.com", f"{sep}bundle.zip!nested/eicar.com"}
    member = by_name(res.flagged, "bundle.zip!nested/eicar.com")
    assert (
        member.in_archive
        and member.disk_path.endswith("bundle.zip")
        and member.verdict == Verdict.MALICIOUS
    )
    f = item_to_finding(member)
    assert f is not None and "TEST file" in f.title and f.confidence == Confidence.LIKELY
    assert all(u.startswith("https://") for u in f.references)


def test_eicar_in_memory_always() -> None:
    from hostguard.scan.engines.yara_engine import YaraEngine as Y

    sc = Scanner(
        ScanSettings(LIMITS),
        hashdb=None,
        yara=Y(Path("/nonexistent"), Path(os.devnull + "_c")),
        clamd=None,
    )
    results = {r.engine: r for r in selftest.run(sc)}
    assert results["yara"].passed and results["verdict"].passed and results["heuristics"].passed
    assert results["clamav"].passed is None  # not installed: reported as n/a, not as a pass


def test_clean_folder_has_no_false_positives(tmp_path: Path) -> None:
    """The project's own source and tests (plus Python's stdlib) must produce zero Malicious verdicts."""
    import sysconfig

    project = Path(__file__).resolve().parents[2]
    roots = [project / "src", project / "tests", Path(sysconfig.get_paths()["stdlib"]) / "json"]
    # As in a real scan: the test-only marker rule is off (it would match its own rule file).
    res = make_scanner(tmp_path, test_rules=False).scan_paths(
        roots, Exclusions([], ["__pycache__", "*.pyc"])
    )
    assert res.stats.files_scanned > 50
    malicious = [i.path for i in res.flagged if i.verdict == Verdict.MALICIOUS]
    assert malicious == []


def test_hash_hit_is_malicious_and_confirmed(tmp_path: Path) -> None:
    import hashlib

    f = tmp_path / "sample.bin"
    f.write_bytes(b"pretend malware sample bytes")
    sha = hashlib.sha256(f.read_bytes()).hexdigest()
    (tmp_path / "hashes").mkdir()
    (tmp_path / "hashes" / "MalwareBazaar-full.txt").write_text(sha + "\n", encoding="utf-8")
    from hostguard.scan import hashdb

    sc = Scanner(
        ScanSettings(LIMITS), hashdb=hashdb.load(tmp_path / "hashes"), yara=None, clamd=None
    )
    res = sc.scan_paths([f], Exclusions([], []))
    item = res.flagged[0]
    assert item.verdict == Verdict.MALICIOUS and item.hits[0].engine == "hash"
    assert item.hits[0].reference == f"https://bazaar.abuse.ch/sample/{sha}/"
    finding = item_to_finding(item)
    assert finding is not None and finding.confidence == Confidence.CONFIRMED


def test_test_marker_rule_and_limits(tmp_path: Path) -> None:
    root = tmp_path / "t"
    root.mkdir()
    (root / "marker.txt").write_bytes(b"harmless " + MARKER)
    (root / "big.bin").write_bytes(b"\0" * (LIMITS.max_file_size + 1))
    (root / "skip.iso").write_bytes(MARKER)
    res = make_scanner(tmp_path).scan_paths([root], Exclusions([], ["*.iso"]))
    assert by_name(res.flagged, "marker.txt").hits[0].name == "hostguard_test:HostGuard_Test_Marker"
    big = by_name(res.items, "big.bin")
    assert big.verdict == Verdict.SKIPPED and "larger than" in big.reason
    assert not any(i.path.endswith("skip.iso") for i in res.items)


@pytest.mark.skipif(sys.platform == "win32", reason="symlink creation needs privileges on Windows")
def test_symlinks_not_followed_and_own_dirs_excluded(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "marker.txt").write_bytes(MARKER)
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    (root / "filelink.txt").symlink_to(outside / "marker.txt")
    own = root / "quarantine"
    own.mkdir()
    (own / "q.bin").write_bytes(MARKER)
    res = make_scanner(tmp_path).scan_paths([root], Exclusions([own], []))
    assert res.flagged == [] and res.stats.files_scanned == 0
    res = make_scanner(tmp_path, follow_symlinks=True).scan_paths([root], Exclusions([own], []))
    assert len(res.flagged) == 2


@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0, reason="needs POSIX permissions as non-root"
)
def test_unreadable_file_is_skipped_not_fatal(tmp_path: Path) -> None:
    f = tmp_path / "secret.bin"
    f.write_bytes(b"x")
    f.chmod(0)
    try:
        res = make_scanner(tmp_path).scan_paths([tmp_path], Exclusions([], []))
        item = by_name(res.items, "secret.bin")
        assert item.verdict == Verdict.SKIPPED and "permission denied" in item.reason
    finally:
        f.chmod(0o600)


def test_unicode_and_long_names(tmp_path: Path) -> None:
    root = tmp_path / "ünïcödé 文件"
    root.mkdir()
    deep = root
    for i in range(8):
        deep = deep / (f"level-{i}-" + "x" * 20)
    deep.mkdir(parents=True)
    (deep / "résumé‮txt.exe").write_bytes(b"MZ")
    res = make_scanner(tmp_path).scan_paths([root], Exclusions([], []))
    flagged = res.flagged
    assert len(flagged) == 1 and "HEUR.BidiName" in {h.name for h in flagged[0].hits}
    assert "<U+202E>" in flagged[0].to_dict()["path"]


def test_allowlist_downgrades_only_heuristics(tmp_path: Path) -> None:
    import hashlib

    script = tmp_path / "updater.ps1"
    script.write_bytes(selftest.synthetic_cradle())
    marker_and_heur = tmp_path / "both.ps1"
    marker_and_heur.write_bytes(selftest.synthetic_cradle() + MARKER)
    info = tmp_path / "dpkg"
    info.mkdir()
    lines = [
        f"{hashlib.md5(p.read_bytes(), usedforsecurity=False).hexdigest()}  {str(p).lstrip('/')}"
        for p in (script, marker_and_heur)
    ]
    (info / "pkg.md5sums").write_text("\n".join(lines) + "\n", encoding="utf-8")
    sc = make_scanner(tmp_path)
    sc.dpkg = DpkgVerifier(info)
    res = sc.scan_paths([script, marker_and_heur], Exclusions([], []))
    # The heuristic-only hit is downgraded; the YARA match is never overridden.
    assert [i.path for i in res.flagged] == [str(marker_and_heur)]
    assert res.flagged[0].verdict == Verdict.MALICIOUS


def test_combine_rules() -> None:
    hi = EngineHit("yara", "r", "", "high")
    lo = EngineHit("yara", "r", "", "low")
    h40 = EngineHit("heuristics", "h", "", "low", score=40)
    assert combine([hi], 60) == Verdict.MALICIOUS
    assert combine([lo], 60) == Verdict.SUSPICIOUS
    assert combine([h40], 60) == Verdict.CLEAN
    assert combine([h40, h40], 60) == Verdict.SUSPICIOUS
    assert combine([EngineHit("virustotal", "x", "", "low")], 60) == Verdict.CLEAN


def test_process_pool_scanning(tmp_path: Path) -> None:
    root = tmp_path / "t"
    root.mkdir()
    for i in range(6):
        (root / f"f{i}.txt").write_bytes(b"clean " * i)
    (root / "marker.txt").write_bytes(MARKER)
    spec = factory.EngineSpec(
        tmp_path / "rules",
        tmp_path / "cache",
        tmp_path / "hashes",
        clamd="off",
        include_test_rules=True,
    )
    settings = ScanSettings(LIMITS, workers=2, engines=("yara", "heuristics"))
    sc = factory.build(spec, settings)
    res = sc.scan_paths([root], Exclusions([], []), process_spec=spec)
    assert res.stats.files_scanned == 7 and [i.path for i in res.flagged] == [
        str(root / "marker.txt")
    ]
    assert res.notes == []


def test_hashdb_selftest_logic() -> None:
    db = HashDB(bytes.fromhex(selftest.EICAR_SHA256), [])
    assert selftest.EICAR_SHA256 in db


# --- CLI ---------------------------------------------------------------------------------------


def test_cli_selftest_and_custom_scan(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--no-color", "scan", "--selftest", "--workers", "1"]) == 0
    assert "PASS" in capsys.readouterr().out
    root = tmp_path / "scanme"
    root.mkdir()
    (root / "ok.txt").write_text("fine", encoding="utf-8")
    assert main(["--no-color", "-q", "scan", str(root), "--workers", "1"]) == 0
    (root / "marker.txt").write_bytes(MARKER)
    out_json = tmp_path / "scan.json"
    rc = main(
        [
            "--no-color",
            "-q",
            "scan",
            str(root),
            "--workers",
            "1",
            "--include-test-rules",
            "--json",
            str(out_json),
        ]
    )
    assert rc == 1
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert (
        data["command"] == "scan" and data["mode"] == "custom" and data["summary"]["malicious"] == 1
    )
    f = data["findings"][0]
    assert f["evidence"] and f["remediation"] and f["retest"] and f["references"]


def test_cli_scan_errors(tmp_path: Path) -> None:
    assert main(["-q", "scan", str(tmp_path / "missing")]) == 2
    assert main(["-q", "scan", str(tmp_path), "--engines", "yara,bogus"]) == 2
