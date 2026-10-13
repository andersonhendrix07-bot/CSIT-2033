"""Scan results: one ScanItem per file (or archive member), with explainable engine hits."""

from __future__ import annotations

import unicodedata
from dataclasses import asdict, dataclass, field
from typing import Any

from hostguard.models import Verdict


class Confidence:
    HIGH = "high"
    LOW = "low"


@dataclass
class EngineHit:
    engine: str  # "hash" | "yara" | "clamav" | "heuristics" | "virustotal" | "allowlist"
    name: str  # signature / rule / heuristic id
    detail: str
    confidence: str = Confidence.HIGH  # high -> Malicious, low -> Suspicious
    score: int = 0  # heuristics only
    # Attribution required by rule licences (e.g. Detection Rule License 1.1).
    author: str = ""
    reference: str = ""
    license: str = ""
    source: str = ""  # rule set / feed name


@dataclass
class ScanItem:
    path: str  # display path; archive members are "archive.zip!inner/file"
    size: int = 0
    sha256: str = ""
    verdict: Verdict = Verdict.CLEAN
    hits: list[EngineHit] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    reason: str = ""  # for SKIPPED / ERROR
    in_archive: bool = False
    disk_path: str = ""  # real file on disk (outermost container for archive members)
    is_pe: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        d["path"] = safe_display(self.path)
        return d


@dataclass
class ScanStats:
    files_seen: int = 0
    files_scanned: int = 0
    archive_members_scanned: int = 0
    bytes_scanned: int = 0
    skipped: int = 0
    errors: int = 0
    excluded_dirs: int = 0
    seconds: float = 0.0


# Characters that can make a hostile file name lie on screen: bidi overrides/isolates
# (e.g. U+202E turns "invoice_cod.exe" into "invoice_exe.doc"), zero-width characters
# and control characters. They are shown as <U+XXXX> instead of being rendered.
_BIDI = {chr(c) for c in (0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A))}
_ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿"}


def suspicious_chars(text: str) -> list[str]:
    return sorted({f"U+{ord(ch):04X}" for ch in text if ch in _BIDI or ch in _ZERO_WIDTH})


def safe_display(text: str) -> str:
    out = []
    for ch in text:
        if ch in _BIDI or ch in _ZERO_WIDTH or unicodedata.category(ch) in ("Cc", "Cf"):
            if ch in ("\t",):
                out.append(" ")
            else:
                out.append(f"<U+{ord(ch):04X}>")
        else:
            out.append(ch)
    return "".join(out)
