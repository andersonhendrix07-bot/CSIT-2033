"""Known-bad SHA-256 database: compact, sorted, binary-searched.

Source lists live in `<data>/hashes/*.txt|*.csv` (one SHA-256 per line, or a CSV
such as a MalwareBazaar export; the first 64-hex-digit field of each row is
used). They are compiled into a sorted array of 32-byte digests (`.idx`),
rebuilt whenever a source file changes. A million hashes take ~32 MB.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from dataclasses import dataclass
from pathlib import Path

from hostguard.logsetup import get_logger

log = get_logger("scan.hashdb")

_HEX64 = re.compile(rb"\b[0-9a-fA-F]{64}\b")
REC = 32


@dataclass
class HashHit:
    sha256: str
    source: str  # list file name
    label: str  # e.g. malware family / signature from the list, if any


class HashDB:
    def __init__(self, blob: bytes, sources: list[Path]) -> None:
        self._blob = blob
        self.sources = sources
        self.count = len(blob) // REC

    def __contains__(self, sha256_hex: str) -> bool:
        try:
            key = bytes.fromhex(sha256_hex)
        except ValueError:
            return False
        lo, hi = 0, self.count
        blob = self._blob
        while lo < hi:
            mid = (lo + hi) // 2
            rec = blob[mid * REC : mid * REC + REC]
            if rec < key:
                lo = mid + 1
            elif rec > key:
                hi = mid
            else:
                return True
        return False

    def lookup(self, sha256_hex: str) -> HashHit | None:
        if sha256_hex not in self:
            return None
        needle = sha256_hex.lower().encode()
        for src in self.sources:
            try:
                for line in src.read_bytes().splitlines():
                    if needle in line.lower():
                        return HashHit(sha256_hex, src.name, _label(src, line))
            except OSError:
                continue
        return HashHit(sha256_hex, "index", "")


def _label(src: Path, line: bytes) -> str:
    """Best-effort family/signature name from a CSV row (column named 'signature')."""
    if src.suffix.lower() != ".csv":
        return ""
    header = _csv_header(src)
    try:
        row = next(csv.reader(io.StringIO(line.decode("utf-8", "replace")), skipinitialspace=True))
    except (StopIteration, csv.Error):
        return ""
    for name in ("signature", "malware", "family"):
        if name in header and header.index(name) < len(row):
            val = row[header.index(name)].strip()
            if val and val.lower() not in ("n/a", "null"):
                return val
    return ""


def _csv_header(src: Path) -> list[str]:
    try:
        with src.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("#") and "sha256" in line.lower():
                    text = line.lstrip("#").strip()
                    return [c.strip().strip('"').lower() for c in next(csv.reader([text]))]
                if not line.startswith("#"):
                    break
    except (OSError, csv.Error, StopIteration):
        pass
    return []


def _sources(hashes_dir: Path) -> list[Path]:
    if not hashes_dir.is_dir():
        return []
    return sorted(
        p for p in hashes_dir.iterdir() if p.suffix.lower() in (".txt", ".csv") and p.is_file()
    )


def load(hashes_dir: Path) -> HashDB:
    """Load (rebuilding the index if any source changed)."""
    sources = _sources(hashes_dir)
    idx, meta_path = hashes_dir / "known-bad.idx", hashes_dir / "known-bad.idx.json"
    stamp = [[p.name, p.stat().st_size, p.stat().st_mtime_ns] for p in sources]
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("sources") == stamp:
            blob = idx.read_bytes()
            if hashlib.sha256(blob).hexdigest() == meta.get("sha256") and len(blob) % REC == 0:
                return HashDB(blob, sources)
    except (OSError, ValueError):
        pass
    digests: set[bytes] = set()
    for src in sources:
        try:
            with src.open("rb") as fh:
                for line in fh:
                    if line.startswith(b"#"):
                        continue
                    m = _HEX64.search(line)
                    if m:
                        digests.add(bytes.fromhex(m.group(0).decode()))
        except OSError as exc:
            log.warning("cannot read hash list %s: %s", src, exc)
    blob = b"".join(sorted(digests))
    if sources:
        try:
            idx.write_bytes(blob)
            meta_path.write_text(
                json.dumps(
                    {
                        "sources": stamp,
                        "sha256": hashlib.sha256(blob).hexdigest(),
                        "count": len(digests),
                    }
                ),
                encoding="utf-8",
            )
        except OSError as exc:
            log.warning("cannot write hash index: %s", exc)
    return HashDB(blob, sources)
