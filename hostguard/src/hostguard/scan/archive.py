"""Read archive members in memory, never extracting anything to disk.

Because nothing is written, path traversal ("../../evil") cannot happen; such
member names are only reported as a heuristic signal. Limits stop
decompression bombs: per-member size, total decompressed bytes per archive
tree, compression ratio, member count and nesting depth (enforced by the caller).
"""

from __future__ import annotations

import bz2
import io
import lzma
import tarfile
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Protocol

CHUNK = 1024 * 1024


class _Readable(Protocol):
    def read(self, n: int = -1, /) -> bytes: ...


@dataclass(frozen=True)
class Limits:
    max_file_size: int
    max_depth: int
    max_total_decompressed: int
    max_ratio: int
    max_members: int = 10_000


class Budget:
    """Decompressed-byte budget shared by one archive and everything nested in it."""

    def __init__(self, limit: int) -> None:
        self.remaining = limit

    def take(self, n: int) -> bool:
        if n > self.remaining:
            return False
        self.remaining -= n
        return True


@dataclass
class Member:
    name: str
    data: bytes


@dataclass
class MemberSkip:
    name: str
    reason: str


def detect(data: bytes) -> str | None:
    """Archive type from magic bytes (extensions are not trusted)."""
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    if data[:3] == b"BZh":
        return "bzip2"
    if data[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    if data[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if data[:7] == b"Rar!\x1a\x07":
        return "rar"
    return None


SUPPORTED = {"zip", "gzip", "bzip2", "xz", "tar"}


def iter_members(
    data: bytes, kind: str, limits: Limits, budget: Budget, outer_name: str = ""
) -> Iterator[Member | MemberSkip]:
    if kind == "zip":
        yield from _zip(data, limits, budget)
    elif kind == "tar":
        yield from _tar(data, limits, budget)
    elif kind in ("gzip", "bzip2", "xz"):
        yield from _single(data, kind, limits, budget, outer_name)
    else:
        yield MemberSkip(
            "*",
            f"{kind} archives are not opened (only zip/tar/gz/bz2/xz); ClamAV, if installed, scans them",
        )


def _ratio_ok(uncompressed: int, compressed: int, limits: Limits) -> bool:
    return uncompressed <= max(compressed, 1) * limits.max_ratio


def _zip(data: bytes, limits: Limits, budget: Budget) -> Iterator[Member | MemberSkip]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        yield MemberSkip("*", f"unreadable zip: {exc}")
        return
    with zf:
        infos = zf.infolist()
        if len(infos) > limits.max_members:
            yield MemberSkip(
                "*", f"{len(infos)} members; only the first {limits.max_members} are scanned"
            )
        for info in infos[: limits.max_members]:
            if info.is_dir():
                continue
            name = info.filename
            if info.flag_bits & 0x1:
                yield MemberSkip(name, "encrypted member (password-protected archive)")
                continue
            if info.file_size > limits.max_file_size:
                yield MemberSkip(name, f"member larger than {limits.max_file_size // 2**20} MB")
                continue
            if not _ratio_ok(info.file_size, info.compress_size, limits):
                yield MemberSkip(
                    name,
                    f"compression ratio above {limits.max_ratio}:1 (possible decompression bomb)",
                )
                continue
            # Header sizes can lie; never read more than the declared size + 1 or the budget.
            cap = min(info.file_size, limits.max_file_size) + 1
            try:
                with zf.open(info) as fh:
                    buf = _read_capped(fh, cap)
            except (
                zipfile.BadZipFile,
                NotImplementedError,
                RuntimeError,
                OSError,
                zlib.error,
                EOFError,
            ) as exc:
                yield MemberSkip(name, f"cannot decompress: {exc}")
                continue
            if len(buf) > info.file_size:
                yield MemberSkip(
                    name, "member is larger than its header claims (malformed or malicious zip)"
                )
                continue
            if not budget.take(len(buf)):
                yield MemberSkip(name, "total decompressed size limit reached for this archive")
                return
            yield Member(name, buf)


def _tar(data: bytes, limits: Limits, budget: Budget) -> Iterator[Member | MemberSkip]:
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")  # noqa: SIM115 - closed by `with tf` below
    except (tarfile.TarError, OSError) as exc:
        yield MemberSkip("*", f"unreadable tar: {exc}")
        return
    with tf:
        count = 0
        try:
            for m in tf:
                count += 1
                if count > limits.max_members:
                    yield MemberSkip(
                        "*", f"more than {limits.max_members} members; rest not scanned"
                    )
                    return
                if not m.isreg():
                    continue  # symlinks, devices etc. are never followed
                if m.size > limits.max_file_size:
                    yield MemberSkip(
                        m.name, f"member larger than {limits.max_file_size // 2**20} MB"
                    )
                    continue
                fh = tf.extractfile(m)
                if fh is None:
                    continue
                buf = _read_capped(fh, m.size + 1)
                if not budget.take(len(buf)):
                    yield MemberSkip(
                        m.name, "total decompressed size limit reached for this archive"
                    )
                    return
                yield Member(m.name, buf)
        except (tarfile.TarError, OSError, EOFError) as exc:
            yield MemberSkip("*", f"tar read error: {exc}")


def _single(
    data: bytes, kind: str, limits: Limits, budget: Budget, outer: str
) -> Iterator[Member | MemberSkip]:
    """gzip / bzip2 / xz single streams, decompressed incrementally with a hard cap."""
    cap = min(limits.max_file_size, budget.remaining, len(data) * limits.max_ratio)
    try:
        if kind == "gzip":
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out = d.decompress(data, cap + 1)
        elif kind == "bzip2":
            out = bz2.BZ2Decompressor().decompress(data, max_length=cap + 1)
        else:
            out = lzma.LZMADecompressor().decompress(data, max_length=cap + 1)
    except (zlib.error, OSError, lzma.LZMAError, EOFError, ValueError) as exc:
        yield MemberSkip("*", f"cannot decompress {kind}: {exc}")
        return
    if len(out) > cap:
        yield MemberSkip(
            "*", f"decompressed {kind} exceeds the size/ratio limit (possible decompression bomb)"
        )
        return
    budget.take(len(out))
    inner = outer.rsplit("/", 1)[-1]
    for suffix in (".gz", ".tgz", ".bz2", ".xz", ".txz"):
        if inner.lower().endswith(suffix):
            inner = inner[: -len(suffix)] + (".tar" if suffix in (".tgz", ".txz") else "")
            break
    yield Member(inner or "(decompressed)", out)


def _read_capped(fh: _Readable, cap: int) -> bytes:
    parts: list[bytes] = []
    total = 0
    while total < cap:
        chunk = fh.read(min(CHUNK, cap - total))
        if not chunk:
            break
        parts.append(chunk)
        total += len(chunk)
    return b"".join(parts)


def traversal_name(name: str) -> bool:
    """Member names that would escape an extraction folder."""
    n = name.replace("\\", "/")
    return n.startswith("/") or n.startswith("../") or "/../" in n or (len(n) > 1 and n[1] == ":")
