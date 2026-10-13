"""Scan orchestration: walk -> read (capped) -> hash -> engines -> archives -> verdict.

Files are only ever *read*. Nothing is executed or opened with its associated app.
Clean files are counted but not kept, so a full scan does not hold millions of
results in memory.
"""

from __future__ import annotations

import contextlib
import errno
import functools
import hashlib
import multiprocessing
import os
import tempfile
import threading
import time
from collections.abc import Callable, Iterable
from concurrent.futures import (
    BrokenExecutor,
    Executor,
    Future,
    ProcessPoolExecutor,
    ThreadPoolExecutor,
)
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from hostguard.credentials import Secret
from hostguard.logsetup import get_logger
from hostguard.models import Verdict
from hostguard.net import HttpClient
from hostguard.scan import archive
from hostguard.scan.allowlist import DpkgVerifier, windows_signatures
from hostguard.scan.engines import heuristics, virustotal
from hostguard.scan.engines.clamav import Clamd, clamscan_batch
from hostguard.scan.engines.yara_engine import YaraEngine
from hostguard.scan.hashdb import HashDB
from hostguard.scan.model import Confidence, EngineHit, ScanItem, ScanStats
from hostguard.scan.targets import Exclusions, WalkFile, long_path, walk
from hostguard.winsys import PowerShell

if TYPE_CHECKING:
    from hostguard.scan.factory import EngineSpec

log = get_logger("scan")

IN_MEMORY_LIMIT = 32 * 2**20
ALL_ENGINES = ("hash", "yara", "clamav", "heuristics")

Progress = Callable[[int, int, str], None]  # files done, bytes done, current path


@dataclass
class ScanSettings:
    limits: archive.Limits
    workers: int = 4
    follow_symlinks: bool = False
    archives: bool = True
    threshold: int = heuristics.DEFAULT_THRESHOLD
    engines: tuple[str, ...] = ALL_ENGINES
    trusted_publishers: tuple[str, ...] = ()
    virustotal_key: Secret | None = None
    virustotal_max: int = 20


@dataclass
class EngineStatus:
    name: str
    available: bool
    detail: str


@dataclass
class ScanResult:
    items: list[ScanItem] = field(default_factory=list)  # flagged, skipped and error items only
    stats: ScanStats = field(default_factory=ScanStats)
    engines: list[EngineStatus] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def flagged(self) -> list[ScanItem]:
        return [i for i in self.items if i.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)]


def combine(hits: list[EngineHit], threshold: int) -> Verdict:
    if any(
        h.confidence == Confidence.HIGH and h.engine in ("hash", "yara", "clamav") for h in hits
    ):
        return Verdict.MALICIOUS
    if any(h.engine == "yara" for h in hits):
        return Verdict.SUSPICIOUS
    if sum(h.score for h in hits if h.engine == "heuristics") >= threshold:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN


def filetype_of(data: bytes) -> str:
    """Coarse type for YARA externals (as used by signature-base / LOKI)."""
    if data[:2] == b"MZ":
        return "EXE"
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:4] == b"PK\x03\x04":
        return "ZIP"
    if data[:4] == b"MDMP":
        return "MDMP"
    return ""


class Scanner:
    def __init__(
        self,
        settings: ScanSettings,
        *,
        hashdb: HashDB | None,
        yara: YaraEngine | None,
        clamd: Clamd | None,
        clamscan_exe: str | None = None,
        powershell: PowerShell | None = None,
        dpkg: DpkgVerifier | None = None,
        http: HttpClient | None = None,
    ) -> None:
        self.s = settings
        self.hashdb = hashdb if "hash" in settings.engines else None
        self.yara = yara if "yara" in settings.engines else None
        self.clamd = clamd if "clamav" in settings.engines else None
        self.clamscan_exe = (
            clamscan_exe if ("clamav" in settings.engines and clamd is None) else None
        )
        self.powershell = powershell
        self.dpkg = dpkg
        self.http = http
        self._lock = threading.Lock()

    # -- engine status -------------------------------------------------------------------

    def engine_status(self) -> list[EngineStatus]:
        out = []
        if "hash" in self.s.engines:
            n = self.hashdb.count if self.hashdb else 0
            out.append(
                EngineStatus(
                    "hash",
                    n > 0,
                    f"{n:,} known-bad SHA-256 hashes"
                    if n
                    else "no hash lists installed (see README: hash lists)",
                )
            )
        if "yara" in self.s.engines and self.yara:
            r = self.yara.report
            sets = ", ".join(s.name for s in self.yara.sets)
            detail = f"{r.rule_count:,} rules from {sets}" + (
                f"; {len(r.files_failed)} rule file(s) failed to compile" if r.files_failed else ""
            )
            out.append(EngineStatus("yara", True, detail))
        if "clamav" in self.s.engines:
            if self.clamd:
                out.append(
                    EngineStatus(
                        "clamav", True, f"clamd at {self.clamd.addr} ({self.clamd.version})"
                    )
                )
            elif self.clamscan_exe:
                out.append(
                    EngineStatus(
                        "clamav",
                        True,
                        f"clamscan fallback ({self.clamscan_exe}); slower, archives inside files handled by ClamAV",
                    )
                )
            else:
                out.append(
                    EngineStatus(
                        "clamav",
                        False,
                        "ClamAV not installed or clamd not running (optional; see README)",
                    )
                )
        if "heuristics" in self.s.engines:
            out.append(
                EngineStatus("heuristics", True, f"suspicious at score >= {self.s.threshold}")
            )
        if self.s.virustotal_key:
            out.append(
                EngineStatus(
                    "virustotal",
                    True,
                    f"hash lookups for flagged files (max {self.s.virustotal_max} per run)",
                )
            )
        return out

    # -- public entry points -----------------------------------------------------------

    def scan_bytes(self, name: str, data: bytes) -> list[ScanItem]:
        """Scan an in-memory buffer (used by the EICAR self-test and tests). Nothing touches disk."""
        budget = archive.Budget(self.s.limits.max_total_decompressed)
        return self._scan_data(name, data, "", 0, budget, in_archive=False)

    def scan_paths(
        self,
        roots: Iterable[Path],
        exclusions: Exclusions,
        progress: Progress | None = None,
        *,
        process_spec: EngineSpec | None = None,
    ) -> ScanResult:
        """Scan files under `roots`. With `process_spec` (a factory.EngineSpec) and more
        than one worker, files are scanned in worker processes."""
        result = ScanResult(targets=[str(r) for r in roots], engines=self.engine_status())
        stats = result.stats
        start = time.monotonic()
        list_fd, list_path = (None, None)
        list_fh = None
        if self.clamscan_exe:
            list_fd, list_path = tempfile.mkstemp(prefix="hostguard-scanlist-", suffix=".txt")
            list_fh = os.fdopen(list_fd, "w", encoding="utf-8")

        sem = threading.BoundedSemaphore(max(1, self.s.workers) * 4)
        bytes_done = 0
        broken = threading.Event()
        retry: list[tuple[Path, int]] = []

        def record(items: list[ScanItem], path: Path, size: int) -> None:
            nonlocal bytes_done
            with self._lock:
                stats.files_scanned += 1
                bytes_done += size
                for it in items:
                    if it.in_archive:
                        stats.archive_members_scanned += 1
                    if it.verdict == Verdict.SKIPPED:
                        stats.skipped += 1
                    elif it.verdict == Verdict.ERROR:
                        stats.errors += 1
                    if it.verdict != Verdict.CLEAN:
                        result.items.append(it)
                if progress:
                    progress(stats.files_scanned, bytes_done, str(path))

        def done(fut: Future[list[ScanItem]], path: Path, size: int) -> None:
            sem.release()
            try:
                items = fut.result()
            except BrokenExecutor:
                # Worker processes died (or could not start): rescan these files in-process.
                with self._lock:
                    retry.append((path, size))
                broken.set()
                return
            except Exception as exc:  # a bug must not abort the whole scan
                log.exception("scan of %s failed", path)
                items = [
                    ScanItem(
                        str(path),
                        size,
                        verdict=Verdict.ERROR,
                        reason=f"internal error: {type(exc).__name__}: {exc}",
                        disk_path=str(path),
                    )
                ]
            record(items, path, size)

        pool: Executor
        if process_spec is not None and self.s.workers > 1:
            from hostguard.scan import factory

            pool = ProcessPoolExecutor(
                max_workers=self.s.workers,
                mp_context=multiprocessing.get_context("spawn"),
                initializer=functools.partial(factory.init_worker, process_spec, self.s),
            )

            def submit(path: Path, size: int) -> Future[list[ScanItem]]:
                return pool.submit(factory.worker_scan, path, size)
        else:
            pool = ThreadPoolExecutor(
                max_workers=max(1, self.s.workers), thread_name_prefix="hg-scan"
            )

            def submit(path: Path, size: int) -> Future[list[ScanItem]]:
                return pool.submit(self.scan_file, path, size)

        try:
            with pool:
                for entry in walk(
                    [Path(r) for r in result.targets],
                    exclusions,
                    follow_symlinks=self.s.follow_symlinks,
                ):
                    if not isinstance(entry, WalkFile):
                        with self._lock:
                            stats.skipped += 1
                            result.items.append(
                                ScanItem(
                                    str(entry.path),
                                    verdict=Verdict.SKIPPED,
                                    reason=entry.reason,
                                    disk_path=str(entry.path),
                                )
                            )
                        continue
                    stats.files_seen += 1
                    if list_fh is not None and entry.size <= self.s.limits.max_file_size:
                        list_fh.write(str(entry.path) + "\n")
                    if broken.is_set():
                        record(self.scan_file(entry.path, entry.size), entry.path, entry.size)
                        continue
                    sem.acquire()
                    try:
                        fut = submit(entry.path, entry.size)
                    except BrokenExecutor:
                        sem.release()
                        broken.set()
                        record(self.scan_file(entry.path, entry.size), entry.path, entry.size)
                        continue
                    fut.add_done_callback(_bind(done, entry.path, entry.size))
        finally:
            if list_fh is not None:
                list_fh.close()
        if retry:
            log.warning(
                "worker processes failed; scanned %d file(s) in the main process", len(retry)
            )
            result.notes.append(
                "worker processes failed to run; files were scanned in a single process instead (slower)"
            )
            for path, size in retry:
                record(self.scan_file(path, size), path, size)

        stats.bytes_scanned = bytes_done
        if self.clamscan_exe and list_path:
            self._clamscan_post(list_path, result)
        self._allowlist_post(result)
        self._virustotal_post(result)
        stats.seconds = round(time.monotonic() - start, 1)
        result.items.sort(key=lambda i: (_verdict_rank(i.verdict), i.path))
        return result

    # -- per file --------------------------------------------------------------------------

    def scan_file(self, path: Path, size: int) -> list[ScanItem]:
        disp = str(path)
        if size > self.s.limits.max_file_size:
            return [
                ScanItem(
                    disp,
                    size,
                    verdict=Verdict.SKIPPED,
                    reason=f"larger than {self.s.limits.max_file_size // 2**20} MB (scan.max_file_size_mb)",
                    disk_path=disp,
                )
            ]
        try:
            if size <= IN_MEMORY_LIMIT:
                with open(long_path(path), "rb") as fh:
                    data = fh.read(self.s.limits.max_file_size + 1)
                budget = archive.Budget(self.s.limits.max_total_decompressed)
                return self._scan_data(disp, data, disp, 0, budget, in_archive=False)
            return [self._scan_large(path)]
        except PermissionError:
            return [
                ScanItem(
                    disp,
                    size,
                    verdict=Verdict.SKIPPED,
                    reason="Skipped: permission denied",
                    disk_path=disp,
                )
            ]
        except OSError as exc:
            if getattr(exc, "winerror", None) in (32, 33) or exc.errno in (
                errno.EBUSY,
                errno.ETXTBSY,
            ):
                return [
                    ScanItem(
                        disp,
                        size,
                        verdict=Verdict.SKIPPED,
                        reason="file is locked by another program",
                        disk_path=disp,
                    )
                ]
            return [
                ScanItem(
                    disp,
                    size,
                    verdict=Verdict.ERROR,
                    reason=f"read error: {exc.strerror or exc}",
                    disk_path=disp,
                )
            ]

    def _scan_large(self, path: Path) -> ScanItem:
        """Files above the in-memory limit: streamed hash, YARA/ClamAV on the file, no heuristics."""
        disp = str(path)
        h = hashlib.sha256()
        size = 0
        with open(long_path(path), "rb") as fh:
            while chunk := fh.read(2**20):
                h.update(chunk)
                size += len(chunk)
        item = ScanItem(disp, size, sha256=h.hexdigest(), disk_path=disp)
        item.notes.append(
            f"larger than {IN_MEMORY_LIMIT // 2**20} MB: heuristics and archive contents skipped"
        )
        self._hash_check(item)
        if self.yara:
            hits, note = self.yara.scan_file(long_path(path), disp)
            item.hits += hits
            if note:
                item.notes.append(note)
        if self.clamd:
            hits, note = self.clamd.scan_file(long_path(path))
            item.hits += hits
            if note:
                item.notes.append(note)
        item.verdict = combine(item.hits, self.s.threshold)
        return item

    def _hash_check(self, item: ScanItem) -> None:
        if self.hashdb and self.hashdb.count:
            hit = self.hashdb.lookup(item.sha256)
            if hit:
                ref = (
                    f"https://bazaar.abuse.ch/sample/{item.sha256}/"
                    if "bazaar" in hit.source.lower()
                    else ""
                )
                item.hits.append(
                    EngineHit(
                        "hash",
                        hit.label or "known-malware-hash",
                        f"SHA-256 listed in {hit.source}",
                        Confidence.HIGH,
                        reference=ref,
                        source=hit.source,
                    )
                )

    def _scan_data(
        self,
        name: str,
        data: bytes,
        disk_path: str,
        depth: int,
        budget: archive.Budget,
        *,
        in_archive: bool,
    ) -> list[ScanItem]:
        item = ScanItem(
            name,
            len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            in_archive=in_archive,
            disk_path=disk_path,
        )
        self._hash_check(item)
        if self.yara:
            hits, note = self.yara.scan_bytes(data, name, disk_path, filetype_of(data))
            item.hits += hits
            if note:
                item.notes.append(note)
        if self.clamd:
            hits, note = self.clamd.scan_bytes(data)
            item.hits += hits
            if note:
                item.notes.append(note)
        if "heuristics" in self.s.engines:
            res, pe = heuristics.analyse(data, name)
            item.hits += res.hits
            if pe:
                item.is_pe = True
                sigs = pe.get("signatures") or []
                if sigs and isinstance(sigs, list):
                    subj = str(sigs[0].get("subject", ""))
                    item.notes.append(
                        f"embedded Authenticode signature, subject {subj} (validated against trusted roots only on Windows)"
                    )
                elif not pe.get("is_signed"):
                    item.notes.append("PE file has no embedded signature")
        out = [item]
        kind = archive.detect(data) if self.s.archives else None
        if kind:
            if depth >= self.s.limits.max_depth:
                item.notes.append(
                    f"nested archive not opened (depth limit {self.s.limits.max_depth})"
                )
            else:
                for m in archive.iter_members(data, kind, self.s.limits, budget, name):
                    if isinstance(m, archive.MemberSkip):
                        item.notes.append(f"archive member {m.name}: {m.reason}")
                        continue
                    if archive.traversal_name(m.name):
                        item.hits.append(
                            EngineHit(
                                "heuristics",
                                "HEUR.ArchivePathTraversal",
                                f"member name escapes the extraction folder: {m.name[:120]}",
                                Confidence.LOW,
                                score=30,
                            )
                        )
                    out += self._scan_data(
                        f"{name}!{m.name}", m.data, disk_path, depth + 1, budget, in_archive=True
                    )
        item.verdict = combine(item.hits, self.s.threshold)
        return out

    # -- post passes ---------------------------------------------------------------------------

    def _clamscan_post(self, list_path: str, result: ScanResult) -> None:
        if not self.clamscan_exe:
            return
        try:
            found, note = clamscan_batch(self.clamscan_exe, list_path)
        finally:
            Path(list_path).unlink(missing_ok=True)
        if note:
            result.notes.append(note)
        by_path = {i.path: i for i in result.items if not i.in_archive}
        for path, sig in found.items():
            item = by_path.get(path)
            if item is None:
                item = ScanItem(path, disk_path=path)
                with contextlib.suppress(OSError):
                    item.sha256 = hashlib.sha256(
                        Path(long_path(Path(path))).read_bytes()
                    ).hexdigest()
                result.items.append(item)
            item.hits.append(
                EngineHit(
                    "clamav",
                    sig,
                    "ClamAV signature match (clamscan)",
                    Confidence.HIGH,
                    source="ClamAV",
                )
            )
            item.verdict = combine(item.hits, self.s.threshold)

    def _allowlist_post(self, result: ScanResult) -> None:
        candidates = [
            i for i in result.items
            if i.verdict == Verdict.SUSPICIOUS and not i.in_archive and i.disk_path
            and all(h.engine == "heuristics" for h in i.hits)
        ]  # fmt: skip
        if not candidates:
            return
        trust: dict[str, object] = {}
        pe_paths = [i.disk_path for i in candidates if i.is_pe]
        if self.powershell is not None and pe_paths:
            trust.update(
                windows_signatures(pe_paths, self.powershell, list(self.s.trusted_publishers))
            )
        for item in candidates:
            t = trust.get(item.disk_path)
            if t is None and self.dpkg is not None:
                t = self.dpkg.check(item.disk_path)
            if t is None:
                continue
            if getattr(t, "trusted", False):
                item.hits.append(
                    EngineHit(
                        "allowlist", "known-good", str(getattr(t, "detail", "")), Confidence.LOW
                    )
                )
                item.notes.append("heuristic findings downgraded: " + str(getattr(t, "detail", "")))
                item.verdict = Verdict.CLEAN
            else:
                item.notes.append(str(getattr(t, "detail", "")))
        result.items = [i for i in result.items if i.verdict != Verdict.CLEAN]

    def _virustotal_post(self, result: ScanResult) -> None:
        if not (self.s.virustotal_key and self.http):
            return
        flagged = [i for i in result.flagged if i.sha256][: self.s.virustotal_max]
        for item in flagged:
            hit, note = virustotal.lookup(self.http, self.s.virustotal_key, item.sha256)
            if hit:
                item.hits.append(hit)
            if note:
                item.notes.append(note)
        if len(result.flagged) > self.s.virustotal_max:
            result.notes.append(
                f"VirusTotal: only the first {self.s.virustotal_max} flagged files were looked up (public API limits)"
            )


def _bind(
    fn: Callable[[Future[list[ScanItem]], Path, int], None], path: Path, size: int
) -> Callable[[Future[list[ScanItem]]], None]:
    def cb(fut: Future[list[ScanItem]]) -> None:
        fn(fut, path, size)

    return cb


def _verdict_rank(v: Verdict) -> int:
    return {Verdict.MALICIOUS: 0, Verdict.SUSPICIOUS: 1, Verdict.ERROR: 2, Verdict.SKIPPED: 3}.get(
        v, 4
    )
