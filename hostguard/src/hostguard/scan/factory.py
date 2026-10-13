"""Build scan engines from a picklable spec, in the main process or in worker processes.

YARA-X's Python binding holds the GIL while scanning (measured: 4 threads were no
faster than 1), so multi-worker scans use processes. Each worker loads the
compiled rules from the cache (~2.5 s, ~120 MB for ~7,000 rules).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, replace
from pathlib import Path

from hostguard.scan import hashdb as hashdb_mod
from hostguard.scan.allowlist import DpkgVerifier
from hostguard.scan.engines.clamav import Clamd, find_clamd, find_clamscan
from hostguard.scan.engines.yara_engine import YaraEngine
from hostguard.scan.scanner import Scanner, ScanSettings
from hostguard.winsys import PowerShell, RealPowerShell


@dataclass(frozen=True)
class EngineSpec:
    rules_dir: Path
    cache_dir: Path
    hashes_dir: Path
    clamd: str = "auto"  # "auto" | "off" | socket path | "tcp:127.0.0.1:3310"
    include_test_rules: bool = False


def build(spec: EngineSpec, settings: ScanSettings, *, worker: bool = False) -> Scanner:
    engines = settings.engines
    yara = (
        YaraEngine(spec.rules_dir, spec.cache_dir, include_test_rules=spec.include_test_rules)
        if "yara" in engines
        else None
    )
    hdb = hashdb_mod.load(spec.hashes_dir) if "hash" in engines else None
    clamd: Clamd | None = find_clamd(spec.clamd) if "clamav" in engines else None
    clamscan = None if (worker or clamd or "clamav" not in engines) else find_clamscan()
    if worker:
        # Workers only run engines; allowlist and VirusTotal post-passes run in the main process.
        settings = replace(settings, virustotal_key=None)
        return Scanner(settings, hashdb=hdb, yara=yara, clamd=clamd)
    powershell, dpkg = allowlist_sources(sys.platform)
    return Scanner(
        settings,
        hashdb=hdb,
        yara=yara,
        clamd=clamd,
        clamscan_exe=clamscan,
        powershell=powershell,
        dpkg=dpkg,
    )


def allowlist_sources(
    platform: str, dpkg_info: Path = Path("/var/lib/dpkg/info")
) -> tuple[PowerShell | None, DpkgVerifier | None]:
    """Known-good sources: OS-validated Authenticode on Windows, dpkg checksums on Debian/Ubuntu."""
    if platform == "win32":
        return RealPowerShell(), None
    return None, (DpkgVerifier(dpkg_info) if dpkg_info.is_dir() else None)


# --- worker-process side --------------------------------------------------------------------

_WORKER: Scanner | None = None


def init_worker(spec: EngineSpec, settings: ScanSettings) -> None:
    global _WORKER
    _WORKER = build(spec, settings, worker=True)


def worker_scan(path: Path, size: int) -> list:  # type: ignore[type-arg]
    if _WORKER is None:  # pragma: no cover - initializer always runs first
        raise RuntimeError("worker not initialised")
    return _WORKER.scan_file(path, size)
