"""Python packages in environments the user points at.

Packages are read from their *.dist-info / *.egg-info metadata files only. The
environment's interpreter is never run and no package code is imported, so a
malicious package cannot execute anything during inventory.
"""

from __future__ import annotations

import re
from importlib.metadata import PathDistribution
from pathlib import Path

from hostguard.inventory.models import PythonPackage, Skip
from hostguard.models import Evidence

MAX_DISTS = 10_000


def normalize(name: str) -> str:
    """PEP 503 name normalisation (what PyPI and OSV use)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def site_packages_dirs(env: Path) -> list[Path]:
    if list(env.glob("*.dist-info")) or list(env.glob("*.egg-info")):
        return [env]  # already a site-packages directory
    candidates = [env / "Lib" / "site-packages"]  # Windows venv / install
    for lib in ("lib", "lib64"):
        candidates += sorted((env / lib).glob("python3*/site-packages"))
    return [c for c in candidates if c.is_dir()]


def collect(envs: list[str], skipped: list[Skip]) -> list[PythonPackage]:
    out: list[PythonPackage] = []
    for raw in envs:
        env = Path(raw).expanduser()
        if not env.is_dir():
            skipped.append(Skip(f"Python environment {raw}", "folder not found"))
            continue
        dirs = site_packages_dirs(env)
        if not dirs:
            skipped.append(Skip(f"Python environment {raw}", "no site-packages folder found"))
            continue
        for sp in dirs:
            metas = sorted([*sp.glob("*.dist-info"), *sp.glob("*.egg-info")])[:MAX_DISTS]
            for meta in metas:
                if not meta.is_dir():
                    continue
                dist = PathDistribution(meta)
                try:
                    name, version = dist.metadata["Name"], dist.version
                except (OSError, KeyError, ValueError, TypeError):
                    skipped.append(Skip(str(meta), "unreadable package metadata"))
                    continue
                if not name or not version:
                    continue
                out.append(
                    PythonPackage(
                        name=normalize(name),
                        version=str(version),
                        environment=str(env),
                        evidence=Evidence(
                            f"file {meta / 'METADATA'}", f"Name: {name}; Version: {version}"
                        ),
                    )
                )
    return out
