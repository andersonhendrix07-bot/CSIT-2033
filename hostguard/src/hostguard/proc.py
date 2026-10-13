"""The only place hostguard starts other programs.

Rules enforced here:
- arguments are always a list (never a shell string), `shell=False` always;
- the executable is resolved to an absolute path, and a match in the current
  working directory is refused (Windows searches the CWD first, which allows
  binary planting);
- stdin is closed, a timeout always applies, output is size-capped and
  decoded with replacement so hostile bytes cannot crash the caller;
- the exact command line is returned so it can be shown as evidence.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

DEFAULT_TIMEOUT = 60.0
MAX_OUTPUT = 1_048_576  # bytes kept per stream


class ToolNotFoundError(Exception):
    pass


@dataclass(frozen=True)
class ProcResult:
    argv: tuple[str, ...]
    returncode: int | None  # None if it timed out
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False

    @property
    def cmdline(self) -> str:
        return subprocess.list2cmdline(self.argv) if os.name == "nt" else " ".join(self.argv)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def resolve_executable(name: str) -> str:
    """Return an absolute path for `name`, refusing matches in the current directory."""
    p = Path(name)
    if p.is_absolute():
        if not p.is_file():
            raise ToolNotFoundError(name)
        return str(p)
    if p.parent != Path():
        raise ValueError(f"relative executable paths are not allowed: {name!r}")
    found = shutil.which(name)
    if not found:
        raise ToolNotFoundError(name)
    resolved = Path(found).resolve()
    if resolved.parent == Path.cwd().resolve():
        raise ToolNotFoundError(f"{name} (refused: found only in the current directory)")
    return str(resolved)


def run(
    argv: Sequence[str], *, timeout: float = DEFAULT_TIMEOUT, input_data: bytes | None = None
) -> ProcResult:
    if isinstance(argv, str | bytes) or not argv:
        raise TypeError("argv must be a non-empty sequence of strings, not a shell string")
    if not all(isinstance(a, str) for a in argv):
        raise TypeError("every argument must be a str")
    exe = resolve_executable(argv[0])
    full = (exe, *argv[1:])

    creationflags = 0
    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NO_WINDOW

    try:
        cp = subprocess.run(  # noqa: S603 - list argv, shell=False, resolved absolute exe
            full,
            stdin=None if input_data is not None else subprocess.DEVNULL,
            input=input_data,
            capture_output=True,
            timeout=timeout,
            shell=False,
            check=False,
            creationflags=creationflags,
        )
    except subprocess.TimeoutExpired as exc:
        out, t1 = _decode(exc.stdout)
        err, t2 = _decode(exc.stderr)
        return ProcResult(tuple(argv), None, out, err, timed_out=True, truncated=t1 or t2)
    out, t1 = _decode(cp.stdout)
    err, t2 = _decode(cp.stderr)
    return ProcResult(tuple(argv), cp.returncode, out, err, truncated=t1 or t2)


def _decode(data: bytes | None) -> tuple[str, bool]:
    if not data:
        return "", False
    truncated = len(data) > MAX_OUTPUT
    return data[:MAX_OUTPUT].decode("utf-8", errors="replace"), truncated
