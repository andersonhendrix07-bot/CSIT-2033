from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

from hostguard import proc


def test_rejects_shell_strings() -> None:
    with pytest.raises(TypeError):
        proc.run("echo hi")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        proc.run([])
    with pytest.raises(TypeError):
        proc.run([sys.executable, 1])  # type: ignore[list-item]


def test_runs_with_list_argv_and_no_shell_expansion() -> None:
    r = proc.run([sys.executable, "-c", "import sys; print(sys.argv[1])", "$(whoami) & dir; |"])
    assert r.ok
    assert r.stdout.strip() == "$(whoami) & dir; |"


def test_stdin_closed() -> None:
    r = proc.run([sys.executable, "-c", "import sys; print(repr(sys.stdin.read()))"])
    assert r.stdout.strip() == "''"


def test_timeout() -> None:
    r = proc.run([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.5)
    assert r.timed_out and r.returncode is None and not r.ok


def test_output_truncated_and_bad_bytes_replaced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proc, "MAX_OUTPUT", 100)
    code = "import sys; sys.stdout.buffer.write(b'\\xff' + b'A' * 500)"
    r = proc.run([sys.executable, "-c", code])
    assert r.truncated
    assert len(r.stdout) == 100
    assert r.stdout[0] == "�"


def test_missing_tool() -> None:
    with pytest.raises(proc.ToolNotFoundError):
        proc.run(["definitely-not-a-real-tool-hg"])


def test_relative_path_refused() -> None:
    with pytest.raises(ValueError, match="relative"):
        proc.resolve_executable("sub/tool")


def test_executable_in_cwd_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate Windows' search-the-current-directory-first behaviour (binary planting)."""
    planted = tmp_path / "planted-tool"
    planted.write_text("", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(shutil, "which", lambda name: str(planted))
    with pytest.raises(proc.ToolNotFoundError, match="current directory"):
        proc.resolve_executable("planted-tool")


def test_cmdline_is_evidence_friendly() -> None:
    r = proc.run([sys.executable, "-c", "pass"])
    assert "-c" in r.cmdline


def test_env_is_passed_to_child() -> None:
    env = {k: v for k, v in os.environ.items() if k != "HG_TEST_VAR"}
    env["HG_TEST_VAR"] = "from-parent"
    r = proc.run([sys.executable, "-c", "import os; print(os.environ.get('HG_TEST_VAR'))"], env=env)
    assert r.stdout.strip() == "from-parent"
