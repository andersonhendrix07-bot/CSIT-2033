from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from hostguard.cli import PLANNED, main


def test_no_command_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 2
    assert "usage: hostguard" in capsys.readouterr().out


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "hostguard 0.1.0" in capsys.readouterr().out


def test_info(capsys: pytest.CaptureFixture[str], isolated_home: Path) -> None:
    assert main(["--no-color", "info"]) == 0
    out = capsys.readouterr().out
    assert "not a replacement" in out
    assert "NVD_API_KEY" in out
    assert (isolated_home / "logs" / "hostguard.log").exists()
    assert (isolated_home / "data" / "quarantine").is_dir()


def test_config_init_show_path(capsys: pytest.CaptureFixture[str], isolated_home: Path) -> None:
    cfg = isolated_home / "config" / "config.toml"
    assert main(["config", "path"]) == 0
    assert str(cfg) in capsys.readouterr().out
    assert main(["config", "init"]) == 0
    assert cfg.exists()
    # Refuses to overwrite without --force.
    assert main(["config", "init"]) == 2
    assert main(["config", "init", "--force"]) == 0
    capsys.readouterr()
    assert main(["config", "show"]) == 0
    assert "max_file_size_mb = 100" in capsys.readouterr().out


def test_bad_config_is_exit_2(tmp_path: Path) -> None:
    bad = tmp_path / "bad.toml"
    bad.write_text("[scan]\nfollow_symlinks = 'yes'\n", encoding="utf-8")
    assert main(["--config", str(bad), "info"]) == 2


@pytest.mark.parametrize("command", sorted(PLANNED))
def test_planned_commands_exit_2(command: str, caplog: pytest.LogCaptureFixture) -> None:
    assert main([command]) == 2


def test_unexpected_exception_is_exit_2(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_: object) -> None:
        raise RuntimeError("bug")

    monkeypatch.setitem(__import__("hostguard.cli").cli.HANDLERS, "info", boom)
    assert main(["info"]) == 2


def test_module_entry_point(isolated_home: Path) -> None:
    r = subprocess.run(
        [sys.executable, "-m", "hostguard", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0
    assert "hostguard 0.1.0" in r.stdout


def test_info_never_truncates_long_paths(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    deep = tmp_path / ("very-long-folder-name-" * 6) / "home"
    monkeypatch.setenv("HOSTGUARD_HOME", str(deep))
    monkeypatch.setenv("COLUMNS", "60")
    assert main(["--no-color", "info"]) == 0
    out = capsys.readouterr().out
    assert "…" not in out
    # The wrapped log path, with table borders and wrapping removed, is complete.
    flat = "".join(ch for ch in out if ch not in "│|\n ")
    assert str(deep / "logs" / "hostguard.log").replace(" ", "") in flat
