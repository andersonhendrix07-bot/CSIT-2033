from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from hostguard.config import (
    DEFAULT_CONFIG_TOML,
    Config,
    ConfigError,
    from_dict,
    load_config,
    to_toml,
)


def test_missing_file_gives_defaults(tmp_path: Path) -> None:
    assert load_config(tmp_path / "nope.toml") == Config()


def test_default_template_matches_dataclass_defaults() -> None:
    assert from_dict(tomllib.loads(DEFAULT_CONFIG_TOML)) == Config()


def test_safe_defaults() -> None:
    c = Config()
    assert c.scan.follow_symlinks is False
    assert c.quarantine.auto_quarantine == "off"
    assert c.cloud.virustotal_enabled is False


def test_to_toml_round_trip_with_windows_paths() -> None:
    c = Config()
    c.scan.exclude_paths = [r"C:\Users\me\VMs", "it's quoted"]
    c.vulns.python_envs = [r"D:\proj\.venv"]
    assert from_dict(tomllib.loads(to_toml(c))) == c


def test_overrides_applied(tmp_path: Path) -> None:
    p = tmp_path / "c.toml"
    p.write_text("[scan]\nmax_file_size_mb = 5\nexclude_globs = ['*.iso']\n", encoding="utf-8")
    c = load_config(p)
    assert c.scan.max_file_size_mb == 5
    assert c.scan.exclude_globs == ["*.iso"]
    assert c.scan.max_archive_depth == 3


def test_log_level_normalised() -> None:
    assert from_dict({"general": {"log_level": "debug"}}).general.log_level == "DEBUG"


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"scan": {"max_file_size_md": 5}}, "unknown config key scan.max_file_size_md"),
        ({"bogus": {}}, "unknown config section"),
        ({"scan": 3}, "must be a table"),
        ({"scan": {"max_file_size_mb": "5"}}, "wrong type"),
        ({"scan": {"follow_symlinks": 1}}, "wrong type"),
        ({"scan": {"max_file_size_mb": True}}, "wrong type"),
        ({"scan": {"exclude_paths": [1]}}, "wrong type"),
        ({"scan": {"max_file_size_mb": 0}}, "between"),
        ({"scan": {"max_archive_depth": 99}}, "between"),
        ({"quarantine": {"auto_quarantine": "suspicious"}}, "auto_quarantine"),
        ({"general": {"log_level": "LOUD"}}, "log_level"),
    ],
)
def test_invalid_config_rejected(data: dict[str, object], message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        from_dict(data)  # type: ignore[arg-type]


def test_invalid_toml(tmp_path: Path) -> None:
    p = tmp_path / "c.toml"
    p.write_text("[scan\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(p)
