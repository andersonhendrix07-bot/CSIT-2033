"""Locations of hostguard's own files.

Default locations come from platformdirs, e.g. on Windows 11:
  config     %LOCALAPPDATA%\\hostguard\\config.toml
  data       %LOCALAPPDATA%\\hostguard\\  (rules, hashes, quarantine)
  cache      %LOCALAPPDATA%\\hostguard\\Cache
  logs       %LOCALAPPDATA%\\hostguard\\Logs

Setting HOSTGUARD_HOME puts everything under one folder instead (used by tests
and for portable installs).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import platformdirs

APP_NAME = "hostguard"
HOME_ENV = "HOSTGUARD_HOME"


@dataclass(frozen=True)
class AppPaths:
    config_dir: Path
    data_dir: Path
    cache_dir: Path
    log_dir: Path

    @property
    def config_file(self) -> Path:
        return self.config_dir / "config.toml"

    @property
    def log_file(self) -> Path:
        return self.log_dir / "hostguard.log"

    @property
    def rules_dir(self) -> Path:
        return self.data_dir / "rules"

    @property
    def hashes_dir(self) -> Path:
        return self.data_dir / "hashes"

    @property
    def quarantine_dir(self) -> Path:
        return self.data_dir / "quarantine"

    def own_dirs(self) -> list[Path]:
        """Folders the scanner always excludes (quarantine, rules, hashes, cache, logs)."""
        return [self.quarantine_dir, self.rules_dir, self.hashes_dir, self.cache_dir, self.log_dir]

    def ensure(self) -> None:
        """Create hostguard's own folders, owner-only where the OS supports it."""
        for d in (self.config_dir, self.data_dir, self.cache_dir, self.log_dir, *self.own_dirs()):
            d.mkdir(parents=True, exist_ok=True, mode=0o700)


def get_paths() -> AppPaths:
    home = os.environ.get(HOME_ENV)
    if home:
        base = Path(home).expanduser().resolve()
        return AppPaths(
            config_dir=base / "config",
            data_dir=base / "data",
            cache_dir=base / "cache",
            log_dir=base / "logs",
        )
    return AppPaths(
        config_dir=Path(platformdirs.user_config_dir(APP_NAME, appauthor=False)),
        data_dir=Path(platformdirs.user_data_dir(APP_NAME, appauthor=False)),
        cache_dir=Path(platformdirs.user_cache_dir(APP_NAME, appauthor=False)),
        log_dir=Path(platformdirs.user_log_dir(APP_NAME, appauthor=False)),
    )
