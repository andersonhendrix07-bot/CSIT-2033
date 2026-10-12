"""TOML configuration: defaults, loading and strict validation.

Unknown keys and wrong types are errors (not silently ignored) so that a typo
such as `max_file_size_md` can never quietly disable a safety limit.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
AUTO_QUARANTINE_MODES = ("off", "malicious")


class ConfigError(Exception):
    """Raised for unreadable, malformed or invalid configuration."""


@dataclass
class GeneralConfig:
    log_level: str = "INFO"
    log_max_bytes: int = 1_048_576
    log_backups: int = 5


@dataclass
class ScanConfig:
    max_file_size_mb: int = 100
    max_archive_depth: int = 3
    max_decompressed_mb: int = 256
    max_compression_ratio: int = 100
    follow_symlinks: bool = False
    hash_workers: int = 0  # 0 = choose automatically from CPU count
    exclude_paths: list[str] = field(default_factory=list)
    exclude_globs: list[str] = field(default_factory=list)
    extra_quick_paths: list[str] = field(default_factory=list)


@dataclass
class QuarantineConfig:
    # "off": only report; "malicious": quarantine Malicious verdicts automatically.
    # Suspicious verdicts are never auto-quarantined.
    auto_quarantine: str = "off"


@dataclass
class VulnsConfig:
    python_envs: list[str] = field(default_factory=list)
    cache_ttl_hours: int = 24
    offline: bool = False


@dataclass
class CloudConfig:
    # Hash-only lookups; file contents are never uploaded by this setting.
    virustotal_enabled: bool = False


@dataclass
class Config:
    general: GeneralConfig = field(default_factory=GeneralConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    quarantine: QuarantineConfig = field(default_factory=QuarantineConfig)
    vulns: VulnsConfig = field(default_factory=VulnsConfig)
    cloud: CloudConfig = field(default_factory=CloudConfig)

    def validate(self) -> None:
        g, s = self.general, self.scan
        if g.log_level.upper() not in LOG_LEVELS:
            raise ConfigError(f"general.log_level must be one of {LOG_LEVELS}")
        g.log_level = g.log_level.upper()
        _positive("general.log_max_bytes", g.log_max_bytes)
        _range("general.log_backups", g.log_backups, 0, 100)
        _range("scan.max_file_size_mb", s.max_file_size_mb, 1, 4096)
        _range("scan.max_archive_depth", s.max_archive_depth, 0, 10)
        _range("scan.max_decompressed_mb", s.max_decompressed_mb, 1, 8192)
        _range("scan.max_compression_ratio", s.max_compression_ratio, 1, 10_000)
        _range("scan.hash_workers", s.hash_workers, 0, 64)
        if self.quarantine.auto_quarantine not in AUTO_QUARANTINE_MODES:
            raise ConfigError(f"quarantine.auto_quarantine must be one of {AUTO_QUARANTINE_MODES}")
        _range("vulns.cache_ttl_hours", self.vulns.cache_ttl_hours, 0, 24 * 365)


def _positive(name: str, value: int) -> None:
    if value <= 0:
        raise ConfigError(f"{name} must be > 0 (got {value})")


def _range(name: str, value: int, lo: int, hi: int) -> None:
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi} (got {value})")


def _check_type(name: str, default: Any, value: Any) -> None:
    if isinstance(default, bool):
        ok = isinstance(value, bool)
    elif isinstance(default, int):
        ok = isinstance(value, int) and not isinstance(value, bool)
    elif isinstance(default, list):
        ok = isinstance(value, list) and all(isinstance(v, str) for v in value)
    else:
        ok = isinstance(value, type(default))
    if not ok:
        raise ConfigError(f"{name} has wrong type: expected {type(default).__name__}")


def from_dict(data: dict[str, Any]) -> Config:
    cfg = Config()
    section_names = {f.name for f in fields(cfg)}
    for section, values in data.items():
        if section not in section_names:
            raise ConfigError(f"unknown config section [{section}]")
        if not isinstance(values, dict):
            raise ConfigError(f"[{section}] must be a table")
        target = getattr(cfg, section)
        allowed = {f.name for f in fields(target)}
        for key, value in values.items():
            name = f"{section}.{key}"
            if key not in allowed:
                raise ConfigError(f"unknown config key {name}")
            _check_type(name, getattr(target, key), value)
            setattr(target, key, value)
    cfg.validate()
    return cfg


def load_config(path: Path) -> Config:
    """Load config from `path`; a missing file means defaults."""
    if not path.exists():
        cfg = Config()
        cfg.validate()
        return cfg
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    return from_dict(data)


def to_toml(cfg: Config) -> str:
    """Render a Config as TOML (only flat scalars and string lists are used)."""
    lines: list[str] = []
    for sec in fields(cfg):
        lines.append(f"[{sec.name}]")
        section = getattr(cfg, sec.name)
        for f in fields(section):
            lines.append(f"{f.name} = {_toml_value(getattr(section, f.name))}")
        lines.append("")
    return "\n".join(lines)


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _toml_str(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_str(v) for v in value) + "]"
    raise TypeError(f"unsupported config value {value!r}")


def _toml_str(s: str) -> str:
    # Literal strings keep Windows paths readable; fall back to escaped basic strings.
    if "'" not in s and "\n" not in s:
        return f"'{s}'"
    escaped = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{escaped}"'


DEFAULT_CONFIG_TOML = """\
# hostguard configuration. Every key is optional; missing keys use the defaults shown.
# Unknown keys are rejected so a typo cannot silently disable a safety limit.

[general]
log_level = "INFO"          # DEBUG | INFO | WARNING | ERROR (log file level)
log_max_bytes = 1048576     # rotate the log file at this size
log_backups = 5             # rotated log files to keep

[scan]
max_file_size_mb = 100      # larger files are reported as Skipped
max_archive_depth = 3       # nested archive levels to open (0 = do not open archives)
max_decompressed_mb = 256   # total decompressed bytes allowed per archive
max_compression_ratio = 100 # stop if an archive member expands more than this
follow_symlinks = false     # also applies to Windows junctions/reparse points
hash_workers = 0            # 0 = automatic
# hostguard's own quarantine, rules, hashes, cache and log folders are always excluded.
exclude_paths = []          # e.g. ['D:\\VMs']
exclude_globs = []          # e.g. ['*.iso']
extra_quick_paths = []      # added to the quick-scan locations

[quarantine]
# "off" = report only | "malicious". Suspicious verdicts are never auto-quarantined.
auto_quarantine = "off"

[vulns]
python_envs = []            # Python environments to inventory, e.g. ['C:\\Projects\\app\\.venv']
cache_ttl_hours = 24
offline = false             # true = use only cached data (with a staleness warning)

[cloud]
virustotal_enabled = false  # hash lookups only; needs VT_API_KEY
"""
