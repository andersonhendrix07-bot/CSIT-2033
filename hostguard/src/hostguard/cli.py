"""Command-line interface. Exit codes: 0 clean, 1 findings, 2 error."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from rich.console import Console
from rich.table import Table

from hostguard import __version__, sysinfo
from hostguard.config import DEFAULT_CONFIG_TOML, Config, ConfigError, load_config, to_toml
from hostguard.credentials import secret_status
from hostguard.logsetup import get_logger, setup_logging
from hostguard.models import ExitCode
from hostguard.paths import AppPaths, get_paths

log = get_logger("cli")

DISCLAIMER = (
    "hostguard complements your built-in antivirus (e.g. Microsoft Defender); "
    "it is not a replacement."
)

# Commands that exist in the plan but are delivered in later phases.
PLANNED: dict[str, tuple[str, str]] = {
    "vulns": ("Phase 2", "Inventory software and match known vulnerabilities"),
    "audit": ("Phase 2", "Read-only configuration audit"),
    "scan": ("Phase 3", "Malware scan (quick | full | custom paths)"),
    "quarantine": ("Phase 4", "List, restore or delete quarantined files"),
    "update": ("Phase 4", "Refresh rules, signatures and hash sets"),
    "report": ("Phase 5", "Write JSON / HTML / terminal reports"),
}


class Context:
    def __init__(
        self, paths: AppPaths, config: Config, console: Console, config_path: Path
    ) -> None:
        self.paths = paths
        self.config = config
        self.console = console
        self.config_path = config_path


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hostguard",
        description="Local-only host vulnerability analysis and malware scanning. " + DISCLAIMER,
    )
    p.add_argument("--version", action="version", version=f"hostguard {__version__}")
    p.add_argument("--config", type=Path, help="config file (default: per-user config folder)")
    p.add_argument(
        "-v", "--verbose", action="count", default=0, help="more console output (-vv for debug)"
    )
    p.add_argument("-q", "--quiet", action="store_true", help="errors only on the console")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    sub.add_parser("info", help="Show host facts, hostguard paths and component status")

    cfg = sub.add_parser("config", help="Show or create the configuration file")
    cfg_sub = cfg.add_subparsers(dest="config_cmd", metavar="ACTION", required=True)
    cfg_sub.add_parser("show", help="Print the effective configuration")
    cfg_sub.add_parser("path", help="Print the configuration file path")
    init = cfg_sub.add_parser("init", help="Write a commented default config file")
    init.add_argument("--force", action="store_true", help="overwrite an existing file")

    for name, (phase, help_text) in PLANNED.items():
        sp = sub.add_parser(name, help=f"{help_text} [{phase}]")
        sp.add_argument("rest", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)
    return p


def _kv_table(title: str) -> Table:
    """Two-column key/value table that wraps long values (paths) instead of truncating them."""
    t = Table(title=title, show_header=False)
    t.add_column(no_wrap=True)
    t.add_column(overflow="fold")
    return t


def cmd_info(ctx: Context, _args: argparse.Namespace) -> ExitCode:
    host = sysinfo.collect()
    c = ctx.console
    t = _kv_table("Host")
    t.add_row("OS", f"{host.os_name} ({host.os_version})")
    t.add_row("Build", host.os_build or "-")
    t.add_row("Architecture", host.arch)
    t.add_row("Python", host.python)
    t.add_row(
        "Elevated",
        "yes (not required; hostguard is designed to run unelevated)" if host.elevated else "no",
    )
    c.print(t)

    t2 = _kv_table("hostguard")
    t2.add_row("Version", __version__)
    cfg_state = "exists" if ctx.config_path.exists() else "not created (defaults in use)"
    t2.add_row("Config file", f"{ctx.config_path} [{cfg_state}]")
    t2.add_row("Data folder", str(ctx.paths.data_dir))
    t2.add_row("Quarantine", str(ctx.paths.quarantine_dir))
    t2.add_row("Cache folder", str(ctx.paths.cache_dir))
    t2.add_row("Log file", str(ctx.paths.log_file))
    for name, state in secret_status().items():
        t2.add_row(name, state)
    c.print(t2)
    c.print(DISCLAIMER)
    return ExitCode.CLEAN


def cmd_config(ctx: Context, args: argparse.Namespace) -> ExitCode:
    if args.config_cmd == "path":
        # Plain print: machine-readable output must not be wrapped or styled.
        print(ctx.config_path)
        return ExitCode.CLEAN
    if args.config_cmd == "show":
        print(to_toml(ctx.config))
        return ExitCode.CLEAN
    # init
    if ctx.config_path.exists() and not args.force:
        log.error("config file already exists: %s (use --force to overwrite)", ctx.config_path)
        return ExitCode.ERROR
    ctx.config_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    ctx.config_path.write_text(DEFAULT_CONFIG_TOML, encoding="utf-8")
    log.info("wrote default config to %s", ctx.config_path)
    print(f"Wrote {ctx.config_path}")
    return ExitCode.CLEAN


def cmd_planned(ctx: Context, args: argparse.Namespace) -> ExitCode:
    phase, _ = PLANNED[args.command]
    log.error("'%s' is not implemented yet (planned for %s)", args.command, phase)
    return ExitCode.ERROR


HANDLERS: dict[str, Callable[[Context, argparse.Namespace], ExitCode]] = {
    "info": cmd_info,
    "config": cmd_config,
    **{name: cmd_planned for name in PLANNED},
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return ExitCode.ERROR

    console = Console(no_color=args.no_color, highlight=False)
    paths = get_paths()
    config_path: Path = args.config or paths.config_file
    console_level = (
        logging.ERROR
        if args.quiet
        else (logging.WARNING, logging.INFO, logging.DEBUG)[min(args.verbose, 2)]
    )

    try:
        paths.ensure()
        # Log with defaults first, so a broken config file is still logged.
        setup_logging(paths.log_file, console_level=console_level)
        config = load_config(config_path)
        setup_logging(
            paths.log_file,
            file_level=config.general.log_level,
            console_level=console_level,
            max_bytes=config.general.log_max_bytes,
            backups=config.general.log_backups,
        )
    except ConfigError as exc:
        log.error("configuration error: %s", exc)
        return ExitCode.ERROR
    except OSError as exc:
        print(f"hostguard: cannot initialise folders or log file: {exc}", file=sys.stderr)
        return ExitCode.ERROR

    log.debug("command=%s argv=%s", args.command, json.dumps(list(argv or sys.argv[1:])))
    ctx = Context(paths, config, console, config_path)
    try:
        return int(HANDLERS[args.command](ctx, args))
    except KeyboardInterrupt:
        log.error("interrupted")
        return ExitCode.ERROR
    except Exception:
        log.exception("unexpected error in '%s'", args.command)
        return ExitCode.ERROR
