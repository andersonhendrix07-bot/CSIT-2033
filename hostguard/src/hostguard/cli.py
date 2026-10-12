"""Command-line interface. Exit codes: 0 clean, 1 findings, 2 error."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Callable, Sequence
from contextlib import nullcontext
from datetime import timedelta
from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from hostguard import __version__, inventory, output, sysinfo
from hostguard.audit import AuditContext, run_checks
from hostguard.config import DEFAULT_CONFIG_TOML, Config, ConfigError, load_config, to_toml
from hostguard.credentials import get_secret, secret_status
from hostguard.logsetup import get_logger, setup_logging
from hostguard.models import CheckStatus, ExitCode, Severity
from hostguard.net import HttpClient, JsonCache
from hostguard.paths import AppPaths, get_paths
from hostguard.vulns import matcher
from hostguard.winsys import RealPowerShell, WinRegistry

log = get_logger("cli")

DISCLAIMER = (
    "hostguard complements your built-in antivirus (e.g. Microsoft Defender); "
    "it is not a replacement."
)

# Commands that exist in the plan but are delivered in later phases.
PLANNED: dict[str, tuple[str, str]] = {
    "scan": ("Phase 3", "Malware scan (quick | full | custom paths)"),
    "quarantine": ("Phase 4", "List, restore or delete quarantined files"),
    "update": ("Phase 4", "Refresh rules, signatures and hash sets"),
    "report": ("Phase 5", "Write JSON / HTML / terminal reports"),
}


class Context:
    def __init__(
        self,
        paths: AppPaths,
        config: Config,
        console: Console,
        config_path: Path,
        verbose: int = 0,
        quiet: bool = False,
    ) -> None:
        self.paths = paths
        self.config = config
        self.console = console
        self.config_path = config_path
        self.verbose = verbose
        self.quiet = quiet


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

    inv = sub.add_parser("inventory", help="List OS, software, listening ports and startup entries")
    _add_env_and_json(inv)

    vul = sub.add_parser("vulns", help="Match installed software against known vulnerabilities")
    _add_env_and_json(vul)
    vul.add_argument("--offline", action="store_true", help="use cached data only (warns if stale)")
    vul.add_argument(
        "--fuzzy",
        action="store_true",
        help="also keyword-match apps without a curated NVD mapping (results: Needs verification)",
    )
    vul.add_argument("--no-os", action="store_true", help="skip the Windows build check")
    vul.add_argument("--no-apps", action="store_true", help="skip desktop apps (NVD)")
    vul.add_argument("--top", type=int, default=10, help="details shown with -v (default 10)")

    aud = sub.add_parser("audit", help="Read-only configuration audit with references")
    aud.add_argument("--check", action="append", metavar="ID", help="run only these check IDs")
    aud.add_argument("--json", type=Path, metavar="FILE", help="also write results as JSON")

    for name, (phase, help_text) in PLANNED.items():
        sp = sub.add_parser(name, help=f"{help_text} [{phase}]")
        sp.add_argument("rest", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)
    return p


def _add_env_and_json(sp: argparse.ArgumentParser) -> None:
    sp.add_argument(
        "--python-env",
        action="append",
        metavar="PATH",
        help="Python environment (venv folder or site-packages) to inventory; repeatable",
    )
    sp.add_argument("--json", type=Path, metavar="FILE", help="also write results as JSON")


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


def _envs(ctx: Context, args: argparse.Namespace) -> list[str]:
    return list(ctx.config.vulns.python_envs) + list(args.python_env or [])


def _progress(ctx: Context) -> tuple[Progress, Callable[[str, int, int], None]]:
    prog = Progress(
        TextColumn("{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=Console(stderr=True, no_color=ctx.console.no_color),
        transient=True,
        disable=ctx.quiet,
    )
    tasks: dict[str, TaskID] = {}

    def update(step: str, done: int, total: int) -> None:
        if step not in tasks:
            tasks[step] = prog.add_task(step, total=total or None)
        prog.update(tasks[step], completed=done, total=total or None)

    return prog, update


def cmd_inventory(ctx: Context, args: argparse.Namespace) -> ExitCode:
    with ctx.console.status("Collecting inventory…") if not ctx.quiet else nullcontext():
        inv = inventory.collect(_envs(ctx, args))
    output.print_inventory(ctx.console, inv, ctx.verbose)
    if args.json:
        output.write_json(args.json, output.inventory_json(inv, sysinfo.collect()))
        ctx.console.print(f"JSON written to {args.json}", markup=False, highlight=False)
    return ExitCode.CLEAN


def cmd_vulns(ctx: Context, args: argparse.Namespace) -> ExitCode:
    offline = args.offline or ctx.config.vulns.offline
    key = get_secret("NVD_API_KEY")
    key_state = (
        f"set ({key.source})"
        if key
        else "not set (NVD lookups are paced at 1 request / 6 s; see README to add a key)"
    )
    with ctx.console.status("Collecting inventory…") if not ctx.quiet else nullcontext():
        inv = inventory.collect(_envs(ctx, args), persistence=False, listeners=False)
    ttl = timedelta(hours=ctx.config.vulns.cache_ttl_hours)
    prog, update = _progress(ctx)
    with HttpClient(JsonCache(ctx.paths.cache_dir), offline=offline) as http, prog:
        res = matcher.scan(
            inv,
            http,
            nvd_key=key,
            ttl=ttl,
            fuzzy=args.fuzzy,
            include_os=not args.no_os,
            include_apps=not args.no_apps,
            progress=update,
        )
        stale = http.stale_sources()
    output.print_vulns(ctx.console, res, key_state, args.top, ctx.verbose)
    output.print_stale(ctx.console, stale)
    if args.json:
        output.write_json(args.json, output.vulns_json(res, sysinfo.collect(), inv))
        ctx.console.print(f"JSON written to {args.json}", markup=False, highlight=False)
    if res.incomplete:
        ctx.console.print(
            f"[bold yellow]Incomplete:[/] lookups failed for {', '.join(res.incomplete)} "
            "(see 'Skipped'). Absence of findings for those components does NOT mean they are safe."
        )
        if not res.findings:
            return ExitCode.ERROR
    return ExitCode.FINDINGS if res.findings else ExitCode.CLEAN


def cmd_audit(ctx: Context, args: argparse.Namespace) -> ExitCode:
    host = sysinfo.collect()
    with ctx.console.status("Running read-only checks…") if not ctx.quiet else nullcontext():
        inv = inventory.collect(software=host.os_family == "windows")
        actx = AuditContext(
            family=host.os_family,
            elevated=host.elevated,
            registry=WinRegistry() if host.os_family == "windows" else None,
            powershell=RealPowerShell() if host.os_family == "windows" else None,
            inventory=inv,
            edition_id=_edition_id(),
        )
        results = run_checks(actx, args.check)
    if not results:
        log.error("no checks matched %s", args.check or "this OS")
        return ExitCode.ERROR
    output.print_audit(ctx.console, results, ctx.verbose)
    if args.json:
        output.write_json(args.json, output.audit_json(results, host, inv))
        ctx.console.print(f"JSON written to {args.json}", markup=False, highlight=False)
    actionable = [
        r for r in results if r.status == CheckStatus.FAILED and r.severity != Severity.INFO
    ]
    return ExitCode.FINDINGS if actionable else ExitCode.CLEAN


def _edition_id() -> str:
    if sys.platform != "win32":
        return ""
    import platform

    return platform.win32_edition() or ""


HANDLERS: dict[str, Callable[[Context, argparse.Namespace], ExitCode]] = {
    "info": cmd_info,
    "config": cmd_config,
    "inventory": cmd_inventory,
    "vulns": cmd_vulns,
    "audit": cmd_audit,
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
    ctx = Context(paths, config, console, config_path, args.verbose, args.quiet)
    try:
        return int(HANDLERS[args.command](ctx, args))
    except KeyboardInterrupt:
        log.error("interrupted")
        return ExitCode.ERROR
    except Exception:
        log.exception("unexpected error in '%s'", args.command)
        return ExitCode.ERROR
