"""Terminal summaries and JSON output for inventory, vulns and audit.

(The full HTML report and executive summary arrive in Phase 5; the JSON
written here already carries every field a finding needs.)
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from hostguard import __version__
from hostguard.audit.base import CheckResult
from hostguard.inventory.models import Inventory, Skip
from hostguard.models import CheckStatus, Finding, Severity, utc_now
from hostguard.net import SourceUse
from hostguard.sysinfo import HostInfo
from hostguard.vulns.matcher import VulnScanResult, vtuple, vuln_severity

SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
STATUS_STYLE = {
    CheckStatus.PASSED: "green",
    CheckStatus.FAILED: "red",
    CheckStatus.SKIPPED: "yellow",
    CheckStatus.NOT_APPLICABLE: "dim",
    CheckStatus.ERROR: "magenta",
}


def severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    c = Counter(f.severity.value for f in findings)
    return {s.value: c.get(s.value, 0) for s in Severity}


def envelope(command: str, host: HostInfo, **body: Any) -> dict[str, Any]:
    return {
        "tool": "hostguard",
        "version": __version__,
        "command": command,
        "generated_at": utc_now(),
        "host": host.to_dict(),
        **body,
    }


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    tmp.replace(path)


def _kv_table(title: str) -> Table:
    t = Table(title=title, show_header=False, title_justify="left")
    t.add_column(no_wrap=True)
    t.add_column(overflow="fold")
    return t


def print_skips(console: Console, skipped: list[Skip]) -> None:
    if not skipped:
        return
    t = Table(title="Skipped (not checked)", title_justify="left")
    t.add_column("What", overflow="fold")
    t.add_column("Reason", overflow="fold")
    for s in skipped:
        t.add_row(s.what, s.reason)
    console.print(t)


def print_stale(console: Console, stale: list[SourceUse]) -> None:
    if stale:
        oldest = min(s.fetched_at for s in stale)
        console.print(
            f"[yellow]Warning:[/] {len(stale)} data source response(s) came from an expired cache "
            f"(oldest fetched {oldest}). Results may miss recent vulnerabilities; run again online.",
        )


# --- inventory -----------------------------------------------------------------------------


def print_inventory(console: Console, inv: Inventory, verbose: int) -> None:
    t = _kv_table("Operating system")
    t.add_row("Name", inv.os.name)
    t.add_row("Version", inv.os.version)
    if inv.os.display_version:
        t.add_row("Release", inv.os.display_version)
    t.add_row("Architecture", inv.os.arch)
    if inv.os.hotfixes:
        newest = max((h.installed_on for h in inv.os.hotfixes if h.installed_on), default="unknown")
        t.add_row("Updates installed", f"{len(inv.os.hotfixes)} (newest {newest})")
    console.print(t)

    by_src = Counter(s.source for s in inv.software)
    t = _kv_table(f"Installed software ({len(inv.software)})")
    for src, n in sorted(by_src.items()):
        t.add_row(src, str(n))
    if inv.python_packages:
        envs = Counter(p.environment for p in inv.python_packages)
        for env, n in envs.items():
            t.add_row(f"Python env {env}", str(n))
    console.print(t)
    if verbose:
        st = Table(title="Software", title_justify="left")
        for col in ("Name", "Version", "Publisher", "Source"):
            st.add_column(col, overflow="fold")
        for s in inv.software:
            st.add_row(s.name, s.version, s.publisher, s.source)
        console.print(st)

    lt = Table(title=f"Listening sockets ({len(inv.listeners)})", title_justify="left")
    for col in ("Proto", "Address", "Port", "Process"):
        lt.add_column(col, overflow="fold")
    for x in inv.listeners:
        style = "" if x.loopback else "bold"
        lt.add_row(x.protocol, x.address, str(x.port), x.process, style=style)
    console.print(lt)

    pt = _kv_table(f"Startup / persistence entries ({len(inv.persistence)})")
    for kind, n in sorted(Counter(p.kind for p in inv.persistence).items()):
        pt.add_row(kind, str(n))
    console.print(pt)
    print_skips(console, inv.skipped)


def inventory_json(inv: Inventory, host: HostInfo) -> dict[str, Any]:
    return envelope("inventory", host, inventory=inv.to_dict())


# --- vulns ---------------------------------------------------------------------------------------


def print_vulns(
    console: Console, res: VulnScanResult, nvd_key_state: str, top: int, verbose: int
) -> None:
    findings = res.findings
    counts = severity_counts(findings)
    console.print(
        f"[bold]Vulnerabilities:[/] {len(findings)} affected component(s) - "
        + ", ".join(f"{k} {v}" for k, v in counts.items() if v)
        if findings
        else "[bold green]No known vulnerabilities found in the checked components.[/]"
    )
    if findings:
        t = Table(title_justify="left")
        for col in ("Severity", "Confidence", "Component", "CVEs", "Top priority", "Fix"):
            t.add_column(col, overflow="fold")
        for f in findings:
            v = f.vulns[0]
            prio = v.cve
            bits = []
            if v.kev:
                bits.append("KEV")
            if v.epss is not None:
                bits.append(f"EPSS {v.epss:.1%}")
            if v.cvss is not None:
                bits.append(f"CVSS {v.cvss}")
            if bits:
                prio += " (" + ", ".join(bits) + ")"
            fixes = [x.fixed_in for x in f.vulns if x.fixed_in]
            kev_n = sum(x.kev for x in f.vulns)
            t.add_row(
                f"[{SEV_STYLE[f.severity]}]{f.severity.value}[/]",
                f.confidence.value,
                f.component,
                f"{len(f.vulns)}" + (f" ({kev_n} KEV)" if kev_n else ""),
                prio,
                max(fixes, key=vtuple) if fixes else "none listed",
            )
        console.print(t)
        if verbose:
            for f in findings[:top]:
                console.print(f"\n[bold]{f.id}[/] {f.title}")
                for v in f.vulns[:10]:
                    sev = vuln_severity(v)
                    console.print(
                        f"  {v.cve:18} {sev.value if sev else '-':8} KEV={'yes' if v.kev else 'no':3} "
                        f"EPSS={v.epss if v.epss is not None else '-'} CVSS={v.cvss if v.cvss is not None else '-'} "
                        f"{v.summary[:90]}",
                        markup=False,
                        highlight=False,
                    )
                console.print(f"  Fix: {f.remediation}", markup=False, highlight=False)

    if findings:
        no_fix = [f for f in findings if not any(v.fixed_in for v in f.vulns)]
        console.print(
            f"{len(findings) - len(no_fix)} component(s) have a fixed version listed; "
            f"{len(no_fix)} have only advisories without a listed fix (for distro packages this "
            "usually means the distribution has not released a fix yet)."
        )

    checked = res.checked
    t = _kv_table("Coverage")
    if "windows_os" in checked:
        t.add_row("Windows build", "checked against NVD (Needs verification)")
    t.add_row("Apps matched to NVD products", str(checked.get("apps_matched_to_cpe", 0)))
    t.add_row(
        "Apps without a product mapping",
        f"{checked.get('apps_without_cpe_mapping', 0)} (not checked; try --fuzzy)",
    )
    if checked.get("distro_source_packages"):
        t.add_row("Distro source packages (OSV)", str(checked["distro_source_packages"]))
    t.add_row("Python packages (OSV)", str(checked.get("python_packages", 0)))
    t.add_row("NVD API key", nvd_key_state)
    if res.kev_version:
        t.add_row("CISA KEV catalog", res.kev_version)
    console.print(t)
    if verbose and res.unmatched_apps:
        console.print(
            "Not checked against NVD: " + "; ".join(res.unmatched_apps),
            markup=False,
            highlight=False,
        )
    print_skips(console, res.skipped)
    for n in res.notices:
        console.print(f"[dim]{n}[/]")


def vulns_json(res: VulnScanResult, host: HostInfo, inv: Inventory) -> dict[str, Any]:
    return envelope(
        "vulns",
        host,
        summary={
            "by_severity": severity_counts(res.findings),
            "findings": len(res.findings),
            "coverage": res.checked,
        },
        findings=[f.to_dict() for f in res.findings],
        skipped=[asdict(s) for s in [*inv.skipped, *res.skipped]],
        not_checked_apps=res.unmatched_apps,
        data_sources=[asdict(s) for s in res.sources],
        stale_sources=[asdict(s) for s in res.sources if s.stale],
        kev_catalog_version=res.kev_version,
        notices=res.notices,
    )


# --- audit -----------------------------------------------------------------------------------------


def print_audit(console: Console, results: list[CheckResult], verbose: int) -> None:
    t = Table(title="Configuration audit (read-only)", title_justify="left")
    for col in ("Check", "Status", "Severity", "Result"):
        t.add_column(col, overflow="fold")
    for r in results:
        sev = r.severity if r.status == CheckStatus.FAILED else None
        t.add_row(
            f"{r.check.id}\n[dim]{r.check.title}[/]",
            f"[{STATUS_STYLE[r.status]}]{r.status.value}[/]",
            f"[{SEV_STYLE[sev]}]{sev.value}[/]" if sev else "",
            r.outcome.detail,
        )
    console.print(t)
    counts = Counter(r.status.value for r in results)
    console.print(", ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
    if verbose:
        for r in results:
            if r.status == CheckStatus.FAILED:
                console.print(f"\n[bold]{r.check.id}[/] {r.check.title}")
                for e in r.outcome.evidence:
                    console.print(
                        f"  Evidence: {e.source}\n    {e.output}", markup=False, highlight=False
                    )
                console.print(f"  Fix: {r.check.remediation}", markup=False, highlight=False)
                console.print(f"  Retest: {r.check.retest}", markup=False, highlight=False)
                console.print(
                    "  References: " + " ".join(r.check.references), markup=False, highlight=False
                )


def audit_json(results: list[CheckResult], host: HostInfo, inv: Inventory | None) -> dict[str, Any]:
    findings = [f for f in (r.to_finding() for r in results) if f]
    return envelope(
        "audit",
        host,
        summary={
            "by_status": dict(Counter(r.status.value for r in results)),
            "by_severity": severity_counts(findings),
        },
        findings=[f.to_dict() for f in findings],
        checks=[r.to_dict() for r in results],
        skipped=[asdict(s) for s in inv.skipped] if inv else [],
    )
