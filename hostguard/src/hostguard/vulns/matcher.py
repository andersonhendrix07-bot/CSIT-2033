"""Turn an inventory into ranked, evidence-backed vulnerability findings.

Sources per component type:
- Python packages            -> OSV (PyPI)                          Confidence: Confirmed
- Linux distro packages      -> OSV (distro ecosystem, source pkg)  Confidence: Confirmed
- Desktop apps (curated CPE) -> NVD cpeName + isVulnerable          Confidence: Likely
- Desktop apps (--fuzzy)     -> NVD CPE keyword search              Confidence: Needs verification
- Windows OS build           -> NVD cpeName + isVulnerable          Confidence: Needs verification
  (Microsoft's Security Update Guide is the authoritative source; not yet approved.)

"Confidence" describes whether the installed version is affected according to
the data source; it does not claim the vulnerability is exploitable on this host.
Every CVE is then enriched with CISA KEV and FIRST EPSS and ranked
KEV -> EPSS -> CVSS.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, replace
from datetime import timedelta
from typing import Any

from hostguard.credentials import Secret
from hostguard.inventory.models import Inventory, Skip, Software
from hostguard.logsetup import get_logger
from hostguard.models import Confidence, Evidence, Finding, Severity, VulnInfo
from hostguard.net import FetchError, HttpClient, SourceUse
from hostguard.vulns import cpe_map, cvss
from hostguard.vulns.sources import (
    NVD_CVES,
    OSV_BATCH,
    KevCatalog,
    NvdClient,
    OsvClient,
    OsvQuery,
    fetch_epss,
    fetch_kev,
)

log = get_logger("vulns")

Progress = Callable[[str, int, int], None]

OSV_WORKERS = 8

NVD_NOTICE = "This product uses the NVD API but is not endorsed or certified by the NVD."
KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
EPSS_URL = "https://www.first.org/epss/"
WINDOWS_UPDATE_URL = "https://learn.microsoft.com/en-us/windows/deployment/update/waas-wu-settings"

_PRIORITY = {
    "negligible": Severity.LOW,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


@dataclass
class VulnScanResult:
    findings: list[Finding] = field(default_factory=list)
    skipped: list[Skip] = field(default_factory=list)
    unmatched_apps: list[str] = field(default_factory=list)
    checked: dict[str, int] = field(default_factory=dict)
    incomplete: list[str] = field(default_factory=list)  # sources that failed entirely
    kev_version: str = ""
    sources: list[SourceUse] = field(default_factory=list)
    notices: list[str] = field(default_factory=lambda: [NVD_NOTICE])


@dataclass
class _Component:
    kind: str  # "pypi" | "distro" | "app" | "windows-os"
    label: str  # human name, e.g. "jinja2 2.10 (env C:\\proj\\.venv)"
    name: str
    version: str
    confidence: Confidence
    evidence: list[Evidence]
    vulns: dict[str, VulnInfo] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)


def vtuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:8])


# -- public entry point -----------------------------------------------------------


def scan(
    inv: Inventory,
    http: HttpClient,
    *,
    nvd_key: Secret | None,
    ttl: timedelta = timedelta(hours=24),
    fuzzy: bool = False,
    include_os: bool = True,
    include_apps: bool = True,
    progress: Progress | None = None,
) -> VulnScanResult:
    res = VulnScanResult()
    prog = progress or (lambda step, done, total: None)
    components: list[_Component] = []

    components += _osv_components(inv, OsvClient(http, ttl), res, prog)
    nvd = NvdClient(http, ttl, nvd_key)
    if include_os:
        components += _windows_os(inv, nvd, res)
    if include_apps:
        components += _nvd_apps(inv, nvd, res, prog, fuzzy, http, ttl)

    affected = [c for c in components if c.vulns]
    _enrich(affected, http, ttl, res, prog)
    res.findings = sorted((_finding(c) for c in affected), key=_finding_rank)
    res.sources = list(http.sources)
    return res


def _finding_rank(f: Finding) -> tuple[Any, ...]:
    top = min((v.sort_key() for v in f.vulns), default=(1, 0.0, 0.0))
    return (*top, f.severity.rank, f.component)


# -- OSV ----------------------------------------------------------------------------


def _osv_components(
    inv: Inventory, osv: OsvClient, res: VulnScanResult, prog: Progress
) -> list[_Component]:
    comps: list[_Component] = []
    queries: list[OsvQuery] = []

    for p in inv.python_packages:
        queries.append(OsvQuery("PyPI", p.name, p.version))
        comps.append(
            _Component(
                "pypi",
                f"{p.name} {p.version} (Python env {p.environment})",
                p.name,
                p.version,
                Confidence.CONFIRMED,
                [p.evidence],
                extra={"env": p.environment, "ecosystem": "PyPI"},
            )
        )
    distro: dict[tuple[str, str, str], list[Software]] = {}
    for s in inv.software:
        if s.ecosystem and s.package and s.package_version:
            distro.setdefault((s.ecosystem, s.package, s.package_version), []).append(s)
    for (eco, pkg, ver), binaries in sorted(distro.items()):
        names = sorted({b.name for b in binaries})
        if _kernel_without_image(pkg, names):
            res.skipped.append(
                Skip(
                    f"Kernel source package {pkg} {ver}",
                    f"only {', '.join(names[:5])} installed (headers/tools, not a kernel image); "
                    "kernel CVEs do not apply to these files",
                )
            )
            continue
        queries.append(OsvQuery(eco, pkg, ver))
        comps.append(
            _Component(
                "distro",
                f"{pkg} {ver} ({eco} source package)",
                pkg,
                ver,
                Confidence.CONFIRMED,
                [
                    Evidence(
                        binaries[0].origin or "package manager",
                        f"binary packages: {', '.join(names[:20])}",
                    )
                ],
                extra={"ecosystem": eco, "binaries": names},
            )
        )
    res.checked["python_packages"] = len(inv.python_packages)
    res.checked["distro_source_packages"] = len(queries) - len(inv.python_packages)
    if not queries:
        return []

    prog("Querying OSV.dev", 0, len(queries))
    try:
        ids_per_query = osv.query_batch(queries)
    except FetchError as exc:
        res.skipped.append(Skip("OSV.dev lookups (Python and distro packages)", str(exc)))
        res.incomplete.append("OSV.dev")
        return []
    prog("Querying OSV.dev", len(queries), len(queries))

    all_ids = sorted({i for ids in ids_per_query for i in ids})
    records = _fetch_osv_records(osv, all_ids, res, prog)

    for comp, q, ids in zip(comps, queries, ids_per_query, strict=True):
        if not ids:
            continue
        comp.evidence.append(
            Evidence(
                f"POST {OSV_BATCH}",
                json.dumps(
                    {"package": {"name": q.name, "ecosystem": q.ecosystem}, "version": q.version}
                )
                + " -> "
                + ", ".join(ids[:30])
                + (" …" if len(ids) > 30 else ""),
            )
        )
        for vid in ids:
            rec = records.get(vid)
            if rec is None:
                comp.vulns.setdefault(vid, VulnInfo(cve=vid, advisory_id=vid))
                continue
            for info in _from_osv(rec, q):
                if info.cve in comp.vulns:  # e.g. GHSA + PYSEC, or UBUNTU-CVE + USN
                    _merge(comp.vulns[info.cve], info)
                else:
                    comp.vulns[info.cve] = info
    return comps


def _merge(old: VulnInfo, new: VulnInfo) -> None:
    """Combine two advisories about the same CVE without losing information."""
    if old.cvss is None and new.cvss is not None:
        old.cvss, old.cvss_vector, old.cvss_source = new.cvss, new.cvss_vector, new.cvss_source
    old.cvss_vector = old.cvss_vector or new.cvss_vector
    old.distro_priority = old.distro_priority or new.distro_priority
    old.summary = old.summary or new.summary
    if new.fixed_in and (not old.fixed_in or vtuple(new.fixed_in) < vtuple(old.fixed_in)):
        old.fixed_in = new.fixed_in  # the earliest version that fixes it is enough
    if new.advisory_id != old.advisory_id and new.advisory_id not in old.related:
        old.related.append(new.advisory_id)


def _kernel_without_image(source_pkg: str, binaries: list[str]) -> bool:
    """Kernel CVEs only apply when a kernel image/modules package from this source is installed."""
    if source_pkg != "linux" and not source_pkg.startswith("linux-"):
        return False
    if source_pkg.startswith(("linux-firmware", "linux-base", "linux-atm")):
        return False
    return not any(b.startswith(("linux-image", "linux-modules", "kernel")) for b in binaries)


def _fetch_osv_records(
    osv: OsvClient, ids: list[str], res: VulnScanResult, prog: Progress
) -> dict[str, dict[str, Any]]:
    """Fetch full advisories in parallel (the HttpClient still paces requests per host)."""
    records: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=OSV_WORKERS) as pool:
        futures = {pool.submit(osv.vuln, vid): vid for vid in ids}
        for n, fut in enumerate(as_completed(futures), 1):
            vid = futures[fut]
            prog("Fetching OSV advisories", n, len(ids))
            try:
                records[vid] = fut.result()
            except FetchError as exc:
                res.skipped.append(Skip(f"OSV advisory {vid}", str(exc)))
    return records


def _from_osv(rec: dict[str, Any], q: OsvQuery) -> list[VulnInfo]:
    """One VulnInfo per CVE the advisory covers (a USN can cover several)."""
    vid = str(rec.get("id", ""))
    cves = list(
        dict.fromkeys(
            str(x)
            for x in [vid, *rec.get("aliases", []), *rec.get("upstream", [])]
            if str(x).startswith("CVE-")
        )
    )
    info = VulnInfo(cve=vid, advisory_id=vid)
    text = str(rec.get("summary") or rec.get("details") or "").strip()
    info.summary = text.splitlines()[0][:300] if text else ""
    for sev in rec.get("severity", []):
        typ, score = sev.get("type"), str(sev.get("score", ""))
        if typ == "CVSS_V3" and info.cvss is None:
            info.cvss = cvss.base_score_v3(score)
            info.cvss_vector = score
            info.cvss_source = "computed from OSV CVSS vector"
        elif typ == "CVSS_V4" and info.cvss_vector is None:
            info.cvss_vector = score
        elif typ == "Ubuntu":
            info.distro_priority = score
    info.fixed_in = _osv_fixed(rec, q)
    return [replace(info, cve=c, related=[]) for c in cves] if cves else [info]


def _osv_fixed(rec: dict[str, Any], q: OsvQuery) -> str:
    mine = vtuple(q.version)
    candidates = []
    for aff in rec.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("name", "").lower() != q.name.lower() or pkg.get("ecosystem") != q.ecosystem:
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                fixed = ev.get("fixed")
                if fixed and vtuple(fixed) > mine:
                    candidates.append(fixed)
    return min(candidates, key=vtuple) if candidates else ""


# -- NVD ------------------------------------------------------------------------------


def _windows_os(inv: Inventory, nvd: NvdClient, res: VulnScanResult) -> list[_Component]:
    if inv.os.family != "windows":
        return []
    cpe = cpe_map.windows_os_cpe(inv.os)
    if cpe is None:
        res.skipped.append(
            Skip("Windows OS vulnerabilities", f"no NVD CPE for {inv.os.name} {inv.os.full_build}")
        )
        return []
    comp = _Component(
        "windows-os",
        f"{inv.os.name} {inv.os.display_version} build {inv.os.full_build}",
        inv.os.name,
        inv.os.version,  # 10.0.<build>.<UBR>, the form NVD uses
        Confidence.NEEDS_VERIFICATION,
        list(inv.os.evidence[:1]),
        extra={"cpe": cpe},
    )
    try:
        records, total = nvd.cves_for_cpe(cpe)
    except FetchError as exc:
        res.skipped.append(Skip("Windows OS vulnerabilities (NVD)", str(exc)))
        res.incomplete.append("NVD (Windows build)")
        return []
    res.checked["windows_os"] = 1
    _add_nvd(comp, records, total, cpe, product_hint=_vendor_product(cpe))
    return [comp]


def _nvd_apps(
    inv: Inventory,
    nvd: NvdClient,
    res: VulnScanResult,
    prog: Progress,
    fuzzy: bool,
    http: HttpClient,
    ttl: timedelta,
) -> list[_Component]:
    comps: list[_Component] = []
    apps = [s for s in inv.software if not s.ecosystem]
    mapped: list[tuple[Software, cpe_map.CpeMatch]] = []
    for s in apps:
        m = cpe_map.lookup(s)
        if m:
            mapped.append((s, m))
        elif s.source.startswith("registry"):
            res.unmatched_apps.append(f"{s.name} {s.version}".strip())
    res.checked["apps_matched_to_cpe"] = len(mapped)
    res.checked["apps_without_cpe_mapping"] = len(res.unmatched_apps)

    for n, (s, m) in enumerate(mapped, 1):
        prog("Checking apps against NVD", n, len(mapped))
        comp = _Component(
            "app",
            _app_label(s),
            s.name,
            m.version,
            Confidence.LIKELY,
            [
                Evidence(
                    s.origin or s.source,
                    f"DisplayName={s.name!r} DisplayVersion={s.version!r} -> NVD version {m.version}",
                )
            ],
            extra={"publisher": s.publisher},
        )
        try:
            for cpe in m.cpe_names():
                records, total = nvd.cves_for_cpe(cpe)
                _add_nvd(comp, records, total, cpe, product_hint=_vendor_product(cpe))
        except FetchError as exc:
            res.skipped.append(Skip(f"NVD lookup for {s.name}", str(exc)))
            if "NVD (apps)" not in res.incomplete:
                res.incomplete.append("NVD (apps)")
            continue
        comps.append(comp)

    if fuzzy and res.unmatched_apps:
        comps += _fuzzy(apps, nvd, http, ttl, res, prog)
    return comps


def _app_label(s: Software) -> str:
    return s.name if not s.version or s.version in s.name else f"{s.name} {s.version}"


def _vendor_product(cpe: str) -> str:
    parts = cpe.split(":")
    return f"{parts[3]}:{parts[4]}"


def _add_nvd(
    comp: _Component, records: list[dict[str, Any]], total: int, cpe: str, product_hint: str
) -> None:
    ids = [r.get("id", "") for r in records]
    comp.evidence.append(
        Evidence(
            f"GET {NVD_CVES}?cpeName={cpe}&isVulnerable",
            f"totalResults={total}: " + ", ".join(ids[:30]) + (" …" if len(ids) > 30 else ""),
        )
    )
    mine = vtuple(comp.version)
    for rec in records:
        cid = str(rec.get("id", ""))
        if not cid or cid in comp.vulns:
            continue
        info = VulnInfo(cve=cid, advisory_id=cid)
        info.summary = next(
            (d.get("value", "") for d in rec.get("descriptions", []) if d.get("lang") == "en"), ""
        )[:300]
        info.cvss, info.cvss_vector = _nvd_cvss(rec.get("metrics", {}))
        info.cvss_source = "NVD" if info.cvss is not None else ""
        info.fixed_in = _nvd_fixed(rec, product_hint, mine)
        comp.vulns[cid] = info


def _nvd_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        entries = metrics.get(key) or []
        entries = sorted(entries, key=lambda e: 0 if e.get("type") == "Primary" else 1)
        for e in entries:
            data = e.get("cvssData", {})
            if "baseScore" in data:
                return float(data["baseScore"]), data.get("vectorString")
    return None, None


def _nvd_fixed(rec: dict[str, Any], product_hint: str, mine: tuple[int, ...]) -> str:
    ends = []
    needle = f":{product_hint}:"
    for cfg in rec.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable") or needle not in m.get("criteria", ""):
                    continue
                end = m.get("versionEndExcluding")
                if end and vtuple(end) > mine:
                    ends.append(end)
    return min(ends, key=vtuple) if ends else ""


def _fuzzy(
    apps: list[Software],
    nvd: NvdClient,
    http: HttpClient,
    ttl: timedelta,
    res: VulnScanResult,
    prog: Progress,
) -> list[_Component]:
    """Keyword-search NVD's CPE dictionary for unmapped apps. Always 'Needs verification'."""
    comps = []
    todo = [
        s
        for s in apps
        if s.source.startswith("registry") and cpe_map.lookup(s) is None and s.version
    ]
    for n, s in enumerate(todo, 1):
        prog("Fuzzy NVD matching", n, len(todo))
        words = [w for w in re.findall(r"[A-Za-z][A-Za-z0-9+]+", s.name) if w.lower() not in _NOISE]
        if not words:
            continue
        try:
            data = http.get_json(
                "https://services.nvd.nist.gov/rest/json/cpes/2.0",
                params={"keywordSearch": " ".join(words[:4]), "resultsPerPage": 50},
                secret_headers=nvd._headers(),
                ttl=ttl,
            ).data
        except FetchError as exc:
            res.skipped.append(Skip(f"Fuzzy NVD search for {s.name}", str(exc)))
            continue
        vp = _best_vendor_product(data, {w.lower() for w in words})
        if not vp:
            continue
        version = ".".join(re.findall(r"\d+", s.version)[:3])
        cpe = f"cpe:2.3:a:{vp}:{version}:*:*:*:*:*:*:*"
        comp = _Component(
            "app",
            _app_label(s),
            s.name,
            version,
            Confidence.NEEDS_VERIFICATION,
            [Evidence(s.origin or s.source, f"DisplayName={s.name!r}; fuzzy CPE guess {vp}")],
            extra={"publisher": s.publisher, "fuzzy": True},
        )
        try:
            records, total = nvd.cves_for_cpe(cpe)
        except FetchError as exc:
            res.skipped.append(Skip(f"NVD lookup for {s.name}", str(exc)))
            continue
        _add_nvd(comp, records, total, cpe, product_hint=vp)
        comps.append(comp)
    return comps


_NOISE = {
    "x64",
    "x86",
    "bit",
    "the",
    "for",
    "and",
    "update",
    "version",
    "edition",
    "setup",
    "installer",
}


def _best_vendor_product(data: dict[str, Any], words: set[str]) -> str | None:
    for p in data.get("products", []):
        name = p.get("cpe", {}).get("cpeName", "")
        parts = name.split(":")
        if len(parts) < 6 or parts[2] != "a" or p.get("cpe", {}).get("deprecated"):
            continue
        prod_words = set(re.split(r"[_\-]", parts[4].lower()))
        if prod_words and prod_words <= words:
            return f"{parts[3]}:{parts[4]}"
    return None


# -- enrichment, severity and findings --------------------------------------------------


def _enrich(
    comps: list[_Component], http: HttpClient, ttl: timedelta, res: VulnScanResult, prog: Progress
) -> None:
    cves = {v.cve for c in comps for v in c.vulns.values() if v.cve.startswith("CVE-")}
    if not cves:
        return
    prog("Loading CISA KEV catalog", 0, 1)
    kev: KevCatalog | None
    try:
        kev = fetch_kev(http, ttl)
        res.kev_version = kev.version
    except FetchError as exc:
        kev = None
        res.skipped.append(Skip("CISA KEV (known exploited) flags", str(exc)))
    prog("Loading FIRST EPSS scores", 0, 1)
    try:
        epss = fetch_epss(http, cves, ttl)
    except FetchError as exc:
        epss = {}
        res.skipped.append(Skip("FIRST EPSS scores", str(exc)))
    for c in comps:
        for v in c.vulns.values():
            if kev and v.cve in kev.entries:
                e = kev.entries[v.cve]
                v.kev, v.kev_date_added, v.kev_ransomware = True, e.date_added, e.ransomware
            if v.cve in epss:
                v.epss, v.epss_percentile = epss[v.cve]


def vuln_severity(v: VulnInfo) -> Severity | None:
    sev = cvss.severity_for(v.cvss) or _PRIORITY.get(v.distro_priority.lower())
    if v.kev and (sev is None or sev.rank > Severity.HIGH.rank):
        sev = Severity.HIGH
    return sev


def _finding(c: _Component) -> Finding:
    vulns = sorted(c.vulns.values(), key=VulnInfo.sort_key)
    sevs = [s for s in (vuln_severity(v) for v in vulns) if s is not None]
    severity = min(sevs, key=lambda s: s.rank) if sevs else Severity.MEDIUM
    n_kev = sum(v.kev for v in vulns)
    fixes = [v.fixed_in for v in vulns if v.fixed_in]
    fixed = max(fixes, key=vtuple) if fixes else ""
    title = f"{c.label}: {len(vulns)} known vulnerabilit{'y' if len(vulns) == 1 else 'ies'}"
    if n_kev:
        title += f" ({n_kev} known exploited)"
    fid = "HG-VULN-" + hashlib.sha256(f"{c.kind}|{c.label}".encode()).hexdigest()[:10].upper()
    refs = _references(c, vulns)
    remediation, retest = _remediation(c, fixed)
    if not sevs:
        remediation += (
            " (No CVSS score or distro priority was published; severity defaulted to medium.)"
        )
    return Finding(
        id=fid,
        title=title,
        severity=severity,
        confidence=c.confidence,
        component=c.label,
        evidence=c.evidence,
        remediation=remediation,
        references=refs,
        retest=retest,
        category="vuln",
        vulns=vulns,
    )


def _references(c: _Component, vulns: list[VulnInfo]) -> list[str]:
    refs: list[str] = []
    for v in vulns[:5]:
        if v.cve.startswith("CVE-"):
            refs.append(f"https://nvd.nist.gov/vuln/detail/{v.cve}")
        for adv in [v.advisory_id, *v.related][:2]:
            if adv and not adv.startswith("CVE-"):
                refs.append(f"https://osv.dev/vulnerability/{adv}")
    if any(v.kev for v in vulns):
        refs.append(KEV_URL)
    if c.kind == "windows-os":
        refs.append(WINDOWS_UPDATE_URL)
    return list(dict.fromkeys(refs))


def _remediation(c: _Component, fixed: str) -> tuple[str, str]:
    if c.kind == "pypi":
        spec = f'"{c.name}>={fixed}"' if fixed else c.name
        return (
            f"In the Python environment {c.extra['env']}, upgrade the package: "
            f"python -m pip install --upgrade {spec}."
            + (
                ""
                if fixed
                else " At least one advisory lists no fixed version; read the advisories."
            )
            + " Then re-run your project's tests.",
            f'Run `hostguard vulns --python-env "{c.extra["env"]}"`; {c.name} should report no vulnerabilities'
            + (f" once version >= {fixed} is installed." if fixed else "."),
        )
    if c.kind == "distro":
        bins = " ".join(c.extra.get("binaries", [])[:10])
        return (
            "Install the distribution's security updates, e.g. `sudo apt update && sudo apt install --only-upgrade "
            f"{bins}` (or your distro's equivalent)."
            + (
                f" Fixed in {c.name} {fixed}."
                if fixed
                else " At least one advisory has no fix published yet by the distribution; monitor its security notices."
            ),
            f"Run `hostguard vulns`; the {c.name} source package should report no vulnerabilities"
            + (
                f" once version {fixed} or later is installed."
                if fixed
                else " once the distribution ships fixes."
            ),
        )
    if c.kind == "windows-os":
        return (
            "Open Settings > Windows Update, select 'Check for updates', install all available updates and restart. "
            "This result comes from NVD's CPE data; confirm against Microsoft's Security Update Guide "
            "(https://msrc.microsoft.com/update-guide) for your exact build.",
            "After updating and restarting, run `hostguard vulns`; the build number shown should be higher and the "
            "CVE count should drop to zero.",
        )
    pub = c.extra.get("publisher") or "the vendor"
    return (
        f"Update {c.name} to the latest version from {pub} (use the app's built-in updater or the vendor's "
        "official download page)."
        + (f" NVD lists fixes up to version {fixed}." if fixed else "")
        + " If you no longer need the app, uninstall it."
        + (
            " This match came from a fuzzy name search: first confirm the CVEs really concern this product."
            if c.extra.get("fuzzy")
            else ""
        ),
        f"Run `hostguard vulns`; {c.name} should no longer be listed"
        + (f" once version {fixed} or later is installed." if fixed else " once updated."),
    )
