from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from hostguard.credentials import Secret
from hostguard.inventory.models import Inventory, OsInfo, PythonPackage, Software
from hostguard.models import Confidence, Evidence, Severity, VulnInfo
from hostguard.net import HttpClient, JsonCache
from hostguard.vulns import cpe_map, cvss, matcher, sources

FIX = Path(__file__).parent.parent / "fixtures"


def fixture(name: str) -> Any:
    return json.loads((FIX / name).read_text(encoding="utf-8"))


# --- CVSS -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        # Scores as published by NVD for these vectors.
        ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8),  # CVE-2024-11477
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", 8.6),  # CVE-2019-10906
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # CVE-2021-44228
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L", 4.1),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss_base_scores(vector: str, score: float) -> None:
    assert cvss.base_score_v3(vector) == score


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "CVSS:2.0/AV:N",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "CVSS:3.1/AV:N/AC:L",
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Q/C:H/I:H/A:H",
        "CVSS:3.1/garbage",
    ],
)
def test_cvss_malformed(vector: str) -> None:
    assert cvss.base_score_v3(vector) is None


def test_severity_scale() -> None:
    assert [cvss.severity_for(x) for x in (None, 0.0, 0.1, 4.0, 7.0, 9.0)] == [
        None,
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]


def test_kev_bumps_severity_and_priority_fallback() -> None:
    assert matcher.vuln_severity(VulnInfo("CVE-1", cvss=3.0, kev=True)) == Severity.HIGH
    assert matcher.vuln_severity(VulnInfo("CVE-1", cvss=9.8, kev=True)) == Severity.CRITICAL
    assert matcher.vuln_severity(VulnInfo("CVE-1", distro_priority="medium")) == Severity.MEDIUM
    assert matcher.vuln_severity(VulnInfo("CVE-1")) is None


def test_ranking_kev_then_epss_then_cvss() -> None:
    vs = [
        VulnInfo("A", cvss=10.0, epss=0.01),
        VulnInfo("B", cvss=5.0, epss=0.9),
        VulnInfo("C", cvss=2.0, epss=0.0, kev=True),
        VulnInfo("D", cvss=9.0, epss=0.01),
    ]
    assert [v.cve for v in sorted(vs, key=VulnInfo.sort_key)] == ["C", "B", "A", "D"]


# --- CPE mapping ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "version", "expected"),
    [
        ("7-Zip 23.01 (x64)", "23.01", ("7-zip:7-zip", "23.01")),
        ("7-Zip 24.08 (x64)", "24.08.00.0", ("7-zip:7-zip", "24.08")),
        ("Python 3.13.14 (64-bit)", "3.13.14150.0", ("python:python", "3.13.14")),
        ("Mozilla Firefox (x64 en-US)", "131.0.3", ("mozilla:firefox", "131.0.3")),
        ("Mozilla Firefox ESR (x64 en-US)", "128.3.1", ("mozilla:firefox_esr", "128.3.1")),
        ("Google Chrome", "141.0.7390.55", ("google:chrome", "141.0.7390.55")),
        ("Brave", "130.1.71.118", ("brave:brave", "1.71.118")),
        ("Notepad++ (64-bit x64)", "8.7.1", ("notepad-plus-plus:notepad\\+\\+", "8.7.1")),
        ("PuTTY release 0.81 (64-bit)", "0.81.0.0", ("putty:putty", "0.81")),
        ("Microsoft .NET Runtime - 8.0.10 (x64)", "8.0.10.34118", ("microsoft:.net", "8.0.10")),
    ],
)
def test_cpe_lookup(name: str, version: str, expected: tuple[str, str]) -> None:
    m = cpe_map.lookup(Software(name, version, "registry:HKLM"))
    assert m is not None
    assert (m.product.cpes[0], m.version) == expected
    assert m.cpe_names()[0] == f"cpe:2.3:a:{expected[0]}:{expected[1]}:*:*:*:*:*:*:*"


@pytest.mark.parametrize(
    ("name", "version"),
    [
        ("Python Launcher", "3.13.14150.0"),
        ("Python 3.13.14 Add to Path (64-bit)", "3.13.14150.0"),
        ("Some Unknown App", "1.0"),
        ("Google Chrome", ""),
        ("Google Chrome", "beta"),
        ("FileZilla Server", "1.8.0"),
    ],
)
def test_cpe_lookup_rejects(name: str, version: str) -> None:
    assert cpe_map.lookup(Software(name, version, "registry:HKLM")) is None


def test_notepad_queries_both_vendors() -> None:
    m = cpe_map.lookup(Software("Notepad++ (64-bit x64)", "8.7.1", "registry:HKLM"))
    assert m is not None and len(m.cpe_names()) == 2


def win11_home() -> OsInfo:
    return OsInfo(
        "windows",
        "Windows 11 Home",
        "10.0.26200.6899",
        build="26200",
        ubr=6899,
        display_version="25H2",
        edition_id="Core",
        arch="AMD64",
        evidence=[Evidence("registry HKLM\\...\\CurrentVersion", "UBR=6899")],
    )


def test_windows_os_cpe() -> None:
    assert (
        cpe_map.windows_os_cpe(win11_home())
        == "cpe:2.3:o:microsoft:windows_11_25h2:10.0.26200.6899:*:*:*:*:*:x64:*"
    )
    server = win11_home()
    server.edition_id = "ServerDatacenter"
    assert cpe_map.windows_os_cpe(server) is None
    no_ubr = win11_home()
    no_ubr.ubr = None
    assert cpe_map.windows_os_cpe(no_ubr) is None


# --- matcher end to end (mocked network, real response shapes) ---------------------


WIN_CPE = "cpe:2.3:o:microsoft:windows_11_25h2:10.0.26200.6899:*:*:*:*:*:x64:*"
ZIP_CPE = "cpe:2.3:a:7-zip:7-zip:23.01:*:*:*:*:*:*:*"


class Router:
    """Mock NVD/OSV/KEV/EPSS endpoints with saved real responses."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.fail: set[str] = set()
        win = fixture("nvd_cves_win11_24h2_page1.json")
        win["totalResults"] = len(win["vulnerabilities"])
        self.win = win
        self.win_ids = [v["cve"]["id"] for v in win["vulnerabilities"]]
        page1 = fixture("nvd_cves_7zip_23.01_page1.json")
        one = fixture("nvd_cve_CVE-2024-11477.json")
        page1["totalResults"] = len(page1["vulnerabilities"]) + 1
        # Synthetic second page: a copy of a real record under a made-up ID, to test pagination.
        extra = json.loads(json.dumps(one["vulnerabilities"][0]))
        extra["cve"]["id"] = "CVE-2099-0001"
        page2 = dict(page1, vulnerabilities=[extra], startIndex=len(page1["vulnerabilities"]))
        self.zip_pages = {"0": page1, str(len(page1["vulnerabilities"])): page2}
        kev = fixture("kev_sample.json")
        # Synthetic: mark one Windows CVE as known exploited to test ranking.
        kev["vulnerabilities"].append(
            {
                "cveID": self.win_ids[-1],
                "dateAdded": "2026-01-01",
                "knownRansomwareCampaignUse": "Known",
                "requiredAction": "Apply updates",
                "dueDate": "2026-01-22",
                "vulnerabilityName": "test",
            }
        )
        self.kev = kev

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        host, path = req.url.host, req.url.path
        for f in self.fail:
            if f in str(req.url):
                return httpx.Response(500)
        if host == "api.osv.dev" and path == "/v1/querybatch":
            body = json.loads(req.content)
            results = []
            for q in body["queries"]:
                if q["package"]["name"] == "jinja2":
                    results.append({"vulns": [{"id": "GHSA-462w-v97r-4m45"}]})
                else:
                    results.append({})
            return httpx.Response(200, json={"results": results})
        if host == "api.osv.dev" and path.startswith("/v1/vulns/"):
            return httpx.Response(200, json=fixture(f"osv_vuln_{path.rsplit('/', 1)[1]}.json"))
        if host == "services.nvd.nist.gov" and path.endswith("/cves/2.0"):
            cpe = req.url.params.get("cpeName")
            if cpe == WIN_CPE:
                return httpx.Response(200, json=self.win)
            if cpe == ZIP_CPE:
                return httpx.Response(
                    200, json=self.zip_pages[req.url.params.get("startIndex", "0")]
                )
            return httpx.Response(200, json=fixture("nvd_cves_empty.json"))
        if host == "services.nvd.nist.gov" and path.endswith("/cpes/2.0"):
            return httpx.Response(
                200,
                json={
                    "products": [
                        {
                            "cpe": {
                                "cpeName": "cpe:2.3:a:acme:foo_editor:1.0:*:*:*:*:*:*:*",
                                "deprecated": False,
                            }
                        }
                    ]
                },
            )
        if host == "www.cisa.gov":
            return httpx.Response(200, json=self.kev)
        if host == "api.first.org":
            ids = req.url.params["cve"].split(",")
            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "cve": c,
                            "epss": "0.5" if c == "CVE-2024-11477" else "0.01",
                            "percentile": "0.9",
                            "date": "2026-10-12",
                        }
                        for c in ids
                    ]
                },
            )
        return httpx.Response(404)


def target_inventory() -> Inventory:
    return Inventory(
        os=win11_home(),
        software=[
            Software(
                "7-Zip 23.01 (x64)",
                "23.01",
                "registry:HKLM",
                publisher="Igor Pavlov",
                origin="registry HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\7-Zip",
            ),
            Software("Foo Editor", "1.0", "registry:HKCU"),
            Software("Microsoft.WindowsCalculator", "11.0", "appx"),
        ],
        python_packages=[
            PythonPackage(
                "jinja2",
                "2.10",
                "C:\\proj\\.venv",
                Evidence("file C:\\proj\\.venv\\...\\METADATA", "Name: Jinja2"),
            )
        ],
    )


def run_scan(tmp_path: Path, router: Router, **kw: Any) -> matcher.VulnScanResult:
    http = HttpClient(
        JsonCache(tmp_path / "c"), transport=httpx.MockTransport(router), sleep=lambda s: None
    )
    with http:
        return matcher.scan(target_inventory(), http, nvd_key=kw.pop("nvd_key", None), **kw)


def test_scan_end_to_end(tmp_path: Path) -> None:
    router = Router()
    res = run_scan(tmp_path, router)
    by_kind = {f.component.split(" ")[0]: f for f in res.findings}
    assert set(by_kind) == {"Windows", "7-Zip", "jinja2"}

    # Ranking: the finding with a known-exploited CVE comes first.
    assert res.findings[0].component.startswith("Windows")
    assert res.findings[0].vulns[0].kev and "known exploited" in res.findings[0].title

    win = by_kind["Windows"]
    assert win.confidence == Confidence.NEEDS_VERIFICATION
    assert any(WIN_CPE in e.source for e in win.evidence)
    assert "Windows Update" in win.remediation

    z = by_kind["7-Zip"]
    assert z.confidence == Confidence.LIKELY
    assert len(z.vulns) == 4  # 3 from page 1 + 1 from page 2 (pagination)
    top = z.vulns[0]
    assert top.cve == "CVE-2024-11477"  # highest EPSS
    assert (top.cvss, top.cvss_source, top.epss) == (7.8, "NVD", 0.5)
    assert top.fixed_in == "24.07"
    assert "Uninstall\\7-Zip" in z.evidence[0].source
    assert "https://nvd.nist.gov/vuln/detail/CVE-2024-11477" in z.references
    assert "25.00 or later" in z.retest  # the highest fix across its CVEs
    assert z.title == "7-Zip 23.01 (x64): 4 known vulnerabilities"

    j = by_kind["jinja2"]
    assert j.confidence == Confidence.CONFIRMED
    v = j.vulns[0]
    assert (v.cve, v.advisory_id, v.cvss, v.fixed_in) == (
        "CVE-2019-10906",
        "GHSA-462w-v97r-4m45",
        8.6,
        "2.10.1",
    )
    assert v.cvss_source.startswith("computed")
    assert 'pip install --upgrade "jinja2>=2.10.1"' in j.remediation
    assert any("querybatch" in e.source for e in j.evidence)

    assert res.unmatched_apps == ["Foo Editor 1.0"]  # appx entries are not counted
    assert res.kev_version and res.notices[0].startswith("This product uses the NVD API")
    assert res.checked["apps_matched_to_cpe"] == 1
    for f in res.findings:
        assert f.evidence and f.remediation and f.retest and f.references


def test_api_key_sent_only_to_nvd_header(tmp_path: Path) -> None:
    router = Router()
    key = "nvd-test-key-123456789"
    run_scan(tmp_path, router, nvd_key=Secret("NVD_API_KEY", key, "env"))
    for r in router.requests:
        if r.url.host == "services.nvd.nist.gov":
            assert r.headers["apiKey"] == key
        else:
            assert "apikey" not in r.headers
        assert key not in str(r.url)


def test_source_failures_become_skips(tmp_path: Path) -> None:
    router = Router()
    router.fail = {"querybatch", "known_exploited"}
    res = run_scan(tmp_path, router)
    what = " ".join(s.what for s in res.skipped)
    assert "OSV.dev" in what and "CISA KEV" in what
    assert {f.component.split(" ")[0] for f in res.findings} == {"Windows", "7-Zip"}
    assert not any(v.kev for f in res.findings for v in f.vulns)


def test_fuzzy_matching_is_needs_verification(tmp_path: Path) -> None:
    router = Router()
    res = run_scan(tmp_path, router, fuzzy=True)
    assert any("cpes/2.0" in str(r.url) for r in router.requests)
    # The fuzzy CPE for Foo Editor returns no CVEs here, so no finding, but the query happened
    # with the derived CPE name.
    assert "cpe:2.3:a:acme:foo_editor:1.0:*:*:*:*:*:*:*" in [
        r.url.params.get("cpeName") for r in router.requests
    ]
    assert all(
        f.confidence != Confidence.NEEDS_VERIFICATION or "fuzzy" not in f.remediation
        for f in res.findings
        if not f.component.startswith("Windows")
    )


def test_os_and_apps_can_be_disabled(tmp_path: Path) -> None:
    router = Router()
    res = run_scan(tmp_path, router, include_os=False, include_apps=False)
    assert [f.component.split(" ")[0] for f in res.findings] == ["jinja2"]
    assert not any(r.url.host == "services.nvd.nist.gov" for r in router.requests)


def test_epss_chunking() -> None:
    ids = [f"CVE-2024-{i:05d}" for i in range(400)]
    chunks = list(sources._chunks_by_length(ids, 2000))
    assert sum(len(c) for c in chunks) == 400
    assert all(len(",".join(c)) <= 2000 for c in chunks)


def test_distro_component_grouping(tmp_path: Path) -> None:
    """Binary packages sharing a source package are queried once, by source name/version."""
    inv = Inventory(
        os=OsInfo("linux", "Ubuntu 24.04.5 LTS", "6.8"),
        software=[
            Software(
                "libssl3t64",
                "3.0.13-0ubuntu3",
                "dpkg",
                ecosystem="Ubuntu:24.04:LTS",
                package="openssl",
                package_version="3.0.13-0ubuntu3",
                origin="dpkg-query -W",
            ),
            Software(
                "openssl",
                "3.0.13-0ubuntu3",
                "dpkg",
                ecosystem="Ubuntu:24.04:LTS",
                package="openssl",
                package_version="3.0.13-0ubuntu3",
                origin="dpkg-query -W",
            ),
        ],
    )
    seen: list[Any] = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/querybatch":
            seen.append(json.loads(req.content))
            return httpx.Response(
                200, json={"results": [{"vulns": [{"id": "UBUNTU-CVE-2024-13176"}]}]}
            )
        if req.url.path.startswith("/v1/vulns/"):
            return httpx.Response(200, json=fixture("osv_vuln_UBUNTU-CVE-2024-13176.json"))
        if req.url.host == "www.cisa.gov":
            return httpx.Response(200, json=fixture("kev_sample.json"))
        if req.url.host == "api.first.org":
            return httpx.Response(200, json=fixture("epss_3cves.json"))
        return httpx.Response(404)

    with HttpClient(
        JsonCache(tmp_path / "c"), transport=httpx.MockTransport(handler), sleep=lambda s: None
    ) as http:
        res = matcher.scan(inv, http, nvd_key=None, ttl=timedelta(hours=1))
    assert seen[0]["queries"] == [
        {
            "package": {"name": "openssl", "ecosystem": "Ubuntu:24.04:LTS"},
            "version": "3.0.13-0ubuntu3",
        }
    ]
    f = res.findings[0]
    assert f.confidence == Confidence.CONFIRMED and "libssl3t64" in f.remediation
    v = f.vulns[0]
    assert v.cve == "CVE-2024-13176" and v.distro_priority == "low" and v.cvss == 4.1
    assert v.epss == pytest.approx(0.00613)


def test_kernel_headers_only_are_skipped(tmp_path: Path) -> None:
    inv = Inventory(
        os=OsInfo("linux", "Ubuntu", "6.18"),
        software=[
            Software(
                "linux-libc-dev",
                "6.8.0-146.146",
                "dpkg",
                ecosystem="Ubuntu:24.04:LTS",
                package="linux",
                package_version="6.8.0-146.146",
                origin="dpkg-query -W",
            ),
        ],
    )

    def handler(req: httpx.Request) -> httpx.Response:
        raise AssertionError(f"no query expected, got {req.url}")

    with HttpClient(JsonCache(tmp_path / "c"), transport=httpx.MockTransport(handler)) as http:
        res = matcher.scan(inv, http, nvd_key=None)
    assert res.findings == []
    assert "headers/tools" in res.skipped[0].reason and res.checked["distro_source_packages"] == 0


def test_kernel_with_image_is_checked() -> None:
    assert matcher._kernel_without_image("linux", ["linux-libc-dev"])
    assert not matcher._kernel_without_image(
        "linux", ["linux-image-6.8.0-146-generic", "linux-libc-dev"]
    )
    assert not matcher._kernel_without_image("linux-firmware", ["linux-firmware"])
    assert not matcher._kernel_without_image("openssl", ["libssl3t64"])


def test_osv_cache_is_per_package_and_works_offline(tmp_path: Path) -> None:
    """Regression: a changed package list must still reuse cached OSV answers (also offline)."""
    router = Router()
    cache = JsonCache(tmp_path / "c")
    with HttpClient(cache, transport=httpx.MockTransport(router), sleep=lambda s: None) as http:
        first = matcher.scan(
            target_inventory(), http, nvd_key=None, include_os=False, include_apps=False
        )
    assert len(first.findings) == 1

    inv = target_inventory()
    inv.python_packages.append(
        PythonPackage("newpkg", "1.0", "C:\\proj\\.venv", Evidence("file METADATA", "Name: newpkg"))
    )

    def offline_handler(req: httpx.Request) -> httpx.Response:
        raise AssertionError("offline must not touch the network")

    with HttpClient(cache, offline=True, transport=httpx.MockTransport(offline_handler)) as http:
        res = matcher.scan(inv, http, nvd_key=None, include_os=False, include_apps=False)
    # newpkg was never looked up, so the OSV source is incomplete rather than "clean".
    assert res.incomplete == ["OSV.dev"]

    router2 = Router()
    with HttpClient(cache, transport=httpx.MockTransport(router2), sleep=lambda s: None) as http:
        res = matcher.scan(inv, http, nvd_key=None, include_os=False, include_apps=False)
    batch = [json.loads(r.content) for r in router2.requests if r.url.path == "/v1/querybatch"]
    assert batch == [
        {"queries": [{"package": {"name": "newpkg", "ecosystem": "PyPI"}, "version": "1.0"}]}
    ]
    assert len(res.findings) == 1 and not res.incomplete


def test_offline_with_cache_reports_findings(tmp_path: Path) -> None:
    cache = JsonCache(tmp_path / "c")
    with HttpClient(cache, transport=httpx.MockTransport(Router()), sleep=lambda s: None) as http:
        online = matcher.scan(target_inventory(), http, nvd_key=None)

    def offline_handler(req: httpx.Request) -> httpx.Response:
        raise AssertionError("offline must not touch the network")

    with HttpClient(cache, offline=True, transport=httpx.MockTransport(offline_handler)) as http:
        offline = matcher.scan(target_inventory(), http, nvd_key=None)
    assert [f.id for f in offline.findings] == [f.id for f in online.findings]
    assert not offline.incomplete


def test_multi_cve_notice_merges_fix_into_each_cve(tmp_path: Path) -> None:
    """Regression: a USN covering several CVEs must not be dropped; its fix applies to each CVE."""
    q = sources.OsvQuery("Ubuntu:24.04:LTS", "poppler", "24.02.0-1ubuntu9.9")
    per_cve = {
        "id": "UBUNTU-CVE-2026-93312",
        "upstream": ["CVE-2026-93312"],
        "severity": [{"type": "Ubuntu", "score": "medium"}],
        "affected": [
            {
                "package": {"name": "poppler", "ecosystem": "Ubuntu:24.04:LTS"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            }
        ],
    }
    usn = {
        "id": "USN-8894-1",
        "upstream": ["CVE-2026-93312", "CVE-2026-93313", "UBUNTU-CVE-2026-93312"],
        "affected": [
            {
                "package": {"name": "poppler", "ecosystem": "Ubuntu:24.04:LTS"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "24.02.0-1ubuntu9.10"}],
                    }
                ],
            }
        ],
    }
    infos = matcher._from_osv(usn, q)
    assert [i.cve for i in infos] == ["CVE-2026-93312", "CVE-2026-93313"]
    assert all(i.fixed_in == "24.02.0-1ubuntu9.10" for i in infos)
    base = matcher._from_osv(per_cve, q)[0]
    assert base.fixed_in == "" and base.distro_priority == "medium"
    matcher._merge(base, infos[0])
    assert base.fixed_in == "24.02.0-1ubuntu9.10"  # fix learned from the USN
    assert base.distro_priority == "medium" and base.related == ["USN-8894-1"]
