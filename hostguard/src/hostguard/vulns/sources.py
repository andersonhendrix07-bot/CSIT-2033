"""Clients for the vulnerability data sources, built on the allowlisted HttpClient.

Endpoints and limits were taken from each provider's documentation on 2026-10-12:
- OSV:  POST /v1/querybatch (ids only, paginated per query), GET /v1/vulns/{id}
- NVD:  GET /rest/json/cves/2.0 with cpeName + isVulnerable, or cveId;
        API key in the `apiKey` request header; default/maximum page size 2000
- KEV:  JSON feed at cisa.gov (catalogVersion, vulnerabilities[cveID, ...])
- EPSS: GET api.first.org/data/v1/epss?cve=a,b,c (cve parameter <= 2000 chars)
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from hostguard.credentials import Secret
from hostguard.net import FetchError, HttpClient, cache_key

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
NVD_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"

OSV_BATCH_SIZE = 500
OSV_MAX_PAGES = 20
NVD_MAX_RESULTS = 5000
EPSS_PARAM_LIMIT = 2000


@dataclass
class OsvQuery:
    ecosystem: str
    name: str
    version: str


class OsvClient:
    def __init__(self, http: HttpClient, ttl: timedelta) -> None:
        self.http = http
        self.ttl = ttl

    def query_batch(self, queries: list[OsvQuery]) -> list[list[str]]:
        """Vulnerability IDs for each query, in the same order.

        Results are cached per package (not per batch) so a changed package list
        still reuses earlier answers, including in offline mode.
        """
        results: list[list[str] | None] = []
        for q in queries:
            hit = self.http.lookup(self._key(q), self._label(q), self.ttl)
            results.append(list(hit) if isinstance(hit, list) else None)
        misses = [i for i, r in enumerate(results) if r is None]
        if misses and self.http.offline:
            raise FetchError(f"offline mode and no cached OSV result for {len(misses)} package(s)")
        for start in range(0, len(misses), OSV_BATCH_SIZE):
            chunk = misses[start : start + OSV_BATCH_SIZE]
            found: dict[int, list[str]] = {i: [] for i in chunk}
            pending: dict[int, str | None] = {i: None for i in chunk}
            for _page in range(OSV_MAX_PAGES):
                if not pending:
                    break
                order = list(pending)
                body = {"queries": [self._q(queries[i], pending[i]) for i in order]}
                data = self.http.post_json(OSV_BATCH, body, ttl=timedelta(0)).data
                nxt: dict[int, str | None] = {}
                for i, res in zip(order, data.get("results", []), strict=False):
                    found[i] += [v["id"] for v in res.get("vulns", []) if "id" in v]
                    if res.get("next_page_token"):
                        nxt[i] = res["next_page_token"]
                pending = nxt
            for i in chunk:
                results[i] = found[i]
                self.http.remember(self._key(queries[i]), self._label(queries[i]), found[i])
        return [r or [] for r in results]

    @staticmethod
    def _key(q: OsvQuery) -> str:
        return cache_key("OSV-QUERY", f"{q.ecosystem}|{q.name}|{q.version}", None, None)

    @staticmethod
    def _label(q: OsvQuery) -> str:
        return f"{OSV_BATCH} ({q.ecosystem} {q.name} {q.version})"

    @staticmethod
    def _q(q: OsvQuery, token: str | None) -> dict[str, Any]:
        d: dict[str, Any] = {
            "package": {"name": q.name, "ecosystem": q.ecosystem},
            "version": q.version,
        }
        if token:
            d["page_token"] = token
        return d

    def vuln(self, vid: str) -> dict[str, Any]:
        data = self.http.get_json(OSV_VULN + vid, ttl=self.ttl).data
        return data if isinstance(data, dict) else {}


class NvdClient:
    def __init__(self, http: HttpClient, ttl: timedelta, api_key: Secret | None) -> None:
        self.http = http
        self.ttl = ttl
        self.api_key = api_key

    def _headers(self) -> dict[str, str] | None:
        return {"apiKey": self.api_key.reveal()} if self.api_key else None

    def cves_for_cpe(self, cpe_name: str) -> tuple[list[dict[str, Any]], int]:
        """CVE records whose configurations mark this exact CPE as vulnerable."""
        out: list[dict[str, Any]] = []
        start, total = 0, 0
        while True:
            params = {"cpeName": cpe_name, "isVulnerable": "", "startIndex": start}
            data = self.http.get_json(
                NVD_CVES, params=params, secret_headers=self._headers(), ttl=self.ttl
            ).data
            total = int(data.get("totalResults", 0))
            batch = [v["cve"] for v in data.get("vulnerabilities", []) if "cve" in v]
            out += batch
            start += len(batch)
            if not batch or start >= total or start >= NVD_MAX_RESULTS:
                return out, total

    def cve(self, cve_id: str) -> dict[str, Any] | None:
        data = self.http.get_json(
            NVD_CVES, params={"cveId": cve_id}, secret_headers=self._headers(), ttl=self.ttl
        ).data
        vulns = data.get("vulnerabilities", [])
        return vulns[0]["cve"] if vulns else None


@dataclass
class KevEntry:
    cve: str
    date_added: str
    ransomware: str
    required_action: str
    due_date: str
    name: str


@dataclass
class KevCatalog:
    version: str
    entries: dict[str, KevEntry] = field(default_factory=dict)


def fetch_kev(http: HttpClient, ttl: timedelta) -> KevCatalog:
    data = http.get_json(KEV_FEED, ttl=ttl).data
    cat = KevCatalog(str(data.get("catalogVersion", "")))
    for v in data.get("vulnerabilities", []):
        cid = v.get("cveID")
        if cid:
            cat.entries[cid] = KevEntry(
                cid,
                str(v.get("dateAdded", "")),
                str(v.get("knownRansomwareCampaignUse", "")),
                str(v.get("requiredAction", "")),
                str(v.get("dueDate", "")),
                str(v.get("vulnerabilityName", "")),
            )
    return cat


def fetch_epss(
    http: HttpClient, cves: Iterable[str], ttl: timedelta
) -> dict[str, tuple[float, float]]:
    """CVE -> (epss probability, percentile)."""
    ids = sorted({c for c in cves if c.startswith("CVE-")})
    out: dict[str, tuple[float, float]] = {}
    for chunk in _chunks_by_length(ids, EPSS_PARAM_LIMIT):
        data = http.get_json(EPSS_API, params={"cve": ",".join(chunk)}, ttl=ttl).data
        for row in data.get("data", []):
            try:
                out[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, TypeError, ValueError):
                continue
    return out


def _chunks_by_length(items: list[str], limit: int) -> Iterable[list[str]]:
    chunk: list[str] = []
    length = 0
    for it in items:
        extra = len(it) + (1 if chunk else 0)
        if chunk and length + extra > limit:
            yield chunk
            chunk, length = [], 0
            extra = len(it)
        chunk.append(it)
        length += extra
    if chunk:
        yield chunk
