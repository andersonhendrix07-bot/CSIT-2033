"""The only way hostguard talks to the network.

- HTTPS only, and only to hosts in APPROVED_HOSTS (the data sources in the
  approved plan). Anything else raises NetworkPolicyError before a socket opens.
- Redirects are not followed, so a response cannot bounce us to another host.
- Per-host pacing follows each provider's documented rate limit; 429/5xx are
  retried with backoff that honours Retry-After.
- Every JSON response is cached on disk with its fetch time. In offline mode,
  or when the network fails, cached data is used and recorded as stale so the
  report can warn about it.
- Secret headers (API keys) are never part of cache keys, cache files or logs.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from hostguard import __version__
from hostguard.logsetup import get_logger

log = get_logger("net")

USER_AGENT = f"hostguard/{__version__} (local host security tool)"
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
RETRY_STATUSES = {429, 500, 502, 503, 504}
MAX_ATTEMPTS = 4
MAX_RETRY_AFTER = 60.0


@dataclass(frozen=True)
class HostPolicy:
    min_interval: float  # seconds between requests to this host
    keyed_min_interval: float | None = None  # when an API key is in use
    doc: str = ""


# Only these hosts may be contacted. Intervals come from each provider's docs
# (checked 2026-10-12):
#   NVD: 5 req / rolling 30 s without key, 50 with key; NVD recommends ~6 s sleeps.
#   FIRST API: 1000 req / minute unauthenticated.
#   OSV: "currently there are no limits on the API" -- we still pace politely.
APPROVED_HOSTS: dict[str, HostPolicy] = {
    "services.nvd.nist.gov": HostPolicy(6.0, 0.6, "https://nvd.nist.gov/developers/start-here"),
    "api.osv.dev": HostPolicy(0.05, None, "https://google.github.io/osv.dev/api/"),
    "www.cisa.gov": HostPolicy(
        1.0, None, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    ),
    "api.first.org": HostPolicy(0.2, None, "https://api.first.org/epss/"),
    # VirusTotal public API: 4 requests/minute, 500/day (docs.virustotal.com). Hash lookups only.
    "www.virustotal.com": HostPolicy(15.5, 15.5, "https://docs.virustotal.com/reference/file-info"),
}


class NetworkPolicyError(Exception):
    """A request to a host or scheme outside the approved plan."""


class FetchError(Exception):
    """Network request failed and no cached copy exists."""


@dataclass
class SourceUse:
    """Provenance of data used in a run (shown in reports)."""

    url: str
    fetched_at: str
    from_cache: bool
    stale: bool


@dataclass
class FetchResult:
    data: Any
    fetched_at: datetime
    from_cache: bool
    stale: bool


@dataclass
class _HostState:
    lock: threading.Lock = field(default_factory=threading.Lock)
    last: float = 0.0


class JsonCache:
    """Timestamped JSON cache, one file per request."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def _path(self, key: str) -> Path:
        return self.root / "http" / key[:2] / f"{key}.json"

    def get(self, key: str) -> tuple[Any, datetime] | None:
        p = self._path(key)
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            return raw["data"], datetime.fromisoformat(raw["fetched_at"])
        except (OSError, ValueError, KeyError):
            return None

    def put(self, key: str, url: str, data: Any, fetched_at: datetime) -> None:
        p = self._path(key)
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = p.with_suffix(".tmp")
        payload = {"url": url, "fetched_at": fetched_at.isoformat(), "data": data}
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        tmp.replace(p)


def cache_key(method: str, url: str, params: Mapping[str, Any] | None, body: Any) -> str:
    material = json.dumps(
        [method.upper(), url, sorted((params or {}).items()), body], sort_keys=True, default=str
    )
    return hashlib.sha256(material.encode()).hexdigest()


def check_url(url: str) -> HostPolicy:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise NetworkPolicyError(f"only HTTPS is allowed: {url}")
    host = (parts.hostname or "").lower()
    if host not in APPROVED_HOSTS:
        raise NetworkPolicyError(f"host not in the approved data-source list: {host}")
    if parts.username or parts.password or (parts.port not in (None, 443)):
        raise NetworkPolicyError(f"credentials or non-standard ports in URLs are refused: {host}")
    return APPROVED_HOSTS[host]


class HttpClient:
    def __init__(
        self,
        cache: JsonCache,
        *,
        offline: bool = False,
        transport: httpx.BaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        timeout: float = 60.0,
    ) -> None:
        self.cache = cache
        self.offline = offline
        self._clock = clock
        self._sleep = sleep
        self._hosts: dict[str, _HostState] = {}
        self._hosts_lock = threading.Lock()
        self.sources: list[SourceUse] = []
        self._client = httpx.Client(
            transport=transport,
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            trust_env=True,  # honours HTTPS_PROXY and SSL_CERT_FILE
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- public API -------------------------------------------------------

    def get_json(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        secret_headers: Mapping[str, str] | None = None,
        ttl: timedelta = timedelta(hours=24),
        missing_ok: bool = False,
    ) -> FetchResult:
        """`missing_ok`: an HTTP 404 is a valid answer (data None) rather than an error."""
        return self._request(
            "GET",
            url,
            params=params,
            body=None,
            secret_headers=secret_headers,
            ttl=ttl,
            missing_ok=missing_ok,
        )

    def post_json(
        self, url: str, body: Any, *, ttl: timedelta = timedelta(hours=24)
    ) -> FetchResult:
        return self._request("POST", url, params=None, body=body, secret_headers=None, ttl=ttl)

    # -- internals --------------------------------------------------------

    def _request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None,
        body: Any,
        secret_headers: Mapping[str, str] | None,
        ttl: timedelta,
        missing_ok: bool = False,
    ) -> FetchResult:
        policy = check_url(url)
        key = cache_key(method, url, params, body)
        cached = self.cache.get(key)
        now = datetime.now(UTC)
        shown = _display_url(url, params)

        if cached is not None:
            data, fetched_at = cached
            age = now - fetched_at
            if age <= ttl or self.offline:
                stale = age > ttl
                self._record(shown, fetched_at, from_cache=True, stale=stale)
                return FetchResult(data, fetched_at, True, stale)
        if self.offline:
            raise FetchError(f"offline mode and no cached copy of {shown}")

        try:
            data = self._fetch(method, url, policy, params, body, secret_headers, missing_ok)
        except FetchError:
            if cached is not None:
                data, fetched_at = cached
                log.warning("using stale cached copy of %s (fetched %s)", shown, fetched_at)
                self._record(shown, fetched_at, from_cache=True, stale=True)
                return FetchResult(data, fetched_at, True, True)
            raise
        self.cache.put(key, shown, data, now)
        self._record(shown, now, from_cache=False, stale=False)
        return FetchResult(data, now, False, False)

    def _fetch(
        self,
        method: str,
        url: str,
        policy: HostPolicy,
        params: Mapping[str, Any] | None,
        body: Any,
        secret_headers: Mapping[str, str] | None,
        missing_ok: bool = False,
    ) -> Any:
        host = urlsplit(url).hostname or ""
        interval = policy.min_interval
        if secret_headers and policy.keyed_min_interval is not None:
            interval = policy.keyed_min_interval
        last_error = ""
        for attempt in range(1, MAX_ATTEMPTS + 1):
            self._pace(host, interval)
            try:
                resp = self._client.request(
                    method,
                    url,
                    params=params,
                    json=body,
                    headers=dict(secret_headers or {}),
                )
            except httpx.HTTPError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                log.warning("request to %s failed (attempt %d): %s", host, attempt, last_error)
                self._sleep(min(2.0**attempt, MAX_RETRY_AFTER))
                continue
            if resp.status_code in RETRY_STATUSES and attempt < MAX_ATTEMPTS:
                wait = _retry_after(resp) or min(2.0**attempt * interval + 1, MAX_RETRY_AFTER)
                log.warning("%s returned %d; retrying in %.1fs", host, resp.status_code, wait)
                self._sleep(wait)
                continue
            if resp.status_code == 404 and missing_ok:
                return None
            if resp.status_code != 200:
                raise FetchError(f"{host} returned HTTP {resp.status_code}")
            if len(resp.content) > MAX_RESPONSE_BYTES:
                raise FetchError(f"{host} response exceeds {MAX_RESPONSE_BYTES} bytes")
            try:
                return resp.json()
            except ValueError as exc:
                raise FetchError(f"{host} returned invalid JSON") from exc
        raise FetchError(f"{host}: giving up after {MAX_ATTEMPTS} attempts ({last_error})")

    def _pace(self, host: str, interval: float) -> None:
        with self._hosts_lock:
            state = self._hosts.setdefault(host, _HostState())
        with state.lock:
            wait = state.last + interval - self._clock()
            if wait > 0:
                self._sleep(wait)
            state.last = self._clock()

    def _record(self, url: str, fetched_at: datetime, *, from_cache: bool, stale: bool) -> None:
        self.sources.append(
            SourceUse(url, fetched_at.isoformat(timespec="seconds"), from_cache, stale)
        )

    def lookup(self, key: str, label: str, ttl: timedelta) -> Any | None:
        """Cached data for a caller-defined key (fresh, or any age when offline)."""
        cached = self.cache.get(key)
        if cached is None:
            return None
        data, fetched_at = cached
        stale = datetime.now(UTC) - fetched_at > ttl
        if stale and not self.offline:
            return None
        self._record(label, fetched_at, from_cache=True, stale=stale)
        return data

    def remember(self, key: str, label: str, data: Any) -> None:
        self.cache.put(key, label, data, datetime.now(UTC))

    def stale_sources(self) -> list[SourceUse]:
        return [s for s in self.sources if s.stale]


def _retry_after(resp: httpx.Response) -> float | None:
    value = resp.headers.get("Retry-After")
    if value is None:
        return None
    try:
        return min(max(float(value), 0.0), MAX_RETRY_AFTER)
    except ValueError:
        return None


def _display_url(url: str, params: Mapping[str, Any] | None) -> str:
    if not params:
        return url
    return str(httpx.URL(url, params=dict(params)))
