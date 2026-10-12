from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from hostguard import net
from hostguard.net import FetchError, HttpClient, JsonCache, NetworkPolicyError, check_url


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, s: float) -> None:
        self.sleeps.append(s)
        self.now += s


def make_client(
    tmp_path: Path, handler: object, *, offline: bool = False, clock: FakeClock | None = None
) -> HttpClient:
    clk = clock or FakeClock()
    return HttpClient(
        JsonCache(tmp_path / "cache"),
        offline=offline,
        transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
        clock=clk.clock,
        sleep=clk.sleep,
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://api.osv.dev/v1/query",
        "https://evil.example.com/",
        "https://api.osv.dev.evil.example.com/",
        "https://user:pw@api.osv.dev/v1/query",
        "https://api.osv.dev:8443/v1/query",
        "ftp://api.osv.dev/",
    ],
)
def test_policy_rejects(url: str) -> None:
    with pytest.raises(NetworkPolicyError):
        check_url(url)


def test_policy_rejects_before_any_request(tmp_path: Path) -> None:
    calls: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        return httpx.Response(200, json={})

    with make_client(tmp_path, handler) as c, pytest.raises(NetworkPolicyError):
        c.get_json("https://example.com/x")
    assert calls == []


def test_get_caches_and_records_sources(tmp_path: Path) -> None:
    calls: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        return httpx.Response(200, json={"n": len(calls)})

    with make_client(tmp_path, handler) as c:
        r1 = c.get_json("https://api.osv.dev/v1/vulns/X", params={"a": "1"})
        r2 = c.get_json("https://api.osv.dev/v1/vulns/X", params={"a": "1"})
    assert r1.data == {"n": 1} and not r1.from_cache
    assert r2.data == {"n": 1} and r2.from_cache and not r2.stale
    assert len(calls) == 1
    assert calls[0].headers["User-Agent"].startswith("hostguard/")
    assert [s.from_cache for s in c.sources] == [False, True]


def test_expired_cache_refetches(tmp_path: Path) -> None:
    n = {"v": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        n["v"] += 1
        return httpx.Response(200, json={"n": n["v"]})

    with make_client(tmp_path, handler) as c:
        c.get_json("https://api.osv.dev/a", ttl=timedelta(0))
        r = c.get_json("https://api.osv.dev/a", ttl=timedelta(0))
    assert r.data == {"n": 2} and not r.from_cache


def test_offline_uses_stale_cache_and_flags_it(tmp_path: Path) -> None:
    cache = JsonCache(tmp_path / "cache")
    url = "https://www.cisa.gov/feed.json"
    old = datetime.now(UTC) - timedelta(days=10)
    cache.put(net.cache_key("GET", url, None, None), url, {"old": True}, old)

    def handler(req: httpx.Request) -> httpx.Response:
        raise AssertionError("must not touch the network offline")

    c = HttpClient(cache, offline=True, transport=httpx.MockTransport(handler))
    r = c.get_json(url, ttl=timedelta(days=1))
    assert r.data == {"old": True} and r.stale
    assert c.stale_sources()[0].url == url
    with pytest.raises(FetchError, match="offline"):
        c.get_json("https://www.cisa.gov/other.json")


def test_network_failure_falls_back_to_stale_cache(tmp_path: Path) -> None:
    cache = JsonCache(tmp_path / "cache")
    url = "https://api.first.org/data/v1/epss"
    cache.put(
        net.cache_key("GET", url, None, None), url, [1], datetime.now(UTC) - timedelta(days=3)
    )

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    clk = FakeClock()
    c = HttpClient(cache, transport=httpx.MockTransport(handler), clock=clk.clock, sleep=clk.sleep)
    r = c.get_json(url, ttl=timedelta(hours=1))
    assert r.data == [1] and r.stale


def test_retries_429_with_retry_after_then_succeeds(tmp_path: Path) -> None:
    seq = [httpx.Response(429, headers={"Retry-After": "7"}), httpx.Response(200, json={"ok": 1})]
    clk = FakeClock()
    with make_client(tmp_path, lambda req: seq.pop(0), clock=clk) as c:
        assert c.get_json("https://api.osv.dev/q").data == {"ok": 1}
    assert 7.0 in clk.sleeps


def test_gives_up_after_max_attempts(tmp_path: Path) -> None:
    clk = FakeClock()
    with (
        make_client(tmp_path, lambda req: httpx.Response(503), clock=clk) as c,
        pytest.raises(FetchError, match="503"),
    ):
        c.get_json("https://api.osv.dev/q")


def test_transport_errors_retried(tmp_path: Path) -> None:
    state = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] < 3:
            raise httpx.ConnectError("boom", request=req)
        return httpx.Response(200, json=[])

    with make_client(tmp_path, handler) as c:
        assert c.get_json("https://api.osv.dev/q").data == []


def test_redirects_not_followed(tmp_path: Path) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://evil.example.com/"})

    with make_client(tmp_path, handler) as c, pytest.raises(FetchError, match="302"):
        c.get_json("https://api.osv.dev/q")


def test_nvd_pacing_keyless_and_keyed(tmp_path: Path) -> None:
    clk = FakeClock()
    with make_client(tmp_path, lambda req: httpx.Response(200, json={}), clock=clk) as c:
        for i in range(3):
            c.get_json("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"i": i})
        keyless = list(clk.sleeps)
        clk.sleeps.clear()
        for i in range(3, 6):
            c.get_json(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"i": i},
                secret_headers={"apiKey": "k" * 20},
            )
    assert keyless == [6.0, 6.0]
    assert clk.sleeps == [pytest.approx(0.6)] * 3


def test_secret_header_sent_but_not_cached_or_in_sources(tmp_path: Path) -> None:
    seen: dict[str, str] = {}
    key = "SECRET-KEY-1234567890"

    def handler(req: httpx.Request) -> httpx.Response:
        seen.update(req.headers)
        return httpx.Response(200, json={"x": 1})

    with make_client(tmp_path, handler) as c:
        c.get_json(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": "CVE-1"},
            secret_headers={"apiKey": key},
        )
    assert seen["apikey"] == key
    blob = "".join(p.read_text() for p in (tmp_path / "cache").rglob("*.json"))
    assert key not in blob
    assert key not in json.dumps([s.__dict__ for s in c.sources])


def test_post_json_and_invalid_json(tmp_path: Path) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/bad":
            return httpx.Response(200, content=b"<html>")
        assert json.loads(req.content) == {"queries": []}
        return httpx.Response(200, json={"results": []})

    with make_client(tmp_path, handler) as c:
        assert c.post_json("https://api.osv.dev/v1/querybatch", {"queries": []}).data == {
            "results": []
        }
        with pytest.raises(FetchError, match="invalid JSON"):
            c.get_json("https://api.osv.dev/bad")


def test_oversized_response_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(net, "MAX_RESPONSE_BYTES", 10)
    with (
        make_client(tmp_path, lambda req: httpx.Response(200, json={"a": "x" * 50})) as c,
        pytest.raises(FetchError, match="exceeds"),
    ):
        c.get_json("https://api.osv.dev/q")
