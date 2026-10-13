"""Optional VirusTotal *hash* lookup (never uploads files).

API (docs.virustotal.com, checked 2026-10-12): GET /api/v3/files/{sha256} with the
`x-apikey` header; 404 = unknown file; public API limited to 4 requests/minute and
500/day and must not be used commercially. hostguard only looks up files that local
engines already flagged, up to a per-run limit, and treats the answer as extra
evidence: it never changes a verdict on its own.
"""

from __future__ import annotations

from datetime import timedelta

from hostguard.credentials import Secret
from hostguard.net import FetchError, HttpClient
from hostguard.scan.model import Confidence, EngineHit

VT_FILES = "https://www.virustotal.com/api/v3/files/"


def lookup(http: HttpClient, key: Secret, sha256: str) -> tuple[EngineHit | None, str]:
    try:
        res = http.get_json(
            VT_FILES + sha256,
            secret_headers={"x-apikey": key.reveal()},
            ttl=timedelta(days=1),
            missing_ok=True,
        )
    except FetchError as exc:
        return None, f"VirusTotal lookup failed: {exc}"
    if res.data is None:
        return None, "VirusTotal: hash not known (the file was never submitted)"
    attrs = (res.data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values() if isinstance(v, int))
    label = ((attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")) or ""
    detail = f"{mal}/{total} engines detect it as malicious, {sus} as suspicious" + (
        f"; label: {label}" if label else ""
    )
    return (
        EngineHit(
            "virustotal",
            label or "VirusTotal report",
            detail,
            Confidence.LOW,
            reference=f"https://www.virustotal.com/gui/file/{sha256}",
            source="VirusTotal (hash lookup)",
        ),
        "",
    )
