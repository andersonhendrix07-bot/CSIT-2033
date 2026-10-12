"""CVSS v3.x base score from a vector string (FIRST CVSS v3.1 specification, section 7).

Used when a source (OSV) provides only the vector. NVD's published score is
preferred whenever it is available.
"""

from __future__ import annotations

import math

from hostguard.models import Severity

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def roundup(x: float) -> float:
    """CVSS v3.1 Roundup: smallest one-decimal number >= x, avoiding float artefacts."""
    i = round(x * 100_000)
    if i % 10_000 == 0:
        return i / 100_000.0
    return (math.floor(i / 10_000) + 1) / 10.0


def base_score_v3(vector: str) -> float | None:
    """Base score for a 'CVSS:3.0/...' or 'CVSS:3.1/...' vector; None if malformed."""
    parts = vector.strip().split("/")
    if not parts or parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    m: dict[str, str] = {}
    for p in parts[1:]:
        if ":" not in p:
            return None
        k, v = p.split(":", 1)
        m[k] = v
    if any(k not in m for k in _REQUIRED):
        return None
    try:
        scope_changed = m["S"] == "C"
        if m["S"] not in ("U", "C"):
            return None
        av, ac, ui = _AV[m["AV"]], _AC[m["AC"]], _UI[m["UI"]]
        pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        return roundup(min(1.08 * (impact + exploitability), 10.0))
    return roundup(min(impact + exploitability, 10.0))


def severity_for(score: float | None) -> Severity | None:
    """Qualitative rating from the CVSS specification's severity scale."""
    if score is None:
        return None
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO
