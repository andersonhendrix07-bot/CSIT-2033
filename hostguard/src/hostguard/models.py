"""Core data types shared by every module (findings, evidence, verdicts, exit codes)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any


class ExitCode(IntEnum):
    """Process exit codes: 0 clean, 1 findings, 2 error."""

    CLEAN = 0
    FINDINGS = 1
    ERROR = 2


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Lower is more severe; used for sorting."""
        return list(Severity).index(self)


class Confidence(StrEnum):
    CONFIRMED = "Confirmed"
    LIKELY = "Likely"
    NEEDS_VERIFICATION = "Needs verification"


class Verdict(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    SKIPPED = "skipped"
    ERROR = "error"


class CheckStatus(StrEnum):
    """Outcome of a configuration-audit check."""

    PASSED = "pass"
    FAILED = "fail"
    SKIPPED = "skipped"  # e.g. "requires admin"; never reported as a failure
    NOT_APPLICABLE = "n/a"  # e.g. a Remote Desktop host check on Windows Home
    ERROR = "error"


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Evidence:
    """Exactly where a claim came from and what it showed."""

    source: str  # command line, registry path, file path, or API URL
    output: str  # the relevant excerpt (already truncated by the producer)
    collected_at: str = field(default_factory=utc_now)


@dataclass
class VulnInfo:
    """One vulnerability affecting a component, with prioritisation data."""

    cve: str  # CVE ID, or the advisory ID when no CVE exists
    advisory_id: str = ""  # e.g. GHSA-..., UBUNTU-CVE-..., or the CVE itself for NVD
    summary: str = ""
    cvss: float | None = None
    cvss_vector: str | None = None
    cvss_source: str = ""  # "NVD" or "computed from OSV vector"
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    kev_date_added: str = ""
    kev_ransomware: str = ""
    fixed_in: str = ""  # version that fixes it, when the data says so
    distro_priority: str = ""  # e.g. Ubuntu priority when no CVSS exists
    related: list[str] = field(default_factory=list)  # other advisories for the same CVE

    def sort_key(self) -> tuple[int, float, float]:
        """Ranking: known-exploited first, then EPSS, then CVSS (all descending)."""
        return (0 if self.kev else 1, -(self.epss or 0.0), -(self.cvss or 0.0))


@dataclass
class Finding:
    """One reportable item. Every field is meant to be shown to the user."""

    id: str
    title: str
    severity: Severity
    confidence: Confidence
    component: str
    evidence: list[Evidence]
    remediation: str
    references: list[str]
    retest: str
    category: str = "general"  # "vuln" | "audit" | "malware" | ...
    vulns: list[VulnInfo] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.evidence:
            # Honesty rule: no finding without evidence.
            raise ValueError(f"finding {self.id!r} has no evidence")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d
