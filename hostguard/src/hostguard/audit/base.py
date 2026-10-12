"""Audit framework: read-only checks with evidence, references and explicit skip reasons.

A check never changes the system. It returns an Outcome:
  PASSED / FAILED        - with evidence of what was read
  SKIPPED                - with a reason (e.g. "Skipped: requires admin")
  NOT_APPLICABLE         - e.g. Remote Desktop host checks on Windows 11 Home
  ERROR                  - the check itself failed; reported, never hidden
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hostguard import proc
from hostguard.inventory.models import Inventory
from hostguard.logsetup import get_logger
from hostguard.models import CheckStatus, Confidence, Evidence, Finding, Severity
from hostguard.winsys import PowerShell, PowerShellError, Registry

log = get_logger("audit")

REQUIRES_ADMIN = "Skipped: requires admin"


@dataclass
class Outcome:
    status: CheckStatus
    detail: str
    evidence: list[Evidence] = field(default_factory=list)
    severity: Severity | None = None  # overrides the check's default severity
    confidence: Confidence = Confidence.CONFIRMED


def passed(detail: str, *ev: Evidence) -> Outcome:
    return Outcome(CheckStatus.PASSED, detail, list(ev))


def failed(
    detail: str,
    *ev: Evidence,
    severity: Severity | None = None,
    confidence: Confidence = Confidence.CONFIRMED,
) -> Outcome:
    return Outcome(CheckStatus.FAILED, detail, list(ev), severity, confidence)


def skipped(reason: str, *ev: Evidence) -> Outcome:
    return Outcome(CheckStatus.SKIPPED, reason, list(ev))


def not_applicable(reason: str, *ev: Evidence) -> Outcome:
    return Outcome(CheckStatus.NOT_APPLICABLE, reason, list(ev))


@dataclass
class AuditContext:
    family: str
    elevated: bool
    registry: Registry | None = None
    powershell: PowerShell | None = None
    run: Callable[[Sequence[str]], proc.ProcResult] = proc.run
    root: Path = Path("/")
    home: Path = field(default_factory=Path.home)
    inventory: Inventory | None = None
    edition_id: str = ""
    _ps_cache: dict[str, tuple[Any, Evidence] | PowerShellError] = field(default_factory=dict)

    def ps(self, script: str) -> tuple[Any, Evidence]:
        """Run a constant PowerShell query once per audit (several checks share results)."""
        if self.powershell is None:
            raise PowerShellError("PowerShell is not available")
        if script not in self._ps_cache:
            try:
                self._ps_cache[script] = self.powershell.run_json(script)
            except PowerShellError as exc:
                self._ps_cache[script] = exc
        cached = self._ps_cache[script]
        if isinstance(cached, PowerShellError):
            raise cached
        return cached

    @property
    def reg(self) -> Registry:
        if self.registry is None:
            raise RuntimeError("registry not available")
        return self.registry


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    families: tuple[str, ...]
    severity: Severity
    remediation: str
    references: tuple[str, ...]
    retest: str
    func: Callable[[AuditContext], Outcome]


CHECKS: list[Check] = []


def check(
    id: str,
    title: str,
    *,
    family: str | tuple[str, ...],
    severity: Severity,
    remediation: str,
    references: Sequence[str],
    retest: str,
) -> Callable[[Callable[[AuditContext], Outcome]], Callable[[AuditContext], Outcome]]:
    fams = (family,) if isinstance(family, str) else family

    def deco(fn: Callable[[AuditContext], Outcome]) -> Callable[[AuditContext], Outcome]:
        if any(c.id == id for c in CHECKS):
            raise ValueError(f"duplicate check id {id}")
        CHECKS.append(Check(id, title, fams, severity, remediation, tuple(references), retest, fn))
        return fn

    return deco


@dataclass
class CheckResult:
    check: Check
    outcome: Outcome

    @property
    def status(self) -> CheckStatus:
        return self.outcome.status

    @property
    def severity(self) -> Severity:
        return self.outcome.severity or self.check.severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.check.id,
            "title": self.check.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "confidence": self.outcome.confidence.value,
            "detail": self.outcome.detail,
            "evidence": [e.__dict__ for e in self.outcome.evidence],
            "references": list(self.check.references),
        }

    def to_finding(self) -> Finding | None:
        if self.status != CheckStatus.FAILED:
            return None
        ev = self.outcome.evidence or [
            Evidence(f"hostguard check {self.check.id}", self.outcome.detail)
        ]
        return Finding(
            id=f"HG-{self.check.id}",
            title=f"{self.check.title}: {self.outcome.detail}"[:300],
            severity=self.severity,
            confidence=self.outcome.confidence,
            component=self.check.title,
            evidence=ev,
            remediation=self.check.remediation,
            references=list(self.check.references),
            retest=self.check.retest,
            category="audit",
        )


def run_checks(ctx: AuditContext, only: Sequence[str] | None = None) -> list[CheckResult]:
    # Import the check modules so their @check decorators register.
    from hostguard.audit import common, linux, macos, windows  # noqa: F401

    results = []
    for c in CHECKS:
        if ctx.family not in c.families or (only and c.id not in only):
            continue
        try:
            outcome = c.func(ctx)
        except PowerShellError as exc:
            outcome = Outcome(
                CheckStatus.ERROR,
                f"PowerShell query failed: {exc}",
                [exc.evidence] if exc.evidence else [],
            )
        except Exception as exc:  # a broken check must not stop the audit
            log.exception("check %s failed", c.id)
            outcome = Outcome(CheckStatus.ERROR, f"{type(exc).__name__}: {exc}")
        results.append(CheckResult(c, outcome))
    return results


def stable_id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:8].upper()
