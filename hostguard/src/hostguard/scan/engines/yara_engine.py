"""YARA-X engine: compile rule sets once, cache the compiled form, scan bytes or files.

Rule sets live in `<data>/rules/<set>/**/*.yar|*.yara`, each optionally with a
SOURCE.json describing licence and confidence. Each set gets its own namespace.
Matches keep the rule's author/reference and the set's licence, as required
by e.g. the Detection Rule License 1.1 (signature-base).

Confidence (decides Malicious vs Suspicious):
  "high"  - every match is high confidence (ReversingLabs family rules, built-ins)
  "score" - rule meta `score` >= threshold is high, below is low (signature-base)
  "low"   - every match is low confidence (unknown third-party sets)
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import io
import json
import re
import threading
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yara_x

from hostguard.logsetup import get_logger
from hostguard.scan.model import Confidence, EngineHit

log = get_logger("scan.yara")

EXTERNALS = ("filename", "filepath", "extension", "filetype", "owner")
SCAN_TIMEOUT = 60


@dataclass
class RuleSet:
    name: str
    files: list[tuple[str, str]]  # (origin, source text)
    confidence: str = "low"
    score_threshold: int = 75
    license: str = ""
    url: str = ""


# Defaults for the two approved sets when no SOURCE.json is present.
KNOWN_SETS: dict[str, dict[str, Any]] = {
    "reversinglabs": {
        "confidence": "high",
        "license": "MIT",
        "url": "https://github.com/reversinglabs/reversinglabs-yara-rules",
    },
    "signature-base": {
        "confidence": "score",
        "score_threshold": 75,
        "license": "Detection Rule License 1.1 (https://github.com/Neo23x0/signature-base/blob/master/LICENSE)",
        "url": "https://github.com/Neo23x0/signature-base",
    },
}


def _namespace(name: str) -> str:
    ns = re.sub(r"[^A-Za-z0-9_]", "_", name)
    return ns if ns and not ns[0].isdigit() else f"r_{ns}"


def discover(rules_dir: Path, include_test_rules: bool = False) -> list[RuleSet]:
    sets = [
        RuleSet(
            "builtin",
            [
                (
                    "builtin.yar",
                    resources.files("hostguard.rules").joinpath("builtin.yar").read_text("utf-8"),
                )
            ],
            confidence="high",
            license="MIT (hostguard)",
        )
    ]
    if include_test_rules:
        sets.append(
            RuleSet(
                "hostguard_test",
                [
                    (
                        "test_only.yar",
                        resources.files("hostguard.rules")
                        .joinpath("test_only.yar")
                        .read_text("utf-8"),
                    )
                ],
                confidence="high",
                license="MIT (hostguard)",
            )
        )
    if not rules_dir.is_dir():
        return sets
    for d in sorted(p for p in rules_dir.iterdir() if p.is_dir() and not p.name.startswith(".")):
        meta: dict[str, Any] = {}
        for key, defaults in KNOWN_SETS.items():
            if d.name.lower().startswith(key):
                meta.update(defaults)
        src_meta = d / "SOURCE.json"
        if src_meta.is_file():
            try:
                meta.update(json.loads(src_meta.read_text(encoding="utf-8")))
            except (OSError, ValueError) as exc:
                log.warning("ignoring invalid %s: %s", src_meta, exc)
        files = []
        for f in sorted(d.rglob("*")):
            if f.suffix.lower() in (".yar", ".yara") and f.is_file():
                try:
                    files.append(
                        (
                            str(f.relative_to(rules_dir)),
                            f.read_text(encoding="utf-8", errors="replace"),
                        )
                    )
                except OSError as exc:
                    log.warning("cannot read rule file %s: %s", f, exc)
        if files:
            sets.append(
                RuleSet(
                    d.name,
                    files,
                    confidence=str(meta.get("confidence", "low")),
                    score_threshold=int(meta.get("score_threshold", 75)),
                    license=str(meta.get("license", "")),
                    url=str(meta.get("url", "")),
                )
            )
    return sets


@dataclass
class CompileReport:
    rule_count: int = 0
    files_ok: int = 0
    files_failed: list[str] = field(default_factory=list)
    from_cache: bool = False


class YaraEngine:
    name = "yara"

    def __init__(
        self, rules_dir: Path, cache_dir: Path, *, include_test_rules: bool = False
    ) -> None:
        self.sets = discover(rules_dir, include_test_rules)
        self._by_ns = {_namespace(s.name): s for s in self.sets}
        self.cache_dir = cache_dir
        self.report = CompileReport()
        self.rules = self._load()
        self._local = threading.local()

    # -- compile / cache ------------------------------------------------------------

    def _cache_key(self) -> str:
        h = hashlib.sha256(importlib.metadata.version("yara-x").encode())
        for s in self.sets:
            h.update(s.name.encode())
            for origin, text in s.files:
                h.update(origin.encode())
                h.update(hashlib.sha256(text.encode()).digest())
        return h.hexdigest()[:32]

    def _load(self) -> yara_x.Rules:
        cache = self.cache_dir / "yara" / f"rules-{self._cache_key()}.bin"
        if cache.is_file():
            try:
                with cache.open("rb") as fh:
                    rules = yara_x.Rules.deserialize_from(fh)
                meta = json.loads(cache.with_suffix(".json").read_text(encoding="utf-8"))
                self.report = CompileReport(
                    meta["rule_count"], meta["files_ok"], meta["files_failed"], True
                )
                return rules
            except Exception as exc:  # corrupt cache: recompile
                log.warning("YARA cache unusable (%s); recompiling", exc)
        compiler = yara_x.Compiler(relaxed_re_syntax=True)
        for g in EXTERNALS:
            compiler.define_global(g, "")
        report = CompileReport()
        for s in self.sets:
            compiler.new_namespace(_namespace(s.name))
            for origin, text in s.files:
                try:
                    compiler.add_source(text, origin=origin)
                    report.files_ok += 1
                except yara_x.CompileError as exc:
                    first = str(exc).splitlines()[0] if str(exc) else "compile error"
                    report.files_failed.append(f"{s.name}/{origin}: {first[:200]}")
        rules = compiler.build()
        report.rule_count = sum(1 for _ in rules)
        self.report = report
        try:
            cache.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            for old in cache.parent.glob("rules-*.bin"):
                old.unlink(missing_ok=True)
            buf = io.BytesIO()
            rules.serialize_into(buf)
            cache.write_bytes(buf.getvalue())
            cache.with_suffix(".json").write_text(
                json.dumps(
                    {
                        "rule_count": report.rule_count,
                        "files_ok": report.files_ok,
                        "files_failed": report.files_failed,
                    }
                ),
                encoding="utf-8",
            )
        except OSError as exc:
            log.warning("cannot cache compiled rules: %s", exc)
        return rules

    # -- scanning ------------------------------------------------------------------------

    def _scanner(self) -> yara_x.Scanner:
        sc = getattr(self._local, "scanner", None)
        if sc is None:
            sc = yara_x.Scanner(self.rules)
            sc.set_timeout(SCAN_TIMEOUT)
            self._local.scanner = sc
        return sc

    def _set_globals(self, sc: yara_x.Scanner, name: str, path: str, filetype: str) -> None:
        base = name.replace("\\", "/").rsplit("/", 1)[-1]
        ext = ("." + base.rsplit(".", 1)[1].lower()) if "." in base else ""
        for k, v in (
            ("filename", base),
            ("filepath", path),
            ("extension", ext),
            ("filetype", filetype),
            ("owner", ""),
        ):
            sc.set_global(k, v)

    def scan_bytes(
        self, data: bytes, name: str, path: str = "", filetype: str = ""
    ) -> tuple[list[EngineHit], str]:
        sc = self._scanner()
        self._set_globals(sc, name, path, filetype)
        try:
            res = sc.scan(data)
        except yara_x.TimeoutError:
            return [], f"YARA scan timed out after {SCAN_TIMEOUT}s"
        except yara_x.ScanError as exc:
            return [], f"YARA scan error: {exc}"
        return [self._hit(r) for r in res.matching_rules], ""

    def scan_file(
        self, file_path: str, name: str, filetype: str = ""
    ) -> tuple[list[EngineHit], str]:
        sc = self._scanner()
        self._set_globals(sc, name, file_path, filetype)
        try:
            res = sc.scan_file(file_path)
        except yara_x.TimeoutError:
            return [], f"YARA scan timed out after {SCAN_TIMEOUT}s"
        except yara_x.ScanError as exc:
            return [], f"YARA scan error: {exc}"
        return [self._hit(r) for r in res.matching_rules], ""

    def _hit(self, rule: Any) -> EngineHit:
        meta = {str(k).lower(): v for k, v in rule.metadata}
        rs = self._by_ns.get(rule.namespace)
        conf = Confidence.LOW
        if rs is not None:
            if rs.confidence == "high":
                conf = Confidence.HIGH
            elif rs.confidence == "score":
                try:
                    conf = (
                        Confidence.HIGH
                        if int(meta.get("score", 0)) >= rs.score_threshold
                        else Confidence.LOW
                    )
                except (TypeError, ValueError):
                    conf = Confidence.LOW
        desc = str(meta.get("description", "") or "")
        score = meta.get("score")
        return EngineHit(
            engine="yara",
            name=f"{rs.name if rs else rule.namespace}:{rule.identifier}",
            detail=(desc[:300] or "rule matched")
            + (f" (rule score {score})" if score is not None else ""),
            confidence=conf,
            author=str(meta.get("author", "") or ""),
            reference=str(meta.get("reference", "") or (rs.url if rs else "")),
            license=str(meta.get("license", "") or (rs.license if rs else "")),
            source=rs.name if rs else rule.namespace,
        )
