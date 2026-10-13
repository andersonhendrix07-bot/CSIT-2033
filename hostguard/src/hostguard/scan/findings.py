"""Turn flagged scan items into Findings (evidence, remediation, retest, references)."""

from __future__ import annotations

import hashlib
import sys

from hostguard.models import Confidence, Evidence, Finding, Severity, Verdict
from hostguard.scan.model import ScanItem, safe_display

DEFENDER_SCAN_DOC = "https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus"
DEFENDER_FP_DOC = "https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-false-positives-negatives"
EICAR_DOC = "https://www.eicar.org/download-anti-malware-testfile/"


def item_to_finding(item: ScanItem) -> Finding | None:
    if item.verdict not in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
        return None
    shown = safe_display(item.path)
    detecting = [h for h in item.hits if h.engine not in ("allowlist", "virustotal")]
    engines = {h.engine for h in detecting}
    is_test = any("EICAR" in h.name or "Test_Marker" in h.name for h in detecting)

    if item.verdict == Verdict.MALICIOUS:
        severity = Severity.HIGH
        confidence = Confidence.CONFIRMED if engines & {"hash", "clamav"} else Confidence.LIKELY
        what = "malicious"
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.NEEDS_VERIFICATION
        what = "suspicious"
    names = ", ".join(dict.fromkeys(h.name for h in detecting))[:200]
    title = f"{what.capitalize()} file: {shown} ({names})"
    if is_test:
        title += " [anti-malware TEST file, not real malware]"

    evidence = [Evidence(f"file {shown}", f"SHA-256 {item.sha256}; size {item.size:,} bytes")]
    for h in item.hits:
        attribution = "; ".join(
            x
            for x in (
                f"author: {h.author}" if h.author else "",
                f"licence: {h.license}" if h.license else "",
                f"source: {h.source}" if h.source else "",
            )
            if x
        )
        out = (
            h.detail
            + (f" (score {h.score})" if h.score else "")
            + (f" [{attribution}]" if attribution else "")
        )
        evidence.append(Evidence(f"{h.engine}: {h.name}", out))
    for n in item.notes[:5]:
        evidence.append(Evidence("note", n))

    disk = safe_display(item.disk_path or item.path)
    member = " (inside the archive " + disk + ")" if item.in_archive else ""
    if sys.platform == "win32":
        confirm = (
            "Confirm with Microsoft Defender: right-click the file and choose 'Scan with Microsoft Defender', "
            f'or run: "%ProgramFiles%\\Windows Defender\\MpCmdRun.exe" -Scan -ScanType 3 -File "{disk}".'
        )
    else:
        confirm = f'Confirm with a second scanner, e.g. `clamscan "{disk}"`.'
    if is_test:
        remediation = (
            f"This is the EICAR/hostguard test file{member}; it is harmless and only proves detection works. "
            "Delete it when you are done testing."
        )
    elif item.verdict == Verdict.MALICIOUS:
        remediation = (
            f"Do not open or run this file{member}. {confirm} If confirmed, let your antivirus remove it or quarantine "
            "it with `hostguard quarantine` (Phase 4), then delete it. If you did not expect this file, also run a "
            "full Microsoft Defender scan and change passwords used on this computer."
        )
    else:
        remediation = (
            f"Treat this file with caution{member}: check where it came from and who signed it (file Properties > "
            f"Digital Signatures). {confirm} Heuristic results can be false positives; if the file is legitimate, "
            "add its folder to scan.exclude_paths only if you trust its source."
        )
    refs: list[str] = []
    for h in detecting:
        if h.reference.startswith("https://"):
            refs.append(h.reference)
    if is_test:
        refs.append(EICAR_DOC)
    refs += [DEFENDER_SCAN_DOC] + ([DEFENDER_FP_DOC] if item.verdict == Verdict.SUSPICIOUS else [])
    vt = [h.reference for h in item.hits if h.engine == "virustotal" and h.reference]
    refs += vt
    fid = "HG-MAL-" + hashlib.sha256(f"{item.path}|{item.sha256}".encode()).hexdigest()[:10].upper()
    return Finding(
        id=fid,
        title=title[:300],
        severity=severity,
        confidence=confidence,
        component=shown,
        evidence=evidence,
        remediation=remediation,
        references=list(dict.fromkeys(refs))[:8],
        retest=f'Run `hostguard scan "{disk}"`; it should report the file as clean, or the file should no longer exist.',
        category="malware",
    )
