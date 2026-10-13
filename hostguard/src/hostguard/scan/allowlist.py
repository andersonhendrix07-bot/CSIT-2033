"""Known-good signals. Used ONLY to downgrade heuristic-only Suspicious verdicts.

They never override a hash, ClamAV or YARA match (those stay Malicious/Suspicious).

- Windows: Authenticode as validated by the OS (Get-AuthenticodeSignature: the
  certificate chain must lead to a trusted root, catalog signatures included)
  AND a signer organisation on the trusted-publisher list. A signature that is
  only "internally consistent" (e.g. YARA-X `verified`) is NOT trusted: anyone
  can self-sign a file with "O=Microsoft Corporation" in the subject.
- Linux (Debian/Ubuntu): the file belongs to an installed package and its MD5
  still matches the package database (/var/lib/dpkg/info/*.md5sums).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from hostguard.logsetup import get_logger
from hostguard.winsys import PowerShell, PowerShellError, iter_dicts

log = get_logger("scan.allowlist")

# Constant script; the list of paths arrives on stdin as JSON data.
PS_SIGNATURES = (
    "$paths = [Console]::In.ReadToEnd() | ConvertFrom-Json; "
    "foreach ($p in @($paths)) { $s = Get-AuthenticodeSignature -LiteralPath $p; "
    "[pscustomobject]@{Path=$p; Status=[string]$s.Status; "
    "Subject=$(if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' }); "
    "SignatureType=[string]$s.SignatureType} } | ConvertTo-Json -Compress"
)


@dataclass
class Trust:
    trusted: bool
    detail: str


def _org(subject: str) -> str:
    m = re.search(r"(?:^|,\s*)O=(\"[^\"]+\"|[^,]+)", subject)
    return m.group(1).strip().strip('"') if m else ""


def windows_signatures(
    paths: list[str], ps: PowerShell, trusted_publishers: list[str]
) -> dict[str, Trust]:
    if not paths:
        return {}
    try:
        data, _ev = ps.run_json(PS_SIGNATURES, timeout=300, stdin=json.dumps(paths).encode("utf-8"))
    except PowerShellError as exc:
        log.warning("signature check failed: %s", exc)
        return {}
    allowed = {t.lower() for t in trusted_publishers}
    out: dict[str, Trust] = {}
    for d in iter_dicts(data):
        path, status, subject = (
            str(d.get("Path", "")),
            str(d.get("Status", "")),
            str(d.get("Subject", "")),
        )
        org = _org(subject)
        if status == "Valid" and org.lower() in allowed:
            out[path] = Trust(
                True,
                f"valid {d.get('SignatureType') or ''} signature by trusted publisher {org}".replace(
                    "  ", " "
                ),
            )
        elif status == "Valid":
            out[path] = Trust(
                False, f"valid signature by {org or subject}, not on the trusted-publisher list"
            )
        else:
            out[path] = Trust(False, f"signature status: {status or 'unknown'}")
    return out


class DpkgVerifier:
    """Is this file an unmodified file from an installed Debian/Ubuntu package?"""

    def __init__(self, info_dir: Path = Path("/var/lib/dpkg/info")) -> None:
        self.info_dir = info_dir
        self._md5: dict[str, str] | None = None

    def _load(self) -> dict[str, str]:
        if self._md5 is None:
            self._md5 = {}
            for f in self.info_dir.glob("*.md5sums") if self.info_dir.is_dir() else []:
                try:
                    for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            self._md5["/" + parts[1].strip()] = parts[0].lower()
                except OSError:
                    continue
        return self._md5

    def check(self, path: str, data: bytes | None = None) -> Trust | None:
        expected = self._load().get(path)
        if expected is None:
            return None
        try:
            actual = hashlib.md5(
                data if data is not None else Path(path).read_bytes(), usedforsecurity=False
            ).hexdigest()
        except OSError:
            return None
        if actual == expected:
            return Trust(
                True,
                "file belongs to an installed package and matches the package database checksum",
            )
        return Trust(False, "file belongs to a package but was MODIFIED since installation")
