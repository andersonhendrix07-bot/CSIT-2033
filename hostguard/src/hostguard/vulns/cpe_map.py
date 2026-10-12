"""Curated mapping from installed-program names to NVD CPE vendor:product pairs.

Every vendor:product below was confirmed to exist in the NVD CPE dictionary
on 2026-10-12. Apps not listed here are not matched against NVD by default
(guessing a product name produces false positives); `--fuzzy` enables a
keyword search whose results are always labelled "Needs verification".

Version handling: the registry's DisplayVersion is not always the product's
public version (e.g. the python.org installer reports 3.13.14150.0 for 3.13.14),
so each entry says how to derive the version NVD uses.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from hostguard.inventory.models import OsInfo, Software


def first(n: int) -> Callable[[str, str], str | None]:
    """Keep the first n numeric components of DisplayVersion."""

    def f(_name: str, version: str) -> str | None:
        parts = re.findall(r"\d+", version)
        return ".".join(parts[:n]) if len(parts) >= min(n, 2) else None

    return f


def from_name(pattern: str) -> Callable[[str, str], str | None]:
    """Take the version from the display name (first capture group)."""
    rx = re.compile(pattern)

    def f(name: str, _version: str) -> str | None:
        m = rx.search(name)
        return m.group(1) if m else None

    return f


def two_digit_minor(_name: str, version: str) -> str | None:
    """7-Zip style: '24.08.00.0' -> '24.08'."""
    m = re.match(r"(\d+)\.(\d+)", version)
    return f"{int(m.group(1))}.{int(m.group(2)):02d}" if m else None


def drop_first(n_keep: int) -> Callable[[str, str], str | None]:
    """Brave style: '130.1.71.118' (Chromium major first) -> '1.71.118'."""

    def f(_name: str, version: str) -> str | None:
        parts = re.findall(r"\d+", version)
        return ".".join(parts[1 : 1 + n_keep]) if len(parts) > n_keep else None

    return f


@dataclass(frozen=True)
class CpeProduct:
    label: str
    name: re.Pattern[str]
    cpes: tuple[str, ...]  # "vendor:product" (CPE-escaped)
    version: Callable[[str, str], str | None]
    publisher: re.Pattern[str] | None = None


def _p(rx: str) -> re.Pattern[str]:
    return re.compile(rx, re.IGNORECASE)


PRODUCTS: tuple[CpeProduct, ...] = (
    CpeProduct("Google Chrome", _p(r"^Google Chrome$"), ("google:chrome",), first(4)),
    CpeProduct("Microsoft Edge", _p(r"^Microsoft Edge$"), ("microsoft:edge_chromium",), first(4)),
    CpeProduct("Firefox ESR", _p(r"^Mozilla Firefox ESR\b"), ("mozilla:firefox_esr",), first(3)),
    CpeProduct("Firefox", _p(r"^Mozilla Firefox\b(?!.*ESR)"), ("mozilla:firefox",), first(3)),
    CpeProduct("Thunderbird", _p(r"^Mozilla Thunderbird\b"), ("mozilla:thunderbird",), first(3)),
    CpeProduct("Brave", _p(r"^Brave$"), ("brave:brave",), drop_first(3)),
    CpeProduct("Opera", _p(r"^Opera Stable\b"), ("opera:opera_browser",), first(4)),
    CpeProduct("7-Zip", _p(r"^7-Zip\b"), ("7-zip:7-zip",), two_digit_minor),
    CpeProduct("WinRAR", _p(r"^WinRAR\b"), ("rarlab:winrar",), first(2)),
    CpeProduct("VLC", _p(r"^VLC media player$"), ("videolan:vlc_media_player",), first(3)),
    CpeProduct(
        "Notepad++",
        _p(r"^Notepad\+\+"),
        ("notepad-plus-plus:notepad\\+\\+", "don_ho:notepad\\+\\+"),
        first(3),
    ),
    CpeProduct(
        "VS Code",
        _p(r"^Microsoft Visual Studio Code\b"),
        ("microsoft:visual_studio_code",),
        first(3),
    ),
    CpeProduct(
        "Python",
        _p(r"^Python (\d+\.\d+\.\d+) \((?:64|32)-bit\)$"),
        ("python:python",),
        from_name(r"(\d+\.\d+\.\d+)"),
    ),
    CpeProduct("Git", _p(r"^Git$"), ("git-scm:git",), first(3)),
    CpeProduct("Node.js", _p(r"^Node\.js$"), ("nodejs:node.js",), first(3)),
    CpeProduct("PuTTY", _p(r"^PuTTY release\b"), ("putty:putty", "simon_tatham:putty"), first(2)),
    CpeProduct("Wireshark", _p(r"^Wireshark\b"), ("wireshark:wireshark",), first(3)),
    CpeProduct(
        "Zoom", _p(r"^Zoom( Workplace)?$"), ("zoom:workplace_desktop", "zoom:meetings"), first(3)
    ),
    CpeProduct(
        "Adobe Acrobat Reader",
        _p(r"^Adobe Acrobat( Reader)?( DC)?( \(64-bit\))?$"),
        ("adobe:acrobat_reader_dc",),
        first(3),
    ),
    CpeProduct("LibreOffice", _p(r"^LibreOffice\b"), ("libreoffice:libreoffice",), first(3)),
    CpeProduct("GIMP", _p(r"^GIMP\b"), ("gimp:gimp",), first(3)),
    CpeProduct(
        "FileZilla",
        _p(r"^FileZilla\b(?! Server)"),
        ("filezilla-project:filezilla_client",),
        first(3),
    ),
    CpeProduct("WinSCP", _p(r"^WinSCP\b"), ("winscp:winscp",), first(3)),
    CpeProduct("KeePass", _p(r"^KeePass Password Safe\b"), ("keepass:keepass",), first(2)),
    CpeProduct("TeamViewer", _p(r"^TeamViewer\b"), ("teamviewer:teamviewer",), first(3)),
    CpeProduct("AnyDesk", _p(r"^AnyDesk$"), ("anydesk:anydesk",), first(3)),
    CpeProduct(
        "VMware Workstation", _p(r"^VMware Workstation\b"), ("vmware:workstation",), first(3)
    ),
    CpeProduct("Docker Desktop", _p(r"^Docker Desktop$"), ("docker:desktop",), first(3)),
    CpeProduct("PowerShell 7", _p(r"^PowerShell 7\b"), ("microsoft:powershell",), first(3)),
    CpeProduct(
        ".NET Runtime",
        _p(r"^Microsoft \.NET Runtime - (\d+\.\d+\.\d+)"),
        ("microsoft:.net",),
        from_name(r"(\d+\.\d+\.\d+)"),
    ),
)


@dataclass(frozen=True)
class CpeMatch:
    product: CpeProduct
    version: str

    def cpe_names(self) -> list[str]:
        return [f"cpe:2.3:a:{vp}:{self.version}:*:*:*:*:*:*:*" for vp in self.product.cpes]


def lookup(sw: Software) -> CpeMatch | None:
    for prod in PRODUCTS:
        if prod.name.search(sw.name) and (
            prod.publisher is None or prod.publisher.search(sw.publisher)
        ):
            ver = prod.version(sw.name, sw.version)
            if ver and re.fullmatch(r"[0-9][0-9A-Za-z.\-]*", ver):
                return CpeMatch(prod, ver)
            return None
    return None


def windows_os_cpe(os_info: OsInfo) -> str | None:
    """CPE for the running Windows client build, e.g.
    cpe:2.3:o:microsoft:windows_11_25h2:10.0.26200.6899:*:*:*:*:*:x64:*
    (format confirmed against the NVD CPE dictionary 2026-10-12)."""
    if os_info.family != "windows" or not os_info.build.isdigit() or os_info.ubr is None:
        return None
    if os_info.edition_id.startswith("Server") or not os_info.display_version:
        return None
    major = "11" if int(os_info.build) >= 22000 else "10"
    arch = {"AMD64": "x64", "x86_64": "x64", "ARM64": "arm64", "x86": "x86"}.get(os_info.arch, "")
    if not arch:
        return None
    product = f"windows_{major}_{os_info.display_version.lower()}"
    return f"cpe:2.3:o:microsoft:{product}:10.0.{os_info.build}.{os_info.ubr}:*:*:*:*:*:{arch}:*"
