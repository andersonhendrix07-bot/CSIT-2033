"""Explainable heuristics: each signal adds points and a reason; the total decides.

A total at or above the threshold (default 60) makes a file Suspicious, never
Malicious. Weak signals (e.g. "executable in Downloads") are deliberately
worth too little to reach the threshold on their own.

Signals:
- file name: bidi/RTLO characters, double extensions, padding before the extension
- location: executables in user-writable folders (weak)
- PE (via the YARA-X `pe` module): packer section names, high-entropy code,
  tiny import tables, injection / downloader / keylogger import combinations
- Office documents (oletools/olevba): VBA or XLM macros, auto-run entry points,
  suspicious keywords
- scripts: encoded PowerShell, download cradles, LOLBin abuse, AMSI tampering,
  long base64 blobs, heavy character-code obfuscation
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

import yara_x

from hostguard.logsetup import get_logger
from hostguard.scan.model import Confidence, EngineHit, suspicious_chars

log = get_logger("scan.heuristics")

DEFAULT_THRESHOLD = 60
MAX_TEXT_SCAN = 5 * 1024 * 1024

EXECUTABLE_EXT = {
    "exe", "scr", "com", "pif", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "hta", "msi", "lnk", "cpl", "jar", "dll", "reg", "iso", "img",
}  # fmt: skip
DECOY_EXT = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png",
    "gif", "bmp", "mp3", "mp4", "avi", "mov", "zip", "rar", "csv", "htm", "html",
}  # fmt: skip
SCRIPT_EXT = {
    "ps1",
    "psm1",
    "psd1",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsf",
    "wsh",
    "hta",
    "bat",
    "cmd",
    "sct",
}
OFFICE_EXT = {
    "doc", "docm", "docx", "dot", "dotm", "xls", "xlsm", "xlsb", "xlsx", "xlt", "xltm",
    "ppt", "pptm", "pptx", "pps", "ppsm", "mht", "mhtml",
}  # fmt: skip
PACKER_SECTIONS = {
    b"UPX0": "UPX", b"UPX1": "UPX", b"UPX2": "UPX", b".aspack": "ASPack", b".adata": "ASPack",
    b".MPRESS1": "MPRESS", b".MPRESS2": "MPRESS", b".petite": "Petite", b".nsp0": "NsPack",
    b".nsp1": "NsPack", b".themida": "Themida", b".winlice": "WinLicense", b".vmp0": "VMProtect",
    b".vmp1": "VMProtect", b".enigma1": "Enigma", b".enigma2": "Enigma", b"PEC2": "PECompact",
}  # fmt: skip
USER_WRITABLE = re.compile(
    r"[\\/](downloads|desktop|temp|tmp|appdata|public)[\\/]|^/tmp/|^/var/tmp/|^/dev/shm/",
    re.IGNORECASE,
)
IMAGE_SCN_MEM_EXECUTE = 0x20000000


@dataclass
class HeuristicResult:
    hits: list[EngineHit] = field(default_factory=list)

    @property
    def score(self) -> int:
        return sum(h.score for h in self.hits)

    def add(self, hid: str, points: int, reason: str) -> None:
        self.hits.append(
            EngineHit("heuristics", f"HEUR.{hid}", reason, Confidence.LOW, score=points)
        )


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def _ext(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[1].lower().strip() if "." in base else ""


# --- file name and location -------------------------------------------------------------


def check_name(name: str, res: HeuristicResult) -> None:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    bad = suspicious_chars(base)
    if bad:
        res.add(
            "BidiName",
            70,
            f"file name contains {', '.join(bad)} (right-to-left/invisible characters can disguise the real extension)",
        )
    parts = base.lower().split(".")
    if len(parts) >= 3 and parts[-1].strip() in EXECUTABLE_EXT and parts[-2].strip() in DECOY_EXT:
        res.add(
            "DoubleExtension",
            60,
            f"double extension '.{parts[-2]}.{parts[-1].strip()}' (a program pretending to be a document)",
        )
    if re.search(r"\s{5,}\.[A-Za-z0-9]{2,4}$", base) or re.search(
        r"_{8,}\.[A-Za-z0-9]{2,4}$", base
    ):
        res.add(
            "PaddedName",
            40,
            "long run of spaces/underscores before the extension (hides it in narrow views)",
        )


def check_location(name: str, is_executable: bool, res: HeuristicResult) -> None:
    if is_executable and USER_WRITABLE.search(name.replace("\\", "/") if "/" in name else name):
        res.add(
            "UserWritableLocation",
            10,
            "executable content in a user-writable folder (Downloads/Desktop/Temp/AppData)",
        )


# --- PE ---------------------------------------------------------------------------------------


def check_pe(data: bytes, res: HeuristicResult) -> dict[str, object]:
    try:
        pe: dict[str, Any] = yara_x.Module("pe").invoke(data)  # type: ignore[arg-type]  # bytes per YARA-X docs
    except Exception as exc:  # malformed input must never crash the scan
        log.debug("pe module failed: %s", exc)
        return {}
    if not pe.get("is_pe"):
        return {}
    sections = pe.get("sections") or []
    packers = sorted(
        {
            PACKER_SECTIONS[s.get("name", b"")]
            for s in sections
            if s.get("name", b"") in PACKER_SECTIONS
        }
    )
    if packers:
        res.add(
            "PackerSections",
            25,
            f"packer section names ({', '.join(packers)}); packing hides code from inspection",
        )
    high_entropy = []
    for s in sections:
        off, size = int(s.get("raw_data_offset", 0)), int(s.get("raw_data_size", 0))
        if size >= 4096 and int(s.get("characteristics", 0)) & IMAGE_SCN_MEM_EXECUTE:
            e = entropy(data[off : off + min(size, 8 * 2**20)])
            if e > 7.2:
                name = s.get("name", b"").decode("ascii", "replace").strip("\x00")
                high_entropy.append(f"{name} ({e:.2f})")
    if high_entropy:
        res.add(
            "HighEntropyCode",
            25,
            f"executable section(s) with near-random data: {', '.join(high_entropy)} (typical of packed/encrypted code)",
        )
    funcs = {
        str(f.get("name", "")).lower()
        for lib in pe.get("import_details") or []
        for f in lib.get("functions") or []
    }
    if int(pe.get("number_of_imported_functions", 0)) < 5 and high_entropy:
        res.add(
            "TinyImportTable",
            20,
            "very few imported functions together with high-entropy code (packed executable)",
        )

    def has(*names: str) -> bool:
        return any(n in funcs for n in names)

    if (
        has("virtualallocex")
        and has("writeprocessmemory")
        and has("createremotethread", "ntcreatethreadex", "queueuserapc")
    ):
        res.add(
            "ProcessInjectionImports",
            40,
            "imports for writing into and starting code in other processes (process injection)",
        )
    if has("urldownloadtofilea", "urldownloadtofilew") and has(
        "shellexecutea", "shellexecutew", "winexec", "createprocessa", "createprocessw"
    ):
        res.add("DownloadExecuteImports", 30, "imports for downloading a file and running it")
    if has("setwindowshookexa", "setwindowshookexw") and has("getasynckeystate", "getkeystate"):
        res.add(
            "KeyloggerImports",
            25,
            "imports for global keyboard hooks and key-state polling (keylogger pattern)",
        )
    return pe


# --- Office documents ------------------------------------------------------------------------


def check_office(data: bytes, name: str, res: HeuristicResult) -> None:
    is_ole = data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    is_ooxml = data[:4] == b"PK\x03\x04" and (
        b"word/" in data[:65536] or b"xl/" in data[:65536] or b"ppt/" in data[:65536]
    )
    if not (is_ole or is_ooxml or _ext(name) in ("mht", "mhtml")):
        return
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:  # pragma: no cover - dependency is pinned
        return
    parser = None
    try:
        parser = VBA_Parser(name or "document", data=data)
        has_vba = parser.detect_vba_macros()
        has_xlm = bool(getattr(parser, "detect_xlm_macros", lambda: False)())
        if not (has_vba or has_xlm):
            return
        if has_xlm:
            res.add("XLMMacros", 30, "Excel 4.0 (XLM) macros present (rarely legitimate today)")
        if has_vba:
            res.add("VBAMacros", 20, "VBA macros present")
            results = parser.analyze_macros()
            autoexec = sorted({kw for typ, kw, _ in results if typ == "AutoExec"})
            suspicious = sorted({kw for typ, kw, _ in results if typ == "Suspicious"})
            if autoexec:
                res.add(
                    "MacroAutoRun",
                    30,
                    f"macro runs automatically on open ({', '.join(autoexec[:5])})",
                )
            if suspicious:
                res.add(
                    "MacroSuspiciousKeywords",
                    min(10 * len(suspicious), 40),
                    f"suspicious macro keywords: {', '.join(suspicious[:8])}",
                )
    except Exception as exc:  # olevba raises many types on malformed files
        log.debug("olevba failed on %s: %s", name, exc)
    finally:
        if parser is not None:
            with contextlib.suppress(Exception):
                parser.close()


# --- scripts -----------------------------------------------------------------------------------

_ENC_PS = re.compile(rb"(?i)-e(?:nc(?:odedcommand)?|c)?\s+([A-Za-z0-9+/]{40,}={0,2})")
_CRADLES: list[tuple[str, int, str, re.Pattern[bytes]]] = [
    ("PSDownloadCradle", 40, "PowerShell download-and-run pattern",
     re.compile(rb"(?is)(net\.webclient|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|start-bitstransfer).{0,300}?(iex\b|invoke-expression|downloadstring|\|\s*iex)")),
    ("CertutilDownload", 40, "certutil used to download files (LOLBin abuse)",
     re.compile(rb"(?i)certutil(?:\.exe)?\s+[^\r\n]*-urlcache")),
    ("BitsadminTransfer", 30, "bitsadmin download (LOLBin abuse)", re.compile(rb"(?i)bitsadmin(?:\.exe)?\s+/transfer")),
    ("MshtaRemote", 40, "mshta running remote content", re.compile(rb"(?i)mshta(?:\.exe)?\s+[\"']?(?:https?|vbscript|javascript):")),
    ("Regsvr32Remote", 50, "regsvr32 loading a remote scriptlet (Squiblydoo)", re.compile(rb"(?i)regsvr32(?:\.exe)?\s+.*?/i:\s*https?://")),
    ("Rundll32Script", 50, "rundll32 running script code", re.compile(rb"(?i)rundll32(?:\.exe)?\s+[^\r\n]*javascript:")),
    ("AmsiTampering", 50, "attempt to disable the Antimalware Scan Interface (AMSI)",
     re.compile(rb"(?is)amsiutils.{0,200}amsiinitfailed|amsiinitfailed.{0,200}amsiutils|amsiscanbuffer.{0,100}virtualprotect")),
    ("HiddenWindowPS", 15, "PowerShell started hidden and without profile",
     re.compile(rb"(?i)powershell(?:\.exe)?[^\r\n]{0,80}-w(?:indowstyle)?\s+hidden")),
]  # fmt: skip
_B64_BLOB = re.compile(rb"[A-Za-z0-9+/]{2000,}={0,2}")
_CHARCODE = re.compile(rb"(?i)\[char\]\s*\d+|chrw?\(\s*\d+\s*\)|string\.fromcharcode")


def check_script(data: bytes, name: str, res: HeuristicResult, *, _depth: int = 0) -> None:
    ext = _ext(name)
    is_lnk = ext == "lnk"
    if ext not in SCRIPT_EXT and not is_lnk and _depth == 0:
        return
    text = data[:MAX_TEXT_SCAN]
    if is_lnk:
        # Shortcut arguments are UTF-16LE; fold to ASCII for pattern matching.
        text = text.replace(b"\x00", b"")
    m = _ENC_PS.search(text)
    if m:
        decoded = _decode_ps(m.group(1))
        res.add(
            "EncodedPowerShell", 40, "PowerShell with a base64-encoded command (hides what it runs)"
        )
        if decoded and _depth == 0:
            check_script(decoded, name + "#decoded", res, _depth=1)
    for hid, pts, reason, rx in _CRADLES:
        if rx.search(text) and not any(h.name == f"HEUR.{hid}" for h in res.hits):
            res.add(hid, pts, reason)
    if _B64_BLOB.search(text):
        res.add("LongBase64Blob", 20, "long base64-encoded blob (embedded payload?)")
    if len(_CHARCODE.findall(text)) > 20:
        res.add("CharCodeObfuscation", 20, "heavy character-code obfuscation")
    if is_lnk and re.search(rb"(?i)powershell|cmd(?:\.exe)?\s+/c|mshta|wscript|cscript", text):
        res.add("ShortcutRunsInterpreter", 30, "shortcut (.lnk) that launches a script interpreter")


def _decode_ps(b64: bytes) -> bytes:
    try:
        raw = base64.b64decode(b64 + b"=" * (-len(b64) % 4), validate=False)
    except (binascii.Error, ValueError):
        return b""
    try:
        return raw.decode("utf-16-le", errors="ignore").encode("ascii", errors="ignore")
    except UnicodeError:
        return raw


# --- entry point -------------------------------------------------------------------------------


def analyse(
    data: bytes, name: str, *, in_user_writable_check: bool = True
) -> tuple[HeuristicResult, dict[str, object]]:
    res = HeuristicResult()
    check_name(name, res)
    pe = check_pe(data, res) if data[:2] == b"MZ" else {}
    check_office(data, name, res)
    check_script(data, name, res)
    if in_user_writable_check:
        executable = bool(pe) or _ext(name) in EXECUTABLE_EXT
        check_location(name, executable, res)
    return res, pe
