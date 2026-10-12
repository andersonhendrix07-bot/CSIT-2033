"""Read-only access to Windows facilities: the registry and fixed PowerShell queries.

Both are behind small interfaces so the inventory and audit code can be unit
tested on any OS with fakes. Nothing here writes to the registry, and every
PowerShell script is a constant string in this codebase: no data from the
system is ever interpolated into a script.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Protocol

from hostguard import proc
from hostguard.models import Evidence

HKLM = "HKLM"
HKCU = "HKCU"


class RegistryError(Exception):
    pass


class Registry(Protocol):
    def values(self, hive: str, path: str, *, view32: bool = False) -> dict[str, Any] | None:
        """All values of a key (name -> data), or None if the key does not exist."""

    def value(self, hive: str, path: str, name: str) -> Any:
        """One value's data, or None if the key or value does not exist."""

    def value_names(self, hive: str, path: str) -> list[str] | None:
        """Value names only. Used where the data is secret (e.g. DefaultPassword)."""

    def subkeys(self, hive: str, path: str, *, view32: bool = False) -> list[str] | None:
        """Names of subkeys, or None if the key does not exist."""


class WinRegistry:
    """Real registry access via winreg, always KEY_READ."""

    def _open(self, hive: str, path: str, view32: bool) -> Any:
        if sys.platform != "win32":
            raise RegistryError("the Windows registry is only available on Windows")
        import winreg

        root = {HKLM: winreg.HKEY_LOCAL_MACHINE, HKCU: winreg.HKEY_CURRENT_USER}[hive]
        access = winreg.KEY_READ | (winreg.KEY_WOW64_32KEY if view32 else winreg.KEY_WOW64_64KEY)
        try:
            return winreg.OpenKey(root, path, 0, access)
        except FileNotFoundError:
            return None
        except PermissionError as exc:
            raise RegistryError(f"access denied: {hive}\\{path}") from exc

    def values(self, hive: str, path: str, *, view32: bool = False) -> dict[str, Any] | None:
        if sys.platform != "win32":
            raise RegistryError("the Windows registry is only available on Windows")
        import winreg

        key = self._open(hive, path, view32)
        if key is None:
            return None
        out: dict[str, Any] = {}
        with key:
            i = 0
            while True:
                try:
                    name, data, _typ = winreg.EnumValue(key, i)
                except OSError:
                    break
                out[name] = data
                i += 1
        return out

    def value(self, hive: str, path: str, name: str) -> Any:
        if sys.platform != "win32":
            raise RegistryError("the Windows registry is only available on Windows")
        import winreg

        key = self._open(hive, path, False)
        if key is None:
            return None
        with key:
            try:
                data, _typ = winreg.QueryValueEx(key, name)
            except FileNotFoundError:
                return None
        return data

    def value_names(self, hive: str, path: str) -> list[str] | None:
        if sys.platform != "win32":
            raise RegistryError("the Windows registry is only available on Windows")
        import winreg

        key = self._open(hive, path, False)
        if key is None:
            return None
        names: list[str] = []
        with key:
            i = 0
            while True:
                try:
                    name, _data, _typ = winreg.EnumValue(key, i)  # data discarded at once
                except OSError:
                    break
                names.append(name)
                i += 1
        return names

    def subkeys(self, hive: str, path: str, *, view32: bool = False) -> list[str] | None:
        if sys.platform != "win32":
            raise RegistryError("the Windows registry is only available on Windows")
        import winreg

        key = self._open(hive, path, view32)
        if key is None:
            return None
        names: list[str] = []
        with key:
            i = 0
            while True:
                try:
                    names.append(winreg.EnumKey(key, i))
                except OSError:
                    break
                i += 1
        return names


def reg_evidence(hive: str, path: str, shown: dict[str, Any] | str) -> Evidence:
    return Evidence(source=f"registry {hive}\\{path}", output=_short(shown))


def _short(obj: Any, limit: int = 2000) -> str:
    text = obj if isinstance(obj, str) else json.dumps(obj, default=str, ensure_ascii=False)
    return text if len(text) <= limit else text[:limit] + " …[truncated]"


class PowerShell(Protocol):
    def run_json(self, script: str, *, timeout: float = 60.0) -> tuple[Any, Evidence]:
        """Run a constant script ending in ConvertTo-Json; return parsed data and evidence."""


class PowerShellError(Exception):
    def __init__(self, message: str, evidence: Evidence | None = None) -> None:
        super().__init__(message)
        self.evidence = evidence


# Forces UTF-8 output so non-ASCII names survive Windows PowerShell 5.1's console encoding.
_PS_PREAMBLE = (
    "$ErrorActionPreference='Stop';"
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
    "$ProgressPreference='SilentlyContinue';"
)


def powershell_path() -> str:
    root = os.environ.get("SYSTEMROOT", r"C:\Windows")
    return str(Path(root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")


class RealPowerShell:
    def run_json(self, script: str, *, timeout: float = 60.0) -> tuple[Any, Evidence]:
        argv = [
            powershell_path(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            _PS_PREAMBLE + script,
        ]
        try:
            r = proc.run(argv, timeout=timeout)
        except proc.ToolNotFoundError as exc:
            raise PowerShellError(f"PowerShell not found: {exc}") from exc
        ev = Evidence(source=f"powershell: {script}", output=_short(r.stdout or r.stderr))
        if r.timed_out:
            raise PowerShellError("PowerShell timed out", ev)
        if r.returncode != 0:
            raise PowerShellError(_first_line(r.stderr) or f"exit code {r.returncode}", ev)
        text = r.stdout.strip()
        if not text:
            return None, ev
        try:
            return json.loads(text), ev
        except ValueError as exc:
            raise PowerShellError("PowerShell did not return JSON", ev) from exc


def _first_line(s: str) -> str:
    for line in s.splitlines():
        if line.strip():
            return line.strip()[:300]
    return ""


def as_list(data: Any) -> list[Any]:
    """ConvertTo-Json returns a bare object for one item and an array for several."""
    if data is None:
        return []
    return data if isinstance(data, list) else [data]


def iter_dicts(data: Any) -> Iterator[dict[str, Any]]:
    for item in as_list(data):
        if isinstance(item, dict):
            yield item
