"""Test doubles for Windows registry and PowerShell access."""

from __future__ import annotations

from typing import Any

from hostguard.models import Evidence
from hostguard.winsys import PowerShellError, RegistryError


class FakeRegistry:
    """Keys are (hive, path, view32). Paths are case-insensitive like the real registry."""

    def __init__(
        self, data: dict[tuple[str, str, bool] | tuple[str, str], dict[str, Any]] | None = None
    ) -> None:
        self.data: dict[tuple[str, str, bool], dict[str, Any]] = {}
        self.denied: set[tuple[str, str]] = set()
        self.reads: list[tuple[str, str, str]] = []  # single-value reads, for secrecy tests
        for k, v in (data or {}).items():
            self.set(k[0], k[1], v, view32=bool(k[2]) if len(k) == 3 else False)  # type: ignore[misc]

    def set(self, hive: str, path: str, values: dict[str, Any], *, view32: bool = False) -> None:
        self.data[(hive, path.lower(), view32)] = values

    def _check(self, hive: str, path: str) -> None:
        if (hive, path.lower()) in {(h, p.lower()) for h, p in self.denied}:
            raise RegistryError(f"access denied: {hive}\\{path}")

    def values(self, hive: str, path: str, *, view32: bool = False) -> dict[str, Any] | None:
        self._check(hive, path)
        key = (hive, path.lower(), view32)
        if key in self.data:
            return dict(self.data[key])
        return {} if self.subkeys(hive, path, view32=view32) else None

    def value(self, hive: str, path: str, name: str) -> Any:
        self._check(hive, path)
        self.reads.append((hive, path.lower(), name))
        return self.data.get((hive, path.lower(), False), {}).get(name)

    def value_names(self, hive: str, path: str) -> list[str] | None:
        v = self.values(hive, path)
        return None if v is None else list(v)

    def subkeys(self, hive: str, path: str, *, view32: bool = False) -> list[str] | None:
        self._check(hive, path)
        prefix = path.lower() + "\\"
        names = []
        for h, p, v32 in self.data:
            if h == hive and v32 == view32 and p.startswith(prefix):
                child = p[len(prefix) :].split("\\", 1)[0]
                if child not in names:
                    names.append(child)
        if not names and (hive, path.lower(), view32) not in self.data:
            return None
        return names


class FakePowerShell:
    """Maps a substring of the script to a result (data) or an exception."""

    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[str] = []

    def run_json(self, script: str, *, timeout: float = 60.0) -> tuple[Any, Evidence]:
        self.calls.append(script)
        for needle, result in self.responses.items():
            if needle in script:
                ev = Evidence(f"powershell: {script}", str(result)[:200])
                if isinstance(result, Exception):
                    if isinstance(result, PowerShellError):
                        result.evidence = ev
                    raise result
                return result, ev
        raise PowerShellError(f"no fake response for script: {script[:60]}")
