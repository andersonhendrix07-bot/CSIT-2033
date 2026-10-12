"""Shared fixtures. Every test gets an isolated HOSTGUARD_HOME and no network."""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest


class NetworkBlockedError(RuntimeError):
    pass


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "hghome"
    monkeypatch.setenv("HOSTGUARD_HOME", str(home))
    for name in ("NVD_API_KEY", "ABUSECH_AUTH_KEY", "VT_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    return home


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Fail any test that tries to open a real network connection (mock it instead)."""

    def guard(self: socket.socket, address: Any, *args: Any, **kwargs: Any) -> Any:
        if self.family in (socket.AF_INET, socket.AF_INET6):
            raise NetworkBlockedError(f"network access attempted in a test: {address!r}")
        return real_connect(self, address, *args, **kwargs)

    real_connect = socket.socket.connect
    monkeypatch.setattr(socket.socket, "connect", guard)
    monkeypatch.setattr(socket.socket, "connect_ex", guard)
    yield


@pytest.fixture(autouse=True)
def no_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never read the developer's real OS keyring during tests."""
    monkeypatch.setattr("hostguard.credentials._from_keyring", lambda name: None)
