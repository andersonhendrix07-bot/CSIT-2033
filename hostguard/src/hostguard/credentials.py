"""API keys from environment variables or the OS keyring; never hard-coded or logged.

Every secret that is read is registered with the logging redaction filter, so
even an accidental `log.debug(url)` containing the key is written as `***`.
"""

from __future__ import annotations

import os
from typing import Final

from hostguard.logsetup import register_secret

KEYRING_SERVICE: Final = "hostguard"

# Name -> human description. These are the only secrets hostguard knows about.
KNOWN_SECRETS: Final = {
    "NVD_API_KEY": "NVD CVE API key (optional; raises the rate limit)",
    "ABUSECH_AUTH_KEY": "abuse.ch Auth-Key (required for MalwareBazaar hash exports)",
    "VT_API_KEY": "VirusTotal API key (optional; hash lookups only)",
}


class Secret:
    """Wrapper whose str/repr never reveal the value."""

    __slots__ = ("_value", "name", "source")

    def __init__(self, name: str, value: str, source: str) -> None:
        self.name = name
        self.source = source  # "env" | "keyring"
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"Secret({self.name!r}, source={self.source!r}, value=***)"

    __str__ = __repr__


def get_secret(name: str) -> Secret | None:
    if name not in KNOWN_SECRETS:
        raise KeyError(f"unknown secret {name!r}")
    value = os.environ.get(name)
    source = "env"
    if not value:
        value = _from_keyring(name)
        source = "keyring"
    if not value:
        return None
    register_secret(value)
    return Secret(name, value, source)


def _from_keyring(name: str) -> str | None:
    try:
        import keyring  # optional dependency
    except ImportError:
        return None
    try:
        return keyring.get_password(KEYRING_SERVICE, name)
    except Exception:  # any keyring backend failure just means "not available"
        return None


def secret_status() -> dict[str, str]:
    """Which secrets are configured and where, without revealing them."""
    status = {}
    for name in KNOWN_SECRETS:
        s = get_secret(name)
        status[name] = f"set ({s.source})" if s else "not set"
    return status
