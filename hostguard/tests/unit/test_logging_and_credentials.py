from __future__ import annotations

import logging
from pathlib import Path

import pytest

from hostguard.credentials import KNOWN_SECRETS, get_secret, secret_status
from hostguard.logsetup import get_logger, redact, setup_logging

FAKE_KEY = "test-key-0123456789abcdef"


def _read_logs(log_file: Path) -> str:
    for h in logging.getLogger("hostguard").handlers:
        h.flush()
    return "".join(p.read_text(encoding="utf-8") for p in log_file.parent.glob("hostguard.log*"))


def test_log_file_written_utf8(tmp_path: Path) -> None:
    log_file = tmp_path / "logs" / "hostguard.log"
    setup_logging(log_file)
    get_logger("t").info("scanned %s", "Résumé‮fdp.exe")
    assert "Résumé" in _read_logs(log_file)


def test_log_rotation(tmp_path: Path) -> None:
    log_file = tmp_path / "logs" / "hostguard.log"
    setup_logging(log_file, max_bytes=500, backups=2)
    lg = get_logger("t")
    for i in range(100):
        lg.info("line %d %s", i, "x" * 50)
    files = sorted(p.name for p in log_file.parent.iterdir())
    assert files == ["hostguard.log", "hostguard.log.1", "hostguard.log.2"]


def test_secret_from_env_is_redacted_everywhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NVD_API_KEY", FAKE_KEY)
    s = get_secret("NVD_API_KEY")
    assert s is not None and s.reveal() == FAKE_KEY and s.source == "env"
    assert FAKE_KEY not in repr(s) and FAKE_KEY not in str(s)

    log_file = tmp_path / "logs" / "hostguard.log"
    setup_logging(log_file, file_level="DEBUG")
    lg = get_logger("t")
    lg.debug("GET https://example.invalid/?apiKey=%s", FAKE_KEY)
    try:
        raise RuntimeError(f"failed with {FAKE_KEY}")
    except RuntimeError:
        lg.exception("boom")
    text = _read_logs(log_file)
    assert FAKE_KEY not in text
    assert "apiKey=***" in text
    assert redact(f"x{FAKE_KEY}y") == "x***y"


def test_missing_secret_returns_none() -> None:
    assert get_secret("VT_API_KEY") is None
    assert set(secret_status()) == set(KNOWN_SECRETS)
    assert all(v == "not set" for v in secret_status().values())


def test_unknown_secret_name_rejected() -> None:
    with pytest.raises(KeyError):
        get_secret("AWS_SECRET_ACCESS_KEY")


def test_keyring_used_when_env_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("hostguard.credentials._from_keyring", lambda name: "from-keyring-123456")
    s = get_secret("ABUSECH_AUTH_KEY")
    assert s is not None and s.source == "keyring"
    assert redact("from-keyring-123456") == "***"
