"""Logging: a rotating UTF-8 log file plus a concise console handler.

A redaction filter replaces any registered secret value with `***` before a
record is written anywhere.
"""

from __future__ import annotations

import logging
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path

from rich.logging import RichHandler

_SECRETS: set[str] = set()
_LOCK = threading.Lock()
_MIN_SECRET_LEN = 6  # avoid redacting trivially short strings everywhere

LOGGER_NAME = "hostguard"


def register_secret(value: str) -> None:
    if len(value) >= _MIN_SECRET_LEN:
        with _LOCK:
            _SECRETS.add(value)


def redact(text: str) -> str:
    with _LOCK:
        secrets = sorted(_SECRETS, key=len, reverse=True)
    for s in secrets:
        text = text.replace(s, "***")
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        record.msg = redact(msg)
        record.args = None
        return True


def setup_logging(
    log_file: Path,
    *,
    file_level: str = "INFO",
    console_level: int = logging.WARNING,
    max_bytes: int = 1_048_576,
    backups: int = 5,
) -> logging.Logger:
    """Configure the `hostguard` logger. Safe to call more than once."""
    logger = logging.getLogger(LOGGER_NAME)
    for h in list(logger.handlers):
        logger.removeHandler(h)
        h.close()
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    log_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fh = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backups, encoding="utf-8")
    fh.setLevel(getattr(logging, file_level.upper()))
    fh.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)-8s %(name)s: %(message)s", "%Y-%m-%dT%H:%M:%S%z"
        )
    )
    fh.addFilter(RedactingFilter())
    logger.addHandler(fh)

    ch = RichHandler(level=console_level, show_time=False, show_path=False, markup=False)
    ch.addFilter(RedactingFilter())
    logger.addHandler(ch)
    return logger


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"{LOGGER_NAME}.{name}")
