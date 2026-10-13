"""ClamAV: clamd over a *local* socket (INSTREAM), with a clamscan batch fallback.

Protocol per ClamAV's "ClamD Protocol" documentation: `zINSTREAM\\0`, then chunks
of a 4-byte big-endian length + data, ended by a zero-length chunk. Replies look
like `stream: OK` or `stream: Eicar-Signature FOUND`. Only Unix sockets or
loopback TCP addresses are accepted: hostguard never talks to other hosts.
"""

from __future__ import annotations

import shutil
import socket
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

from hostguard import proc
from hostguard.logsetup import get_logger
from hostguard.scan.model import Confidence, EngineHit

log = get_logger("scan.clamav")

UNIX_SOCKETS = (
    "/run/clamav/clamd.ctl",
    "/var/run/clamav/clamd.ctl",
    "/run/clamav/clamd.sock",
    "/var/run/clamd.scan/clamd.sock",
    "/tmp/clamd.socket",  # noqa: S108 - a well-known clamd socket path, only probed
)
DEFAULT_TCP = ("127.0.0.1", 3310)
LOOPBACK = {"127.0.0.1", "::1", "localhost"}
CHUNK = 1024 * 1024
TIMEOUT = 120.0
WINDOWS_CLAMSCAN = (
    r"C:\Program Files\ClamAV\clamscan.exe",
    r"C:\Program Files (x86)\ClamAV\clamscan.exe",
)


@dataclass(frozen=True)
class ClamdAddress:
    unix_path: str = ""
    host: str = ""
    port: int = 0

    def __str__(self) -> str:
        return self.unix_path or f"tcp://{self.host}:{self.port}"


def parse_address(spec: str) -> ClamdAddress:
    """'auto' handled by the caller; '/path/to/socket' or 'tcp:127.0.0.1:3310'."""
    if spec.startswith("tcp:"):
        host, _, port = spec[4:].rpartition(":")
        host = host.strip("[]")
        if host not in LOOPBACK:
            raise ValueError(f"clamd address must be on this machine (loopback), got {host!r}")
        return ClamdAddress(host=host, port=int(port))
    return ClamdAddress(unix_path=spec)


def _connect(addr: ClamdAddress, timeout: float) -> socket.socket:
    if addr.unix_path:
        if not hasattr(socket, "AF_UNIX"):
            raise OSError("Unix sockets are not available on this OS")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(addr.unix_path)
        return s
    if addr.host not in LOOPBACK:
        raise OSError("refusing non-loopback clamd address")
    s = socket.create_connection((addr.host, addr.port), timeout=timeout)
    return s


def _recv_all(s: socket.socket, limit: int = 65536) -> bytes:
    out = b""
    while len(out) < limit:
        chunk = s.recv(4096)
        if not chunk:
            break
        out += chunk
        if out.endswith(b"\0"):
            break
    return out


class Clamd:
    name = "clamav"

    def __init__(self, addr: ClamdAddress) -> None:
        self.addr = addr
        self.version = ""

    def ping(self) -> bool:
        try:
            with _connect(self.addr, 3.0) as s:
                s.sendall(b"zPING\0")
                if _recv_all(s).rstrip(b"\0") != b"PONG":
                    return False
            with _connect(self.addr, 3.0) as s:
                s.sendall(b"zVERSION\0")
                self.version = _recv_all(s).rstrip(b"\0").decode("utf-8", "replace")
            return True
        except OSError:
            return False

    def scan_bytes(self, data: bytes) -> tuple[list[EngineHit], str]:
        try:
            with _connect(self.addr, TIMEOUT) as s:
                s.sendall(b"zINSTREAM\0")
                for i in range(0, len(data), CHUNK):
                    part = data[i : i + CHUNK]
                    s.sendall(struct.pack(">I", len(part)) + part)
                s.sendall(struct.pack(">I", 0))
                reply = _recv_all(s).rstrip(b"\0").decode("utf-8", "replace").strip()
        except OSError as exc:
            return [], f"clamd error: {exc}"
        return parse_reply(reply)

    def scan_file(self, path: str) -> tuple[list[EngineHit], str]:
        try:
            with open(path, "rb") as fh, _connect(self.addr, TIMEOUT) as s:
                s.sendall(b"zINSTREAM\0")
                while True:
                    part = fh.read(CHUNK)
                    if not part:
                        break
                    s.sendall(struct.pack(">I", len(part)) + part)
                s.sendall(struct.pack(">I", 0))
                reply = _recv_all(s).rstrip(b"\0").decode("utf-8", "replace").strip()
        except OSError as exc:
            return [], f"clamd error: {exc}"
        return parse_reply(reply)


def parse_reply(reply: str) -> tuple[list[EngineHit], str]:
    body = reply.split(": ", 1)[1] if ": " in reply else reply
    if body.endswith(" FOUND"):
        sig = body[: -len(" FOUND")].strip()
        return [
            EngineHit("clamav", sig, "ClamAV signature match", Confidence.HIGH, source="ClamAV")
        ], ""
    if body == "OK":
        return [], ""
    return [], f"clamd: {reply[:200]}"


def find_clamd(spec: str) -> Clamd | None:
    if spec == "off":
        return None
    candidates: list[ClamdAddress] = []
    if spec and spec != "auto":
        candidates.append(parse_address(spec))
    else:
        candidates += [ClamdAddress(unix_path=p) for p in UNIX_SOCKETS if Path(p).exists()]
        candidates.append(ClamdAddress(host=DEFAULT_TCP[0], port=DEFAULT_TCP[1]))
    for addr in candidates:
        c = Clamd(addr)
        if c.ping():
            return c
    return None


def find_clamscan() -> str | None:
    found = shutil.which("clamscan")
    if found:
        return found
    if sys.platform == "win32":
        for p in WINDOWS_CLAMSCAN:
            if Path(p).is_file():
                return p
    return None


def clamscan_batch(
    exe: str, list_file: str, timeout: float = 6 * 3600.0
) -> tuple[dict[str, str], str]:
    """Scan many on-disk files with one clamscan run (it loads its database only once).

    Paths come from a --file-list file so hostile names are never parsed as options.
    Returns {path: signature} for detections, and an error note.
    """
    r = proc.run(
        [exe, "--no-summary", "--infected", "--stdout", f"--file-list={list_file}"], timeout=timeout
    )
    found: dict[str, str] = {}
    for line in r.stdout.splitlines():
        if line.endswith(" FOUND") and ": " in line:
            path, sig = line[: -len(" FOUND")].rsplit(": ", 1)
            found[path] = sig.strip()
    note = ""
    if r.timed_out:
        note = "clamscan timed out"
    elif r.returncode not in (0, 1):
        note = f"clamscan reported errors (exit {r.returncode}): {(r.stderr or '').strip()[:200]}"
    return found, note
