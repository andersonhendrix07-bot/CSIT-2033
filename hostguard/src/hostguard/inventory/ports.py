"""Listening sockets on this machine, from the OS socket table (not a network scan)."""

from __future__ import annotations

import socket
from typing import Any

import psutil

from hostguard.inventory.models import Listener, Skip
from hostguard.models import Evidence

SOURCE = "psutil.net_connections(kind='inet')"


def collect(skipped: list[Skip]) -> tuple[list[Listener], Evidence | None]:
    try:
        conns: list[Any] = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        skipped.append(Skip("Listening ports", "Skipped: requires admin on this OS"))
        return [], None
    except OSError as exc:
        skipped.append(Skip("Listening ports", str(exc)))
        return [], None

    names: dict[int, tuple[str, str]] = {}
    out: list[Listener] = []
    seen: set[tuple[str, str, int]] = set()
    for c in conns:
        is_tcp = c.type == socket.SOCK_STREAM
        if is_tcp and c.status != psutil.CONN_LISTEN:
            continue
        if not is_tcp and c.raddr:  # connected UDP socket, not a listener
            continue
        if not c.laddr:
            continue
        proto = "tcp" if is_tcp else "udp"
        key = (proto, c.laddr.ip, c.laddr.port)
        if key in seen:
            continue
        seen.add(key)
        pname, exe = _process(c.pid, names)
        out.append(Listener(proto, c.laddr.ip, c.laddr.port, c.pid, pname, exe))
    out.sort(key=lambda listener: (listener.protocol, listener.port, listener.address))
    ev = Evidence(SOURCE, f"{len(out)} listening sockets")
    return out, ev


def _process(pid: int | None, cache: dict[int, tuple[str, str]]) -> tuple[str, str]:
    if not pid:
        return "unknown (not visible to this user)", ""
    if pid in cache:
        return cache[pid]
    try:
        p = psutil.Process(pid)
        name = p.name()
        try:
            exe = p.exe()
        except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
            exe = ""
        result = (name, exe)
    except psutil.AccessDenied:
        result = ("unknown (access denied)", "")
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        result = ("exited", "")
    cache[pid] = result
    return result
