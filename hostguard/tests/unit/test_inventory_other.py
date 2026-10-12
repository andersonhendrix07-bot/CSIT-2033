from __future__ import annotations

import plistlib
import socket
from collections import namedtuple
from collections.abc import Sequence
from pathlib import Path

import psutil
import pytest

from hostguard import proc
from hostguard.inventory import linux, macos, ports, python_envs
from hostguard.inventory.models import Skip

UBUNTU_OS_RELEASE = """PRETTY_NAME="Ubuntu 24.04.5 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.5 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
"""


def fake_runner(outputs: dict[str, proc.ProcResult | Exception]):  # type: ignore[no-untyped-def]
    def run(argv: Sequence[str]) -> proc.ProcResult:
        out = outputs.get(argv[0])
        if out is None:
            raise proc.ToolNotFoundError(argv[0])
        if isinstance(out, Exception):
            raise out
        return out

    return run


def ok(argv: list[str], stdout: str) -> proc.ProcResult:
    return proc.ProcResult(tuple(argv), 0, stdout, "")


# --- Linux -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("osr", "expected"),
    [
        (
            {"ID": "ubuntu", "VERSION_ID": "24.04", "VERSION": "24.04.5 LTS (Noble Numbat)"},
            "Ubuntu:24.04:LTS",
        ),
        ({"ID": "ubuntu", "VERSION_ID": "25.04", "VERSION": "25.04 (Plucky)"}, "Ubuntu:25.04"),
        ({"ID": "debian", "VERSION_ID": "12"}, "Debian:12"),
        ({"ID": "almalinux", "VERSION_ID": "9.4"}, "AlmaLinux:9"),
        ({"ID": "rocky", "VERSION_ID": "9.4"}, "Rocky Linux:9"),
        ({"ID": "arch"}, ""),
        ({"ID": "fedora", "VERSION_ID": "40"}, ""),
    ],
)
def test_osv_ecosystem(osr: dict[str, str], expected: str) -> None:
    assert linux.osv_ecosystem(osr) == expected


def test_os_release_and_collect_os(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text(UBUNTU_OS_RELEASE, encoding="utf-8")
    osr = linux.read_os_release(tmp_path)
    assert osr["ID"] == "ubuntu" and osr["PRETTY_NAME"] == "Ubuntu 24.04.5 LTS"
    info = linux.collect_os(tmp_path)
    assert info.distro_version == "24.04" and "ID=ubuntu" in info.evidence[0].output


def test_linux_software_dpkg_rpm_snap_flatpak() -> None:
    dpkg = (
        "ii \tlibssl3t64:amd64\t3.0.13-0ubuntu3.16\topenssl\t3.0.13-0ubuntu3.16\n"
        "rc \told-removed\t1.0\told\t1.0\n"
        "ii \tbash\t5.2.21-2ubuntu4\tbash\t5.2.21-2ubuntu4\n"
    )
    rpm = "gpg-pubkey\t0:abc-def\t\nopenssl\t1:3.0.7-27.el9\tAlmaLinux\nbash\t0:5.1.8-9.el9\tAlmaLinux\n"
    snap = "Name  Version  Rev  Tracking  Publisher  Notes\nfirefox  131.0  4932  latest/stable  mozilla**  -\n"
    runner = fake_runner(
        {
            "dpkg-query": ok(["dpkg-query"], dpkg),
            "rpm": ok(["rpm"], rpm),
            "snap": ok(["snap"], snap),
            "flatpak": proc.ProcResult(("flatpak",), 1, "", "error: not configured"),
        }
    )
    skipped: list[Skip] = []
    sw, ev = linux.collect_software("Ubuntu:24.04:LTS", skipped, runner)
    by = {(s.source, s.name): s for s in sw}
    libssl = by[("dpkg", "libssl3t64")]
    assert (libssl.package, libssl.package_version, libssl.ecosystem) == (
        "openssl",
        "3.0.13-0ubuntu3.16",
        "Ubuntu:24.04:LTS",
    )
    assert ("dpkg", "old-removed") not in by
    assert by[("rpm", "openssl")].version == "1:3.0.7-27.el9"
    assert by[("rpm", "bash")].version == "5.1.8-9.el9"
    assert ("rpm", "gpg-pubkey") not in by
    assert by[("snap", "firefox")].version == "131.0"
    assert any("flatpak" in s.what for s in skipped)
    assert ev[0].output == "2 installed packages"


def test_missing_package_managers_are_not_skips() -> None:
    skipped: list[Skip] = []
    sw, _ = linux.collect_software("", skipped, fake_runner({}))
    assert sw == [] and skipped == []


def test_linux_persistence(tmp_path: Path) -> None:
    root, home = tmp_path / "root", tmp_path / "home"
    (root / "etc/cron.d").mkdir(parents=True)
    (root / "etc/crontab").write_text(
        "SHELL=/bin/sh\n# comment\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"
    )
    (root / "etc/cron.d/backup").write_text("0 2 * * * root /opt/backup.sh\n")
    wants = root / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True)
    (wants / "evil.service").write_text("[Service]\nExecStart=/tmp/.x/miner --quiet\n")
    auto = home / ".config/autostart"
    auto.mkdir(parents=True)
    (auto / "app.desktop").write_text("[Desktop Entry]\nExec=/home/me/.local/bin/app\n")
    skipped: list[Skip] = []
    entries = linux.collect_persistence(skipped, root, home)
    cmds = {(e.kind, e.command) for e in entries}
    assert ("cron", "0 2 * * * root /opt/backup.sh") in cmds
    assert ("systemd", "/tmp/.x/miner --quiet") in cmds
    assert ("xdg-autostart", "/home/me/.local/bin/app") in cmds
    assert not any("SHELL" in c for _, c in cmds)


# --- Python environments ------------------------------------------------------


def _dist(sp: Path, name: str, version: str) -> None:
    d = sp / f"{name}-{version}.dist-info"
    d.mkdir(parents=True)
    (d / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", encoding="utf-8"
    )


def test_python_envs_windows_and_posix_layouts(tmp_path: Path) -> None:
    win = tmp_path / "winvenv"
    _dist(win / "Lib" / "site-packages", "Jinja2", "2.10")
    nix = tmp_path / "nixvenv"
    _dist(nix / "lib" / "python3.13" / "site-packages", "zope.interface", "6.0")
    # A package whose code would do harm if imported: it must never be executed.
    (nix / "lib/python3.13/site-packages/evil.py").write_text("raise SystemExit('executed!')\n")
    (nix / "lib/python3.13/site-packages/evil.pth").write_text("import evil\n")
    skipped: list[Skip] = []
    pkgs = python_envs.collect([str(win), str(nix), str(tmp_path / "missing")], skipped)
    assert {(p.name, p.version) for p in pkgs} == {("jinja2", "2.10"), ("zope-interface", "6.0")}
    assert "METADATA" in pkgs[0].evidence.source
    assert skipped[0].reason == "folder not found"


def test_python_env_pointing_at_site_packages(tmp_path: Path) -> None:
    _dist(tmp_path, "requests", "2.32.5")
    assert python_envs.collect([str(tmp_path)], [])[0].name == "requests"


def test_python_env_without_site_packages(tmp_path: Path) -> None:
    skipped: list[Skip] = []
    assert python_envs.collect([str(tmp_path)], skipped) == []
    assert "no site-packages" in skipped[0].reason


# --- Ports --------------------------------------------------------------------

Addr = namedtuple("Addr", "ip port")
Conn = namedtuple("Conn", "fd family type laddr raddr status pid")


def test_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    conns = [
        Conn(
            1, socket.AF_INET, socket.SOCK_STREAM, Addr("0.0.0.0", 445), (), psutil.CONN_LISTEN, 4
        ),
        Conn(
            2,
            socket.AF_INET,
            socket.SOCK_STREAM,
            Addr("127.0.0.1", 9000),
            (),
            psutil.CONN_LISTEN,
            None,
        ),
        Conn(
            3,
            socket.AF_INET,
            socket.SOCK_STREAM,
            Addr("10.0.0.5", 50000),
            Addr("1.2.3.4", 443),
            psutil.CONN_ESTABLISHED,
            5,
        ),
        Conn(4, socket.AF_INET6, socket.SOCK_DGRAM, Addr("::", 5353), (), psutil.CONN_NONE, 6),
        Conn(
            5,
            socket.AF_INET,
            socket.SOCK_DGRAM,
            Addr("10.0.0.5", 5000),
            Addr("8.8.8.8", 53),
            psutil.CONN_NONE,
            6,
        ),
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda kind: conns)

    class P:
        def __init__(self, pid: int) -> None:
            if pid == 4:
                raise psutil.AccessDenied(pid)
            self.pid = pid

        def name(self) -> str:
            return "mdns.exe"

        def exe(self) -> str:
            raise psutil.AccessDenied(self.pid)

    monkeypatch.setattr(psutil, "Process", P)
    skipped: list[Skip] = []
    listeners, ev = ports.collect(skipped)
    got = {(x.protocol, x.address, x.port, x.process) for x in listeners}
    assert got == {
        ("tcp", "0.0.0.0", 445, "unknown (access denied)"),
        ("tcp", "127.0.0.1", 9000, "unknown (not visible to this user)"),
        ("udp", "::", 5353, "mdns.exe"),
    }
    smb = next(x for x in listeners if x.port == 445)
    assert smb.all_interfaces and not smb.loopback
    assert ev is not None and "3 listening" in ev.output


def test_ports_access_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    def deny(kind: str) -> list[object]:
        raise psutil.AccessDenied()

    monkeypatch.setattr(psutil, "net_connections", deny)
    skipped: list[Skip] = []
    assert ports.collect(skipped) == ([], None)
    assert "requires admin" in skipped[0].reason


# --- macOS --------------------------------------------------------------------


def test_macos_apps_and_launch_agents(tmp_path: Path) -> None:
    app = tmp_path / "Apps" / "Firefox.app" / "Contents"
    app.mkdir(parents=True)
    with (app / "Info.plist").open("wb") as fh:
        plistlib.dump({"CFBundleName": "Firefox", "CFBundleShortVersionString": "131.0"}, fh)
    broken = tmp_path / "Apps" / "Broken.app" / "Contents"
    broken.mkdir(parents=True)
    (broken / "Info.plist").write_bytes(b"not a plist")
    sw = macos.collect_software([], fake_runner({}), (tmp_path / "Apps",))
    assert {(s.name, s.version) for s in sw} == {("Firefox", "131.0"), ("Broken", "")}

    agents = tmp_path / "home" / "Library/LaunchAgents"
    agents.mkdir(parents=True)
    with (agents / "com.x.plist").open("wb") as fh:
        plistlib.dump({"Label": "com.x", "ProgramArguments": ["/Users/me/x", "--run"]}, fh)
    entries = macos.collect_persistence([], tmp_path / "home")
    assert ("com.x", "/Users/me/x --run") in {(e.name, e.command) for e in entries}
