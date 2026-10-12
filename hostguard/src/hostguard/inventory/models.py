"""Inventory data types. Everything is read-only facts plus the evidence behind them."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from hostguard.models import Evidence


@dataclass
class Software:
    name: str
    version: str
    source: (
        str  # "registry:HKLM", "registry:HKLM-WOW6432Node", "registry:HKCU", "appx", "dpkg", ...
    )
    publisher: str = ""
    install_location: str = ""
    # For ecosystem-aware matching (OSV): ecosystem plus the package name/version that
    # the ecosystem's advisories use (e.g. Debian *source* package and version).
    ecosystem: str = ""
    package: str = ""
    package_version: str = ""
    origin: str = ""  # exact place this entry was read from (registry key, command)


@dataclass
class Hotfix:
    id: str
    description: str = ""
    installed_on: str = ""  # YYYY-MM-DD when known


@dataclass
class OsInfo:
    family: str
    name: str
    version: str
    build: str = ""
    ubr: int | None = None  # Windows update build revision (the number after the build)
    display_version: str = ""  # e.g. "25H2"
    edition_id: str = ""  # e.g. "Core" (= Home)
    arch: str = ""
    distro_id: str = ""  # Linux: os-release ID, e.g. "ubuntu"
    distro_version: str = ""  # Linux: VERSION_ID, e.g. "24.04"
    hotfixes: list[Hotfix] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)

    @property
    def full_build(self) -> str:
        return f"{self.build}.{self.ubr}" if self.ubr is not None else self.build


@dataclass
class PythonPackage:
    name: str
    version: str
    environment: str
    evidence: Evidence


@dataclass
class Listener:
    protocol: str  # "tcp" | "udp"
    address: str
    port: int
    pid: int | None
    process: str  # name, or a reason it is unknown
    exe: str = ""

    @property
    def all_interfaces(self) -> bool:
        return self.address in ("0.0.0.0", "::", "*")  # noqa: S104 - comparison, not a bind

    @property
    def loopback(self) -> bool:
        return self.address.startswith("127.") or self.address == "::1"


@dataclass
class PersistenceEntry:
    kind: str  # "run-key", "startup-folder", "service", "scheduled-task", "cron", "systemd", ...
    name: str
    command: str
    location: str  # where it was found (registry path, file path, task path)
    enabled: bool = True
    notes: str = ""


@dataclass
class Skip:
    """Something that could not be collected, and why. Always shown in reports."""

    what: str
    reason: str


@dataclass
class Inventory:
    os: OsInfo
    software: list[Software] = field(default_factory=list)
    python_packages: list[PythonPackage] = field(default_factory=list)
    listeners: list[Listener] = field(default_factory=list)
    persistence: list[PersistenceEntry] = field(default_factory=list)
    skipped: list[Skip] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    listeners_collected: bool = False
    persistence_collected: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["os"]["full_build"] = self.os.full_build
        return d
