"""Parse `ifconfig` (spec §4.1 global IPv6, §9 doctor AWDL check)."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

_GLOBAL_V6 = ipaddress.ip_network("2000::/3")


@dataclass
class Interface:
    name: str
    active: bool | None = None  # from "status: active|inactive"; None if not reported
    ipv4: list[str] = field(default_factory=list)
    ipv6_global: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class IfconfigResult:
    ok: bool
    error: str | None = None
    interfaces: dict[str, Interface] = field(default_factory=dict)

    def has_global_ipv6(self, name: str) -> bool:
        iface = self.interfaces.get(name)
        return bool(iface and iface.ipv6_global)

    def is_active(self, name: str) -> bool:
        iface = self.interfaces.get(name)
        return bool(iface and iface.active)


_HEADER = re.compile(r"^([A-Za-z0-9]+): flags=")


def parse(text: str) -> IfconfigResult:
    interfaces: dict[str, Interface] = {}
    current: Interface | None = None
    for line in text.splitlines():
        header = _HEADER.match(line)
        if header:
            current = interfaces.setdefault(header.group(1), Interface(header.group(1)))
            continue
        if current is None:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "inet":
            current.ipv4.append(parts[1])
        elif len(parts) >= 2 and parts[0] == "inet6":
            addr = parts[1].split("%")[0]
            try:
                if ipaddress.IPv6Address(addr) in _GLOBAL_V6:
                    current.ipv6_global.append(addr)
            except ValueError:
                pass
        elif len(parts) >= 2 and parts[0] == "status:":
            current.active = parts[1] == "active"
    if not interfaces:
        return IfconfigResult(ok=False, error="no interfaces in ifconfig output")
    return IfconfigResult(ok=True, interfaces=interfaces)
