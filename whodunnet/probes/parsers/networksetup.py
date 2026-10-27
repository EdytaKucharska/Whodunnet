"""Parse `networksetup -listallhardwareports` (spec §4.7)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Ports:
    ok: bool
    error: str | None = None
    ports: dict[str, str] = field(default_factory=dict)  # device -> hardware port name


_BLOCK = re.compile(r"Hardware Port:\s*(.+?)\s*\nDevice:\s*(\S+)")


def parse_ports(text: str) -> Ports:
    ports = {device: name for name, device in _BLOCK.findall(text)}
    if not ports:
        return Ports(ok=False, error="no hardware ports found")
    return Ports(ok=True, ports=ports)


def medium(port_name: str | None) -> str:
    """wifi | wired | other, from a hardware port name (spec §4.7)."""
    if port_name is None:
        return "other"
    name = port_name.strip().lower()
    if name in ("wi-fi", "airport"):
        return "wifi"
    if name.startswith(("thunderbolt", "iphone usb", "bluetooth pan")):
        return "other"
    return "wired"
