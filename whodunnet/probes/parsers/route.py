"""Parse `route -n get default` / `route -n get <ip>` output (spec §4.1, §4.7)."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class RouteInfo:
    ok: bool
    error: str | None = None
    destination: str | None = None
    gateway: str | None = None
    interface: str | None = None


_FIELD = re.compile(r"^\s*(destination|gateway|interface):\s*(\S+)\s*$", re.MULTILINE)


def parse_route_get(text: str) -> RouteInfo:
    fields = dict(_FIELD.findall(text))
    if "interface" not in fields:
        error = text.strip().splitlines()[-1] if text.strip() else "empty output"
        return RouteInfo(ok=False, error=error)
    return RouteInfo(
        ok=True,
        destination=fields.get("destination"),
        gateway=fields.get("gateway"),
        interface=fields["interface"],
    )


def parse_default(text: str) -> RouteInfo:
    """`route -n get default`: same format; a missing gateway means no default route."""
    info = parse_route_get(text)
    if info.ok and not info.gateway:
        return RouteInfo(ok=False, error="no default gateway", interface=info.interface)
    return info
