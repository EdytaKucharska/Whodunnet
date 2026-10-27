"""Parse `arp -n <gateway>` (spec §4.1 router-change detection). Caller hashes the MAC."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class MacResult:
    ok: bool
    error: str | None = None
    mac: str | None = None  # normalised: lower case, two hex digits per byte


_ENTRY = re.compile(r"\bat\s+((?:[0-9A-Fa-f]{1,2}:){5}[0-9A-Fa-f]{1,2})\b")


def parse_mac(text: str) -> MacResult:
    m = _ENTRY.search(text)
    if not m:
        return MacResult(ok=False, error="no ARP entry for the gateway")
    mac = ":".join(part.zfill(2) for part in m.group(1).lower().split(":"))
    return MacResult(ok=True, mac=mac)
