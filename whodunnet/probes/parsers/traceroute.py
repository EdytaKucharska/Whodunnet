"""Parse `traceroute` / `traceroute6` output (spec §4.6).

Each hop keeps the first responding IP and every RTT seen for it. A hop with no answers has
ip=None and no RTTs. Annotations such as !H / !N are ignored.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Hop:
    ttl: int
    ip: str | None
    rtts: list[float] = field(default_factory=list)


@dataclass(frozen=True)
class TraceResult:
    ok: bool
    error: str | None = None
    hops: list[Hop] = field(default_factory=list)


_HOP_LINE = re.compile(r"^\s*(\d+)\s+(.*)$")


def _is_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token.split("%")[0])
        return True
    except ValueError:
        return False


def parse(text: str) -> TraceResult:
    hops: list[Hop] = []
    for line in text.splitlines():
        m = _HOP_LINE.match(line)
        if not m:
            continue
        ttl, rest = int(m.group(1)), m.group(2).split()
        ip: str | None = None
        rtts: list[float] = []
        i = 0
        while i < len(rest):
            token = rest[i]
            if _is_ip(token):
                ip = ip or token
            elif i + 1 < len(rest) and rest[i + 1] == "ms":
                try:
                    rtts.append(float(token))
                except ValueError:
                    pass
                i += 1
            i += 1
        hops.append(Hop(ttl=ttl, ip=ip, rtts=rtts))
    if not hops:
        return TraceResult(ok=False, error="no hops in traceroute output")
    return TraceResult(ok=True, hops=hops)
