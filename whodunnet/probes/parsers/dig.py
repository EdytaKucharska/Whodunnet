"""Parse `dig` output (spec §4.5) and `dig +short` answers (spec §4 resolution)."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class DigResult:
    ok: bool  # an answer arrived (any rcode); the probe decides what counts as healthy
    error: str | None = None
    rcode: str | None = None  # NOERROR, NXDOMAIN, SERVFAIL, ...
    ms: float | None = None
    server: str | None = None


@dataclass(frozen=True)
class ShortResult:
    ok: bool
    error: str | None = None
    ips: list[str] = field(default_factory=list)


_STATUS = re.compile(r"->>HEADER<<-.*?\bstatus:\s*([A-Z]+)")
_QUERY_TIME = re.compile(r";; Query time:\s*(\d+)\s*msec")
_SERVER = re.compile(r";; SERVER:\s*([^#\s]+)")


def parse(text: str) -> DigResult:
    if "connection timed out" in text or "no servers could be reached" in text:
        return DigResult(ok=False, error="timeout")
    status = _STATUS.search(text)
    qtime = _QUERY_TIME.search(text)
    if not status or not qtime:
        return DigResult(ok=False, error="unexpected dig output")
    server = _SERVER.search(text)
    return DigResult(
        ok=True,
        rcode=status.group(1),
        ms=float(qtime.group(1)),
        server=server.group(1) if server else None,
    )


def parse_short(text: str) -> ShortResult:
    """IP lines only; CNAME lines (ending in '.') and comments are skipped."""
    if "connection timed out" in text or "no servers could be reached" in text:
        return ShortResult(ok=False, error="timeout")
    ips = []
    for line in text.splitlines():
        candidate = line.strip()
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        ips.append(candidate)
    return ShortResult(ok=True, ips=ips)
