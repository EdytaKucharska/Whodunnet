"""Resolver health (spec §4.5), every 60 s: a `cached` and an `nxdomain` lookup.

Context only in v0. DNS results never feed layer attribution.
"""

from __future__ import annotations

import random
import string
from typing import Callable

from whodunnet.core.models import DnsRow
from whodunnet.probes.discover import is_lan_or_link_local
from whodunnet.probes.parsers import dig
from whodunnet.probes.runner import Runner, run_command

CACHED_NAME = "www.google.com"
NXDOMAIN_PARENT = "example.com"
HEALTHY_RCODES = ("NOERROR", "NXDOMAIN")
TIMEOUT_S = 5  # dig itself gives up after +time=2


def random_label(rng: random.Random | None = None) -> str:
    rng = rng or random.SystemRandom()
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(12))


def _lookup(
    resolver: str,
    name: str,
    kind: str,
    link: str | None,
    vpn: int,
    clock: Callable[[], int],
    runner: Runner,
) -> DnsRow:
    ts = clock()
    result = runner(["dig", "+tries=1", "+time=2", f"@{resolver}", name], TIMEOUT_S)
    parsed = dig.parse(result.output)
    if parsed.ok:
        healthy = parsed.rcode in HEALTHY_RCODES
        return DnsRow(
            ts=ts,
            ok=int(healthy),
            error=None if healthy else f"rcode:{parsed.rcode}",
            resolver=resolver,
            query_kind=kind,
            ms=parsed.ms,
            rcode=parsed.rcode,
            link=link,
            vpn=vpn,
        )
    # A send error or timeout to a LAN resolver may be Local Network blocking. That is
    # decided at read time (spec §6.1), so here it only gets a recognisable error.
    error = "lan_unreachable" if is_lan_or_link_local(resolver) else (parsed.error or "error")
    if result.timed_out and error != "lan_unreachable":
        error = "timeout"
    return DnsRow(ts=ts, ok=0, error=error, resolver=resolver, query_kind=kind, link=link, vpn=vpn)


def probe_dns(
    resolver: str | None,
    link: str | None,
    vpn: int,
    clock: Callable[[], int],
    runner: Runner = run_command,
    rng: random.Random | None = None,
) -> list[DnsRow]:
    """Two rows: `cached` (www.google.com) then `nxdomain` (random label under example.com)."""
    names = (("cached", CACHED_NAME), ("nxdomain", f"{random_label(rng)}.{NXDOMAIN_PARENT}"))
    if not resolver:
        now = clock()
        return [
            DnsRow(ts=now, ok=0, error="no_resolver", query_kind=kind, link=link, vpn=vpn)
            for kind, _ in names
        ]
    return [_lookup(resolver, name, kind, link, vpn, clock, runner) for kind, name in names]
