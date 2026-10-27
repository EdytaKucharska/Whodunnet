"""Parse `scutil --dns` and `scutil --get LocalHostName` (spec §4.5, §7.3)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Resolvers:
    ok: bool
    error: str | None = None
    nameservers: list[str] = field(default_factory=list)  # of the primary resolver, in order


@dataclass(frozen=True)
class Hostname:
    ok: bool
    error: str | None = None
    hostname: str | None = None


_RESOLVER_SPLIT = re.compile(r"^resolver #\d+\s*$", re.MULTILINE)
_NAMESERVER = re.compile(r"^\s*nameserver\[\d+\]\s*:\s*(\S+)", re.MULTILINE)
_DOMAIN = re.compile(r"^\s*domain\s*:", re.MULTILINE)  # not "search domain[n] :"


def parse_resolvers(text: str) -> Resolvers:
    """Primary resolver: first in the main section with nameservers and no `domain :` line."""
    main = text.split("DNS configuration (for scoped queries)")[0]
    for block in _RESOLVER_SPLIT.split(main)[1:]:
        if _DOMAIN.search(block):
            continue
        servers = _NAMESERVER.findall(block)
        if servers:
            return Resolvers(ok=True, nameservers=servers)
    return Resolvers(ok=False, error="no primary DNS resolver found")


def parse_hostname(text: str) -> Hostname:
    name = text.strip()
    if not name or " " in name or "\n" in name:
        return Hostname(ok=False, error="no LocalHostName")
    return Hostname(ok=True, hostname=name)
