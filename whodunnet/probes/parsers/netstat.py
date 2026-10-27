"""Parse `netstat -ibn` byte counters per interface (spec §4.9 local load)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Counters:
    rx_bytes: int
    tx_bytes: int


@dataclass(frozen=True)
class NetstatResult:
    ok: bool
    error: str | None = None
    counters: dict[str, Counters] = field(default_factory=dict)


def parse_ibn(text: str) -> NetstatResult:
    """Uses each interface's <Link#n> row. Columns are read from the right
    (Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll), because Address may be blank."""
    counters: dict[str, Counters] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 9 or not parts[2].startswith("<Link#"):
            continue
        try:
            ibytes, obytes = int(parts[-5]), int(parts[-2])
        except ValueError:
            continue
        counters[parts[0].rstrip("*")] = Counters(rx_bytes=ibytes, tx_bytes=obytes)
    if not counters:
        return NetstatResult(ok=False, error="no interface counters in netstat output")
    return NetstatResult(ok=True, counters=counters)
