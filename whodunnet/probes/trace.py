"""Traceroutes to every active anchor and CDN (spec §4.6), every 20 min.

Targets run sequentially within a 90 s budget per round. Targets not started before the budget
ran out go first in the next round. Hops are stored as JSON for the report.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable
from typing import Callable

from whodunnet.core.models import Target, TracerouteRow
from whodunnet.probes.parsers import traceroute
from whodunnet.probes.runner import Runner, run_command

BUDGET_S = 90.0
MAX_TTL = 20
MIN_COMMAND_TIMEOUT_S = 5.0
TRACED_KINDS = ("anchor", "cdn")


def trace_argv(ip: str, af: int) -> list[str]:
    tool = "traceroute6" if af == 6 else "traceroute"
    return [tool, "-I", "-n", "-q", "3", "-w", "1", "-m", str(MAX_TTL), ip]


def hops_json(hops: Iterable[traceroute.Hop]) -> str:
    return json.dumps([{"ttl": h.ttl, "ip": h.ip, "rtts": h.rtts} for h in hops])


class TraceRound:
    """Keeps the order across rounds so that unfinished targets go first next time."""

    def __init__(self, budget_s: float = BUDGET_S, monotonic: Callable[[], float] = time.monotonic):
        self.budget_s = budget_s
        self.monotonic = monotonic
        self._first: list[int] = []  # target ids left over from the previous round

    def _order(self, targets: list[Target]) -> list[Target]:
        by_id = {t.id: t for t in targets}
        first = [by_id[i] for i in self._first if i in by_id]
        rest = [t for t in targets if t.id not in set(self._first)]
        return first + rest

    def run(
        self,
        targets: Iterable[Target],
        link: str | None,
        vpn: int,
        clock: Callable[[], int],
        runner: Runner = run_command,
    ) -> list[TracerouteRow]:
        eligible = [t for t in targets if t.active and t.ip and t.kind in TRACED_KINDS]
        ordered = self._order(eligible)
        started = self.monotonic()
        rows: list[TracerouteRow] = []
        for index, target in enumerate(ordered):
            remaining = self.budget_s - (self.monotonic() - started)
            if remaining < MIN_COMMAND_TIMEOUT_S:
                self._first = [t.id for t in ordered[index:]]
                return rows
            assert target.ip is not None
            ts = clock()
            result = runner(trace_argv(target.ip, target.af), remaining)
            parsed = traceroute.parse(result.stdout)
            error = "timeout" if result.timed_out else parsed.error
            ok = int(parsed.ok and not result.timed_out)
            rows.append(
                TracerouteRow(
                    ts=ts,
                    target_id=target.id,
                    ok=ok,
                    error=error,
                    hops_json=hops_json(parsed.hops) if parsed.hops else None,
                    link=link,
                    vpn=vpn,
                )
            )
        self._first = []
        return rows
