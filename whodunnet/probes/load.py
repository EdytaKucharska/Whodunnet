"""The Mac's own traffic per minute (spec §4.9), from `netstat -ibn` counter deltas."""

from __future__ import annotations

import sqlite3

from whodunnet.core import store
from whodunnet.core.models import LocalLoadRow
from whodunnet.probes.parsers import netstat
from whodunnet.probes.runner import Runner, run_command


class LoadMeter:
    def __init__(self) -> None:
        self._last: tuple[str, int, int, int] | None = None  # interface, ts_ms, rx, tx

    def sample(
        self, interface: str | None, now_ms: int, runner: Runner = run_command
    ) -> LocalLoadRow | None:
        """Throughput since the previous sample, keyed by the minute of the interval's midpoint.

        None on the first sample, after an interface change, or if counters went backwards.
        """
        result = netstat.parse_ibn(runner(["netstat", "-ibn"], 10).output)
        counters = result.counters.get(interface) if (result.ok and interface) else None
        if counters is None:
            self._last = None
            return None
        previous = self._last
        self._last = (interface, now_ms, counters.rx_bytes, counters.tx_bytes)
        if previous is None or previous[0] != interface:
            return None
        _, then_ms, rx0, tx0 = previous
        seconds = (now_ms - then_ms) / 1000
        if seconds <= 0 or counters.rx_bytes < rx0 or counters.tx_bytes < tx0:
            return None
        midpoint = (then_ms + now_ms) // 2
        return LocalLoadRow(
            minute=midpoint // 60_000 * 60_000,
            rx_mbps=(counters.rx_bytes - rx0) * 8 / seconds / 1e6,
            tx_mbps=(counters.tx_bytes - tx0) * 8 / seconds / 1e6,
        )


def record_load(
    conn: sqlite3.Connection,
    meter: LoadMeter,
    interface: str | None,
    now_ms: int,
    runner: Runner = run_command,
) -> LocalLoadRow | None:
    """Every 60 s: sample and upsert into local_load (nothing on the first sample)."""
    row = meter.sample(interface, now_ms, runner)
    if row is not None:
        store.upsert_local_load(conn, [row])
    return row
