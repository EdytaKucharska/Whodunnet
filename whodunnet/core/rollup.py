"""Raw ping → minute_rollup (spec §5 rollup rules, §4.3 WiFi-probe sample drop).

- A minute is rolled up once `now > minute_end + 15 s`. Each run re-rolls the last 10 closed
  minutes (`INSERT OR REPLACE`), so late inserts from the 10 s ping hold are picked up. Each run
  also catches up anything not rolled since the last run, at most 24 h back.
- Percentiles are nearest-rank over the minute's non-NULL RTTs. `jitter_ms` is the mean absolute
  difference between consecutive *received* RTTs; a loss breaks the pair. A minute with 0 replies
  has NULL p50/p95/max/jitter.
- `link` / `vpn` are the majority value among the minute's samples.
- Samples sent within [wifi.started_ts − 3 s, wifi.ts + 3 s] are dropped: the WiFi readout itself
  spikes latency. The minute is not excluded, it just has fewer samples.

Pure SQL in, rows out. No subprocess, no macOS.
"""

from __future__ import annotations

import math
import sqlite3
from collections import Counter
from collections.abc import Iterable, Sequence

from whodunnet.core import store
from whodunnet.core.models import RollupRow

MINUTE_MS = 60_000
CLOSE_DELAY_MS = 15_000
REROLL_MINUTES = 10
MAX_CATCH_UP_MS = 24 * 3600 * 1000
DROP_PINGS_AROUND_WIFI_PROBE = True
WIFI_PROBE_MARGIN_MS = 3_000


def minute_of(ts_ms: int) -> int:
    return ts_ms // MINUTE_MS * MINUTE_MS


def nearest_rank(sorted_values: Sequence[float], pct: float) -> float | None:
    """Nearest-rank percentile: the value at rank ceil(p/100 · n), 1-based."""
    if not sorted_values:
        return None
    rank = max(1, math.ceil(pct / 100 * len(sorted_values)))
    return sorted_values[min(rank, len(sorted_values)) - 1]


def jitter(rtts_in_order: Sequence[float | None]) -> float | None:
    diffs = [
        abs(b - a)
        for a, b in zip(rtts_in_order, rtts_in_order[1:])
        if a is not None and b is not None
    ]
    return sum(diffs) / len(diffs) if diffs else None


def _majority(values: Iterable) -> object:
    counts = Counter(values)
    if not counts:
        return None
    # Most common; ties broken deterministically by the value's string form.
    return min(counts.items(), key=lambda kv: (-kv[1], str(kv[0])))[0]


def summarise(minute: int, target_id: int, samples: Sequence[sqlite3.Row]) -> RollupRow:
    """samples: the minute's ping rows for one target, in send order."""
    rtts = [s["rtt_ms"] for s in samples]
    received = sorted(r for r in rtts if r is not None)
    vpn = _majority(s["vpn"] or 0 for s in samples)
    return RollupRow(
        minute=minute,
        target_id=target_id,
        sent=len(samples),
        lost=sum(1 for r in rtts if r is None),
        p50_ms=nearest_rank(received, 50),
        p95_ms=nearest_rank(received, 95),
        max_ms=received[-1] if received else None,
        jitter_ms=jitter(rtts),
        link=_majority(s["link"] for s in samples),
        vpn=int(vpn or 0),
    )


def _probe_windows(conn: sqlite3.Connection, start: int, end: int) -> list[tuple[int, int]]:
    if not DROP_PINGS_AROUND_WIFI_PROBE:
        return []
    rows = conn.execute(
        "SELECT started_ts, ts FROM wifi WHERE ts >= ? AND started_ts < ?",
        (start - WIFI_PROBE_MARGIN_MS, end + WIFI_PROBE_MARGIN_MS),
    ).fetchall()
    return [
        (r["started_ts"] - WIFI_PROBE_MARGIN_MS, r["ts"] + WIFI_PROBE_MARGIN_MS)
        for r in rows
        if r["started_ts"] is not None
    ]


def rollup_range(conn: sqlite3.Connection, start_ms: int, end_ms: int) -> list[RollupRow]:
    """Compute (and store) rollups for the whole minutes in [start_ms, end_ms)."""
    start, end = minute_of(start_ms), minute_of(end_ms)
    if end <= start:
        return []
    windows = _probe_windows(conn, start, end)
    samples: dict[tuple[int, int], list[sqlite3.Row]] = {}
    for row in store.read_raw(conn, "ping", start, end):
        ts = row["ts"]
        if any(lo <= ts <= hi for lo, hi in windows):
            continue
        samples.setdefault((minute_of(ts), row["target_id"]), []).append(row)
    rows = [
        summarise(minute, target_id, rows_in_minute)
        for (minute, target_id), rows_in_minute in sorted(samples.items())
    ]
    if rows:
        store.upsert_rollups(conn, rows)
    return rows


def rollup_recent(conn: sqlite3.Connection, now_ms: int) -> list[RollupRow]:
    """The collector hook: closed minutes not yet rolled, plus a re-roll of the last 10."""
    closed_end = minute_of(now_ms - CLOSE_DELAY_MS)  # minutes ending at or before now − 15 s
    reroll_start = closed_end - REROLL_MINUTES * MINUTE_MS
    last = conn.execute("SELECT MAX(minute) FROM minute_rollup").fetchone()[0]
    if last is None:
        first = conn.execute("SELECT MIN(ts) FROM ping").fetchone()[0]
        start = minute_of(first) if first is not None else reroll_start
    else:
        start = last + MINUTE_MS
    start = max(min(start, reroll_start), closed_end - MAX_CATCH_UP_MS)
    return rollup_range(conn, start, closed_end)
