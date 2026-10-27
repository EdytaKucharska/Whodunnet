"""Covered minutes, gaps, exclusions and derived target status (spec §6.1).

`load(conn, start_ms, end_ms)` reads everything the analysis needs for a range once and returns
a `Coverage`. Every question after that ("is this minute covered?", "is the gateway blocked?",
"is this target unresponsive?") is answered from memory. Pure: SQL in, Python out. Nothing is
stored.
"""

from __future__ import annotations

import bisect
import sqlite3
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from whodunnet.core import store
from whodunnet.core import thresholds as th
from whodunnet.core.models import RollupRow, Target

MINUTE_MS = 60_000
DOWNSTREAM_KINDS = ("anchor", "cdn")


def minute_of(ts_ms: int) -> int:
    return ts_ms // MINUTE_MS * MINUTE_MS


@dataclass
class Coverage:
    start: int  # first minute (inclusive)
    end: int  # end minute (exclusive)
    targets: dict[int, Target]
    gateway_id: int | None
    rollups: dict[int, dict[int, RollupRow]]  # minute -> target_id -> row
    heartbeats: dict[int, int]  # minute -> count
    heartbeat_ts: list[int]
    nq_windows: list[tuple[int, int]]
    local_load: dict[int, tuple[float | None, float | None]]
    status_history: dict[
        int, list[tuple[int, str, str | None]]
    ]  # target -> [(from_ts, status, reason)]
    ip_epochs: dict[int, list[int]]  # target -> sorted epoch start times
    blocked: set[int] = field(default_factory=set)  # minutes with the gateway blocked
    unresponsive: dict[int, list[tuple[int, int]]] = field(
        default_factory=dict
    )  # target -> [(from, to)]

    # ---- minutes ------------------------------------------------------------------------------

    @property
    def minutes(self) -> range:
        return range(self.start, self.end, MINUTE_MS)

    def gateway_row(self, minute: int) -> RollupRow | None:
        if self.gateway_id is None:
            return None
        return self.rollups.get(minute, {}).get(self.gateway_id)

    def link(self, minute: int) -> str | None:
        row = self.gateway_row(minute)
        return row.link if row else None

    def vpn(self, minute: int) -> int:
        row = self.gateway_row(minute)
        return row.vpn if row else 0

    def exclusion(self, minute: int) -> str | None:
        """Why a minute with data is excluded from analysis, or None."""
        end = minute + MINUTE_MS
        for lo, hi in self.nq_windows:
            if lo < end and minute < hi:
                return "nq"
        row = self.gateway_row(minute)
        if row is not None and row.vpn:
            return "vpn"
        if row is not None and row.link == "other":
            return "link_other"
        rx, tx = self.local_load.get(minute, (None, None))
        if (rx or 0) > th.LOCAL_LOAD_MBPS or (tx or 0) > th.LOCAL_LOAD_MBPS:
            return "local_load"
        return None

    def has_data(self, minute: int) -> bool:
        """≥ 3 heartbeats and a gateway rollup row (before exclusions)."""
        return (
            self.heartbeats.get(minute, 0) >= th.COVERED_MIN_HEARTBEATS
            and self.gateway_row(minute) is not None
        )

    def covered(self, minute: int) -> bool:
        return self.has_data(minute) and self.exclusion(minute) is None

    def covered_minutes(self, minutes: Iterable[int] | None = None) -> list[int]:
        return [m for m in (self.minutes if minutes is None else minutes) if self.covered(m)]

    def window_covered(self, minutes: Sequence[int]) -> bool:
        """A window (evening, daytime, hour) is covered if ≥ 50% of its minutes are covered."""
        if not minutes:
            return False
        return len(self.covered_minutes(minutes)) >= th.WINDOW_COVERED_SHARE * len(minutes)

    def gaps(self) -> list[tuple[int, int]]:
        """Intervals longer than 30 s with no heartbeat, clipped to the range."""
        out = []
        previous = self.start
        for ts in [*self.heartbeat_ts, self.end]:
            if ts - previous > th.GAP_MS:
                out.append((previous, ts))
            previous = max(previous, ts)
        return out

    # ---- derived status -----------------------------------------------------------------------

    def gateway_blocked(self, minute: int) -> bool:
        return minute in self.blocked

    def discovery_status(self, target_id: int, minute: int) -> str | None:
        """Latest target_status at or before the minute (None if nothing recorded yet)."""
        history = self.status_history.get(target_id, [])
        times = [h[0] for h in history]
        i = bisect.bisect_right(times, minute + MINUTE_MS - 1) - 1
        return history[i][1] if i >= 0 else None

    def is_unresponsive(self, target_id: int, minute: int) -> bool:
        return any(lo <= minute < hi for lo, hi in self.unresponsive.get(target_id, []))

    def downstream(self, af: int | None = None) -> list[Target]:
        return [
            t
            for t in self.targets.values()
            if t.kind in DOWNSTREAM_KINDS and (af is None or t.af == af)
        ]


# ---- derivations --------------------------------------------------------------------------------


def _all_lost(row: RollupRow | None) -> bool:
    return row is not None and row.sent > 0 and row.lost >= row.sent


def _derive_blocked(cov: Coverage) -> set[int]:
    """Spec §6.1: blocked from the first of ≥ 10 consecutive minutes where the gateway lost every
    ping while > 50% of downstream targets had < 2 lost, until the gateway's next reply."""
    downstream_ids = [t.id for t in cov.downstream()]
    if cov.gateway_id is None or not downstream_ids:
        return set()

    def qualifies(minute: int) -> bool:
        if not _all_lost(cov.gateway_row(minute)):
            return False
        rows = cov.rollups.get(minute, {})
        ok = sum(
            1 for t in downstream_ids if t in rows and rows[t].lost < th.DOWNSTREAM_OK_MAX_LOST
        )
        return ok > th.BLOCKED_DOWNSTREAM_SHARE * len(downstream_ids)

    blocked: set[int] = set()
    run: list[int] = []
    in_block = False
    for minute in cov.minutes:
        row = cov.gateway_row(minute)
        if in_block:
            if row is not None and row.lost < row.sent:  # the gateway's next reply ends it
                in_block = False
            else:
                blocked.add(minute)
                continue
        if qualifies(minute) and (not run or run[-1] == minute - MINUTE_MS):
            run.append(minute)
        elif qualifies(minute):
            run = [minute]
        else:
            run = []
        if len(run) >= th.BLOCKED_MIN_MINUTES:
            blocked.update(run)
            run = []
            in_block = True
    return blocked


def _derive_unresponsive(
    conn: sqlite3.Connection, cov: Coverage
) -> dict[int, list[tuple[int, int]]]:
    """Spec §6.1: > 50% loss across a target's first 10 rolled-up minutes of an IP epoch, while
    the gateway lost < 2 pings in those minutes → unresponsive until its IP changes."""
    out: dict[int, list[tuple[int, int]]] = {}
    for target in cov.targets.values():
        if target.kind not in (*DOWNSTREAM_KINDS, "isp_edge"):
            continue
        epochs = cov.ip_epochs.get(target.id) or ([target.first_seen] if target.first_seen else [])
        for i, epoch_start in enumerate(epochs):
            epoch_end = epochs[i + 1] if i + 1 < len(epochs) else None
            if epoch_end is not None and epoch_end <= cov.start:
                continue
            if epoch_start >= cov.end:
                continue
            upper = epoch_end if epoch_end is not None else 2**62
            first = conn.execute(
                "SELECT minute, sent, lost FROM minute_rollup WHERE target_id = ? "
                "AND minute >= ? AND minute < ? ORDER BY minute LIMIT ?",
                (target.id, minute_of(epoch_start), upper, th.UNRESPONSIVE_FIRST_MINUTES),
            ).fetchall()
            if len(first) < th.UNRESPONSIVE_FIRST_MINUTES:
                continue
            sent = sum(r["sent"] for r in first)
            lost = sum(r["lost"] for r in first)
            if not sent or lost <= th.UNRESPONSIVE_LOSS_SHARE * sent:
                continue
            gateway_lost = 0
            if cov.gateway_id is not None:
                minutes = [r["minute"] for r in first]
                gateway_lost = conn.execute(
                    f"SELECT COALESCE(SUM(lost), 0) FROM minute_rollup WHERE target_id = ? "
                    f"AND minute IN ({', '.join('?' * len(minutes))})",
                    (cov.gateway_id, *minutes),
                ).fetchone()[0]
            if gateway_lost < th.UNRESPONSIVE_GATEWAY_MAX_LOST:
                out.setdefault(target.id, []).append(
                    (minute_of(epoch_start), epoch_end if epoch_end is not None else cov.end)
                )
    return out


def load(conn: sqlite3.Connection, start_ms: int, end_ms: int) -> Coverage:
    start, end = minute_of(start_ms), minute_of(end_ms)
    targets = {t.id: t for t in store.list_targets(conn)}
    gateway = next((t for t in targets.values() if t.kind == "gateway" and t.af == 4), None)

    rollups: dict[int, dict[int, RollupRow]] = defaultdict(dict)
    for row in store.read_rollups(conn, start, end):
        rollups[row.minute][row.target_id] = row

    heartbeat_ts = [
        r[0]
        for r in conn.execute(
            "SELECT ts FROM heartbeat WHERE ts >= ? AND ts < ? ORDER BY ts", (start, end)
        )
    ]
    heartbeats: dict[int, int] = defaultdict(int)
    for ts in heartbeat_ts:
        heartbeats[minute_of(ts)] += 1

    margin = th.NQ_EXCLUSION_MARGIN_MS
    nq_windows = [
        (r["started_ts"] - margin, (r["ended_ts"] or r["started_ts"]) + margin)
        for r in conn.execute(
            "SELECT started_ts, ended_ts FROM nq WHERE ok = 1 AND started_ts IS NOT NULL "
            "AND started_ts < ? AND COALESCE(ended_ts, started_ts) >= ?",
            (end + margin, start - margin),
        )
    ]
    local_load = {
        r["minute"]: (r["rx_mbps"], r["tx_mbps"])
        for r in conn.execute(
            "SELECT minute, rx_mbps, tx_mbps FROM local_load WHERE minute >= ? AND minute < ?",
            (start, end),
        )
    }
    status_history: dict[int, list[tuple[int, str, str | None]]] = defaultdict(list)
    for r in conn.execute(
        "SELECT target_id, status, reason, from_ts FROM target_status ORDER BY from_ts, rowid"
    ):
        status_history[r["target_id"]].append((r["from_ts"], r["status"], r["reason"]))
    ip_epochs: dict[int, list[int]] = defaultdict(list)
    for r in conn.execute("SELECT target_id, from_ts FROM target_ips ORDER BY from_ts, rowid"):
        ip_epochs[r["target_id"]].append(r["from_ts"])

    cov = Coverage(
        start=start,
        end=end,
        targets=targets,
        gateway_id=gateway.id if gateway else None,
        rollups=dict(rollups),
        heartbeats=dict(heartbeats),
        heartbeat_ts=heartbeat_ts,
        nq_windows=nq_windows,
        local_load=local_load,
        status_history=dict(status_history),
        ip_epochs=dict(ip_epochs),
    )
    cov.blocked = _derive_blocked(cov)
    cov.unresponsive = _derive_unresponsive(conn, cov)
    return cov
