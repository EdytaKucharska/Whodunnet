"""networkQuality runs at fixed local-time slots (spec §4.4).

A slot fires once, within 5 min of its time. A slot missed while the Mac slept is not retried.
Runs are skipped on battery (or unknown power state) and within 2 min of a `lag` event. A
skipped run is still a row (`ok = 0`, `error = "skipped:<reason>"`), so coverage can explain it.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Callable

from whodunnet.core import store
from whodunnet.core.models import NqRow
from whodunnet.probes import power
from whodunnet.probes.parsers import networkquality
from whodunnet.probes.runner import Runner, run_command

SLOT_WINDOW_MS = 5 * 60_000
LAG_QUIET_MS = 2 * 60_000
TIMEOUT_S = 60
BASE_ARGV = ["networkQuality", "-c", "-s"]
MAX_RUNTIME_ARGS = ["-M", "20"]
_UNKNOWN_OPTION_MARKERS = ("illegal option", "invalid option", "unrecognized option", "usage:")

GRADES = ((30, "A"), (60, "B"), (200, "C"), (400, "D"))


def grade(bufferbloat_ms: float | None) -> str | None:
    """Initial bands: A < 30, B < 60, C < 200, D < 400, F >= 400 (ms of added latency)."""
    if bufferbloat_ms is None:
        return None
    for limit, letter in GRADES:
        if bufferbloat_ms < limit:
            return letter
    return "F"


def local_datetime(ms: int) -> datetime:
    """Aware local time in the Mac's system time zone."""
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).astimezone()


def due_slot(
    now_ms: int,
    schedule: Sequence[str],
    to_local: Callable[[int], datetime] = local_datetime,
) -> datetime | None:
    """The slot (local datetime) whose 5-minute window contains now, if any."""
    now = to_local(now_ms)
    for hhmm in schedule:
        hour, minute = (int(part) for part in hhmm.split(":"))
        slot = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if slot <= now < slot + timedelta(milliseconds=SLOT_WINDOW_MS):
            return slot
    return None


class NqRunner:
    """Decides when a slot fires and runs (or skips) networkQuality."""

    def __init__(
        self,
        runner: Runner = run_command,
        on_battery: Callable[[Runner], bool] = power.on_battery,
        to_local: Callable[[int], datetime] = local_datetime,
    ) -> None:
        self.runner = runner
        self.on_battery = on_battery
        self.to_local = to_local
        self.use_max_runtime = True  # cleared if this macOS rejects -M
        self._fired: set[datetime] = set()

    def _already_ran(self, conn: sqlite3.Connection, now_ms: int, slot: datetime) -> bool:
        """A row already exists for this slot's window (survives collector restarts)."""
        if slot in self._fired:
            return True
        slot_ms = now_ms - int((self.to_local(now_ms) - slot).total_seconds() * 1000)
        rows = conn.execute(
            "SELECT 1 FROM nq WHERE started_ts >= ? AND started_ts < ? LIMIT 1",
            (slot_ms, slot_ms + SLOT_WINDOW_MS),
        ).fetchone()
        return rows is not None

    def maybe_run(
        self,
        conn: sqlite3.Connection,
        schedule: Sequence[str],
        link: str | None,
        vpn: int,
        clock: Callable[[], int],
    ) -> NqRow | None:
        """Call every tick. Runs (or skips) at most once per slot and stores the row."""
        now = clock()
        slot = due_slot(now, schedule, self.to_local)
        if slot is None or self._already_ran(conn, now, slot):
            return None
        self._fired.add(slot)
        row = self.run(conn, link, vpn, clock)
        store.insert_rows(conn, [row])
        return row

    def _skip_reason(self, conn: sqlite3.Connection, now_ms: int) -> str | None:
        if self.on_battery(self.runner):
            return "skipped:battery"
        if store.list_events(conn, now_ms - LAG_QUIET_MS, now_ms + 1, kinds=["lag"]):
            return "skipped:recent_lag"
        return None

    def _command(self, timeout: float):
        argv = BASE_ARGV + (MAX_RUNTIME_ARGS if self.use_max_runtime else [])
        result = self.runner(argv, timeout)
        if self.use_max_runtime and not result.ok and not result.timed_out:
            text = result.output.lower()
            if any(marker in text for marker in _UNKNOWN_OPTION_MARKERS):
                self.use_max_runtime = False
                result = self.runner(BASE_ARGV, timeout)
        return result

    def run(
        self,
        conn: sqlite3.Connection,
        link: str | None,
        vpn: int,
        clock: Callable[[], int],
    ) -> NqRow:
        """One run (or skip), not stored. The skip rules apply to `run --nq-now` too."""
        started = clock()
        reason = self._skip_reason(conn, started)
        if reason:
            return NqRow(
                ts=started,
                started_ts=started,
                ended_ts=None,
                ok=0,
                error=reason,
                link=link,
                vpn=vpn,
            )
        result = self._command(TIMEOUT_S)
        ended = clock()
        if result.timed_out:
            return NqRow(
                ts=started,
                started_ts=started,
                ended_ts=ended,
                ok=0,
                error="timeout",
                link=link,
                vpn=vpn,
            )
        parsed = networkquality.parse(result.stdout)
        if not parsed.ok:
            return NqRow(
                ts=started,
                started_ts=started,
                ended_ts=ended,
                ok=0,
                error=parsed.error,
                link=link,
                vpn=vpn,
            )
        loaded = 60_000 / parsed.rpm if parsed.rpm else None
        bloat = None
        if loaded is not None and parsed.base_rtt_ms is not None:
            bloat = loaded - parsed.base_rtt_ms
        return NqRow(
            ts=started,
            started_ts=started,
            ended_ts=ended,
            ok=1,
            dl_mbps=parsed.dl_mbps,
            ul_mbps=parsed.ul_mbps,
            rpm=round(parsed.rpm) if parsed.rpm else None,
            base_rtt_ms=parsed.base_rtt_ms,
            loaded_ms=loaded,
            bufferbloat_ms=bloat,
            grade=grade(bloat),
            macos_version=parsed.os_version,
            raw_json=json.dumps(json.loads(result.stdout), sort_keys=True),
            link=link,
            vpn=vpn,
        )

    def run_now(
        self, conn: sqlite3.Connection, link: str | None, vpn: int, clock: Callable[[], int]
    ) -> NqRow:
        """`run --nq-now`: one run outside the schedule, stored."""
        row = self.run(conn, link, vpn, clock)
        store.insert_rows(conn, [row])
        return row
