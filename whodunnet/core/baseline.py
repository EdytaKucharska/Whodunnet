"""Per-target, per-local-day baselines (spec §6.2). Computed inside `analyse`; nothing stored.

For each target and each local day `d` in the analysis range:

1. Look-back: the 7 days ending at the end of `d`, starting no earlier than the start of the
   target's baseline epoch. Epochs restart when the IP moves to a different /24 (/48). Minutes
   before an epoch boundary are judged with the previous epoch's baseline.
2. Candidate hours: local clock hours with ≥ 45 covered minutes in which the target has a row.
3. Prefer candidate hours inside `quiet_window`. If there are fewer than 4, use the 25% of
   candidate hours with the lowest hourly p95 summed across all targets.
4. Baseline = median p50 and median jitter over those hours' minutes. The ISP-edge rule (§6.3)
   also needs the median lost per minute.
5. Fewer than 4 chosen hours → no baseline for that target that day.

The Coverage passed in must start ≥ 7 days before the analysis range (the analysis loads it so).
"""

from __future__ import annotations

import math
import statistics
import time
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field

from whodunnet.core import store
from whodunnet.core import thresholds as th
from whodunnet.core.coverage import MINUTE_MS, Coverage
from whodunnet.core.rollup import nearest_rank

DAY_MS = 24 * 3600 * 1000


@dataclass(frozen=True)
class Baseline:
    p50_ms: float
    jitter_ms: float | None
    hours: int
    edge_lost_median: float


@dataclass
class _Hour:
    start: int
    quiet: bool
    minutes: int = 0  # covered minutes with a row for this target
    p50s: list[float] = field(default_factory=list)
    jitters: list[float] = field(default_factory=list)
    losts: list[int] = field(default_factory=list)


# ---- local time helpers -------------------------------------------------------------------------


def local_midnight(ms: int) -> int:
    t = time.localtime(ms / 1000)
    return int(time.mktime((t.tm_year, t.tm_mon, t.tm_mday, 0, 0, 0, 0, 0, -1)) * 1000)


def next_midnight(midnight_ms: int) -> int:
    t = time.localtime(midnight_ms / 1000)
    return int(time.mktime((t.tm_year, t.tm_mon, t.tm_mday + 1, 0, 0, 0, 0, 0, -1)) * 1000)


def local_days(start_ms: int, end_ms: int) -> list[int]:
    """Local midnights of every day overlapping [start_ms, end_ms)."""
    days, day = [], local_midnight(start_ms)
    while day < end_ms:
        days.append(day)
        day = next_midnight(day)
    return days


def hour_start(minute_ms: int) -> int:
    return minute_ms - time.localtime(minute_ms / 1000).tm_min * MINUTE_MS


def _hhmm(text: str) -> int:
    hours, minutes = text.split(":")
    return int(hours) * 60 + int(minutes)


def in_window(ms: int, window: Sequence[str]) -> bool:
    """Local time of `ms` inside [start, end); windows may wrap past midnight."""
    t = time.localtime(ms / 1000)
    now, start, end = t.tm_hour * 60 + t.tm_min, _hhmm(window[0]), _hhmm(window[1])
    return start <= now < end if start <= end else (now >= start or now < end)


# ---- epochs -------------------------------------------------------------------------------------


def epoch_starts(cov: Coverage, target_id: int) -> list[int]:
    """Times the target's baseline epoch (re)started: its first IP, then every /24 (/48) move."""
    history = cov.ip_history.get(target_id, [])
    starts: list[int] = []
    previous_ip = None
    for from_ts, ip in history:
        if previous_ip is None or not store.same_network(previous_ip, ip):
            starts.append(from_ts)
        previous_ip = ip
    if not starts:
        target = cov.targets.get(target_id)
        starts = [target.first_seen if target and target.first_seen else cov.start]
    return starts


# ---- computation --------------------------------------------------------------------------------


class Baselines:
    """Lookup: the baseline that applies to a target at a minute (or None)."""

    def __init__(self, cov: Coverage, values: dict[tuple[int, int, int], Baseline | None]):
        self._cov = cov
        self._values = values
        self._epochs = {t: epoch_starts(cov, t) for t in cov.targets}
        self._days: dict[int, int] = {}  # minute -> local midnight (localtime is slow)

    def epoch_of(self, target_id: int, minute: int) -> int:
        starts = self._epochs.get(target_id) or [self._cov.start]
        current = starts[0]
        for start in starts:
            if start <= minute:
                current = start
        return current

    def get(self, target_id: int, minute: int) -> Baseline | None:
        day = self._days.get(minute)
        if day is None:
            day = self._days[minute] = local_midnight(minute)
        key = (target_id, day, self.epoch_of(target_id, minute))
        return self._values.get(key)

    def items(self):
        return self._values.items()


def _hours_by_target(cov: Coverage, quiet_window: Sequence[str]) -> tuple[dict, dict[int, float]]:
    """Per target: hour start → _Hour; plus per hour the hourly p95 summed across all targets."""
    hours: dict[int, dict[int, _Hour]] = defaultdict(dict)
    p95s: dict[int, dict[int, list[float]]] = defaultdict(lambda: defaultdict(list))
    quiet_cache: dict[int, bool] = {}
    for minute in cov.minutes:
        if not cov.covered(minute):
            continue
        hour = hour_start(minute)
        if hour not in quiet_cache:
            quiet_cache[hour] = in_window(hour, quiet_window)
        for target_id, row in cov.rollups.get(minute, {}).items():
            h = hours[target_id].get(hour)
            if h is None:
                h = hours[target_id][hour] = _Hour(hour, quiet_cache[hour])
            h.minutes += 1
            h.losts.append(row.lost)
            if row.p50_ms is not None:
                h.p50s.append(row.p50_ms)
            if row.jitter_ms is not None:
                h.jitters.append(row.jitter_ms)
            if row.p95_ms is not None:
                p95s[hour][target_id].append(row.p95_ms)
    score = {
        hour: sum(nearest_rank(sorted(values), 95) or 0.0 for values in per_target.values())
        for hour, per_target in p95s.items()
    }
    return hours, score


def _baseline(chosen: list[_Hour]) -> Baseline | None:
    if len(chosen) < th.BASELINE_MIN_HOURS:
        return None
    p50s = [v for h in chosen for v in h.p50s]
    if not p50s:
        return None
    jitters = [v for h in chosen for v in h.jitters]
    losts = [v for h in chosen for v in h.losts]
    return Baseline(
        p50_ms=statistics.median(p50s),
        jitter_ms=statistics.median(jitters) if jitters else None,
        hours=len(chosen),
        edge_lost_median=statistics.median(losts) if losts else 0.0,
    )


def choose_hours(candidates: list[_Hour], score: dict[int, float]) -> list[_Hour]:
    quiet = [h for h in candidates if h.quiet]
    if len(quiet) >= th.BASELINE_MIN_HOURS:
        return quiet
    n = math.ceil(th.BASELINE_FALLBACK_SHARE * len(candidates))
    return sorted(candidates, key=lambda h: (score.get(h.start, 0.0), h.start))[:n]


def compute(cov: Coverage, cfg: dict, start_ms: int, end_ms: int) -> Baselines:
    """Baselines for every target, local day in [start_ms, end_ms) and epoch active that day."""
    hours, score = _hours_by_target(cov, cfg["quiet_window"])
    values: dict[tuple[int, int, int], Baseline | None] = {}
    for target_id in cov.targets:
        epochs = epoch_starts(cov, target_id)
        target_hours = sorted(hours.get(target_id, {}).values(), key=lambda h: h.start)
        for day in local_days(start_ms, end_ms):
            day_end = next_midnight(day)
            for i, epoch in enumerate(epochs):
                epoch_end = epochs[i + 1] if i + 1 < len(epochs) else None
                if epoch >= day_end or (epoch_end is not None and epoch_end <= day):
                    continue  # this epoch isn't active on this day
                lo = max(day_end - th.BASELINE_LOOKBACK_DAYS * DAY_MS, epoch)
                hi = day_end if epoch_end is None else min(day_end, epoch_end)
                candidates = [
                    h
                    for h in target_hours
                    if lo <= h.start
                    and h.start + 3600_000 <= hi
                    and h.minutes >= th.BASELINE_HOUR_MIN_COVERED
                ]
                values[(target_id, day, epoch)] = _baseline(choose_hours(candidates, score))
    return Baselines(cov, values)
