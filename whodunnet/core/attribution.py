"""Bad minutes (spec §6.3) and per-minute layer attribution (spec §6.4).

For every covered minute and each address family, each target is judged "bad" or not against its
baseline. The rule table then names the layer to blame:
`wifi` / `home_network` / `isp_network` / `isp_upstream` / `video_path` / `ok` / `inconclusive`.
Pure: it works on a loaded `Coverage` and `Baselines`, plus the WiFi readings for context.
"""

from __future__ import annotations

import bisect
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from whodunnet.core import thresholds as th
from whodunnet.core.baseline import Baseline, Baselines
from whodunnet.core.coverage import MINUTE_MS, Coverage
from whodunnet.core.models import RollupRow, Target

LAYERS = ("wifi", "home_network", "isp_network", "isp_upstream", "video_path")


@dataclass(frozen=True)
class WifiReading:
    ts: int
    rssi_dbm: int | None
    noise_dbm: int | None
    channel: int | None
    band: str | None


@dataclass
class MinuteResult:
    minute: int
    af: int
    layer: str  # one of LAYERS, "ok" or "inconclusive"
    tags: list[str] = field(default_factory=list)
    bad: list[int] = field(default_factory=list)  # ids of bad targets (gateway/edge/downstream)
    d_size: int = 0
    gateway_unknown: bool = False
    edge_unknown: bool = False
    wifi_context: list[str] = field(default_factory=list)


def is_bad(row: RollupRow, base: Baseline, kind: str) -> bool:
    """Spec §6.3. Only called for a target with a baseline in a covered minute."""
    if kind == "isp_edge":
        if row.lost >= base.edge_lost_median + th.EDGE_LOST_MARGIN:
            return True
    elif row.lost >= th.BAD_LOST_PINGS:
        return True
    if row.p95_ms is not None and row.p95_ms > base.p50_ms + th.BAD_P95_MARGIN_MS:
        return True
    return (
        row.jitter_ms is not None
        and base.jitter_ms is not None
        and row.jitter_ms > base.jitter_ms + th.BAD_JITTER_MARGIN_MS
    )


def majority_bad(members: Sequence[int], bad: set[int]) -> bool:
    n_bad = sum(1 for m in members if m in bad)
    return bool(members) and n_bad * 2 > len(members) and n_bad >= th.MAJORITY_MIN_BAD


def majority_ok(members: Sequence[int], bad: set[int]) -> bool:
    return bool(members) and not majority_bad(members, bad)


def wifi_context(
    readings: Sequence[WifiReading], minute_end: int, times: Sequence[int] | None = None
) -> list[str]:
    """Flags from the latest reading at or before the minute end (vs the reading before it).
    `readings` are sorted by ts; `times` (their ts values) can be passed to avoid rebuilding."""
    times = [r.ts for r in readings] if times is None else times
    i = bisect.bisect_right(times, minute_end)
    if i == 0:
        return []
    latest, previous = readings[i - 1], (readings[i - 2] if i >= 2 else None)
    flags = []
    if latest.rssi_dbm is not None and latest.rssi_dbm < th.WEAK_RSSI_DBM:
        flags.append("weak_signal")
    if (
        latest.rssi_dbm is not None
        and latest.noise_dbm is not None
        and latest.rssi_dbm - latest.noise_dbm < th.LOW_SNR_DB
    ):
        flags.append("low_snr")
    if latest.band == "2.4":
        flags.append("band_2_4")
    if previous is not None and (
        (latest.channel, latest.band) != (previous.channel, previous.band)
    ):
        flags.append("band_changed")
    return flags


class _Context:
    """Per-minute facts shared by both address families."""

    def __init__(self, cov: Coverage, baselines: Baselines, minute: int):
        self.cov, self.baselines, self.minute = cov, baselines, minute
        self.rows = cov.rollups.get(minute, {})

    def judged(self, target: Target) -> bool | None:
        """True/False = bad/not bad; None = no data or no baseline (unknown)."""
        row = self.rows.get(target.id)
        if row is None:
            return None
        base = self.baselines.get(target.id, self.minute)
        if base is None:
            return None
        return is_bad(row, base, target.kind)

    def usable(self, target: Target) -> bool:
        return self.cov.discovery_status(
            target.id, self.minute
        ) != "unavailable" and not self.cov.is_unresponsive(target.id, self.minute)


def classify(
    ctx: _Context,
    af: int,
    gateway: Target | None,
    edge: Target | None,
    downstream: Sequence[Target],
    streaks: dict[int, int],
) -> MinuteResult:
    """The §6.4 rule table for one minute and one address family."""
    minute = ctx.minute
    bad: set[int] = set()
    a_ids: list[int] = []
    c_ids: list[int] = []
    for t in downstream:
        if not ctx.usable(t):
            continue
        verdict = ctx.judged(t)
        if verdict is None:
            continue
        (a_ids if t.kind == "anchor" else c_ids).append(t.id)
        if verdict:
            bad.add(t.id)
    d_ids = a_ids + c_ids

    gw_bad = None
    if gateway is not None and not ctx.cov.gateway_blocked(minute):
        gw_bad = ctx.judged(gateway)
    edge_bad = None
    if edge is not None and ctx.usable(edge):
        edge_bad = ctx.judged(edge)

    result = MinuteResult(
        minute,
        af,
        "inconclusive",
        d_size=len(d_ids),
        gateway_unknown=gw_bad is None,
        edge_unknown=edge_bad is None,
    )
    if gw_bad:
        result.bad.append(gateway.id)  # type: ignore[union-attr]
    if edge_bad:
        result.bad.append(edge.id)  # type: ignore[union-attr]
    result.bad.extend(sorted(bad))
    if len(d_ids) < th.MIN_DOWNSTREAM:
        return result

    d_majority_bad = majority_bad(d_ids, bad)
    d_majority_ok = majority_ok(d_ids, bad)
    names = {t.id: t.name for t in downstream}

    def layer(name: str, *tags: str) -> MinuteResult:
        result.layer = name
        result.tags.extend(tags)
        return result

    # rows 1–2: gateway (skipped while unknown)
    if gw_bad is not None:
        if gw_bad and d_majority_bad:
            wired = ctx.cov.link(minute) == "wired"
            return layer("home_network" if wired else "wifi")
        if gw_bad and d_majority_ok:
            return layer("ok", "router_icmp_slow")
    # row 3: ISP edge (skipped while unknown)
    if edge_bad and d_majority_bad:
        return layer("isp_network")
    # rows 4–6 need both A and C
    if a_ids and c_ids:
        a_bad, c_bad = majority_bad(a_ids, bad), majority_bad(c_ids, bad)
        if a_bad and c_bad:
            return layer("isp_upstream", *(["edge_unknown"] if edge_bad is None else []))
        if a_bad and majority_ok(c_ids, bad):
            return layer("isp_upstream", "general_internet_only")
        if majority_ok(a_ids, bad):
            bad_cdns = [c for c in c_ids if c in bad]
            streaky = [c for c in bad_cdns if streaks.get(c, 0) >= th.VIDEO_PATH_STREAK]
            if len(bad_cdns) >= th.VIDEO_PATH_MIN_CDNS or streaky:
                return layer("video_path", *sorted(names[c] for c in bad_cdns))
    # row 7: ISP edge de-prioritising ICMP
    if edge_bad and d_majority_ok:
        return layer("ok", "isp_edge_icmp")
    # row 8: nothing (or one isolated target) bad
    n_bad_d = sum(1 for d in d_ids if d in bad)
    if n_bad_d <= 1:
        return layer("ok")
    return result  # row 9: inconclusive


def attribute(
    cov: Coverage,
    baselines: Baselines,
    start_ms: int,
    end_ms: int,
    wifi_readings: Iterable[WifiReading] = (),
) -> dict[int, list[MinuteResult]]:
    """Per-minute results for af 4 and af 6 over the covered minutes of [start_ms, end_ms)."""
    readings = sorted(wifi_readings, key=lambda r: r.ts)
    reading_times = [r.ts for r in readings]
    targets = list(cov.targets.values())
    gateway = next((t for t in targets if t.kind == "gateway"), None)
    edge = next((t for t in targets if t.kind == "isp_edge"), None)
    out: dict[int, list[MinuteResult]] = {4: [], 6: []}
    for af in (4, 6):
        downstream = [t for t in targets if t.kind in ("anchor", "cdn") and t.af == af]
        if not downstream:
            continue
        cdns = [t for t in downstream if t.kind == "cdn"]
        streaks: dict[int, int] = {}
        previous = None
        for minute in range(start_ms // MINUTE_MS * MINUTE_MS, end_ms, MINUTE_MS):
            if not cov.covered(minute):
                continue
            ctx = _Context(cov, baselines, minute)
            adjacent = previous is not None and minute - previous == MINUTE_MS
            for c in cdns:  # consecutive covered minutes in which this CDN was bad
                if ctx.usable(c) and ctx.judged(c):
                    streaks[c.id] = (streaks.get(c.id, 0) if adjacent else 0) + 1
                else:
                    streaks[c.id] = 0
            previous = minute
            result = classify(ctx, af, gateway, edge, downstream, streaks)
            if result.layer == "wifi":
                result.wifi_context = wifi_context(readings, minute + MINUTE_MS, reading_times)
            out[af].append(result)
    return out


def choose_family(results: dict[int, list[MinuteResult]]) -> int:
    """af 6 if it had |D| ≥ 3 in ≥ 50% of covered minutes (video apps prefer IPv6), else af 4."""
    v6 = results.get(6) or []
    covered = max(len(results.get(4) or []), len(v6))
    if not covered:
        return 4
    enough = sum(1 for r in v6 if r.d_size >= th.MIN_DOWNSTREAM)
    return 6 if enough >= th.AF6_MIN_SHARE * covered else 4


def read_wifi(conn, start_ms: int, end_ms: int) -> list[WifiReading]:
    """WiFi readings for context, starting an hour early so the first minutes have one."""
    rows = conn.execute(
        "SELECT ts, rssi_dbm, noise_dbm, channel, band FROM wifi WHERE ok = 1 AND ts >= ? "
        "AND ts < ? ORDER BY ts",
        (start_ms - 3600_000, end_ms),
    ).fetchall()
    return [WifiReading(*tuple(r)) for r in rows]
