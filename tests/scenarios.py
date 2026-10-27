"""Synthetic datasets for analysis tests (plan M2.0, spec §11).

A `Scenario` writes the tables the analysis reads directly, with no raw pings: `targets`,
`target_ips`, `target_status`, `minute_rollup`, `heartbeat`, `wifi`, `nq`, `local_load`,
`traceroute` and `events`. Each scenario in the spec §11 table is one function that returns a
built Scenario plus its expected verdict. Everything is seeded and deterministic.

Times are generated in *local* time, using the process time zone (tests pin TZ=Europe/London),
because the analysis windows (evening 19:00–23:00, daytime 10:00–16:00, quiet 02:00–06:00) are
local.
"""

from __future__ import annotations

import dataclasses
import json
import random
import sqlite3
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from whodunnet.core import store
from whodunnet.core.models import LocalLoadRow, NqRow, RollupRow, TracerouteRow, WifiRow

MIN = 60_000
HOUR = 60 * MIN
DAY = 24 * HOUR

# Healthy per-minute values per target kind: (p50, p95, jitter) in ms.
NORMAL = {
    "gateway": (3.0, 8.0, 1.0),
    "isp_edge": (6.0, 10.0, 1.0),
    "anchor": (14.0, 20.0, 2.0),
    "cdn": (12.0, 18.0, 2.0),
}
BAD_EXTRA = (60.0, 120.0, 30.0)  # added to a bad minute's p50/p95/jitter
BAD_LOST = 3  # ≥ 2 lost pings = bad (spec §6.3)
SENT = 30  # pings per minute at a 2 s interval

STANDARD_TARGETS = [
    ("gateway", "gateway", 4, "192.168.1.1"),
    ("isp_edge", "isp_edge", 4, "203.0.113.17"),
    ("anchor", "cloudflare", 4, "1.1.1.1"),
    ("anchor", "google", 4, "8.8.8.8"),
    ("anchor", "bbc", 4, "198.51.100.10"),
    ("cdn", "youtube", 4, "198.51.100.30"),
    ("cdn", "instagram", 4, "198.51.100.20"),
    ("cdn", "netflix", 4, "198.51.100.40"),
]
V6_TARGETS = [
    ("anchor", "cloudflare", 6, "2606:4700:4700::1111"),
    ("anchor", "google", 6, "2001:4860:4860::8888"),
    ("anchor", "bbc", 6, "2001:db8:bbc::1"),
    ("cdn", "youtube", 6, "2001:db8:1::30"),
    ("cdn", "instagram", 6, "2001:db8:1::20"),
    ("cdn", "netflix", 6, "2001:db8:1::40"),
]


def local_ms(year: int, month: int, day: int, hour: int = 0, minute: int = 0) -> int:
    return int(time.mktime((year, month, day, hour, minute, 0, 0, 0, -1)) * 1000)


def local_hour(ms: int) -> float:
    t = time.localtime(ms / 1000)
    return t.tm_hour + t.tm_min / 60


def is_evening(ms: int) -> bool:
    return 19 <= local_hour(ms) < 23


def is_daytime(ms: int) -> bool:
    return 10 <= local_hour(ms) < 16


# A rule decides, per minute, which targets are bad. It gets (minute_ms, target) -> bool.
Rule = Callable[[int, "TargetSpec"], bool]


@dataclass(frozen=True)
class TargetSpec:
    id: int
    kind: str
    name: str
    af: int


@dataclass
class Scenario:
    conn: sqlite3.Connection
    start: int  # local midnight of the first day
    days: int
    seed: int = 1
    targets: list[TargetSpec] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)
    gaps: list[tuple[int, int]] = field(default_factory=list)  # no heartbeat, no rollups
    link: Callable[[int], str] = lambda minute: "wifi"
    blocked_gateway: Callable[[int], bool] = lambda minute: False  # gateway loses everything
    always_lossy: set[str] = field(default_factory=set)  # names losing BAD_LOST every minute
    expected: dict = field(default_factory=dict)

    @property
    def end(self) -> int:
        return self.start + self.days * DAY

    # ---- setup ----------------------------------------------------------------------------

    def add_targets(self, specs: Iterable[tuple[str, str, int, str]]) -> None:
        for kind, name, af, ip in specs:
            target_id = store.upsert_target(self.conn, kind, name, af, None, ip, "ok", self.start)
            self.targets.append(TargetSpec(target_id, kind, name, af))

    def target(self, name: str, af: int = 4) -> TargetSpec:
        return next(t for t in self.targets if t.name == name and t.af == af)

    def bad_when(self, when: Callable[[int], bool], who: Callable[[TargetSpec], bool]) -> None:
        self.rules.append(lambda minute, t: when(minute) and who(t))

    # ---- extra rows -----------------------------------------------------------------------

    def add_wifi_readings(self, every_min: int = 5, band: str = "5", rssi: int = -55) -> None:
        rows = [
            WifiRow(
                ts=m + 11_000,
                started_ts=m,
                ok=1,
                rssi_dbm=rssi,
                noise_dbm=-92,
                channel=149 if band == "5" else 6,
                band=band,
                width_mhz=80,
                tx_rate_mbps=576.0,
                phy_mode="802.11ax",
            )
            for m in range(self.start, self.end, every_min * MIN)
            if not self._in_gap(m)
        ]
        store.insert_rows(self.conn, rows)

    def add_nq(self, ts: int, bufferbloat_ms: float, ok: int = 1, link: str = "wifi") -> None:
        from whodunnet.probes.nq import grade

        row = NqRow(
            ts=ts,
            started_ts=ts,
            ended_ts=ts + 20_000,
            ok=ok,
            dl_mbps=450.0,
            ul_mbps=140.0,
            rpm=int(60_000 / (13 + bufferbloat_ms)),
            base_rtt_ms=13.0,
            loaded_ms=13 + bufferbloat_ms,
            bufferbloat_ms=bufferbloat_ms,
            grade=grade(bufferbloat_ms),
            link=link,
            vpn=0,
        )
        store.insert_rows(self.conn, [row])

    def add_lag(self, ts: int) -> None:
        store.add_event(self.conn, "lag", "", "phone", ts)

    def add_event(self, kind: str, ts: int, note: str = "") -> None:
        store.add_event(self.conn, kind, note, "cli", ts)

    def add_local_load(self, minute: int, rx_mbps: float) -> None:
        store.upsert_local_load(self.conn, [LocalLoadRow(minute, rx_mbps, 1.0)])

    def add_traceroute(self, ts: int, target: TargetSpec) -> None:
        hops = [
            {"ttl": 1, "ip": "192.168.1.1", "rtts": [3.0]},
            {"ttl": 2, "ip": "203.0.113.17", "rtts": [6.0]},
        ]
        store.insert_rows(
            self.conn, [TracerouteRow(ts, target.id, 1, None, json.dumps(hops), "wifi", 0)]
        )

    def set_status(self, name: str, status: str, reason: str, af: int = 4) -> None:
        t = self.target(name, af)
        store.record_target_status(self.conn, t.id, status, reason, self.start)

    # ---- build ----------------------------------------------------------------------------

    def _in_gap(self, ms: int) -> bool:
        return any(lo <= ms < hi for lo, hi in self.gaps)

    def _rollup(self, minute: int, t: TargetSpec, rng: random.Random, link: str) -> tuple:
        """One minute_rollup row as a tuple, in column order (fast path for big scenarios)."""
        p50, p95, jit = NORMAL[t.kind]
        lost = 1 if rng.random() < 0.05 else 0  # isolated background loss
        noise = rng.uniform(-0.5, 0.5)
        if t.kind == "gateway" and self.blocked_gateway(minute):
            return (minute, t.id, SENT, SENT, None, None, None, None, link, 0)
        if t.name in self.always_lossy:
            lost = BAD_LOST
        if any(rule(minute, t) for rule in self.rules):
            p50, p95, jit = p50 + BAD_EXTRA[0], p95 + BAD_EXTRA[1], jit + BAD_EXTRA[2]
            lost = max(lost, BAD_LOST)
        return (
            minute,
            t.id,
            SENT,
            lost,
            p50 + noise,
            p95 + noise,
            p95 + 5 + noise,
            jit + abs(noise),
            link,
            0,
        )

    def build(self) -> Scenario:
        rng = random.Random(self.seed)
        rollups: list[tuple] = []
        beats: list[tuple[int]] = []
        for minute in range(self.start, self.end, MIN):
            if self._in_gap(minute):
                continue
            beats.extend((minute + s * 1000,) for s in (5, 25, 45))
            link = self.link(minute)
            rollups.extend(self._rollup(minute, t, rng, link) for t in self.targets)
        columns = ", ".join(f.name for f in dataclasses.fields(RollupRow))
        with self.conn:
            self.conn.executemany(
                f"INSERT OR REPLACE INTO minute_rollup ({columns}) VALUES ({', '.join('?' * 10)})",
                rollups,
            )
            self.conn.executemany("INSERT INTO heartbeat (ts) VALUES (?)", beats)
        return self


def new(conn: sqlite3.Connection, days: int = 8, seed: int = 1, v6: bool = False) -> Scenario:
    """A clean scenario starting 2026-10-01 (local midnight) with the standard targets."""
    s = Scenario(conn, local_ms(2026, 10, 1), days, seed)
    s.add_targets(STANDARD_TARGETS + (V6_TARGETS if v6 else []))
    return s


def is_kind(*kinds: str) -> Callable[[TargetSpec], bool]:
    return lambda t: t.kind in kinds


def is_named(*names: str) -> Callable[[TargetSpec], bool]:
    return lambda t: t.name in names


def every_evening_except(skip_days: Iterable[int], start: int) -> Callable[[int], bool]:
    """Evening minutes on every day except the given day indexes."""
    skip = set(skip_days)
    return lambda m: is_evening(m) and (m - start) // DAY not in skip


def burst_minutes(centres: Iterable[int], half_width_min: int = 2) -> Callable[[int], bool]:
    windows = [(c - half_width_min * MIN, c + half_width_min * MIN) for c in centres]
    return lambda m: any(lo <= m <= hi for lo, hi in windows)


# ---- the spec §11 scenarios ------------------------------------------------------------------
# Each returns a built Scenario whose `expected` holds verdict / qualifier / confidence (None =
# "not checked") plus `not_verdict` where the table says "not X".


def wifi_bad_evenings(conn):
    s = new(conn, days=8)
    s.bad_when(is_evening, is_kind("gateway", "anchor", "cdn"))
    s.add_wifi_readings()
    s.expected = {"verdict": "wifi", "qualifier": "evening", "confidence": "high"}
    return s.build()


def wifi_bad_plus_wired_evening(conn):
    s = new(conn, days=5)
    wired_day = 4
    s.link = lambda m: "wired" if (m - s.start) // DAY == wired_day else "wifi"
    s.bad_when(every_evening_except([wired_day], s.start), is_kind("gateway", "anchor", "cdn"))
    s.add_wifi_readings()
    s.expected = {"verdict": "wifi", "qualifier": "evening", "confidence": "high"}
    s.expected["note"] = "medium from 4 evenings, +1 for the clean wired evening"
    return s.build()


def wired_bad_evenings(conn):
    s = new(conn, days=8)
    s.link = lambda m: "wired"
    s.bad_when(is_evening, is_kind("gateway", "anchor", "cdn"))
    s.expected = {"verdict": "home_network", "qualifier": "evening", "confidence": "high"}
    return s.build()


def isp_network_evenings(conn):
    s = new(conn, days=8)
    s.bad_when(is_evening, is_kind("isp_edge", "anchor", "cdn"))
    s.expected = {"verdict": "isp_network", "qualifier": "evening", "confidence": "high"}
    return s.build()


def isp_upstream_evenings(conn):
    s = new(conn, days=4)
    s.bad_when(is_evening, is_kind("anchor", "cdn"))
    s.expected = {"verdict": "isp_upstream", "qualifier": "evening", "confidence": "medium"}
    return s.build()


def video_path_evenings(conn):
    s = new(conn, days=8)
    s.bad_when(is_evening, is_named("youtube", "netflix"))
    s.expected = {"verdict": "video_path", "qualifier": "evening", "confidence": "high"}
    return s.build()


def all_day_problem(conn):
    s = new(conn, days=8)
    s.bad_when(lambda m: is_evening(m) or is_daytime(m), is_kind("anchor", "cdn"))
    s.expected = {"verdict": "isp_upstream", "qualifier": "all_day", "confidence": "high"}
    return s.build()


def lag_moment_bursts(conn):
    s = new(conn, days=8)
    moments = [s.start + d * DAY + 20 * HOUR + 30 * MIN for d in range(6)]
    s.bad_when(burst_minutes(moments), is_kind("anchor", "cdn"))
    for m in moments:
        s.add_lag(m)
    s.expected = {"verdict": "isp_upstream", "qualifier": "at_lag_moments", "confidence": "medium"}
    return s.build()


def bufferbloat_runs(conn):
    s = new(conn, days=8)
    for i in range(10):
        ts = s.start + i * 18 * HOUR + 12 * HOUR
        s.add_nq(ts, bufferbloat_ms=250.0 if i < 4 else 20.0)  # D on 4 of 10
    s.expected = {"verdict": "bufferbloat", "qualifier": None, "confidence": "medium"}
    return s.build()


def device_or_app(conn):
    s = new(conn, days=8)
    for d in range(6):
        s.add_lag(s.start + d * DAY + 21 * HOUR)
    s.expected = {"verdict": "device_or_app", "qualifier": None, "confidence": "medium"}
    return s.build()


def clean_network(conn):
    s = new(conn, days=8)
    s.expected = {"verdict": "no_problem_found", "qualifier": None, "confidence": "medium"}
    return s.build()


def insufficient_data(conn):
    s = new(conn, days=1)
    s.gaps = [(s.start + 20 * HOUR, s.end)]  # < 24 h of data
    s.expected = {"verdict": "insufficient_data", "qualifier": None, "confidence": "low"}
    return s.build()


def gateway_slow_only(conn):
    s = new(conn, days=8)
    s.bad_when(is_evening, is_kind("gateway"))
    s.expected = {"not_verdict": "wifi"}
    return s.build()


def gateway_blocked_upstream_bad(conn):
    s = new(conn, days=8)
    s.blocked_gateway = lambda m: True
    s.bad_when(is_evening, is_kind("anchor", "cdn"))
    s.expected = {
        "verdict": "isp_upstream",
        "qualifier": "evening",
        "not_measurable": ["wifi", "home_network"],
    }
    return s.build()


def isp_edge_always_lossy(conn):
    s = new(conn, days=8)
    s.always_lossy = {"isp_edge"}
    s.expected = {"not_verdict": "isp_network"}
    return s.build()


def single_flaky_cdn(conn):
    s = new(conn, days=8)
    s.bad_when(is_evening, is_named("instagram"))
    s.expected = {"verdict": "no_problem_found"}
    return s.build()


def bad_only_during_nq_and_local_load(conn):
    s = new(conn, days=8)
    nq_starts = [s.start + d * DAY + 20 * HOUR + 30 * MIN for d in range(8)]
    for ts in nq_starts:
        s.add_nq(ts, bufferbloat_ms=20.0)
    load_minutes = [s.start + d * DAY + 21 * HOUR + k * MIN for d in range(8) for k in range(30)]
    for m in load_minutes:
        s.add_local_load(m, rx_mbps=300.0)
    nq_window = burst_minutes([t + 10_000 for t in nq_starts], half_width_min=0)
    load_set = set(load_minutes)
    s.bad_when(lambda m: nq_window(m) or m in load_set, is_kind("gateway", "anchor", "cdn"))
    s.expected = {"verdict": "no_problem_found"}
    return s.build()


def long_sleep_gaps(conn):
    s = new(conn, days=8)
    s.gaps = [(s.start + d * DAY + 1 * HOUR, s.start + d * DAY + 7 * HOUR) for d in range(8)]
    s.expected = {"verdict": "no_problem_found", "gaps_not_loss": True}
    return s.build()


def ipv6_bad_ipv4_clean(conn):
    s = new(conn, days=7, v6=True)  # 14 targets: 7 days keeps the build under a second
    s.bad_when(is_evening, lambda t: t.af == 6 and t.kind in ("anchor", "cdn"))
    s.expected = {"verdict": "isp_upstream", "qualifier": "evening", "address_family": 6}
    return s.build()


SCENARIOS: dict[str, Callable[[sqlite3.Connection], Scenario]] = {
    "wifi_bad_evenings": wifi_bad_evenings,
    "wifi_bad_plus_wired_evening": wifi_bad_plus_wired_evening,
    "wired_bad_evenings": wired_bad_evenings,
    "isp_network_evenings": isp_network_evenings,
    "isp_upstream_evenings": isp_upstream_evenings,
    "video_path_evenings": video_path_evenings,
    "all_day_problem": all_day_problem,
    "lag_moment_bursts": lag_moment_bursts,
    "bufferbloat_runs": bufferbloat_runs,
    "device_or_app": device_or_app,
    "clean_network": clean_network,
    "insufficient_data": insufficient_data,
    "gateway_slow_only": gateway_slow_only,
    "gateway_blocked_upstream_bad": gateway_blocked_upstream_bad,
    "isp_edge_always_lossy": isp_edge_always_lossy,
    "single_flaky_cdn": single_flaky_cdn,
    "bad_only_during_nq_and_local_load": bad_only_during_nq_and_local_load,
    "long_sleep_gaps": long_sleep_gaps,
    "ipv6_bad_ipv4_clean": ipv6_bad_ipv4_clean,
}
