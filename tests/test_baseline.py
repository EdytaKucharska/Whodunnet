"""Per-target daily baselines (spec §6.2, plan M2.3)."""

from __future__ import annotations

import time

import pytest

from tests import scenarios as sc
from whodunnet import config
from whodunnet.core import baseline, coverage, store
from whodunnet.core import thresholds as th

CFG, _ = config.validate({})


@pytest.fixture(autouse=True)
def london(monkeypatch):
    monkeypatch.setenv("TZ", "Europe/London")
    time.tzset()
    yield
    monkeypatch.delenv("TZ")
    time.tzset()


@pytest.fixture
def conn():
    c = store.connect(":memory:")
    yield c
    c.close()


def compute(conn, s, start=None, end=None):
    cov = coverage.load(conn, s.start, s.end)
    start = start if start is not None else s.start
    end = end if end is not None else s.end
    return cov, baseline.compute(cov, CFG, start, end)


def test_local_days_and_windows():
    days = baseline.local_days(sc.local_ms(2026, 10, 24, 12), sc.local_ms(2026, 10, 27))
    assert days == [sc.local_ms(2026, 10, d) for d in (24, 25, 26)]
    assert days[2] - days[1] == 25 * sc.HOUR  # clocks go back on the 25th
    assert baseline.in_window(sc.local_ms(2026, 10, 2, 3, 0), ["02:00", "06:00"])
    assert not baseline.in_window(sc.local_ms(2026, 10, 2, 6, 0), ["02:00", "06:00"])
    assert baseline.in_window(sc.local_ms(2026, 10, 2, 23, 30), ["23:00", "01:00"])
    assert baseline.in_window(sc.local_ms(2026, 10, 2, 0, 30), ["23:00", "01:00"])


def test_quiet_window_baseline_from_clean_data(conn):
    s = sc.clean_network(conn)
    _, b = compute(conn, s)
    cf = s.target("cloudflare")
    value = b.get(cf.id, sc.local_ms(2026, 10, 5, 20, 0))
    assert value is not None
    assert value.hours >= 4 * 4  # 4 quiet hours a day over the look-back
    assert 13.4 <= value.p50_ms <= 14.6  # NORMAL anchor p50 is 14 ± 0.5 noise
    assert value.edge_lost_median == 0


def test_quiet_hours_preferred_over_bad_evenings(conn):
    s = sc.wifi_bad_evenings(conn)
    _, b = compute(conn, s)
    value = b.get(s.target("gateway").id, sc.local_ms(2026, 10, 6, 20, 0))
    assert value.p50_ms < 4  # never the bad evening values (> 60 ms)


def test_fallback_to_calmest_hours_when_quiet_window_missing(conn):
    s = sc.new(conn, days=3)
    # asleep every night 01:00–07:00 → no quiet-window hours; evenings bad
    s.gaps = [
        (s.start + d * sc.DAY + 1 * sc.HOUR, s.start + d * sc.DAY + 7 * sc.HOUR) for d in range(3)
    ]
    s.bad_when(sc.is_evening, sc.is_kind("anchor", "cdn"))
    s.build()
    _, b = compute(conn, s)
    value = b.get(s.target("google").id, sc.local_ms(2026, 10, 3, 12, 0))
    assert value is not None and value.hours >= 4
    assert value.p50_ms < 15  # the calmest 25% of hours are never the bad evenings


def test_fewer_than_four_hours_means_no_baseline(conn):
    s = sc.new(conn, days=1)
    s.gaps = [(s.start + 3 * sc.HOUR, s.end)]  # only 00:00–03:00 = 3 hours of data
    s.build()
    _, b = compute(conn, s)
    assert b.get(s.target("google").id, s.start + 2 * sc.HOUR) is None


def test_exactly_four_quiet_hours_is_enough(conn):
    s = sc.new(conn, days=1)
    s.gaps = [(s.start, s.start + 2 * sc.HOUR), (s.start + 6 * sc.HOUR, s.end)]  # 02:00–06:00
    s.build()
    _, b = compute(conn, s)
    value = b.get(s.target("google").id, s.start + 3 * sc.HOUR)
    assert value is not None and value.hours == 4


def test_hour_needs_45_covered_minutes(conn):
    s = sc.new(conn, days=1)
    # 4 full hours from 02:00, but hour 05:00 has only 44 covered minutes → 3 quiet + fallback
    s.gaps = [(s.start, s.start + 2 * sc.HOUR), (s.start + 5 * sc.HOUR + 44 * sc.MIN, s.end)]
    s.build()
    _, b = compute(conn, s)
    assert b.get(s.target("google").id, s.start + 3 * sc.HOUR) is None
    conn2 = store.connect(":memory:")
    s2 = sc.new(conn2, days=1)
    s2.gaps = [(s2.start, s2.start + 2 * sc.HOUR), (s2.start + 5 * sc.HOUR + 45 * sc.MIN, s2.end)]
    s2.build()
    _, b2 = compute(conn2, s2)
    assert b2.get(s2.target("google").id, s2.start + 3 * sc.HOUR).hours == 4
    conn2.close()


def test_epoch_reset_on_new_subnet(conn):
    s = sc.new(conn, days=6)
    s.build()
    yt = s.target("youtube")
    switch = sc.local_ms(2026, 10, 4, 12, 0)
    store.switch_target_ip(conn, yt.id, "203.0.113.200", switch)  # different /24
    cov, b = compute(conn, s)
    before = b.get(yt.id, switch - sc.HOUR)
    after = b.get(yt.id, switch + sc.HOUR)
    assert before is not None
    assert after is None  # new epoch: no 4 qualifying hours yet on that day after 12:00
    next_day = b.get(yt.id, sc.local_ms(2026, 10, 5, 20, 0))
    assert next_day is not None and next_day.hours == 4  # 02–06 on the 5th only
    assert baseline.epoch_starts(cov, yt.id)[-1] == switch


def test_same_subnet_change_keeps_epoch(conn):
    s = sc.new(conn, days=4)
    s.build()
    yt = s.target("youtube")
    store.switch_target_ip(conn, yt.id, "198.51.100.31", sc.local_ms(2026, 10, 3, 12, 0))
    cov, b = compute(conn, s)
    assert len(baseline.epoch_starts(cov, yt.id)) == 1
    assert b.get(yt.id, sc.local_ms(2026, 10, 3, 13, 0)) is not None


def test_isp_edge_lost_median(conn):
    s = sc.isp_edge_always_lossy(conn)
    _, b = compute(conn, s)
    edge = b.get(s.target("isp_edge").id, sc.local_ms(2026, 10, 5, 20, 0))
    assert edge.edge_lost_median == sc.BAD_LOST


def test_blocked_gateway_has_no_baseline(conn):
    s = sc.gateway_blocked_upstream_bad(conn)
    _, b = compute(conn, s)
    assert b.get(s.target("gateway").id, sc.local_ms(2026, 10, 5, 20, 0)) is None
    assert b.get(s.target("google").id, sc.local_ms(2026, 10, 5, 20, 0)) is not None


def test_lookback_is_seven_days(conn):
    s = sc.new(conn, days=10)
    # Oct 1–6 all bad. Day 10's look-back (Oct 4–10) has 3 bad and 4 good days → good median;
    # without the 7-day limit it would be 6 bad vs 4 good → bad median.
    s.bad_when(lambda m: m < s.start + 6 * sc.DAY, lambda t: True)
    s.build()
    _, b = compute(conn, s)
    late = b.get(s.target("google").id, sc.local_ms(2026, 10, 10, 12, 0))
    early = b.get(s.target("google").id, sc.local_ms(2026, 10, 2, 12, 0))
    assert late.p50_ms < 15
    assert early.p50_ms > 60
    assert th.BASELINE_LOOKBACK_DAYS == 7


def test_compute_speed(conn):
    s = sc.ipv6_bad_ipv4_clean(conn)
    started = time.monotonic()
    compute(conn, s)
    assert time.monotonic() - started < 3.0
