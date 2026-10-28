"""The scenario generator itself (plan M2.0): every §11 scenario builds fast and as described."""

from __future__ import annotations

import time

import pytest

from tests import scenarios as sc
from whodunnet.core import store


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


def test_every_spec_scenario_is_present():
    assert len(sc.SCENARIOS) == 19


@pytest.mark.parametrize("name", sorted(sc.SCENARIOS))
def test_scenario_builds_in_under_a_second(name, conn):
    started = time.process_time()  # CPU time: unaffected by other load on the machine
    s = sc.SCENARIOS[name](conn)
    assert time.process_time() - started < 1.0
    assert s.expected
    assert conn.execute("SELECT COUNT(*) FROM minute_rollup").fetchone()[0] > 0


def test_deterministic(tmp_path):
    def dump(path):
        c = store.connect(":memory:")
        sc.wifi_bad_evenings(c)
        rows = c.execute("SELECT * FROM minute_rollup ORDER BY minute, target_id").fetchall()
        c.close()
        return [tuple(r) for r in rows]

    assert dump(tmp_path / "a.db") == dump(tmp_path / "b.db")


def test_evening_minutes_are_bad_for_the_named_layers(conn):
    s = sc.wifi_bad_evenings(conn)
    evening = sc.local_ms(2026, 10, 2, 20, 0)
    noon = sc.local_ms(2026, 10, 2, 12, 0)
    for t in s.targets:
        (ev,) = store.read_rollups(conn, evening, evening + sc.MIN, t.id)
        (day,) = store.read_rollups(conn, noon, noon + sc.MIN, t.id)
        if t.kind == "isp_edge":
            assert ev.p95_ms < 20
        else:
            assert ev.lost >= 2 and ev.p95_ms > 100
        assert day.lost <= 1 and day.p95_ms < 25


def test_heartbeats_three_per_covered_minute_and_none_in_gaps(conn):
    s = sc.long_sleep_gaps(conn)
    minute = sc.local_ms(2026, 10, 3, 12, 0)
    asleep = sc.local_ms(2026, 10, 3, 3, 0)
    beats = lambda m: conn.execute(
        "SELECT COUNT(*) FROM heartbeat WHERE ts >= ? AND ts < ?", (m, m + sc.MIN)
    ).fetchone()[0]
    assert beats(minute) == 3
    assert beats(asleep) == 0
    assert store.read_rollups(conn, asleep, asleep + sc.MIN) == []
    assert s.expected["gaps_not_loss"]


def test_dst_change_day_has_25_hours(conn):
    s = sc.new(conn, days=26)  # 2026-10-25: clocks go back (not built: only times checked)
    day = sc.local_ms(2026, 10, 25)
    next_day = sc.local_ms(2026, 10, 26)
    assert next_day - day == 25 * sc.HOUR
    assert s.end > next_day


def test_blocked_gateway_loses_everything(conn):
    s = sc.gateway_blocked_upstream_bad(conn)
    gw = s.target("gateway")
    rows = store.read_rollups(conn, s.start, s.start + sc.HOUR, gw.id)
    assert all(r.lost == r.sent and r.p50_ms is None for r in rows)


def test_extras_written(conn):
    sc.bufferbloat_runs(conn)
    grades = [r[0] for r in conn.execute("SELECT grade FROM nq ORDER BY ts")]
    assert grades.count("D") == 4 and len(grades) == 10
    s = sc.bad_only_during_nq_and_local_load(conn)
    assert conn.execute("SELECT COUNT(*) FROM local_load").fetchone()[0] == 8 * 30
    assert s.expected == {"verdict": "no_problem_found"}


def test_v6_targets(conn):
    s = sc.ipv6_bad_ipv4_clean(conn)
    assert {t.af for t in s.targets} == {4, 6}
    assert s.expected["address_family"] == 6
