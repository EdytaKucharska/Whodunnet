"""Coverage, gaps, exclusions and derived status (spec §6.1, plan M2.2)."""

from __future__ import annotations

import time

import pytest

from tests import scenarios as sc
from whodunnet.core import coverage, store
from whodunnet.core import thresholds as th
from whodunnet.core.models import LocalLoadRow, NqRow, RollupRow

MIN = 60_000
T0 = 1_793_000_000_000 // MIN * MIN


@pytest.fixture
def conn():
    c = store.connect(":memory:")
    yield c
    c.close()


def targets(conn):
    ids = {}
    for kind, name, ip in [
        ("gateway", "gateway", "192.168.1.1"),
        ("isp_edge", "isp_edge", "203.0.113.17"),
        ("anchor", "cloudflare", "1.1.1.1"),
        ("anchor", "google", "8.8.8.8"),
        ("cdn", "youtube", "198.51.100.30"),
    ]:
        ids[name] = store.upsert_target(conn, kind, name, 4, None, ip, "ok", T0)
    return ids


def fill(conn, ids, minutes, lost=None, link="wifi", vpn=0, beats=3):
    """Healthy rollups for every target over `minutes`; lost = {name: lost per minute}."""
    lost = lost or {}
    rows = []
    for m in minutes:
        for name, tid in ids.items():
            n = lost.get(name, 0)
            n = n(m) if callable(n) else n
            rtt = None if n >= 30 else 10.0
            rows.append(
                RollupRow(m, tid, 30, n, rtt, rtt, rtt, None if rtt is None else 1.0, link, vpn)
            )
        with conn:
            conn.executemany(
                "INSERT INTO heartbeat (ts) VALUES (?)",
                [(m + i * 20_000 + 1,) for i in range(beats)],
            )
    store.upsert_rollups(conn, rows)


def mins(start, n):
    return [start + i * MIN for i in range(n)]


def test_covered_needs_three_heartbeats_and_a_gateway_row(conn):
    ids = targets(conn)
    fill(conn, ids, mins(T0, 2))
    fill(conn, {"cloudflare": ids["cloudflare"]}, mins(T0 + 2 * MIN, 1))  # no gateway row
    fill(conn, ids, mins(T0 + 3 * MIN, 1), beats=2)
    cov = coverage.load(conn, T0, T0 + 4 * MIN)
    assert [cov.covered(m) for m in cov.minutes] == [True, True, False, False]


def test_nq_exclusion_plus_minus_30s_successful_runs_only(conn):
    ids = targets(conn)
    fill(conn, ids, mins(T0, 6))
    store.insert_rows(
        conn,
        [
            NqRow(
                ts=T0 + 2 * MIN + 40_000,
                started_ts=T0 + 2 * MIN + 40_000,
                ended_ts=T0 + 3 * MIN + 0,
                ok=1,
            )
        ],
    )
    store.insert_rows(
        conn,
        [
            NqRow(
                ts=T0 + 5 * MIN,
                started_ts=T0 + 5 * MIN,
                ended_ts=None,
                ok=0,
                error="skipped:battery",
            )
        ],
    )
    cov = coverage.load(conn, T0, T0 + 6 * MIN)
    # run 2:40–3:00, ±30 s → 2:10–3:30 overlaps minutes 2 and 3
    assert [cov.exclusion(m) for m in cov.minutes] == [None, None, "nq", "nq", None, None]


def test_vpn_link_other_and_local_load_exclusions(conn):
    ids = targets(conn)
    fill(conn, ids, mins(T0, 1), vpn=1)
    fill(conn, ids, mins(T0 + MIN, 1), link="other")
    fill(conn, ids, mins(T0 + 2 * MIN, 3))
    store.upsert_local_load(
        conn,
        [
            LocalLoadRow(T0 + 2 * MIN, th.LOCAL_LOAD_MBPS, 1.0),  # exactly 20: not excluded
            LocalLoadRow(T0 + 3 * MIN, 1.0, th.LOCAL_LOAD_MBPS + 0.1),
        ],
    )
    cov = coverage.load(conn, T0, T0 + 5 * MIN)
    assert [cov.exclusion(m) for m in cov.minutes] == [
        "vpn",
        "link_other",
        None,
        "local_load",
        None,
    ]
    assert cov.link(T0 + MIN) == "other" and cov.vpn(T0) == 1


def test_gaps_from_heartbeats(conn):
    ids = targets(conn)
    fill(conn, ids, mins(T0, 3))
    fill(conn, ids, mins(T0 + 10 * MIN, 2))
    cov = coverage.load(conn, T0, T0 + 12 * MIN)
    (gap,) = cov.gaps()
    assert gap[0] < T0 + 3 * MIN and gap[1] > T0 + 10 * MIN
    assert not cov.covered(T0 + 5 * MIN)


def test_window_covered_at_50_percent(conn):
    ids = targets(conn)
    fill(conn, ids, mins(T0, 5))
    cov = coverage.load(conn, T0, T0 + 10 * MIN)
    assert cov.window_covered(mins(T0, 10))  # exactly 5 of 10
    assert not cov.window_covered(mins(T0, 11))
    assert not cov.window_covered([])


def gateway_all_lost(start, n):
    window = set(mins(start, n))
    return lambda m: 30 if m in window else 0


def test_gateway_blocked_after_ten_minutes_until_next_reply(conn):
    ids = targets(conn)
    lost = {"gateway": gateway_all_lost(T0 + 5 * MIN, 12)}
    fill(conn, ids, mins(T0, 30), lost=lost)
    cov = coverage.load(conn, T0, T0 + 30 * MIN)
    blocked = [m for m in cov.minutes if cov.gateway_blocked(m)]
    assert blocked == mins(T0 + 5 * MIN, 12)
    assert cov.covered(T0 + 6 * MIN)  # blocked minutes stay covered


def test_nine_minutes_is_not_blocked(conn):
    ids = targets(conn)
    fill(conn, ids, mins(T0, 20), lost={"gateway": gateway_all_lost(T0, 9)})
    cov = coverage.load(conn, T0, T0 + 20 * MIN)
    assert not cov.blocked


def test_block_continues_until_reply_even_if_downstream_goes_bad(conn):
    ids = targets(conn)
    all_lost = gateway_all_lost(T0, 15)
    later_bad = lambda m: 5 if m >= T0 + 12 * MIN else 0
    fill(
        conn,
        ids,
        mins(T0, 20),
        lost={
            "gateway": all_lost,
            "cloudflare": later_bad,
            "google": later_bad,
            "youtube": later_bad,
        },
    )
    cov = coverage.load(conn, T0, T0 + 20 * MIN)
    assert sorted(cov.blocked) == mins(T0, 15)


def test_everything_down_is_not_blocked(conn):
    ids = targets(conn)
    fill(conn, ids, mins(T0, 20), lost={n: 30 for n in ids})
    assert not coverage.load(conn, T0, T0 + 20 * MIN).blocked


def test_target_unresponsive_until_ip_changes(conn):
    ids = targets(conn)
    fill(conn, ids, mins(T0, 20), lost={"youtube": 30})
    cov = coverage.load(conn, T0, T0 + 20 * MIN)
    assert cov.is_unresponsive(ids["youtube"], T0 + 15 * MIN)
    assert not cov.is_unresponsive(ids["cloudflare"], T0)
    # a new IP starts a new epoch, which answers
    store.switch_target_ip(conn, ids["youtube"], "198.51.100.99", T0 + 20 * MIN)
    fill(conn, ids, mins(T0 + 20 * MIN, 15))
    cov = coverage.load(conn, T0, T0 + 35 * MIN)
    assert cov.is_unresponsive(ids["youtube"], T0 + 19 * MIN)
    assert not cov.is_unresponsive(ids["youtube"], T0 + 25 * MIN)


def test_not_unresponsive_when_the_gateway_was_also_losing(conn):
    ids = targets(conn)
    fill(conn, ids, mins(T0, 20), lost={"youtube": 30, "gateway": 1})
    cov = coverage.load(conn, T0, T0 + 20 * MIN)
    assert not cov.is_unresponsive(ids["youtube"], T0 + 5 * MIN)


def test_exactly_half_loss_is_not_unresponsive(conn):
    ids = targets(conn)
    fill(conn, ids, mins(T0, 20), lost={"youtube": 15})
    assert not coverage.load(conn, T0, T0 + 20 * MIN).unresponsive


def test_discovery_status_at_a_minute(conn):
    ids = targets(conn)
    store.record_target_status(conn, ids["youtube"], "approximate", "iad66s07", T0 + 5 * MIN)
    cov = coverage.load(conn, T0, T0 + 10 * MIN)
    assert cov.discovery_status(ids["youtube"], T0) == "ok"
    assert cov.discovery_status(ids["youtube"], T0 + 5 * MIN) == "approximate"
    assert cov.discovery_status(999, T0) is None


@pytest.fixture
def london(monkeypatch):
    monkeypatch.setenv("TZ", "Europe/London")
    time.tzset()
    yield
    monkeypatch.delenv("TZ")
    time.tzset()


def test_scenario_blocked_gateway_and_load_speed(conn, london):
    s = sc.gateway_blocked_upstream_bad(conn)
    started = time.monotonic()
    cov = coverage.load(conn, s.start, s.end)
    assert time.monotonic() - started < 2.0
    share = len(cov.blocked) / len(cov.covered_minutes())
    assert share > 0.9


def test_scenario_nq_and_local_load_minutes_excluded(conn, london):
    s = sc.bad_only_during_nq_and_local_load(conn)
    cov = coverage.load(conn, s.start, s.end)
    evening = sc.local_ms(2026, 10, 2, 20, 30)
    assert cov.exclusion(evening) == "nq"
    assert cov.exclusion(sc.local_ms(2026, 10, 2, 21, 10)) == "local_load"
    assert cov.covered(sc.local_ms(2026, 10, 2, 22, 0))


def test_scenario_sleep_gaps_not_covered(conn, london):
    s = sc.long_sleep_gaps(conn)
    cov = coverage.load(conn, s.start, s.end)
    assert len(cov.gaps()) == 8
    assert not cov.covered(sc.local_ms(2026, 10, 3, 3, 0))
