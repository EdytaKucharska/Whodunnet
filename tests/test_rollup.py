"""Rollup: raw pings → minute_rollup (spec §5 rollup rules, §4.3 WiFi-probe drop)."""

from __future__ import annotations

import pytest

from whodunnet.core import rollup, store
from whodunnet.core.models import PingRow, WifiRow

M0 = 1_793_000_040_000 // 60_000 * 60_000  # a minute boundary
MIN = 60_000


@pytest.fixture
def conn(tmp_path):
    c = store.connect(tmp_path / "r.db")
    yield c
    c.close()


def pings(target_id, minute, rtts, link="wifi", vpn=0, start_s=0, step_s=2):
    return [
        PingRow(minute + (start_s + i * step_s) * 1000, target_id, i, r, None, link, vpn)
        for i, r in enumerate(rtts)
    ]


def test_nearest_rank():
    values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
    assert rollup.nearest_rank(values, 50) == 5.0
    assert rollup.nearest_rank(values, 95) == 10.0
    assert rollup.nearest_rank([7.0], 95) == 7.0
    assert rollup.nearest_rank([], 50) is None
    assert rollup.nearest_rank([1.0, 2.0, 3.0, 4.0], 50) == 2.0  # rank ceil(2) = 2


def test_jitter_uses_consecutive_received_pairs_only():
    assert rollup.jitter([10.0, 14.0, 12.0]) == 3.0  # (4 + 2) / 2
    assert rollup.jitter([10.0, None, 30.0, 32.0]) == 2.0  # loss breaks 10→30
    assert rollup.jitter([10.0, None, 30.0]) is None
    assert rollup.jitter([]) is None


def test_hand_computed_minute(conn):
    # 30 samples: 28 replies with RTTs 10..37 ms, plus 2 losses (seq 5 and 6)
    rtts = [10.0 + i for i in range(30)]
    rtts[5] = rtts[6] = None
    store.insert_rows(conn, pings(1, M0, rtts))
    (row,) = rollup.rollup_range(conn, M0, M0 + MIN)
    received = sorted(r for r in rtts if r is not None)  # 28 values
    assert (row.minute, row.target_id, row.sent, row.lost) == (M0, 1, 30, 2)
    assert row.p50_ms == received[13]  # ceil(0.5*28) = 14th
    assert row.p95_ms == received[26]  # ceil(0.95*28) = 27th
    assert row.max_ms == 39.0
    # consecutive received pairs all differ by 1 ms (the 4→7 jump spans the losses: not a pair)
    assert row.jitter_ms == 1.0
    assert (row.link, row.vpn) == ("wifi", 0)
    stored = store.read_rollups(conn, M0, M0 + MIN)
    assert stored == [row]


def test_all_lost_minute_has_null_stats(conn):
    store.insert_rows(conn, pings(1, M0, [None] * 30))
    (row,) = rollup.rollup_range(conn, M0, M0 + MIN)
    assert (row.sent, row.lost) == (30, 30)
    assert row.p50_ms is row.p95_ms is row.max_ms is row.jitter_ms is None


def test_minutes_and_targets_are_separate(conn):
    store.insert_rows(conn, pings(1, M0, [10.0] * 30) + pings(2, M0, [20.0] * 30))
    store.insert_rows(conn, pings(1, M0 + MIN, [11.0] * 30))
    rows = rollup.rollup_range(conn, M0, M0 + 2 * MIN)
    assert [(r.minute, r.target_id, r.p50_ms) for r in rows] == [
        (M0, 1, 10.0),
        (M0, 2, 20.0),
        (M0 + MIN, 1, 11.0),
    ]


def test_majority_link_and_vpn(conn):
    rows = pings(1, M0, [10.0] * 20, link="wifi", vpn=0)
    rows += pings(1, M0, [10.0] * 10, link="wired", vpn=1, start_s=40, step_s=1)
    store.insert_rows(conn, rows)
    (row,) = rollup.rollup_range(conn, M0, M0 + MIN)
    assert (row.link, row.vpn) == ("wifi", 0)


def test_wifi_probe_samples_are_dropped(conn):
    store.insert_rows(conn, pings(1, M0, [10.0] * 30))  # ts = M0 + 0, 2, ..., 58 s
    # probe ran 20 s → 31 s: drop pings sent in [17 s, 34 s] → 18..34 = 9 samples
    store.insert_rows(conn, [WifiRow(ts=M0 + 31_000, started_ts=M0 + 20_000, ok=1)])
    (row,) = rollup.rollup_range(conn, M0, M0 + MIN)
    assert row.sent == 30 - 9


def test_wifi_probe_from_previous_minute_still_drops_early_samples(conn):
    store.insert_rows(conn, pings(1, M0, [10.0] * 30))
    store.insert_rows(conn, [WifiRow(ts=M0 + 1_000, started_ts=M0 - 10_000, ok=1)])
    (row,) = rollup.rollup_range(conn, M0, M0 + MIN)
    assert row.sent == 30 - 3  # 0, 2, 4 s fall inside [.., 4 s]


def test_rollup_recent_only_closed_minutes(conn):
    store.insert_rows(conn, pings(1, M0, [10.0] * 30) + pings(1, M0 + MIN, [10.0] * 30))
    # now = 10 s after the second minute ended: it is not closed yet (needs +15 s)
    rows = rollup.rollup_recent(conn, M0 + 2 * MIN + 10_000)
    assert [r.minute for r in rows] == [M0]
    rows = rollup.rollup_recent(conn, M0 + 2 * MIN + 15_000)
    assert [r.minute for r in rows] == [M0, M0 + MIN]


def test_rollup_recent_rerolls_late_rows(conn):
    store.insert_rows(conn, pings(1, M0, [10.0] * 20))
    rollup.rollup_recent(conn, M0 + MIN + 20_000)
    # ping hold flushes late rows for the same minute afterwards
    store.insert_rows(conn, pings(1, M0, [None] * 10, start_s=40))
    rollup.rollup_recent(conn, M0 + 2 * MIN + 20_000)
    (row,) = store.read_rollups(conn, M0, M0 + MIN)
    assert (row.sent, row.lost) == (30, 10)


def test_rollup_recent_catches_up_after_a_long_worker_delay(conn):
    store.insert_rows(conn, pings(1, M0, [10.0] * 30))
    rollup.rollup_recent(conn, M0 + MIN + 20_000)
    later = M0 + 30 * MIN
    store.insert_rows(conn, pings(1, M0 + 5 * MIN, [12.0] * 30))  # older than the 10-min window
    rows = rollup.rollup_recent(conn, later + 20_000)
    assert M0 + 5 * MIN in [r.minute for r in rows]


def test_rollup_recent_first_run_starts_at_first_ping_bounded_to_24h(conn):
    old = M0 - 3 * 24 * 60 * MIN
    store.insert_rows(conn, pings(1, old, [10.0] * 5) + pings(1, M0, [10.0] * 5))
    rows = rollup.rollup_recent(conn, M0 + MIN + 20_000)
    assert [r.minute for r in rows] == [M0]


def test_rollup_recent_with_no_pings(conn):
    assert rollup.rollup_recent(conn, M0) == []
