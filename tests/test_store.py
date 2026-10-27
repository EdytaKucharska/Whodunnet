"""Tests for whodunnet/core/schema.py and whodunnet/core/store.py (plan M1.2)."""

import sqlite3

import pytest

from whodunnet.core import schema, store
from whodunnet.core.models import (
    DnsRow,
    LocalLoadRow,
    NqRow,
    PingRow,
    RollupRow,
    TracerouteRow,
    WifiRow,
)

T0 = 1_793_000_000_000  # a fixed UTC epoch-ms instant


@pytest.fixture
def conn(tmp_path):
    c = store.connect(tmp_path / "w.db")
    yield c
    c.close()


def test_fresh_db_migrates_and_is_idempotent(tmp_path):
    db = tmp_path / "w.db"
    c = store.connect(db)
    assert schema.current_version(c) == schema.SCHEMA_VERSION
    assert c.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"targets", "ping", "minute_rollup", "events", "local_load", "target_status"} <= tables
    c.close()
    c2 = store.connect(db)  # second open: no error, same version
    assert schema.migrate(c2) == schema.SCHEMA_VERSION
    c2.close()


def test_newer_schema_is_refused(conn):
    store.set_meta(conn, "schema_version", str(schema.SCHEMA_VERSION + 1))
    with pytest.raises(RuntimeError, match="newer"):
        schema.migrate(conn)


def test_meta(conn):
    assert store.get_meta(conn, "double_nat") is None
    store.set_meta(conn, "double_nat", "1")
    store.set_meta(conn, "double_nat", "0")
    assert store.get_meta(conn, "double_nat") == "0"


# ---- targets ----------------------------------------------------------------------------------


def test_upsert_target_creates_then_refreshes_same_identity(conn):
    tid = store.upsert_target(conn, "anchor", "cloudflare", 4, None, "1.1.1.1", "ok", T0)
    again = store.upsert_target(conn, "anchor", "cloudflare", 4, None, "1.1.1.1", "ok", T0 + 1000)
    assert again == tid
    t = store.get_target(conn, tid)
    assert (t.ip, t.status, t.active, t.first_seen, t.last_seen) == (
        "1.1.1.1",
        "ok",
        1,
        T0,
        T0 + 1000,
    )
    assert t.baseline_epoch_ms == T0  # first IP starts the baseline
    assert len(store.target_ip_history(conn, tid)) == 1
    assert len(store.target_status_history(conn, tid)) == 1
    # a different address family is a different target
    v6 = store.upsert_target(
        conn, "anchor", "cloudflare", 6, None, "2606:4700:4700::1111", "ok", T0
    )
    assert v6 != tid


def test_ip_change_within_slash24_keeps_baseline(conn):
    tid = store.upsert_target(
        conn, "cdn", "instagram", 4, "scontent.cdninstagram.com", "198.51.100.10", "ok", T0
    )
    reset = store.switch_target_ip(conn, tid, "198.51.100.77", T0 + 60_000)
    assert reset is False
    t = store.get_target(conn, tid)
    assert t.ip == "198.51.100.77" and t.baseline_epoch_ms == T0
    assert [r["ip"] for r in store.target_ip_history(conn, tid)] == [
        "198.51.100.10",
        "198.51.100.77",
    ]


def test_ip_change_across_networks_resets_baseline(conn):
    tid = store.upsert_target(conn, "cdn", "instagram", 4, "h", "198.51.100.10", "ok", T0)
    assert store.switch_target_ip(conn, tid, "203.0.113.5", T0 + 5) is True
    assert store.get_target(conn, tid).baseline_epoch_ms == T0 + 5


def test_ipv6_uses_slash48(conn):
    tid = store.upsert_target(conn, "cdn", "netflix", 6, "h", "2001:db8:1:1::1", "ok", T0)
    assert store.switch_target_ip(conn, tid, "2001:db8:1:2::9", T0 + 1) is False  # same /48
    assert store.switch_target_ip(conn, tid, "2001:db8:2::1", T0 + 2) is True


def test_same_ip_is_a_no_op(conn):
    tid = store.upsert_target(conn, "gateway", "gateway", 4, None, "192.168.1.1", "ok", T0)
    assert store.switch_target_ip(conn, tid, "192.168.1.1", T0 + 9) is False
    assert len(store.target_ip_history(conn, tid)) == 1


def test_status_history_only_on_change(conn):
    tid = store.upsert_target(
        conn, "cdn", "netflix", 4, None, None, "unavailable", T0, reason="token not found"
    )
    assert store.get_target(conn, tid).ip is None
    assert store.record_target_status(conn, tid, "unavailable", "token not found", T0 + 1) is False
    assert store.record_target_status(conn, tid, "ok", None, T0 + 2) is True
    hist = store.target_status_history(conn, tid)
    assert [(r["status"], r["reason"]) for r in hist] == [
        ("unavailable", "token not found"),
        ("ok", None),
    ]
    assert store.get_target(conn, tid).status == "ok"


def test_target_validation(conn):
    with pytest.raises(ValueError):
        store.upsert_target(conn, "router", "x", 4, None, None, "ok", T0)
    with pytest.raises(ValueError):
        store.upsert_target(conn, "anchor", "x", 5, None, None, "ok", T0)
    with pytest.raises(ValueError):
        store.upsert_target(
            conn, "anchor", "x", 4, None, None, "blocked", T0
        )  # derived, never stored


def test_active_flag_and_listing(conn):
    a = store.upsert_target(conn, "anchor", "a", 4, None, "1.1.1.1", "ok", T0)
    b = store.upsert_target(conn, "anchor", "b", 4, None, "8.8.8.8", "ok", T0)
    store.set_target_active(conn, b, False)
    assert [t.id for t in store.list_targets(conn, active_only=True)] == [a]
    assert [t.id for t in store.list_targets(conn)] == [a, b]
    # rediscovery re-activates
    store.upsert_target(conn, "anchor", "b", 4, None, "8.8.8.8", "ok", T0 + 1)
    assert len(store.list_targets(conn, active_only=True)) == 2


# ---- raw rows ---------------------------------------------------------------------------------


def test_insert_and_read_every_raw_type(conn):
    tid = store.upsert_target(conn, "anchor", "cloudflare", 4, None, "1.1.1.1", "ok", T0)
    store.insert_rows(
        conn,
        [
            PingRow(T0, tid, 0, 13.2, link="wifi"),
            PingRow(T0 + 2000, tid, 1, None, error="timeout", link="wifi"),
        ],
    )
    store.insert_rows(
        conn,
        [
            WifiRow(
                T0 + 11_000,
                T0,
                1,
                rssi_dbm=-55,
                noise_dbm=-96,
                channel=100,
                band="5",
                width_mhz=80,
                tx_rate_mbps=576,
                phy_mode="802.11ax",
            )
        ],
    )
    store.insert_rows(
        conn,
        [
            DnsRow(
                T0,
                1,
                resolver="192.168.1.1",
                query_kind="cached",
                ms=3,
                rcode="NOERROR",
                link="wifi",
            )
        ],
    )
    store.insert_rows(
        conn, [NqRow(T0, T0, T0 + 20_000, 1, dl_mbps=447.1, ul_mbps=142.7, rpm=514, grade="C")]
    )
    store.insert_rows(conn, [TracerouteRow(T0, tid, 1, hops_json="[]", link="wifi")])
    store.insert_heartbeat(conn, T0)

    pings = store.read_raw(conn, "ping", T0, T0 + 10_000, target_id=tid)
    assert [p["rtt_ms"] for p in pings] == [13.2, None]
    assert pings[1]["error"] == "timeout"
    assert store.read_raw(conn, "wifi", T0, T0 + 20_000)[0]["band"] == "5"
    assert store.read_raw(conn, "nq", T0, T0 + 1)[0]["grade"] == "C"
    assert len(store.read_raw(conn, "heartbeat", T0, T0 + 1)) == 1
    assert store.read_raw(conn, "ping", T0 + 2000, T0 + 2000) == []  # end is exclusive
    assert store.insert_rows(conn, []) == 0


def test_read_raw_guards(conn):
    with pytest.raises(ValueError):
        store.read_raw(conn, "events", 0, 1)
    with pytest.raises(ValueError):
        store.read_raw(conn, "wifi", 0, 1, target_id=1)


def test_gateway_mac_only_on_change(conn):
    assert store.record_gateway_mac(conn, "abc", T0) is True
    assert store.record_gateway_mac(conn, "abc", T0 + 1) is False
    assert store.record_gateway_mac(conn, "def", T0 + 2) is True


def test_rollups_and_local_load_upsert(conn):
    row = RollupRow(T0, 1, 30, 0, 3.0, 9.0, 12.0, 1.5, "wifi", 0)
    store.upsert_rollups(conn, [row])
    store.upsert_rollups(conn, [RollupRow(T0, 1, 30, 2, 3.0, 9.0, 12.0, 1.5, "wifi", 0)])  # re-roll
    got = store.read_rollups(conn, T0, T0 + 60_000)
    assert len(got) == 1 and got[0].lost == 2
    store.upsert_local_load(conn, [LocalLoadRow(T0, 1.0, 0.5), LocalLoadRow(T0, 2.0, 0.5)])
    assert conn.execute("SELECT rx_mbps FROM local_load").fetchall()[0][0] == 2.0


# ---- events -----------------------------------------------------------------------------------


def test_events_crud(conn):
    a = store.add_event(conn, "router_change", "Router replaced", "cli", T0)
    lag = store.add_event(conn, "lag", "", "phone", T0 + 1)
    sysv = store.add_event(conn, "system", "Gap 5 min", "auto", T0 + 2)
    assert [e.id for e in store.list_events(conn, T0, T0 + 10)] == [a, lag, sysv]
    assert [e.id for e in store.list_events(conn, T0, T0 + 10, kinds=["lag"])] == [lag]
    assert store.delete_event(conn, sysv) is False  # system events aren't user-deletable
    assert store.delete_event(conn, a) is True
    assert store.delete_event(conn, a) is False
    assert store.delete_event(conn, sysv, user_only=False) is True
    with pytest.raises(ValueError):
        store.add_event(conn, "note", "x", "cli", T0)
    with pytest.raises(ValueError):
        store.add_event(conn, "other", "x", "email", T0)


# ---- retention --------------------------------------------------------------------------------


def test_prune_and_purge(conn):
    tid = store.upsert_target(conn, "anchor", "a", 4, None, "1.1.1.1", "ok", T0)
    store.insert_rows(conn, [PingRow(T0, tid, 0, 1.0), PingRow(T0 + 10, tid, 1, 1.0)])
    store.upsert_rollups(conn, [RollupRow(T0, tid, 1, 0, 1, 1, 1, None, "wifi", 0)])
    store.insert_heartbeat(conn, T0)
    store.add_event(conn, "other", "keep me", "cli", T0)

    assert store.prune_raw_ping(conn, T0 + 5) == 1
    assert len(store.read_rollups(conn, 0, T0 + 1)) == 1  # rollups survive pruning

    deleted = store.purge_before(conn, T0 + 100)
    assert deleted["ping"] == 1 and deleted["minute_rollup"] == 1 and deleted["heartbeat"] == 1
    assert len(store.list_events(conn, 0, T0 + 100)) == 1  # events kept


# ---- concurrency ------------------------------------------------------------------------------


def test_reader_works_while_writer_holds_a_transaction(tmp_path):
    db = tmp_path / "w.db"
    writer = store.connect(db)
    tid = store.upsert_target(writer, "anchor", "a", 4, None, "1.1.1.1", "ok", T0)
    store.insert_rows(writer, [PingRow(T0, tid, 0, 5.0)])

    writer.execute("BEGIN IMMEDIATE")
    writer.execute(
        "INSERT INTO ping (ts, target_id, seq, rtt_ms) VALUES (?, ?, 1, 6.0)", (T0 + 1, tid)
    )
    reader = store.connect_readonly(db)
    rows = store.read_raw(reader, "ping", T0, T0 + 10)  # doesn't block, sees committed data only
    assert [r["rtt_ms"] for r in rows] == [5.0]
    with pytest.raises(sqlite3.OperationalError):
        reader.execute("INSERT INTO heartbeat (ts) VALUES (1)")  # read-only
    writer.commit()
    assert len(store.read_raw(reader, "ping", T0, T0 + 10)) == 2
    reader.close()
    writer.close()


def test_readonly_connection_handles_spaces_in_path(tmp_path):
    db = tmp_path / "Application Support" / "Whodunnet" / "whodunnet.db"
    store.connect(db).close()  # creates folders + schema
    reader = store.connect_readonly(db)
    assert schema.current_version(reader) == schema.SCHEMA_VERSION
    reader.close()
