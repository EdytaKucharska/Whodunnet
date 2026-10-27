"""Read/write helpers; the only place SQL lives besides core/schema.py (spec §5).

Connections: the collector holds one read-write connection (WAL mode, so readers never block
it). The web server opens a read-only connection per GET and a short-lived read-write one per
POST/DELETE. All times are UTC epoch milliseconds.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import sqlite3
from collections.abc import Iterable, Sequence
from pathlib import Path

from whodunnet.core import schema
from whodunnet.core.models import (
    DISCOVERY_STATUSES,
    EVENT_KINDS,
    EVENT_SOURCES,
    TARGET_KINDS,
    USER_EVENT_KINDS,
    DnsRow,
    Event,
    LocalLoadRow,
    NqRow,
    PingRow,
    RollupRow,
    Target,
    TracerouteRow,
    WifiRow,
)

BUSY_TIMEOUT_MS = 5000


# ---- connections ------------------------------------------------------------------------------


def connect(path: Path | str) -> sqlite3.Connection:
    """Read-write connection: WAL mode, busy timeout, schema migrated."""
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=BUSY_TIMEOUT_MS / 1000)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    schema.migrate(conn)
    return conn


def connect_readonly(path: Path | str) -> sqlite3.Connection:
    """Read-only connection for the dashboard and reports. The database must already exist."""
    uri = Path(path).resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=BUSY_TIMEOUT_MS / 1000)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    return conn


# ---- meta -------------------------------------------------------------------------------------


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    with conn:
        conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))


# ---- targets ----------------------------------------------------------------------------------


def _row_to_target(row: sqlite3.Row) -> Target:
    return Target(**{f.name: row[f.name] for f in dataclasses.fields(Target)})


def get_target(conn: sqlite3.Connection, target_id: int) -> Target | None:
    row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
    return _row_to_target(row) if row else None


def find_target(conn: sqlite3.Connection, kind: str, name: str, af: int) -> Target | None:
    row = conn.execute(
        "SELECT * FROM targets WHERE kind = ? AND name = ? AND af = ?", (kind, name, af)
    ).fetchone()
    return _row_to_target(row) if row else None


def list_targets(conn: sqlite3.Connection, active_only: bool = False) -> list[Target]:
    sql = "SELECT * FROM targets" + (" WHERE active = 1" if active_only else "") + " ORDER BY id"
    return [_row_to_target(r) for r in conn.execute(sql)]


def _same_network(old_ip: str, new_ip: str) -> bool:
    """True if both IPs are in the same /24 (IPv4) or /48 (IPv6) — spec §4.1 sticky IPs."""
    a, b = ipaddress.ip_address(old_ip), ipaddress.ip_address(new_ip)
    if a.version != b.version:
        return False
    prefix = 24 if a.version == 4 else 48
    return ipaddress.ip_network(f"{a}/{prefix}", strict=False) == ipaddress.ip_network(
        f"{b}/{prefix}", strict=False
    )


def upsert_target(
    conn: sqlite3.Connection,
    kind: str,
    name: str,
    af: int,
    host: str | None,
    ip: str | None,
    status: str,
    now_ms: int,
    reason: str | None = None,
) -> int:
    """Create or refresh the target identified by (kind, name, af). Returns its id.

    A new IP goes through switch_target_ip (history + baseline reset rule); a new discovery
    status goes through record_target_status (history only on change).
    """
    if kind not in TARGET_KINDS:
        raise ValueError(f"unknown target kind {kind!r}")
    if af not in (4, 6):
        raise ValueError(f"address family must be 4 or 6, got {af!r}")
    existing = find_target(conn, kind, name, af)
    with conn:
        if existing is None:
            cur = conn.execute(
                "INSERT INTO targets (kind, name, af, host, ip, status, active, "
                "baseline_epoch_ms, first_seen, last_seen) VALUES (?, ?, ?, ?, NULL, ?, 1, NULL, ?, ?)",
                (kind, name, af, host, status, now_ms, now_ms),
            )
            target_id = cur.lastrowid
        else:
            target_id = existing.id
            conn.execute(
                "UPDATE targets SET host = ?, active = 1, last_seen = ? WHERE id = ?",
                (host, now_ms, target_id),
            )
    if ip is not None:
        switch_target_ip(conn, target_id, ip, now_ms)
    record_target_status(conn, target_id, status, reason, now_ms)
    return target_id


def switch_target_ip(conn: sqlite3.Connection, target_id: int, new_ip: str, now_ms: int) -> bool:
    """Point a target at a new IP. Returns True if the baseline epoch was reset.

    Appends to target_ips. The baseline restarts when there was no IP before or the new IP is
    in a different /24 (IPv4) or /48 (IPv6).
    """
    target = get_target(conn, target_id)
    if target is None:
        raise KeyError(target_id)
    if target.ip == new_ip:
        return False
    reset = target.ip is None or not _same_network(target.ip, new_ip)
    with conn:
        conn.execute(
            "INSERT INTO target_ips (target_id, ip, from_ts) VALUES (?, ?, ?)",
            (target_id, new_ip, now_ms),
        )
        if reset:
            conn.execute(
                "UPDATE targets SET ip = ?, baseline_epoch_ms = ? WHERE id = ?",
                (new_ip, now_ms, target_id),
            )
        else:
            conn.execute("UPDATE targets SET ip = ? WHERE id = ?", (new_ip, target_id))
    return reset


def record_target_status(
    conn: sqlite3.Connection,
    target_id: int,
    status: str,
    reason: str | None,
    now_ms: int,
) -> bool:
    """Append to target_status only when status or reason changed. Returns True if appended."""
    if status not in DISCOVERY_STATUSES:
        raise ValueError(f"unknown discovery status {status!r}")
    last = conn.execute(
        "SELECT status, reason FROM target_status WHERE target_id = ? "
        "ORDER BY from_ts DESC, rowid DESC LIMIT 1",
        (target_id,),
    ).fetchone()
    if last is not None and (last["status"], last["reason"]) == (status, reason):
        return False
    with conn:
        conn.execute(
            "INSERT INTO target_status (target_id, status, reason, from_ts) VALUES (?, ?, ?, ?)",
            (target_id, status, reason, now_ms),
        )
        conn.execute("UPDATE targets SET status = ? WHERE id = ?", (status, target_id))
    return True


def set_target_active(conn: sqlite3.Connection, target_id: int, active: bool) -> None:
    with conn:
        conn.execute("UPDATE targets SET active = ? WHERE id = ?", (int(active), target_id))


def target_ip_history(conn: sqlite3.Connection, target_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT ip, from_ts FROM target_ips WHERE target_id = ? ORDER BY from_ts, rowid",
        (target_id,),
    ).fetchall()


def target_status_history(conn: sqlite3.Connection, target_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT status, reason, from_ts FROM target_status WHERE target_id = ? "
        "ORDER BY from_ts, rowid",
        (target_id,),
    ).fetchall()


# ---- raw measurements -------------------------------------------------------------------------

_ROW_TABLES = {
    PingRow: "ping",
    WifiRow: "wifi",
    DnsRow: "dns",
    NqRow: "nq",
    TracerouteRow: "traceroute",
}


def insert_rows(conn: sqlite3.Connection, rows: Sequence) -> int:
    """Batch-insert rows of one *Row type. Returns the number inserted."""
    if not rows:
        return 0
    cls = type(rows[0])
    table = _ROW_TABLES[cls]
    names = [f.name for f in dataclasses.fields(cls)]
    sql = f"INSERT INTO {table} ({', '.join(names)}) VALUES ({', '.join('?' * len(names))})"
    with conn:
        conn.executemany(sql, [dataclasses.astuple(r) for r in rows])
    return len(rows)


def insert_heartbeat(conn: sqlite3.Connection, ts: int) -> None:
    with conn:
        conn.execute("INSERT INTO heartbeat (ts) VALUES (?)", (ts,))


def last_gateway_mac(conn: sqlite3.Connection) -> str | None:
    row = conn.execute("SELECT mac_hash FROM gateway_mac ORDER BY ts DESC LIMIT 1").fetchone()
    return row[0] if row else None


def record_gateway_mac(conn: sqlite3.Connection, mac_hash: str, ts: int) -> bool:
    """Store the (salted, hashed) gateway MAC if it changed. Returns True if it changed."""
    last = conn.execute("SELECT mac_hash FROM gateway_mac ORDER BY ts DESC LIMIT 1").fetchone()
    if last is not None and last[0] == mac_hash:
        return False
    with conn:
        conn.execute("INSERT INTO gateway_mac (ts, mac_hash) VALUES (?, ?)", (ts, mac_hash))
    return True


def upsert_local_load(conn: sqlite3.Connection, rows: Iterable[LocalLoadRow]) -> None:
    with conn:
        conn.executemany(
            "INSERT OR REPLACE INTO local_load (minute, rx_mbps, tx_mbps) VALUES (?, ?, ?)",
            [dataclasses.astuple(r) for r in rows],
        )


def upsert_rollups(conn: sqlite3.Connection, rows: Iterable[RollupRow]) -> None:
    names = [f.name for f in dataclasses.fields(RollupRow)]
    sql = (
        f"INSERT OR REPLACE INTO minute_rollup ({', '.join(names)}) "
        f"VALUES ({', '.join('?' * len(names))})"
    )
    with conn:
        conn.executemany(sql, [dataclasses.astuple(r) for r in rows])


def read_raw(
    conn: sqlite3.Connection,
    table: str,
    start_ms: int,
    end_ms: int,
    target_id: int | None = None,
) -> list[sqlite3.Row]:
    """Rows of a raw table with start_ms <= ts < end_ms, oldest first."""
    if table not in schema.RAW_TABLES:
        raise ValueError(f"not a raw table: {table!r}")
    sql = f"SELECT * FROM {table} WHERE ts >= ? AND ts < ?"
    params: list = [start_ms, end_ms]
    if target_id is not None:
        if table not in ("ping", "traceroute"):
            raise ValueError(f"{table} has no target_id")
        sql += " AND target_id = ?"
        params.append(target_id)
    return conn.execute(sql + " ORDER BY ts, rowid", params).fetchall()


def read_rollups(
    conn: sqlite3.Connection, start_ms: int, end_ms: int, target_id: int | None = None
) -> list[RollupRow]:
    sql = "SELECT * FROM minute_rollup WHERE minute >= ? AND minute < ?"
    params: list = [start_ms, end_ms]
    if target_id is not None:
        sql += " AND target_id = ?"
        params.append(target_id)
    rows = conn.execute(sql + " ORDER BY minute, target_id", params).fetchall()
    names = [f.name for f in dataclasses.fields(RollupRow)]
    return [RollupRow(**{n: r[n] for n in names}) for r in rows]


# ---- events -----------------------------------------------------------------------------------


def add_event(conn: sqlite3.Connection, kind: str, note: str, source: str, ts: int) -> int:
    if kind not in EVENT_KINDS:
        raise ValueError(f"unknown event kind {kind!r}")
    if source not in EVENT_SOURCES:
        raise ValueError(f"unknown event source {source!r}")
    with conn:
        cur = conn.execute(
            "INSERT INTO events (ts, kind, note, source) VALUES (?, ?, ?, ?)",
            (ts, kind, note, source),
        )
    return cur.lastrowid


def list_events(
    conn: sqlite3.Connection,
    start_ms: int,
    end_ms: int,
    kinds: Sequence[str] | None = None,
) -> list[Event]:
    sql = "SELECT id, ts, kind, note, source FROM events WHERE ts >= ? AND ts < ?"
    params: list = [start_ms, end_ms]
    if kinds:
        sql += f" AND kind IN ({', '.join('?' * len(kinds))})"
        params.extend(kinds)
    return [Event(*r) for r in conn.execute(sql + " ORDER BY ts, id", params)]


def delete_event(conn: sqlite3.Connection, event_id: int, user_only: bool = True) -> bool:
    """Delete an event. By default only user-created kinds can be deleted (spec §7.3)."""
    sql = "DELETE FROM events WHERE id = ?"
    params: list = [event_id]
    if user_only:
        sql += f" AND kind IN ({', '.join('?' * len(USER_EVENT_KINDS))})"
        params.extend(USER_EVENT_KINDS)
    with conn:
        cur = conn.execute(sql, params)
    return cur.rowcount == 1


# ---- retention --------------------------------------------------------------------------------


def prune_raw_ping(conn: sqlite3.Connection, older_than_ms: int) -> int:
    """Delete raw pings older than the cutoff (rollups are kept). Returns rows deleted."""
    with conn:
        cur = conn.execute("DELETE FROM ping WHERE ts < ?", (older_than_ms,))
    return cur.rowcount


def purge_before(conn: sqlite3.Connection, before_ms: int) -> dict[str, int]:
    """Delete measurements and rollups before a time (CLI `purge`). Events are kept."""
    deleted: dict[str, int] = {}
    with conn:
        for table in schema.RAW_TABLES:
            deleted[table] = conn.execute(
                f"DELETE FROM {table} WHERE ts < ?", (before_ms,)
            ).rowcount
        for table in ("minute_rollup", "local_load"):
            deleted[table] = conn.execute(
                f"DELETE FROM {table} WHERE minute < ?", (before_ms,)
            ).rowcount
    return deleted
