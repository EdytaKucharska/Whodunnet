"""SQLite DDL and forward-only migrations (spec §5).

`migrate(conn)` is idempotent: it brings any database up to SCHEMA_VERSION and does nothing
on an up-to-date one. Never edit a released migration; append a new one.
"""

from __future__ import annotations

import sqlite3

V1 = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  af INTEGER NOT NULL,
  host TEXT,
  ip TEXT,
  status TEXT NOT NULL,
  active INTEGER NOT NULL,
  baseline_epoch_ms INTEGER,
  first_seen INTEGER,
  last_seen INTEGER,
  UNIQUE (kind, name, af));
CREATE TABLE IF NOT EXISTS target_ips (target_id INTEGER, ip TEXT, from_ts INTEGER);
CREATE TABLE IF NOT EXISTS target_status (target_id INTEGER, status TEXT, reason TEXT,
                                          from_ts INTEGER);
CREATE TABLE IF NOT EXISTS gateway_mac (ts INTEGER, mac_hash TEXT);

CREATE TABLE IF NOT EXISTS ping (ts INTEGER, target_id INTEGER, seq INTEGER, rtt_ms REAL,
                                 error TEXT, link TEXT, vpn INTEGER);
CREATE TABLE IF NOT EXISTS wifi (ts INTEGER, started_ts INTEGER, ok INTEGER, error TEXT,
                                 rssi_dbm INTEGER, noise_dbm INTEGER, channel INTEGER, band TEXT,
                                 width_mhz INTEGER, tx_rate_mbps REAL, phy_mode TEXT);
CREATE TABLE IF NOT EXISTS dns (ts INTEGER, ok INTEGER, error TEXT, resolver TEXT,
                                query_kind TEXT, ms REAL, rcode TEXT, link TEXT, vpn INTEGER);
CREATE TABLE IF NOT EXISTS nq (ts INTEGER, started_ts INTEGER, ended_ts INTEGER, ok INTEGER,
                               error TEXT, dl_mbps REAL, ul_mbps REAL, rpm INTEGER,
                               base_rtt_ms REAL, loaded_ms REAL, bufferbloat_ms REAL, grade TEXT,
                               macos_version TEXT, raw_json TEXT, link TEXT, vpn INTEGER);
CREATE TABLE IF NOT EXISTS traceroute (ts INTEGER, target_id INTEGER, ok INTEGER, error TEXT,
                                       hops_json TEXT, link TEXT, vpn INTEGER);
CREATE TABLE IF NOT EXISTS local_load (minute INTEGER PRIMARY KEY, rx_mbps REAL, tx_mbps REAL);
CREATE TABLE IF NOT EXISTS heartbeat (ts INTEGER);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, ts INTEGER, kind TEXT, note TEXT,
                                   source TEXT);
CREATE TABLE IF NOT EXISTS minute_rollup (
  minute INTEGER,
  target_id INTEGER,
  sent INTEGER,
  lost INTEGER,
  p50_ms REAL,
  p95_ms REAL,
  max_ms REAL,
  jitter_ms REAL,
  link TEXT,
  vpn INTEGER,
  PRIMARY KEY (minute, target_id));

CREATE INDEX IF NOT EXISTS ping_ts ON ping (ts);
CREATE INDEX IF NOT EXISTS ping_target_ts ON ping (target_id, ts);
CREATE INDEX IF NOT EXISTS wifi_ts ON wifi (ts);
CREATE INDEX IF NOT EXISTS dns_ts ON dns (ts);
CREATE INDEX IF NOT EXISTS nq_ts ON nq (ts);
CREATE INDEX IF NOT EXISTS traceroute_ts ON traceroute (ts);
CREATE INDEX IF NOT EXISTS heartbeat_ts ON heartbeat (ts);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS gateway_mac_ts ON gateway_mac (ts);
CREATE INDEX IF NOT EXISTS target_ips_target ON target_ips (target_id, from_ts);
CREATE INDEX IF NOT EXISTS target_status_target ON target_status (target_id, from_ts);
"""

# Index i holds the script that upgrades version i to i + 1.
MIGRATIONS = [V1]
SCHEMA_VERSION = len(MIGRATIONS)

# Tables with a `ts` column holding raw measurements (range readers, purge).
RAW_TABLES = ("ping", "wifi", "dns", "nq", "traceroute", "heartbeat", "gateway_mac")


def current_version(conn: sqlite3.Connection) -> int:
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta'"
    ).fetchone()
    if not exists:
        return 0
    row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    return int(row[0]) if row else 0


def migrate(conn: sqlite3.Connection) -> int:
    """Apply pending migrations. Returns the resulting schema version."""
    version = current_version(conn)
    if version > SCHEMA_VERSION:
        raise RuntimeError(
            f"database schema v{version} is newer than this Whodunnet (v{SCHEMA_VERSION}); "
            "update the app"
        )
    for target in range(version, SCHEMA_VERSION):
        with conn:
            conn.executescript(MIGRATIONS[target])
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)",
                (str(target + 1),),
            )
    return SCHEMA_VERSION
