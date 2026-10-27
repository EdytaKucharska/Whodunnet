"""Dataclasses for rows and results (spec §5).

Field order of each *Row class matches its table's columns, so core/store.py can insert any
row generically. Times are UTC epoch milliseconds.
"""

from __future__ import annotations

from dataclasses import dataclass

TARGET_KINDS = ("gateway", "isp_edge", "anchor", "cdn")
DISCOVERY_STATUSES = ("ok", "approximate", "unavailable")
LINKS = ("wifi", "wired", "other")
EVENT_KINDS = ("router_change", "package_change", "isp_contact", "lag", "system", "other")
USER_EVENT_KINDS = ("router_change", "package_change", "isp_contact", "other")
EVENT_SOURCES = ("dashboard", "cli", "phone", "auto")
DNS_QUERY_KINDS = ("cached", "nxdomain")


@dataclass
class Target:
    id: int
    kind: str
    name: str
    af: int
    host: str | None
    ip: str | None
    status: str
    active: int
    baseline_epoch_ms: int | None
    first_seen: int | None
    last_seen: int | None


@dataclass
class PingRow:
    ts: int
    target_id: int
    seq: int | None
    rtt_ms: float | None  # None = lost
    error: str | None = None
    link: str | None = None
    vpn: int = 0


@dataclass
class WifiRow:
    ts: int
    started_ts: int
    ok: int
    error: str | None = None
    rssi_dbm: int | None = None
    noise_dbm: int | None = None
    channel: int | None = None
    band: str | None = None
    width_mhz: int | None = None
    tx_rate_mbps: float | None = None
    phy_mode: str | None = None


@dataclass
class DnsRow:
    ts: int
    ok: int
    error: str | None = None
    resolver: str | None = None
    query_kind: str | None = None
    ms: float | None = None
    rcode: str | None = None
    link: str | None = None
    vpn: int = 0


@dataclass
class NqRow:
    ts: int
    started_ts: int | None
    ended_ts: int | None
    ok: int
    error: str | None = None
    dl_mbps: float | None = None
    ul_mbps: float | None = None
    rpm: int | None = None
    base_rtt_ms: float | None = None
    loaded_ms: float | None = None
    bufferbloat_ms: float | None = None
    grade: str | None = None
    macos_version: str | None = None
    raw_json: str | None = None
    link: str | None = None
    vpn: int = 0


@dataclass
class TracerouteRow:
    ts: int
    target_id: int
    ok: int
    error: str | None = None
    hops_json: str | None = None
    link: str | None = None
    vpn: int = 0


@dataclass
class LocalLoadRow:
    minute: int
    rx_mbps: float | None
    tx_mbps: float | None


@dataclass
class RollupRow:
    minute: int
    target_id: int
    sent: int
    lost: int
    p50_ms: float | None
    p95_ms: float | None
    max_ms: float | None
    jitter_ms: float | None
    link: str | None
    vpn: int


@dataclass
class Event:
    id: int
    ts: int
    kind: str
    note: str
    source: str
