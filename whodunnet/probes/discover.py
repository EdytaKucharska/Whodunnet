"""Target discovery (spec §4.1): what to ping, and router/ISP-edge change detection.

Run at start, every 30 min, on wake and when the default route changes. `Discovery` keeps a
little state between runs (the ISP-edge candidate and sticky-IP absence counts) in memory; after
a restart the current edge is simply adopted again, which is harmless.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import secrets
import socket
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Callable

from whodunnet.core import store
from whodunnet.core.models import Target
from whodunnet.probes import link as link_probe
from whodunnet.probes import netflix, youtube
from whodunnet.probes.parsers import arp, dig, ifconfig, scutil, traceroute
from whodunnet.probes.runner import Fetch, Runner, http_get, run_command

log = logging.getLogger(__name__)

INSTAGRAM_HOST = "scontent.cdninstagram.com"
EDGE_TRACE_TARGET = "1.1.1.1"
EDGE_MAX_TTLS_AFTER_HOME = 2  # spec §4.1 (§6.9 threshold)
DOUBLE_NAT_RTT_MS = 1.0  # spec §4.1 (§6.9 threshold)
EDGE_CONFIRM_RUNS = 2
STICKY_ABSENT_RUNS = 2

_RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]

Resolve = Callable[[str, int], list]  # (host, af) -> list of IP strings


def system_resolve(host: str, af: int) -> list[str]:
    """Fallback resolver (system DNS). Used only when `dig` to a LAN resolver fails."""
    family = socket.AF_INET if af == 4 else socket.AF_INET6
    try:
        infos = socket.getaddrinfo(host, None, family, socket.SOCK_DGRAM)
    except OSError:
        return []
    ips: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


@dataclass
class DiscoveryReport:
    gateway: str | None = None
    interface: str | None = None
    medium: str | None = None
    isp_edge: str | None = None
    double_nat: bool = False
    resolver: str | None = None
    ipv6: bool = False
    targets: list[Target] = field(default_factory=list)  # active targets after this run
    events: list[str] = field(default_factory=list)  # system events recorded this run
    warnings: list[str] = field(default_factory=list)


def _is_ip(value: str, af: int | None = None) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return af is None or ip.version == af


def is_lan_or_link_local(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return addr.is_private or addr.is_link_local


def _is_rfc1918(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.version == 4 and any(addr in net for net in _RFC1918)


def find_isp_edge(
    hops: Sequence[traceroute.Hop], gateway: str, destination: str
) -> tuple[str | None, bool]:
    """(edge IP or None, double NAT?) from traceroute hops, per spec §4.1."""
    gateway_hop = next((h for h in hops if h.ip == gateway), None)
    if gateway_hop is None:
        return None, False
    home_ttl, double_nat = gateway_hop.ttl, False
    gateway_rtt = min(gateway_hop.rtts) if gateway_hop.rtts else None
    for hop in hops:
        if hop.ttl <= gateway_hop.ttl or hop.ip is None:
            continue
        if hop.ttl > home_ttl + EDGE_MAX_TTLS_AFTER_HOME or hop.ip == destination:
            break
        if (
            _is_rfc1918(hop.ip)
            and hop.rtts
            and gateway_rtt is not None
            and abs(min(hop.rtts) - gateway_rtt) <= DOUBLE_NAT_RTT_MS
        ):
            double_nat, home_ttl = True, hop.ttl  # second home router: skip it
            continue
        return hop.ip, double_nat
    return None, double_nat


def mac_hash(salt: str, mac: str) -> str:
    return hashlib.sha256((salt + mac).encode()).hexdigest()[:16]


class Discovery:
    def __init__(
        self,
        runner: Runner = run_command,
        fetch: Fetch = http_get,
        resolve: Resolve = system_resolve,
        still_answering: Callable[[int], bool] = lambda target_id: False,
    ) -> None:
        self.runner, self.fetch, self.resolve = runner, fetch, resolve
        self.still_answering = still_answering
        self._edge_candidate: str | None = None
        self._edge_seen = 0
        self._absent: dict[int, int] = {}

    # ---- helpers ------------------------------------------------------------------------------

    def _event(
        self, conn: sqlite3.Connection, report: DiscoveryReport, note: str, now_ms: int
    ) -> None:
        store.add_event(conn, "system", note, "auto", now_ms)
        report.events.append(note)

    def _lookup(
        self, host: str, af: int, resolver: str | None, report: DiscoveryReport
    ) -> tuple[list[str], str]:
        """(IPs, status) for a host. IP literals pass through. dig first; system DNS fallback."""
        if _is_ip(host, af):
            return [host], "ok"
        if _is_ip(host):
            return [], "ok"  # an IP of the other family
        if resolver:
            record = "A" if af == 4 else "AAAA"
            res = self.runner(
                ["dig", "+short", "+tries=1", "+time=2", record, f"@{resolver}", host], 10
            )
            parsed = dig.parse_short(res.output)
            if res.ok and parsed.ok:
                return parsed.ips, "ok"
            if not is_lan_or_link_local(resolver):
                report.warnings.append(f"DNS lookup for {host} failed")
                return [], "ok"
        fallback = self.resolve(host, af)
        return fallback, "approximate"

    def _choose_ip(self, existing: Target | None, candidates: list[str]) -> str | None:
        """Sticky IPs (spec §4.1)."""
        if existing is None or existing.ip is None:
            return candidates[0] if candidates else None
        if existing.ip in candidates:
            self._absent[existing.id] = 0
            return existing.ip
        misses = self._absent.get(existing.id, 0) + 1
        self._absent[existing.id] = misses
        if candidates and misses >= STICKY_ABSENT_RUNS and not self.still_answering(existing.id):
            self._absent[existing.id] = 0
            return candidates[0]
        return existing.ip

    def _hostname_target(
        self,
        conn: sqlite3.Connection,
        kind: str,
        name: str,
        af: int,
        host: str,
        resolver: str | None,
        now_ms: int,
        report: DiscoveryReport,
        status: str = "ok",
        reason: str | None = None,
        skip_if_no_address: bool = False,
    ) -> int | None:
        ips, lookup_status = self._lookup(host, af, resolver, report)
        if not ips and skip_if_no_address:
            return None
        existing = store.find_target(conn, kind, name, af)
        ip = self._choose_ip(existing, ips)
        if ip is None:
            status, reason = "unavailable", reason or f"no {('A' if af == 4 else 'AAAA')} record"
        elif lookup_status == "approximate" and status == "ok":
            status, reason = "approximate", "resolved with system DNS (router DNS unreachable)"
        stored_host = None if _is_ip(host) else host
        return store.upsert_target(conn, kind, name, af, stored_host, ip, status, now_ms, reason)

    # ---- main entry point ----------------------------------------------------------------------

    def run(self, conn: sqlite3.Connection, cfg: dict, now_ms: int) -> DiscoveryReport:
        report = DiscoveryReport()
        state = link_probe.current_link(self.runner)
        report.interface, report.medium, report.gateway = (
            state.interface,
            state.medium,
            state.gateway,
        )
        if not state.gateway:
            report.warnings.append("no default gateway — not connected?")
            report.targets = store.list_targets(conn, active_only=True)
            return report

        produced: set[int] = set()
        produced.add(self._gateway(conn, state.gateway, now_ms, report))
        edge_id = self._isp_edge(conn, state.gateway, now_ms, report)
        if edge_id is not None:
            produced.add(edge_id)

        resolvers = scutil.parse_resolvers(self.runner(["scutil", "--dns"], 5).output)
        report.resolver = resolvers.nameservers[0] if resolvers.ok else None

        families = [4]
        if cfg["ipv6"] == "auto" and state.interface:
            ifc = ifconfig.parse(self.runner(["ifconfig", state.interface], 5).output)
            if ifc.ok and ifc.has_global_ipv6(state.interface):
                families.append(6)
                report.ipv6 = True

        lookups = self._video_lookups(cfg)  # once per run, shared by both address families
        for af in families:
            anchors = cfg["anchors"] if af == 4 else cfg["anchors_v6"]
            for name, host in anchors.items():
                tid = self._hostname_target(
                    conn, "anchor", name, af, host, report.resolver, now_ms, report
                )
                produced.add(tid)
            produced.update(self._cdns(conn, cfg, lookups, af, report.resolver, now_ms, report))

        self._activate_only(conn, produced)
        report.targets = store.list_targets(conn, active_only=True)
        return report

    def _gateway(
        self, conn: sqlite3.Connection, gateway: str, now_ms: int, report: DiscoveryReport
    ) -> int:
        previous = store.find_target(conn, "gateway", "gateway", 4)
        ip_changed = previous is not None and previous.ip not in (None, gateway)
        tid = store.upsert_target(conn, "gateway", "gateway", 4, None, gateway, "ok", now_ms)

        mac_changed = False
        mac = arp.parse_mac(self.runner(["arp", "-n", gateway], 5).output)
        if mac.ok and mac.mac:
            salt = store.get_meta(conn, "install_salt")
            if not salt:
                salt = secrets.token_hex(16)
                store.set_meta(conn, "install_salt", salt)
            had_previous = store.last_gateway_mac(conn) is not None
            changed = store.record_gateway_mac(conn, mac_hash(salt, mac.mac), now_ms)
            mac_changed = changed and had_previous
        if ip_changed or mac_changed:
            self._event(
                conn, report, "Router changed? (gateway address or hardware changed)", now_ms
            )
        return tid

    def _isp_edge(
        self, conn: sqlite3.Connection, gateway: str, now_ms: int, report: DiscoveryReport
    ) -> int | None:
        trace = traceroute.parse(
            self.runner(
                ["traceroute", "-I", "-n", "-q", "3", "-w", "1", "-m", "8", EDGE_TRACE_TARGET], 40
            ).output
        )
        candidate, double_nat = (None, False)
        if trace.ok:
            candidate, double_nat = find_isp_edge(trace.hops, gateway, EDGE_TRACE_TARGET)
        else:
            report.warnings.append("traceroute for the ISP edge failed")
        report.double_nat = double_nat
        store.set_meta(conn, "double_nat", "1" if double_nat else "0")

        existing = store.find_target(conn, "isp_edge", "isp_edge", 4)
        known = existing.ip if existing is not None and existing.active else None
        adopted = known
        if candidate == known:
            self._edge_candidate, self._edge_seen = None, 0
        elif known is None and candidate is not None:
            adopted = candidate  # first edge: adopt immediately
        else:
            if candidate == self._edge_candidate:
                self._edge_seen += 1
            else:
                self._edge_candidate, self._edge_seen = candidate, 1
            if self._edge_seen >= EDGE_CONFIRM_RUNS:
                adopted = candidate
                self._edge_candidate, self._edge_seen = None, 0
                self._event(
                    conn, report, f"ISP edge changed ({known} → {adopted or 'unknown'})", now_ms
                )

        report.isp_edge = adopted
        if adopted is None:
            return None
        return store.upsert_target(conn, "isp_edge", "isp_edge", 4, None, adopted, "ok", now_ms)

    def _video_lookups(self, cfg: dict) -> tuple[youtube.YoutubeResult, netflix.NetflixResult]:
        if cfg["discovery_lookups"]:
            yt = youtube.lookup(self.fetch) if cfg["cdn_youtube"] else None
            nf = netflix.lookup(self.fetch) if cfg["cdn_netflix"] else None
        else:
            yt = youtube.YoutubeResult(
                youtube.REDIRECTOR, "approximate", "discovery lookups disabled"
            )
            nf = netflix.NetflixResult("unavailable", "discovery lookups disabled")
        return yt, nf

    def _cdns(
        self,
        conn: sqlite3.Connection,
        cfg: dict,
        lookups: tuple,
        af: int,
        resolver: str | None,
        now_ms: int,
        report: DiscoveryReport,
    ) -> set[int]:
        ids: set[int] = set()
        v6_optional = af == 6  # an IPv6 CDN target only exists if it has an AAAA answer

        def add(tid: int | None) -> None:
            if tid is not None:
                ids.add(tid)

        if cfg["cdn_instagram"]:
            add(
                self._hostname_target(
                    conn,
                    "cdn",
                    "instagram",
                    af,
                    INSTAGRAM_HOST,
                    resolver,
                    now_ms,
                    report,
                    skip_if_no_address=v6_optional,
                )
            )
        yt, nf = lookups
        if cfg["cdn_youtube"] and yt is not None:
            add(
                self._hostname_target(
                    conn,
                    "cdn",
                    "youtube",
                    af,
                    yt.host,
                    resolver,
                    now_ms,
                    report,
                    status="approximate",
                    reason=yt.reason,
                    skip_if_no_address=v6_optional,
                )
            )
        if cfg["cdn_netflix"] and nf is not None:
            host = nf.host_v4 if af == 4 else nf.host_v6
            if nf.status == "ok" and host:
                add(
                    self._hostname_target(
                        conn,
                        "cdn",
                        "netflix",
                        af,
                        host,
                        resolver,
                        now_ms,
                        report,
                        skip_if_no_address=v6_optional,
                    )
                )
            elif af == 4:
                store.upsert_target(
                    conn, "cdn", "netflix", 4, None, None, "unavailable", now_ms, nf.reason
                )
        return ids

    def _activate_only(self, conn: sqlite3.Connection, produced: set[int]) -> None:
        """Ping exactly the targets this run produced that have an IP and aren't unavailable."""
        for target in store.list_targets(conn):
            want = (
                target.id in produced and target.ip is not None and target.status != "unavailable"
            )
            if bool(target.active) != want:
                store.set_target_active(conn, target.id, want)
