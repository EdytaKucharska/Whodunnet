"""The collector process: probes, scheduler, heartbeat, sleep handling (spec §3, §4.8).

One process does everything. The main thread runs the 1 s tick loop:
- sleep detection
- heartbeat every 10 s
- ping batch writes every 5 s
- link refresh every 10 s (a route change triggers rediscovery)
- caffeinate on charger

Slow or command-heavy probes run one at a time on the scheduler's worker thread, with that
thread's own SQLite connection: discovery, WiFi, DNS, local load, traceroute, networkQuality,
doctor, prune and the rollup hook. Hooks for rollup (M2.1) and the web server (M3.1) are no-ops
until those land.
"""

from __future__ import annotations

import logging
import os
import secrets
import signal
import sqlite3
import threading
import time
from typing import Any, Callable

from whodunnet import doctor
from whodunnet.collector.scheduler import Scheduler
from whodunnet.core import rollup, store
from whodunnet.paths import Paths
from whodunnet.probes import dns, load, nq, power, trace, wifi
from whodunnet.probes.discover import Discovery
from whodunnet.probes.link import LinkCache, LinkState
from whodunnet.probes.parsers import scutil
from whodunnet.probes.ping import PingStreams, default_popen, link_context_from, nudge_local_network
from whodunnet.probes.runner import Fetch, Runner, http_get, run_command, spawn

log = logging.getLogger(__name__)

HEARTBEAT_S = 10
PING_WRITE_S = 5
LINK_S = 10
POWER_S = 60
LOAD_S = 60
NQ_CHECK_S = 30
DOCTOR_S = 600
PRUNE_S = 24 * 3600
ROLLUP_S = 60
TRACE_FIRST_IN_S = 120  # let discovery and pings settle before the first traceroute round
SLEEP_THRESHOLD_MS = 30_000
DAY_MS = 24 * 3600 * 1000


def wall_ms() -> int:
    return int(time.time() * 1000)


class SleepWatch:
    """Detects that the Mac slept (or the process was stopped).

    `time.monotonic()` stops during sleep on macOS while the wall clock keeps going, so the wall
    clock running ahead by more than 30 s between two checks means a gap (spec §4.8).
    """

    def __init__(
        self,
        wall: Callable[[], int],
        monotonic: Callable[[], float],
        threshold_ms: int = SLEEP_THRESHOLD_MS,
    ) -> None:
        self.wall, self.monotonic, self.threshold_ms = wall, monotonic, threshold_ms
        self._last: tuple[int, float] | None = None
        self.gaps: list[tuple[int, int]] = []  # (start_ms, end_ms), most recent last

    def check(self) -> tuple[int, int] | None:
        now_wall, now_mono = self.wall(), self.monotonic()
        last, self._last = self._last, (now_wall, now_mono)
        if last is None:
            return None
        wall_delta = now_wall - last[0]
        mono_delta_ms = (now_mono - last[1]) * 1000
        if wall_delta - mono_delta_ms > self.threshold_ms:
            gap = (last[0], now_wall)
            self.gaps = [*self.gaps[-49:], gap]
            return gap
        return None

    def overlaps(self, start_ms: int, end_ms: int) -> bool:
        return any(g_start < end_ms and start_ms < g_end for g_start, g_end in self.gaps)


class Collector:
    def __init__(
        self,
        paths: Paths,
        cfg: dict[str, Any],
        runner: Runner = run_command,
        fetch: Fetch = http_get,
        wall: Callable[[], int] = wall_ms,
        monotonic: Callable[[], float] = time.monotonic,
        popen=default_popen,
        spawner=spawn,
        nudge: Callable[[str | None], bool] = nudge_local_network,
        threaded: bool = True,
    ) -> None:
        self.paths, self.cfg, self.runner, self.wall = paths, cfg, runner, wall
        self.nudge = nudge
        self.conn: sqlite3.Connection | None = None
        self._local = threading.local()
        self.stop_event = threading.Event()
        self.scheduler = Scheduler(monotonic, threaded=threaded)
        self.sleep = SleepWatch(wall, monotonic)
        self.link_cache = LinkCache(runner, clock=monotonic)
        self.pings = PingStreams(
            interval_s=cfg["ping_interval_s"],
            clock=wall,
            popen=popen,
            link_context=link_context_from(self.link_cache),
            in_gap=self.sleep.overlaps,
        )
        self.discovery = Discovery(runner, fetch, still_answering=self.pings.still_answering)
        self.meter = load.LoadMeter()
        self.traces = trace.TraceRound(monotonic=monotonic)
        self.nq = nq.NqRunner(runner)
        self.caffeinate = power.Caffeinate(spawner)
        self.resolver: str | None = None
        self._targets_changed = threading.Event()
        self._route: tuple[str | None, str | None] | None = None
        self.rollup_hook: Callable[[sqlite3.Connection, int], object] | None = rollup.rollup_recent
        self.web_hook: Callable[[Collector], object] | None = None  # cli run: the dashboard
        self.web = None  # the WebServer, once web_hook started it

    # ---- connections and context ---------------------------------------------------------------

    def _worker_conn(self) -> sqlite3.Connection:
        """Each thread gets its own connection (sqlite3 connections are per-thread)."""
        if threading.current_thread() is threading.main_thread() and self.conn is not None:
            return self.conn
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._local.conn = store.connect(self.paths.db)
        return conn

    def _link(self) -> LinkState | None:
        return self.link_cache.peek()

    def _link_fields(self) -> tuple[str | None, int]:
        state = self._link()
        return (state.medium, state.vpn) if state else (None, 0)

    # ---- startup ------------------------------------------------------------------------------

    def _write_meta(self) -> None:
        assert self.conn is not None
        if not store.get_meta(self.conn, "install_salt"):
            store.set_meta(self.conn, "install_salt", secrets.token_hex(16))
        host = scutil.parse_hostname(self.runner(["scutil", "--get", "LocalHostName"], 5).stdout)
        if host.ok and host.hostname:
            store.set_meta(self.conn, "local_hostname", host.hostname)
        version = self.runner(["sw_vers", "-productVersion"], 5)
        if version.ok and version.stdout.strip():
            store.set_meta(self.conn, "macos_version", version.stdout.strip())

    def start(self) -> None:
        """Open the database, discover targets, start pings and register every job."""
        self.paths.data_dir.mkdir(parents=True, exist_ok=True)
        self.conn = store.connect(self.paths.db)
        self._write_meta()
        state = self.link_cache.get(force=True)
        self._route = (state.interface, state.gateway)
        self.nudge(state.gateway)  # macOS 15+ Local Network prompt
        self._discover()
        self.pings.sync_from_db(self.conn)
        self._targets_changed.clear()
        self._power()
        store.insert_heartbeat(self.conn, self.wall())
        self.sleep.check()
        self._register_jobs()
        if self.web_hook:
            self.web_hook(self)

    def _register_jobs(self) -> None:
        s, cfg = self.scheduler, self.cfg
        s.every("heartbeat", HEARTBEAT_S, self._heartbeat, first_in_s=HEARTBEAT_S)
        s.every("pings", PING_WRITE_S, self._pings, first_in_s=PING_WRITE_S)
        s.every("link", LINK_S, self._refresh_link, first_in_s=LINK_S)
        s.every("power", POWER_S, self._power, first_in_s=POWER_S)
        bg = {"background": True}
        s.every(
            "discover",
            cfg["discover_interval_s"],
            self._discover,
            first_in_s=cfg["discover_interval_s"],
            **bg,
        )
        s.every("wifi", cfg["wifi_interval_s"], self._wifi, **bg)
        s.every("dns", cfg["dns_interval_s"], self._dns, **bg)
        s.every("load", LOAD_S, self._load, **bg)
        s.every("trace", cfg["trace_interval_s"], self._trace, first_in_s=TRACE_FIRST_IN_S, **bg)
        s.every("nq", NQ_CHECK_S, self._nq, **bg)
        s.every("doctor", DOCTOR_S, self._doctor, **bg)
        s.every("prune", PRUNE_S, self._prune, **bg)
        s.every("rollup", ROLLUP_S, self._rollup, first_in_s=ROLLUP_S, **bg)

    # ---- main-thread jobs ---------------------------------------------------------------------

    def _heartbeat(self) -> None:
        assert self.conn is not None
        store.insert_heartbeat(self.conn, self.wall())

    def _pings(self) -> None:
        assert self.conn is not None
        if self._targets_changed.is_set():
            self._targets_changed.clear()
            self.pings.sync_from_db(self.conn)
        self.pings.tick()
        self.pings.write(self.conn)

    def _refresh_link(self) -> None:
        state = self.link_cache.get(force=True)
        route = (state.interface, state.gateway)
        if self._route is not None and route != self._route:
            log.info("default route changed; rediscovering")
            self.scheduler.run_soon("discover")
        self._route = route

    def _power(self) -> None:
        if power.on_battery(self.runner):
            self.caffeinate.stop()
        else:
            self.caffeinate.start(os.getpid())

    def check_sleep(self) -> tuple[int, int] | None:
        """Every tick: after a sleep, record the gap, restart pings and rediscover."""
        gap = self.sleep.check()
        if gap is None:
            return None
        start, end = gap
        minutes = max(1, round((end - start) / 60_000))
        assert self.conn is not None
        store.add_event(self.conn, "system", f"Gap {minutes} min (asleep/stopped)", "auto", end)
        log.info("woke after a %s min gap; restarting pings and rediscovering", minutes)
        self.pings.write(self.conn)
        self.pings.restart_all()
        self.link_cache.get(force=True)
        if "discover" in self.scheduler.jobs:
            self.scheduler.run_soon("discover")
        return gap

    # ---- worker-thread jobs -------------------------------------------------------------------

    def _discover(self) -> None:
        report = self.discovery.run(self._worker_conn(), self.cfg, self.wall())
        self.resolver = report.resolver
        for warning in report.warnings:
            log.warning("discovery: %s", warning)
        self._targets_changed.set()

    def _wifi(self) -> None:
        state = self._link()
        row = wifi.read_wifi(
            state.interface if state else None,
            state.medium if state else None,
            self.wall,
            self.runner,
        )
        store.insert_rows(self._worker_conn(), [row])

    def _dns(self) -> None:
        link, vpn = self._link_fields()
        rows = dns.probe_dns(self.resolver, link, vpn, self.wall, self.runner)
        store.insert_rows(self._worker_conn(), rows)

    def _load(self) -> None:
        state = self._link()
        load.record_load(
            self._worker_conn(),
            self.meter,
            state.interface if state else None,
            self.wall(),
            self.runner,
        )

    def _trace(self) -> None:
        conn = self._worker_conn()
        link, vpn = self._link_fields()
        rows = self.traces.run(
            store.list_targets(conn, active_only=True), link, vpn, self.wall, self.runner
        )
        if rows:
            store.insert_rows(conn, rows)

    def _nq(self) -> None:
        link, vpn = self._link_fields()
        self.nq.maybe_run(self._worker_conn(), self.cfg["nq_schedule"], link, vpn, self.wall)

    def nq_now(self) -> None:
        link, vpn = self._link_fields()
        row = self.nq.run_now(self._worker_conn(), link, vpn, self.wall)
        log.info("nq now: ok=%s error=%s grade=%s", row.ok, row.error, row.grade)

    def _doctor(self) -> None:
        conn = self._worker_conn()
        link, vpn = self._link_fields()
        ctx = doctor.Context(
            conn=conn,
            paths=self.paths,
            cfg=self.cfg,
            now_ms=self.wall(),
            runner=self.runner,
            link_medium=link,
            vpn=vpn,
            collector=True,
        )
        doctor.store_results(conn, doctor.run_checks(ctx))

    def _prune(self) -> None:
        cutoff = self.wall() - self.cfg["raw_ping_retention_days"] * DAY_MS
        deleted = store.prune_raw_ping(self._worker_conn(), cutoff)
        if deleted:
            log.info("pruned %s raw ping rows", deleted)

    def _rollup(self) -> None:
        if self.rollup_hook is not None:
            self.rollup_hook(self._worker_conn(), self.wall())

    # ---- loop ---------------------------------------------------------------------------------

    def tick(self) -> list[str]:
        self.check_sleep()
        return self.scheduler.run_pending()

    def run(self, nq_now: bool = False, tick_s: float = 1.0) -> None:
        self.start()
        if nq_now:
            self.scheduler.every("nq_now", 10**9, self.nq_now, background=True)
        try:
            while not self.stop_event.is_set():
                self.tick()
                self.stop_event.wait(tick_s)
        finally:
            self.stop()

    def stop(self) -> None:
        """Graceful stop: finish the running probe, flush pings, release caffeinate."""
        self.stop_event.set()
        if self.web is not None:
            self.web.stop()
            self.web = None
        self.scheduler.shutdown()
        rows = self.pings.stop_all()
        if self.conn is not None:
            if rows:
                store.insert_rows(self.conn, rows)
            self.conn.close()
            self.conn = None
        self.caffeinate.stop()

    def install_signal_handlers(self) -> None:
        def handler(signum, frame):
            log.info("signal %s: stopping", signum)
            self.stop_event.set()

        signal.signal(signal.SIGTERM, handler)
        signal.signal(signal.SIGINT, handler)
