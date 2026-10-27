"""Collector: scheduler, sleep detection, startup, jobs, shutdown, doctor (plan M1.7)."""

from __future__ import annotations

import json
import threading
import time

import pytest

from tests.test_probes_discovery import FakeFetch, fx, mac_responses
from tests.test_probes_ping import FakePopen, reply, wait_until
from whodunnet import config, doctor, paths
from whodunnet.collector import main
from whodunnet.collector.scheduler import Scheduler
from whodunnet.core import store
from whodunnet.core.models import NqRow, PingRow, WifiRow
from whodunnet.probes.runner import CommandResult

T0 = 1_793_000_000_000


class Mono:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


class Wall:
    def __init__(self, ms=T0):
        self.ms = ms

    def __call__(self):
        return self.ms


# ---- scheduler --------------------------------------------------------------------------------


def test_scheduler_runs_due_jobs_once_per_interval():
    mono, calls = Mono(), []
    s = Scheduler(mono, threaded=False)
    s.every("a", 10, lambda: calls.append("a"))
    s.every("b", 30, lambda: calls.append("b"), first_in_s=5)
    assert s.run_pending() == ["a"]
    assert s.run_pending() == []
    mono.t += 5
    assert s.run_pending() == ["b"]
    mono.t += 5
    assert s.run_pending() == ["a"]
    assert calls == ["a", "b", "a"]


def test_scheduler_no_catch_up_burst_after_long_pause():
    mono, calls = Mono(), []
    s = Scheduler(mono, threaded=False)
    s.every("a", 10, lambda: calls.append(1))
    s.run_pending()
    mono.t += 3600
    s.run_pending()
    s.run_pending()
    mono.t += 9
    s.run_pending()
    assert len(calls) == 2


def test_scheduler_failing_job_is_logged_and_rescheduled(caplog):
    mono = Mono()
    s = Scheduler(mono, threaded=False)

    def boom():
        raise RuntimeError("probe broke")

    s.every("bad", 10, boom)
    s.every("good", 10, lambda: None)
    assert s.run_pending() == ["bad", "good"]
    assert s.jobs["bad"].failures == 1 and "probe broke" in s.jobs["bad"].last_error
    assert s.jobs["good"].runs == 1
    mono.t += 10
    s.run_pending()
    assert s.jobs["bad"].failures == 2
    assert "job bad failed" in caplog.text


def test_scheduler_run_soon():
    mono, calls = Mono(), []
    s = Scheduler(mono, threaded=False)
    s.every("d", 1800, lambda: calls.append(1), first_in_s=1800)
    assert s.run_pending() == []
    s.run_soon("d")
    assert s.run_pending() == ["d"]


def test_background_jobs_run_sequentially_and_are_not_requeued_while_pending():
    mono = Mono()
    s = Scheduler(mono, threaded=True)
    release = threading.Event()
    running, order = [], []

    def slow():
        running.append(1)
        assert len(running) == 1  # never two background jobs at once
        release.wait(5)
        order.append("slow")
        running.pop()

    def quick():
        running.append(1)
        assert len(running) == 1
        order.append("quick")
        running.pop()

    s.every("slow", 10, slow, background=True)
    s.every("quick", 10, quick, background=True)
    assert s.run_pending() == ["slow", "quick"]
    mono.t += 10
    assert s.run_pending() == []  # both still pending: not queued twice
    release.set()
    assert wait_until(s.idle)
    assert order == ["slow", "quick"]
    s.shutdown()


def test_background_job_does_not_block_main_thread():
    mono = Mono()
    s = Scheduler(mono, threaded=True)
    gate = threading.Event()
    s.every("slow", 10, lambda: gate.wait(5), background=True)
    started = time.monotonic()
    s.run_pending()
    assert time.monotonic() - started < 1
    gate.set()
    s.shutdown()


# ---- sleep detection --------------------------------------------------------------------------


def test_sleep_watch_detects_wall_clock_jump():
    wall, mono = Wall(), Mono()
    w = main.SleepWatch(wall, mono)
    assert w.check() is None
    wall.ms += 1000
    mono.t += 1
    assert w.check() is None
    wall.ms += 10 * 60_000  # asleep 10 min: monotonic didn't move
    mono.t += 1
    gap = w.check()
    assert gap == (T0 + 1000, T0 + 1000 + 600_000)
    assert w.overlaps(T0 + 2000, T0 + 3000)
    assert not w.overlaps(T0, T0 + 999)


def test_sleep_watch_ignores_small_drift():
    wall, mono = Wall(), Mono()
    w = main.SleepWatch(wall, mono)
    w.check()
    wall.ms += 25_000
    mono.t += 0
    assert w.check() is None  # under the 30 s threshold


# ---- collector --------------------------------------------------------------------------------


def collector_responses(**extra):
    r = mac_responses(
        **{
            "scutil --get LocalHostName": "Example-Mac\n",
            "sw_vers -productVersion": "26.6.2\n",
            "system_profiler SPAirPortDataType -json": fx("system_profiler/wifi.json"),
            "xcode-select -p": "/Library/Developer/CommandLineTools\n",
            "ifconfig awdl0": fx("ifconfig/awdl0.txt"),
            f"{doctor.FIREWALL} --getglobalstate": fx("firewall/globalstate.txt"),
            "dig +tries=1 +time=2 @192.168.1.1 www.google.com": fx("dig/cached.txt"),
        }
    )
    r.update(extra)
    return r


class PrefixRunner:
    """Exact match first, then prefix match (for random DNS labels and traceroute targets)."""

    def __init__(self, responses):
        self.responses = responses
        self.calls: list[str] = []

    def __call__(self, argv, timeout):
        key = " ".join(argv)
        self.calls.append(key)
        value = self.responses.get(key)
        if value is None:
            if key.startswith("dig +tries=1 +time=2 @192.168.1.1 "):
                value = fx("dig/nxdomain.txt")
            elif key.startswith("traceroute -I -n -q 3 -w 1 -m 20 "):
                value = fx("traceroute/icmp_1.1.1.1_m20.txt")
            elif key.startswith("networkQuality"):
                value = fx("networkquality/run.json")
            else:
                return CommandResult(1, "", f"unexpected: {key}")
        if isinstance(value, CommandResult):
            return value
        return CommandResult(0, value, "")


class Spawner:
    def __init__(self):
        self.started = []

    def __call__(self, argv):
        proc = FakePopen()(argv)
        self.started.append(proc)
        return proc


@pytest.fixture
def setup(tmp_path):
    p = paths.resolve(tmp_path / "data", env={}, home=tmp_path / "home")
    cfg, _ = config.validate({})
    wall, mono = Wall(), Mono()
    runner = PrefixRunner(collector_responses())
    popen, spawner, nudged = FakePopen(), Spawner(), []
    c = main.Collector(
        p,
        cfg,
        runner=runner,
        fetch=FakeFetch(),
        wall=wall,
        monotonic=mono,
        popen=popen,
        spawner=spawner,
        nudge=lambda gw: nudged.append(gw) or True,
        threaded=False,
    )
    yield c, wall, mono, runner, popen, spawner, nudged
    c.stop()


def test_start_discovers_pings_nudges_and_writes_meta(setup):
    c, _wall, _mono, _runner, popen, spawner, nudged = setup
    c.start()
    conn = c.conn
    assert nudged == ["192.168.1.1"]
    assert store.get_meta(conn, "local_hostname") == "Example-Mac"
    assert store.get_meta(conn, "macos_version") == "26.6.2"
    assert store.get_meta(conn, "install_salt")
    targets = store.list_targets(conn, active_only=True)
    assert {t.kind for t in targets} >= {"gateway", "isp_edge", "anchor", "cdn"}
    assert sorted(c.pings.running) == sorted(t.id for t in targets if t.ip)
    assert all(p.argv[0] == "ping" for p in popen.procs)
    assert spawner.started and spawner.started[0].argv[:3] == ["caffeinate", "-i", "-w"]
    assert conn.execute("SELECT COUNT(*) FROM heartbeat").fetchone()[0] == 1


def test_tick_runs_every_probe_and_stores_rows(setup):
    c, wall, mono, _runner, _popen, *_ = setup
    c.start()
    gateway = store.find_target(c.conn, "gateway", "gateway", 4)
    c.tick()  # t = 0: wifi, dns, load, nq check, doctor, prune
    for i in range(1, 25):  # 2 min of 5 s steps
        mono.t += 5
        wall.ms += 5000
        c.pings.running[gateway.id].stream.feed(reply(i), wall.ms)
        c.tick()
    conn = c.conn

    def count(table):
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    assert count("wifi") == 1
    assert count("dns") == 2 * 3  # t = 0, 60, 120
    assert count("local_load") >= 1
    assert count("traceroute") > 0  # first round at 120 s
    assert count("heartbeat") >= 12
    assert count("ping") > 0
    assert count("minute_rollup") > 0  # the rollup hook ran on the worker
    checks = json.loads(store.get_meta(conn, "doctor_json"))
    names = {ch["check"] for ch in checks}
    assert {"xcode_tools", "collector", "gateway", "power", "firewall", "targets"} <= names
    assert all(ch["status"] in doctor.STATUSES for ch in checks)


def test_sleep_gap_records_event_restarts_pings_and_rediscovers(setup):
    c, wall, mono, runner, popen, *_ = setup
    c.start()
    c.tick()
    procs_before = len(popen.procs)
    discover_calls = runner.calls.count("traceroute -I -n -q 3 -w 1 -m 8 1.1.1.1")
    wall.ms += 5 * 60_000  # lid closed 5 min
    mono.t += 1
    c.tick()
    events = store.list_events(c.conn, 0, wall.ms + 1, kinds=["system"])
    assert [e.note for e in events] == ["Gap 5 min (asleep/stopped)"]
    assert len(popen.procs) >= procs_before * 2
    assert runner.calls.count("traceroute -I -n -q 3 -w 1 -m 8 1.1.1.1") == discover_calls + 1


def test_route_change_triggers_rediscovery(setup):
    c, wall, mono, runner, *_ = setup
    c.start()
    c.tick()
    before = runner.calls.count("traceroute -I -n -q 3 -w 1 -m 8 1.1.1.1")
    runner.responses["route -n get default"] = fx("route/default.txt").replace("en0", "en7")
    mono.t += main.LINK_S
    wall.ms += main.LINK_S * 1000
    c.tick()  # link job sees the change and makes discovery due
    c.tick()
    assert runner.calls.count("traceroute -I -n -q 3 -w 1 -m 8 1.1.1.1") == before + 1


def test_battery_releases_caffeinate(setup):
    c, _wall, mono, runner, _popen, spawner, _ = setup
    c.start()
    assert c.caffeinate.running
    runner.responses["pmset -g batt"] = "Now drawing from 'Battery Power'\n"
    mono.t += main.POWER_S
    c.tick()
    assert not c.caffeinate.running
    assert spawner.started[0].terminated


def test_stop_flushes_pings_and_stops_everything(setup):
    c, wall, _mono, _runner, popen, _spawner, _ = setup
    c.start()
    gateway = store.find_target(c.conn, "gateway", "gateway", 4)
    c.pings.running[gateway.id].stream.feed(reply(0), wall.ms)
    db = c.paths.db
    c.stop()
    conn = store.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM ping").fetchone()[0] == 1
    assert all(p.terminated for p in popen.procs)
    assert not c.caffeinate.running
    conn.close()


def test_nq_now_runs_once(setup):
    c, _wall, _mono, _runner, *_ = setup
    c.start()
    c.nq_now()
    row = c.conn.execute("SELECT ok, grade FROM nq").fetchone()
    assert tuple(row) == (1, "C")


def test_probe_failure_never_kills_the_loop(setup):
    c, _wall, _mono, runner, *_ = setup
    c.start()
    runner.responses["system_profiler SPAirPortDataType -json"] = CommandResult(
        -1, "", "", timed_out=True
    )

    def broken(*a, **k):
        raise RuntimeError("bug")

    c.scheduler.jobs["dns"].fn = broken
    c.tick()
    assert c.scheduler.jobs["dns"].failures == 1
    assert c.conn.execute("SELECT error FROM wifi").fetchone()[0] == "timeout"


def test_run_loop_stops_on_event(tmp_path):
    p = paths.resolve(tmp_path / "data", env={}, home=tmp_path / "home")
    cfg, _ = config.validate({})
    c = main.Collector(
        p,
        cfg,
        runner=PrefixRunner(collector_responses()),
        fetch=FakeFetch(),
        popen=FakePopen(),
        spawner=Spawner(),
        nudge=lambda gw: True,
    )
    thread = threading.Thread(target=c.run, kwargs={"tick_s": 0.05})
    thread.start()
    assert wait_until(lambda: c.conn is not None and c.scheduler.jobs, 10)
    c.stop_event.set()
    thread.join(30)
    assert not thread.is_alive()
    conn = store.connect(p.db)
    assert conn.execute("SELECT COUNT(*) FROM heartbeat").fetchone()[0] >= 1
    conn.close()


# ---- doctor -----------------------------------------------------------------------------------


def ctx_for(conn, tmp_path, runner=None, **kw):
    p = paths.resolve(tmp_path / "data", env={}, home=tmp_path / "home")
    cfg, _ = config.validate({})
    return doctor.Context(
        conn=conn,
        paths=p,
        cfg=cfg,
        now_ms=T0,
        runner=runner or PrefixRunner(collector_responses()),
        which=lambda name: f"/usr/bin/{name}",
        **kw,
    )


@pytest.fixture
def conn(tmp_path):
    c = store.connect(tmp_path / "d.db")
    yield c
    c.close()


def by_name(results):
    return {r.check: r for r in results}


def test_doctor_runs_every_check_and_serialises(conn, tmp_path):
    results = doctor.run_checks(ctx_for(conn, tmp_path))
    data = json.loads(doctor.to_json(results))
    assert all(set(d) == {"check", "status", "message", "fix"} for d in data)
    r = by_name(results)
    assert r["xcode_tools"].status == "ok"
    assert r["python"].status == "ok"
    assert r["commands"].status == "ok"
    assert r["collector"].status == "fail"  # no heartbeat in an empty DB
    assert r["power"].status == "ok"
    assert r["awdl"].status == "info"
    assert r["firewall"].status == "ok"
    assert r["lid"].status == "info" and r["private_relay"].status == "info"


def test_doctor_missing_commands(conn, tmp_path):
    ctx = ctx_for(conn, tmp_path)
    ctx.which = lambda name: None if name in ("dig", "networkQuality") else "/bin/x"
    assert by_name(doctor.run_checks(ctx))["commands"].status == "fail"
    ctx.which = lambda name: None if name == "networkQuality" else "/bin/x"
    assert by_name(doctor.run_checks(ctx))["commands"].status == "warn"


def test_doctor_collector_running_from_heartbeat(conn, tmp_path):
    store.insert_heartbeat(conn, T0 - 5000)
    assert by_name(doctor.run_checks(ctx_for(conn, tmp_path)))["collector"].status == "ok"


def _target(conn, kind, name, ip):
    return store.upsert_target(conn, kind, name, 4, None, ip, "ok", T0 - 3_600_000)


def _pings(conn, target_id, lost, n=20):
    rows = [PingRow(T0 - 60_000 + i * 2000, target_id, i, None if lost else 10.0) for i in range(n)]
    store.insert_rows(conn, rows)


def test_doctor_gateway_ok(conn, tmp_path):
    gw = _target(conn, "gateway", "gateway", "192.168.1.1")
    _pings(conn, gw, lost=False)
    r = by_name(doctor.run_checks(ctx_for(conn, tmp_path)))
    assert r["gateway"].status == "ok" and r["local_network"].status == "ok"


def test_doctor_local_network_blocked(conn, tmp_path):
    gw = _target(conn, "gateway", "gateway", "192.168.1.1")
    cf = _target(conn, "anchor", "cloudflare", "1.1.1.1")
    _pings(conn, gw, lost=True)
    _pings(conn, cf, lost=False)
    r = by_name(doctor.run_checks(ctx_for(conn, tmp_path)))
    assert r["gateway"].status == "fail"
    assert r["local_network"].status == "fail" and "Local Network" in r["local_network"].fix


def test_doctor_everything_down_is_not_blamed_on_local_network(conn, tmp_path):
    gw = _target(conn, "gateway", "gateway", "192.168.1.1")
    cf = _target(conn, "anchor", "cloudflare", "1.1.1.1")
    _pings(conn, gw, lost=True)
    _pings(conn, cf, lost=True)
    r = by_name(doctor.run_checks(ctx_for(conn, tmp_path)))
    assert r["gateway"].status == "warn" and "local_network" not in r


def test_doctor_double_nat_vpn_band_and_battery(conn, tmp_path):
    store.set_meta(conn, "double_nat", "1")
    store.insert_rows(conn, [WifiRow(ts=T0, started_ts=T0, ok=1, band="2.4")])
    runner = PrefixRunner(
        collector_responses(**{"pmset -g batt": "Now drawing from 'Battery Power'\n"})
    )
    r = by_name(
        doctor.run_checks(ctx_for(conn, tmp_path, runner=runner, vpn=1, link_medium="wifi"))
    )
    assert r["double_nat"].status == "warn"
    assert r["vpn"].status == "warn"
    assert r["wifi_band"].status == "warn"
    assert r["power"].status == "warn"


def test_doctor_firewall_on(conn, tmp_path):
    runner = PrefixRunner(
        collector_responses(
            **{f"{doctor.FIREWALL} --getglobalstate": "Firewall is enabled. (State = 1)\n"}
        )
    )
    assert (
        by_name(doctor.run_checks(ctx_for(conn, tmp_path, runner=runner)))["firewall"].status
        == "warn"
    )


def test_doctor_nq_data_use_estimate(conn, tmp_path):
    raw = fx("networkquality/run.json")
    store.insert_rows(conn, [NqRow(ts=T0, started_ts=T0, ended_ts=T0, ok=1, raw_json=raw)])
    check = by_name(doctor.run_checks(ctx_for(conn, tmp_path)))["nq_data_use"]
    assert "GB/day" in check.message


def test_doctor_targets_listed(conn, tmp_path):
    _target(conn, "anchor", "cloudflare", "1.1.1.1")
    check = by_name(doctor.run_checks(ctx_for(conn, tmp_path)))["targets"]
    assert "anchor/cloudflare/v4: 1.1.1.1 (ok)" in check.message


def test_doctor_crashing_check_becomes_warn(conn, tmp_path):
    def check_explodes(ctx):
        raise RuntimeError("nope")

    results = doctor.run_checks(ctx_for(conn, tmp_path), checks=[check_explodes])
    assert results == [doctor.Check("explodes", "warn", "Check failed: RuntimeError: nope")]
