"""Periodic probes: wifi, dns, local load, traceroute and networkQuality (spec §4.3–4.6, §4.9)."""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from whodunnet.core import store
from whodunnet.core.models import Target
from whodunnet.probes import dns, load, nq, trace, wifi
from whodunnet.probes.runner import CommandResult

FX = Path(__file__).parent / "fixtures" / "macos"
T0 = 1_700_000_000_000


def fx(name: str) -> str:
    return (FX / name).read_text()


class FakeRunner:
    """argv-prefix -> CommandResult | str | callable(argv, timeout)."""

    def __init__(self, responses):
        self.responses = responses
        self.calls: list[tuple[str, float]] = []

    def __call__(self, argv, timeout):
        key = " ".join(argv)
        self.calls.append((key, timeout))
        for prefix, value in self.responses.items():
            if key.startswith(prefix):
                if callable(value):
                    value = value(argv, timeout)
                if isinstance(value, CommandResult):
                    return value
                return CommandResult(0, value, "")
        return CommandResult(127, "", f"unexpected command: {key}")


class Clock:
    def __init__(self, now=T0, step=0):
        self.now, self.step = now, step

    def __call__(self):
        value = self.now
        self.now += self.step
        return value


@pytest.fixture
def conn(tmp_path):
    return store.connect(tmp_path / "w.db")


# ---- wifi -------------------------------------------------------------------------------------


def test_wifi_reading_from_fixture_records_start_and_end():
    runner = FakeRunner({"system_profiler": fx("system_profiler/wifi.json")})
    row = wifi.read_wifi("en0", "wifi", Clock(step=11_000), runner)
    assert (row.started_ts, row.ts, row.ok) == (T0, T0 + 11_000, 1)
    assert row.rssi_dbm == -55 and row.noise_dbm is not None and row.band == "5"
    assert runner.calls == [("system_profiler SPAirPortDataType -json", wifi.TIMEOUT_S)]


def test_wifi_reads_first_wifi_interface_when_default_route_is_wired():
    runner = FakeRunner({"system_profiler": fx("system_profiler/wifi.json")})
    row = wifi.read_wifi("en7", "wired", Clock(), runner)
    assert row.ok == 1 and row.rssi_dbm == -55


def test_wifi_timeout_and_bad_output():
    timed_out = FakeRunner({"system_profiler": CommandResult(-1, "", "", timed_out=True)})
    assert wifi.read_wifi("en0", "wifi", Clock(), timed_out).error == "timeout"
    garbage = FakeRunner({"system_profiler": "not json"})
    row = wifi.read_wifi("en0", "wifi", Clock(), garbage)
    assert row.ok == 0 and row.error


def test_wifi_not_associated_is_ok_with_nulls():
    data = json.loads(fx("system_profiler/wifi.json"))
    for iface in data["SPAirPortDataType"][0]["spairport_airport_interfaces"]:
        iface.pop("spairport_current_network_information", None)
    runner = FakeRunner({"system_profiler": json.dumps(data)})
    row = wifi.read_wifi("en0", "wifi", Clock(), runner)
    assert row.ok == 1 and row.rssi_dbm is None and row.channel is None


# ---- dns --------------------------------------------------------------------------------------


def test_dns_two_lookups_from_fixtures():
    runner = FakeRunner(
        {
            "dig +tries=1 +time=2 @192.168.1.1 www.google.com": fx("dig/cached.txt"),
            "dig +tries=1 +time=2 @192.168.1.1": fx("dig/nxdomain.txt"),
        }
    )
    rows = dns.probe_dns("192.168.1.1", "wifi", 0, Clock(), runner, random.Random(1))
    assert [(r.query_kind, r.ok, r.rcode, r.ms) for r in rows] == [
        ("cached", 1, "NOERROR", 3.0),
        ("nxdomain", 1, "NOERROR", 17.0),  # the router answers NOERROR for random names
    ]
    nx_name = runner.calls[1][0].split()[-1]
    assert nx_name.endswith(".example.com") and len(nx_name.split(".")[0]) == 12
    assert all(r.resolver == "192.168.1.1" and r.link == "wifi" for r in rows)


def test_dns_lan_resolver_failure_is_lan_unreachable():
    runner = FakeRunner({"dig": ";; connection timed out; no servers could be reached\n"})
    rows = dns.probe_dns("192.168.1.1", "wifi", 0, Clock(), runner)
    assert [(r.ok, r.error) for r in rows] == [(0, "lan_unreachable")] * 2
    rows = dns.probe_dns("fe80::1%en0", "wifi", 0, Clock(), runner)
    assert rows[0].error == "lan_unreachable"


def test_dns_public_resolver_timeout():
    runner = FakeRunner({"dig": ";; connection timed out; no servers could be reached\n"})
    rows = dns.probe_dns("1.1.1.1", "wifi", 0, Clock(), runner)
    assert [(r.ok, r.error) for r in rows] == [(0, "timeout")] * 2


def test_dns_servfail_is_not_healthy():
    text = fx("dig/cached.txt").replace("status: NOERROR", "status: SERVFAIL")
    rows = dns.probe_dns("1.1.1.1", None, 0, Clock(), FakeRunner({"dig": text}))
    assert (rows[0].ok, rows[0].rcode, rows[0].error) == (0, "SERVFAIL", "rcode:SERVFAIL")


def test_dns_nxdomain_rcode_is_healthy():
    text = fx("dig/nxdomain.txt").replace("status: NOERROR", "status: NXDOMAIN")
    rows = dns.probe_dns("1.1.1.1", None, 0, Clock(), FakeRunner({"dig": text}))
    assert rows[1].ok == 1 and rows[1].rcode == "NXDOMAIN"


def test_dns_without_resolver():
    rows = dns.probe_dns(None, "wifi", 1, Clock(), FakeRunner({}))
    assert [(r.query_kind, r.ok, r.error, r.vpn) for r in rows] == [
        ("cached", 0, "no_resolver", 1),
        ("nxdomain", 0, "no_resolver", 1),
    ]


def test_random_label_is_lowercase_alnum():
    label = dns.random_label()
    assert len(label) == 12 and label.isalnum() and label == label.lower()


# ---- local load -------------------------------------------------------------------------------


def test_record_load_upserts_after_second_sample(conn):
    text = fx("netstat/ibn.txt")
    meter = load.LoadMeter()
    runner = FakeRunner({"netstat -ibn": text})
    assert load.record_load(conn, meter, "en0", T0, runner) is None
    # Same counters a minute later = zero throughput, but a row.
    row = load.record_load(conn, meter, "en0", T0 + 60_000, runner)
    assert row is not None and row.rx_mbps == 0
    stored = conn.execute("SELECT minute, rx_mbps FROM local_load").fetchall()
    assert [tuple(r) for r in stored] == [(row.minute, 0.0)]


# ---- traceroute -------------------------------------------------------------------------------


def tgt(id_, kind="anchor", ip="1.1.1.1", af=4, active=1):
    return Target(id_, kind, f"t{id_}", af, None, ip, "ok", active, None, T0, T0)


def test_trace_argv():
    assert trace.trace_argv("1.1.1.1", 4) == [
        "traceroute",
        "-I",
        "-n",
        "-q",
        "3",
        "-w",
        "1",
        "-m",
        "20",
        "1.1.1.1",
    ]
    assert trace.trace_argv("2001:db8::1", 6)[0] == "traceroute6"


def test_trace_round_traces_anchors_and_cdns_only():
    runner = FakeRunner({"traceroute": fx("traceroute/icmp_1.1.1.1_m20.txt")})
    targets = [tgt(1, "gateway"), tgt(2, "isp_edge"), tgt(3), tgt(4, "cdn"), tgt(5, active=0)]
    rows = trace.TraceRound().run(targets, "wifi", 0, Clock(), runner)
    assert [r.target_id for r in rows] == [3, 4]
    hops = json.loads(rows[0].hops_json)
    assert hops[0] == {"ttl": 1, "ip": "192.168.1.1", "rtts": [3.867, 2.473, 3.072]}
    assert rows[0].ok == 1 and rows[0].link == "wifi"


def test_trace_budget_carries_unfinished_targets_to_next_round():
    mono = {"t": 0.0}

    def slow(argv, timeout):
        mono["t"] += 40.0
        return fx("traceroute/icmp_1.1.1.1_m20.txt")

    runner = FakeRunner({"traceroute": slow})
    rnd = trace.TraceRound(budget_s=90, monotonic=lambda: mono["t"])
    targets = [tgt(1), tgt(2), tgt(3), tgt(4)]
    first = rnd.run(targets, None, 0, Clock(), runner)
    # 0, 40, 80 s: three started (10 s left is enough to start one more); #4 never started.
    assert [r.target_id for r in first] == [1, 2, 3]
    assert runner.calls[2][1] == pytest.approx(10.0)  # timeout capped at the remaining budget
    mono["t"] = 1000.0
    second = rnd.run(targets, None, 0, Clock(), runner)
    assert [r.target_id for r in second] == [4, 1, 2]


def test_trace_timeout_keeps_partial_hops():
    partial = CommandResult(-1, fx("traceroute/icmp_1.1.1.1_m20.txt")[:200], "", timed_out=True)
    rows = trace.TraceRound().run([tgt(1)], None, 0, Clock(), FakeRunner({"traceroute": partial}))
    assert rows[0].ok == 0 and rows[0].error == "timeout" and json.loads(rows[0].hops_json)


def test_trace_timeout_never_exceeds_remaining_budget():
    runner = FakeRunner({"traceroute": fx("traceroute/icmp_1.1.1.1_m20.txt")})
    trace.TraceRound(budget_s=30, monotonic=lambda: 0.0).run([tgt(1)], None, 0, Clock(), runner)
    assert runner.calls[0][1] <= 30


# ---- networkQuality ---------------------------------------------------------------------------


UTC = timezone.utc


def at(hhmm: str, extra_s: int = 0) -> int:
    hour, minute = map(int, hhmm.split(":"))
    dt = datetime(2026, 10, 27, hour, minute, tzinfo=UTC) + timedelta(seconds=extra_s)
    return int(dt.timestamp() * 1000)


def utc_local(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, tz=UTC)


SCHEDULE = ["04:00", "19:30", "20:30"]


@pytest.mark.parametrize(
    ("now", "expected"),
    [
        (at("19:30"), "19:30"),
        (at("19:34", 59), "19:30"),
        (at("19:35"), None),
        (at("19:29", 59), None),
        (at("04:02"), "04:00"),
        (at("12:00"), None),
    ],
)
def test_due_slot_window(now, expected):
    slot = nq.due_slot(now, SCHEDULE, utc_local)
    assert (slot.strftime("%H:%M") if slot else None) == expected


@pytest.mark.parametrize(
    ("bloat", "letter"),
    [
        (None, None),
        (0, "A"),
        (29.9, "A"),
        (30, "B"),
        (59, "B"),
        (60, "C"),
        (199, "C"),
        (200, "D"),
        (399, "D"),
        (400, "F"),
        (5000, "F"),
    ],
)
def test_grade_bands(bloat, letter):
    assert nq.grade(bloat) == letter


def nq_runner(battery=False, responses=None):
    runner = FakeRunner(responses or {"networkQuality": fx("networkquality/run.json")})
    return nq.NqRunner(runner, on_battery=lambda r: battery, to_local=utc_local), runner


def test_nq_fires_once_per_slot_and_stores_row(conn):
    probe, runner = nq_runner()
    clock = Clock(at("19:31"), step=1000)
    row = probe.maybe_run(conn, SCHEDULE, "wifi", 0, clock)
    assert row is not None and row.ok == 1
    assert runner.calls[0][0] == "networkQuality -c -s -M 20"
    assert row.dl_mbps == pytest.approx(447.131328)
    assert row.rpm == 514 and row.grade == "C"
    assert row.loaded_ms == pytest.approx(60_000 / 513.7443237304688)
    assert row.bufferbloat_ms == pytest.approx(row.loaded_ms - row.base_rtt_ms)
    assert json.loads(row.raw_json)["dl_throughput"] == 447131328
    clock.now = at("19:33")
    assert probe.maybe_run(conn, SCHEDULE, "wifi", 0, clock) is None
    assert len(runner.calls) == 1
    assert conn.execute("SELECT COUNT(*) FROM nq").fetchone()[0] == 1


def test_nq_slot_not_refired_after_collector_restart(conn):
    probe, _ = nq_runner()
    probe.maybe_run(conn, SCHEDULE, None, 0, Clock(at("20:30", 10)))
    fresh, runner = nq_runner()
    assert fresh.maybe_run(conn, SCHEDULE, None, 0, Clock(at("20:32"))) is None
    assert runner.calls == []


def test_nq_missed_slot_is_not_retried(conn):
    probe, runner = nq_runner()
    # asleep 19:28-19:40: the first tick after wake is outside the window
    assert probe.maybe_run(conn, SCHEDULE, None, 0, Clock(at("19:40"))) is None
    assert probe.maybe_run(conn, SCHEDULE, None, 0, Clock(at("19:55"))) is None
    assert runner.calls == []


def test_nq_next_day_same_slot_fires_again(conn):
    probe, runner = nq_runner()
    probe.maybe_run(conn, SCHEDULE, None, 0, Clock(at("04:00")))
    probe.maybe_run(conn, SCHEDULE, None, 0, Clock(at("04:00") + 86_400_000))
    assert len(runner.calls) == 2


def test_nq_skipped_on_battery_is_recorded(conn):
    probe, runner = nq_runner(battery=True)
    row = probe.maybe_run(conn, SCHEDULE, None, 0, Clock(at("19:30")))
    assert (row.ok, row.error, row.ended_ts) == (0, "skipped:battery", None)
    assert runner.calls == []
    assert conn.execute("SELECT error FROM nq").fetchone()[0] == "skipped:battery"


def test_nq_skipped_after_recent_lag_event(conn):
    store.add_event(conn, "lag", "", "phone", at("19:29"))
    probe, runner = nq_runner()
    row = probe.maybe_run(conn, SCHEDULE, None, 0, Clock(at("19:30", 30)))
    assert row.error == "skipped:recent_lag" and runner.calls == []


def test_nq_lag_event_older_than_two_minutes_does_not_skip(conn):
    store.add_event(conn, "lag", "", "phone", at("19:27"))
    probe, _ = nq_runner()
    assert probe.maybe_run(conn, SCHEDULE, None, 0, Clock(at("19:30"))).ok == 1


def test_nq_unknown_battery_state_counts_as_battery(conn):
    responses = {
        "pmset": "garbage\n",
        "networkQuality": fx("networkquality/run.json"),
    }
    runner = FakeRunner(responses)
    probe = nq.NqRunner(runner, to_local=utc_local)  # real power.on_battery over the fake runner
    row = probe.run(conn, None, 0, Clock(at("12:00")))
    assert row.error == "skipped:battery"
    runner2 = FakeRunner(
        {"pmset": fx("pmset/batt.txt"), "networkQuality": responses["networkQuality"]}
    )
    assert nq.NqRunner(runner2, to_local=utc_local).run(conn, None, 0, Clock()).ok == 1


def test_nq_retries_without_max_runtime_once_and_remembers(conn):
    def nq_cmd(argv, timeout):
        if "-M" in argv:
            return CommandResult(64, "", "networkQuality: illegal option -- M\nUSAGE: ...")
        return fx("networkquality/run.json")

    probe, runner = nq_runner(responses={"networkQuality": nq_cmd})
    assert probe.run(conn, None, 0, Clock()).ok == 1
    assert probe.run(conn, None, 0, Clock()).ok == 1
    assert [c for c, _ in runner.calls] == [
        "networkQuality -c -s -M 20",
        "networkQuality -c -s",
        "networkQuality -c -s",
    ]


def test_nq_other_failure_does_not_drop_max_runtime(conn):
    probe, _ = nq_runner(responses={"networkQuality": CommandResult(1, "{}", "")})
    row = probe.run(conn, None, 0, Clock())
    assert row.ok == 0 and probe.use_max_runtime


def test_nq_timeout_and_error_json(conn):
    probe, _ = nq_runner(responses={"networkQuality": CommandResult(-1, "", "", timed_out=True)})
    assert probe.run(conn, None, 0, Clock()).error == "timeout"
    err = json.dumps(
        {"error_code": -1009, "error_description": "The Internet connection appears to be offline."}
    )
    probe, _ = nq_runner(responses={"networkQuality": CommandResult(1, err, "")})
    row = probe.run(conn, None, 0, Clock())
    assert row.ok == 0 and "offline" in row.error


def test_nq_run_now_stores_outside_schedule(conn):
    probe, _ = nq_runner()
    row = probe.run_now(conn, "wired", 0, Clock(at("13:13")))
    assert row.ok == 1
    assert conn.execute("SELECT link FROM nq").fetchone()[0] == "wired"
