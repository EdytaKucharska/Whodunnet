"""Tests for M1.4: runner, link, power, load, youtube, netflix and discovery.

A fake runner answers each command with text from the real macOS captures in
tests/fixtures/macos (or synthetic text for cases the capture didn't hit). No network, no macOS.
"""

import json
import logging
import sys
from pathlib import Path

import pytest

from whodunnet import config
from whodunnet.core import store
from whodunnet.probes import discover, link, load, netflix, power, youtube
from whodunnet.probes.runner import CommandResult, run_command

FX = Path(__file__).resolve().parent / "fixtures" / "macos"
T0 = 1_793_000_000_000
DIG = "dig +short +tries=1 +time=2"
NETFLIX_HOST = "ipv4-c001-pop001-isp-example.1.oca.nflxvideo.net"
TOKEN = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
CLIENT_IP = "86.12.34.56"  # synthetic "household IP" that must never leak


def fx(name):
    return (FX / name).read_text()


class FakeRunner:
    def __init__(self, responses):
        self.responses = dict(responses)
        self.calls = []

    def __call__(self, argv, timeout):
        key = " ".join(argv)
        self.calls.append(key)
        value = self.responses.get(key)
        if value is None:
            return CommandResult(1, "", f"unexpected command: {key}")
        if isinstance(value, CommandResult):
            return value
        return CommandResult(0, value, "")


def mac_responses(**overrides):
    r = {
        "route -n get default": fx("route/default.txt"),
        "networksetup -listallhardwareports": fx("networksetup/listallhardwareports.txt"),
        "route -n get 1.1.1.1": fx("route/get_1.1.1.1.txt"),
        "route -n get -inet6 2606:4700:4700::1111": CommandResult(1, "", fx("route/get_inet6.txt")),
        "arp -n 192.168.1.1": fx("arp/gateway.txt"),
        "traceroute -I -n -q 3 -w 1 -m 8 1.1.1.1": fx("traceroute/icmp_1.1.1.1_m8.txt"),
        "scutil --dns": fx("scutil/dns.txt"),
        "ifconfig en0": fx("ifconfig/ifconfig.txt"),
        f"{DIG} A @192.168.1.1 www.bbc.co.uk": fx("dig/short_a_bbc.txt"),
        f"{DIG} A @192.168.1.1 scontent.cdninstagram.com": fx("dig/short_a_instagram.txt"),
        f"{DIG} A @192.168.1.1 redirector.googlevideo.com": "198.51.100.30\n",
        f"{DIG} A @192.168.1.1 {NETFLIX_HOST}": "198.51.100.40\n",
        "netstat -ibn": fx("netstat/ibn.txt"),
        "pmset -g batt": fx("pmset/batt.txt"),
    }
    r.update(overrides)
    return r


def fast_api_body(hosts):
    return json.dumps(
        {
            "client": {"ip": CLIENT_IP, "asn": "12345", "location": {"city": "Somewhere"}},
            "targets": [
                {"name": h, "url": f"https://{h}/speedtest?c=gb", "location": {}} for h in hosts
            ],
        }
    )


class FakeFetch:
    def __init__(self, pages=None, fail=()):
        self.pages = {
            youtube.MAPPING_URL: f"{CLIENT_IP} => iad66s07 (86.12.34.0/23)",
            netflix.FAST_URL: '<html><script src="/app-1a2b3c.js"></script></html>',
            "https://fast.com/app-1a2b3c.js": f'var x={{token:"{TOKEN}",urlCount:5}}',
            netflix.API_URL.format(token=TOKEN): fast_api_body([NETFLIX_HOST] * 5),
        }
        self.pages.update(pages or {})
        self.fail = set(fail)

    def __call__(self, url, timeout):
        if url in self.fail or url not in self.pages:
            raise OSError("network unreachable")
        return self.pages[url]


@pytest.fixture
def conn(tmp_path):
    c = store.connect(tmp_path / "w.db")
    yield c
    c.close()


def cfg(**overrides):
    c, _ = config.validate(overrides)
    return c


def by_key(targets):
    return {(t.kind, t.name, t.af): t for t in targets}


# ---- runner -----------------------------------------------------------------------------------


def test_run_command_success_timeout_and_missing_binary():
    ok = run_command([sys.executable, "-c", "print('hi')"], 10)
    assert ok.ok and ok.stdout.strip() == "hi"
    slow = run_command([sys.executable, "-c", "import time; time.sleep(5)"], 0.3)
    assert slow.timed_out and not slow.ok
    missing = run_command(["whodunnet-no-such-binary"], 5)
    assert missing.rc == 127 and not missing.ok


# ---- link / power / load ----------------------------------------------------------------------


def test_link_from_real_captures():
    state = link.current_link(FakeRunner(mac_responses()))
    assert state == link.LinkState(interface="en0", gateway="192.168.1.1", medium="wifi", vpn=0)


def test_link_detects_vpn_and_wired():
    vpn_route = "   route to: 1.1.1.1\ndestination: 0.0.0.0\n  interface: utun4\n"
    state = link.current_link(FakeRunner(mac_responses(**{"route -n get 1.1.1.1": vpn_route})))
    assert state.vpn == 1
    wired_default = fx("route/default.txt").replace("interface: en0", "interface: en4")
    assert (
        link.current_link(
            FakeRunner(mac_responses(**{"route -n get default": wired_default}))
        ).medium
        == "wired"
    )


def test_link_cache_ttl():
    clock = [0.0]
    runner = FakeRunner(mac_responses())
    cache = link.LinkCache(runner, clock=lambda: clock[0], ttl=10)
    cache.get()
    calls = len(runner.calls)
    clock[0] = 5
    cache.get()
    assert len(runner.calls) == calls  # cached
    clock[0] = 11
    cache.get()
    assert len(runner.calls) > calls


def test_power_state():
    assert power.on_battery(FakeRunner(mac_responses())) is False
    battery = FakeRunner(mac_responses(**{"pmset -g batt": "Now drawing from 'Battery Power'\n"}))
    assert power.on_battery(battery) is True
    assert power.on_battery(FakeRunner({})) is True  # unknown counts as battery


class FakeProc:
    def __init__(self):
        self.alive, self.terminated = True, False

    def poll(self):
        return None if self.alive else 0

    def terminate(self):
        self.terminated, self.alive = True, False

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.alive = False


def test_caffeinate_start_stop():
    spawned = []

    def spawner(argv):
        spawned.append(argv)
        return FakeProc()

    caf = power.Caffeinate(spawner)
    caf.start(4242)
    caf.start(4242)  # already running: no second process
    assert spawned == [["caffeinate", "-i", "-w", "4242"]] and caf.running
    caf.stop()
    assert not caf.running
    caf.stop()  # idempotent


def netstat_text(rx, tx):
    return (
        "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n"
        f"en0 1500 <Link#15> aa:bb:cc:00:00:0d 10 0 {rx} 10 0 {tx} 0\n"
    )


def test_load_meter_deltas():
    meter = load.LoadMeter()
    assert meter.sample("en0", T0, FakeRunner({"netstat -ibn": netstat_text(0, 0)})) is None
    row = meter.sample(
        "en0", T0 + 60_000, FakeRunner({"netstat -ibn": netstat_text(75_000_000, 7_500_000)})
    )
    assert row.rx_mbps == pytest.approx(10.0) and row.tx_mbps == pytest.approx(1.0)
    assert row.minute == (T0 + 30_000) // 60_000 * 60_000
    # counters reset (e.g. reboot of the interface) → no sample, then resumes
    assert (
        meter.sample("en0", T0 + 120_000, FakeRunner({"netstat -ibn": netstat_text(5, 5)})) is None
    )
    assert (
        meter.sample("en0", T0 + 180_000, FakeRunner({"netstat -ibn": netstat_text(5, 5)})).rx_mbps
        == 0
    )
    # interface change → restart
    assert (
        meter.sample("en9", T0 + 240_000, FakeRunner({"netstat -ibn": netstat_text(5, 5)})) is None
    )


def test_load_meter_real_capture_first_sample():
    assert load.LoadMeter().sample("en0", T0, FakeRunner(mac_responses())) is None


# ---- youtube / netflix ------------------------------------------------------------------------


def test_youtube_records_pop_never_client_ip():
    yt = youtube.lookup(FakeFetch())
    assert (yt.host, yt.status, yt.reason) == (
        "redirector.googlevideo.com",
        "approximate",
        "Google POP iad66s07",
    )
    assert CLIENT_IP not in yt.reason
    real = youtube.lookup(FakeFetch({youtube.MAPPING_URL: fx("youtube/report_mapping.txt")}))
    assert real.reason == "Google POP iad66s07"


def test_youtube_failure_falls_back():
    yt = youtube.lookup(FakeFetch(fail={youtube.MAPPING_URL}))
    assert yt.status == "approximate" and "failed" in yt.reason


def test_netflix_success_derives_other_family(caplog):
    caplog.set_level(logging.DEBUG)
    nf = netflix.lookup(FakeFetch())
    assert nf.status == "ok" and nf.host_v4 == NETFLIX_HOST
    assert nf.host_v6 == "ipv6-" + NETFLIX_HOST[len("ipv4-") :]
    assert CLIENT_IP not in caplog.text and TOKEN not in caplog.text


@pytest.mark.parametrize(
    "pages, fail, reason_part",
    [
        ({netflix.FAST_URL: "<html>nothing</html>"}, (), "page format"),
        ({"https://fast.com/app-1a2b3c.js": "no token here"}, (), "token not found"),
        ({}, {netflix.API_URL.format(token=TOKEN)}, "lookup failed"),
        ({netflix.API_URL.format(token=TOKEN): '{"targets": []}'}, (), "no Netflix servers"),
        ({netflix.API_URL.format(token=TOKEN): "not json"}, (), "lookup failed"),
    ],
)
def test_netflix_failures_are_unavailable_and_leak_nothing(pages, fail, reason_part):
    nf = netflix.lookup(FakeFetch(pages, fail))
    assert nf.status == "unavailable" and reason_part in nf.reason
    assert TOKEN not in nf.reason and CLIENT_IP not in nf.reason


def test_netflix_time_budget():
    ticks = iter([0.0, 0.0, 20.0, 20.0, 20.0])
    nf = netflix.lookup(FakeFetch(), budget_s=10, clock=lambda: next(ticks))
    assert nf.status == "unavailable" and "TimeoutError" in nf.reason


# ---- ISP edge rules ---------------------------------------------------------------------------


def hops(*rows):
    return [discover.traceroute.Hop(ttl, ip, list(rtts)) for ttl, ip, rtts in rows]


def test_edge_from_real_capture():
    trace = discover.traceroute.parse(fx("traceroute/icmp_1.1.1.1_m8.txt"))
    assert discover.find_isp_edge(trace.hops, "192.168.1.1", "1.1.1.1") == ("203.0.113.17", False)


def test_edge_double_nat_is_skipped():
    h = hops((1, "192.168.1.1", [1.0]), (2, "10.0.0.1", [1.5]), (3, "203.0.113.5", [6.0]))
    assert discover.find_isp_edge(h, "192.168.1.1", "1.1.1.1") == ("203.0.113.5", True)


def test_edge_private_isp_internal_hop_counts():
    h = hops((1, "192.168.1.1", [1.0]), (2, "10.20.0.1", [7.0]), (3, "203.0.113.5", [8.0]))
    assert discover.find_isp_edge(h, "192.168.1.1", "1.1.1.1") == ("10.20.0.1", False)


def test_edge_cgnat_and_too_far_and_destination():
    cgnat = hops((1, "192.168.1.1", [1.0]), (2, "100.72.0.1", [5.0]))
    assert discover.find_isp_edge(cgnat, "192.168.1.1", "1.1.1.1")[0] == "100.72.0.1"
    far = hops((1, "192.168.1.1", [1.0]), (2, None, []), (3, None, []), (4, "203.0.113.9", [9.0]))
    assert discover.find_isp_edge(far, "192.168.1.1", "1.1.1.1")[0] is None
    dest = hops((1, "192.168.1.1", [1.0]), (2, "1.1.1.1", [9.0]))
    assert discover.find_isp_edge(dest, "192.168.1.1", "1.1.1.1")[0] is None
    assert discover.find_isp_edge(dest, "192.168.9.9", "1.1.1.1") == (None, False)  # no gateway hop


# ---- discovery --------------------------------------------------------------------------------


def run_discovery(conn, runner=None, fetch=None, now=T0, settings=None, **kw):
    d = kw.pop("discovery", None) or discover.Discovery(
        runner or FakeRunner(mac_responses()), fetch or FakeFetch(), **kw
    )
    return d, d.run(conn, settings or cfg(), now)


def test_full_discovery_on_real_captures(conn):
    _, report = run_discovery(conn)
    assert (report.gateway, report.interface, report.medium) == ("192.168.1.1", "en0", "wifi")
    assert report.isp_edge == "203.0.113.17" and report.double_nat is False
    assert report.resolver == "192.168.1.1" and report.ipv6 is False
    t = by_key(report.targets)
    assert t[("gateway", "gateway", 4)].ip == "192.168.1.1"
    assert t[("isp_edge", "isp_edge", 4)].ip == "203.0.113.17"
    assert t[("anchor", "cloudflare", 4)].ip == "1.1.1.1"
    assert t[("anchor", "google", 4)].ip == "8.8.8.8"
    assert (
        t[("anchor", "bbc", 4)].ip == "203.0.113.9"
        and t[("anchor", "bbc", 4)].host == "www.bbc.co.uk"
    )
    assert t[("cdn", "instagram", 4)].ip == "203.0.113.15"
    yt = t[("cdn", "youtube", 4)]
    assert (yt.ip, yt.status) == ("198.51.100.30", "approximate")
    assert store.target_status_history(conn, yt.id)[-1]["reason"] == "Google POP iad66s07"
    nf = t[("cdn", "netflix", 4)]
    assert (nf.ip, nf.host, nf.status) == ("198.51.100.40", NETFLIX_HOST, "ok")
    assert not [k for k in t if k[2] == 6]  # no IPv6 on this connection
    assert report.events == []  # first run: no "changed" events
    assert store.get_meta(conn, "double_nat") == "0"
    assert store.get_meta(conn, "install_salt")  # generated if install hasn't set one
    assert store.last_gateway_mac(conn) is not None and ":" not in store.last_gateway_mac(conn)
    everything = json.dumps([vars(x) for x in report.targets])
    assert CLIENT_IP not in everything


def test_second_identical_run_is_quiet(conn):
    d, _ = run_discovery(conn)
    report = d.run(conn, cfg(), T0 + 1_800_000)
    assert report.events == [] and len(report.targets) == 8


def test_router_change_detected_by_mac(conn):
    d, _ = run_discovery(conn)
    d.runner.responses["arp -n 192.168.1.1"] = (
        "? (192.168.1.1) at 11:22:33:44:55:66 on en0 ifscope [ethernet]"
    )
    report = d.run(conn, cfg(), T0 + 1)
    assert any("Router changed" in e for e in report.events)
    assert [e.kind for e in store.list_events(conn, 0, T0 + 10)] == ["system"]


def test_router_change_detected_by_gateway_ip(conn):
    d, _ = run_discovery(conn)
    new_default = fx("route/default.txt").replace("192.168.1.1", "192.168.0.1")
    d.runner.responses.update(
        {
            "route -n get default": new_default,
            "arp -n 192.168.0.1": fx("arp/gateway.txt").replace("192.168.1.1", "192.168.0.1"),
            "traceroute -I -n -q 3 -w 1 -m 8 1.1.1.1": fx("traceroute/icmp_1.1.1.1_m8.txt").replace(
                "192.168.1.1", "192.168.0.1"
            ),
        }
    )
    report = d.run(conn, cfg(), T0 + 1)
    assert any("Router changed" in e for e in report.events)


def trace_with_edge(edge):
    return f"traceroute to 1.1.1.1\n 1  192.168.1.1  3.0 ms  3.0 ms  3.0 ms\n 2  {edge}  5.0 ms  5.0 ms  5.0 ms\n 3  1.1.1.1  13.0 ms\n"


def test_isp_edge_needs_two_runs_to_change(conn):
    d, _ = run_discovery(conn)
    d.runner.responses["traceroute -I -n -q 3 -w 1 -m 8 1.1.1.1"] = trace_with_edge("198.51.100.99")
    first = d.run(conn, cfg(), T0 + 1)
    assert first.isp_edge == "203.0.113.17" and first.events == []  # one sighting: keep old edge
    second = d.run(conn, cfg(), T0 + 2)
    assert second.isp_edge == "198.51.100.99"
    assert any("ISP edge changed" in e for e in second.events)


def test_isp_edge_flap_does_not_change(conn):
    d, _ = run_discovery(conn)
    trace_key = "traceroute -I -n -q 3 -w 1 -m 8 1.1.1.1"
    original = d.runner.responses[trace_key]
    for i, text in enumerate(
        [trace_with_edge("198.51.100.99"), original, trace_with_edge("198.51.100.99"), original]
    ):
        d.runner.responses[trace_key] = text
        assert d.run(conn, cfg(), T0 + i + 1).isp_edge == "203.0.113.17"


def test_isp_edge_lost_for_two_runs_is_deactivated(conn):
    d, _ = run_discovery(conn)
    d.runner.responses["traceroute -I -n -q 3 -w 1 -m 8 1.1.1.1"] = CommandResult(
        1, "", "timed out"
    )
    assert d.run(conn, cfg(), T0 + 1).isp_edge == "203.0.113.17"
    report = d.run(conn, cfg(), T0 + 2)
    assert report.isp_edge is None
    assert ("isp_edge", "isp_edge", 4) not in by_key(report.targets)


def bbc_answers(*ips):
    return "www.bbc.co.uk.pri.bbc.co.uk.\n" + "".join(f"{ip}\n" for ip in ips)


def test_sticky_ip_keeps_current_while_in_answer_set(conn):
    d, _ = run_discovery(conn)
    d.runner.responses[f"{DIG} A @192.168.1.1 www.bbc.co.uk"] = bbc_answers(
        "203.0.113.12", "203.0.113.9"
    )
    report = d.run(conn, cfg(), T0 + 1)
    assert by_key(report.targets)[("anchor", "bbc", 4)].ip == "203.0.113.9"


def test_sticky_ip_switches_after_two_absent_runs(conn):
    d, _ = run_discovery(conn)
    d.runner.responses[f"{DIG} A @192.168.1.1 www.bbc.co.uk"] = bbc_answers("198.51.100.77")
    assert by_key(d.run(conn, cfg(), T0 + 1).targets)[("anchor", "bbc", 4)].ip == "203.0.113.9"
    bbc = by_key(d.run(conn, cfg(), T0 + 2).targets)[("anchor", "bbc", 4)]
    assert bbc.ip == "198.51.100.77"
    assert bbc.baseline_epoch_ms == T0 + 2  # different /24 → baseline restarts


def test_sticky_ip_waits_while_old_ip_still_answers(conn):
    d, _ = run_discovery(conn, still_answering=lambda target_id: True)
    d.runner.responses[f"{DIG} A @192.168.1.1 www.bbc.co.uk"] = bbc_answers("198.51.100.77")
    for i in range(3):
        assert (
            by_key(d.run(conn, cfg(), T0 + i + 1).targets)[("anchor", "bbc", 4)].ip == "203.0.113.9"
        )


def test_router_dns_unreachable_falls_back_to_system_dns(conn):
    blocked = CommandResult(9, ";; connection timed out; no servers could be reached\n", "")
    responses = mac_responses(
        **{
            f"{DIG} A @192.168.1.1 www.bbc.co.uk": blocked,
            f"{DIG} A @192.168.1.1 scontent.cdninstagram.com": blocked,
        }
    )
    _, report = run_discovery(
        conn, runner=FakeRunner(responses), resolve=lambda host, af: ["198.51.100.5"]
    )
    t = by_key(report.targets)
    assert (t[("anchor", "bbc", 4)].ip, t[("anchor", "bbc", 4)].status) == (
        "198.51.100.5",
        "approximate",
    )
    assert t[("cdn", "instagram", 4)].status == "approximate"


def test_ipv6_targets_when_mac_has_global_ipv6(conn):
    v6_ifconfig = fx("ifconfig/ifconfig.txt").replace(
        "inet 192.168.1.174",
        "inet6 2001:db8:abcd::10 prefixlen 64 autoconf secured\n\tinet 192.168.1.174",
    )
    responses = mac_responses(
        **{
            "ifconfig en0": v6_ifconfig,
            f"{DIG} AAAA @192.168.1.1 www.bbc.co.uk": fx("dig/short_aaaa_bbc.txt"),  # CNAMEs only
            f"{DIG} AAAA @192.168.1.1 scontent.cdninstagram.com": fx(
                "dig/short_aaaa_instagram.txt"
            ),
            f"{DIG} AAAA @192.168.1.1 redirector.googlevideo.com": "",
            f"{DIG} AAAA @192.168.1.1 ipv6-c001-pop001-isp-example.1.oca.nflxvideo.net": "2001:db8:7::1\n",
        }
    )
    # The real capture's ifconfig has no global IPv6; give en0 one for this test.
    fetch = FakeFetch()
    urls = []
    counting = lambda url, timeout: urls.append(url) or fetch(url, timeout)
    _, report = run_discovery(conn, runner=FakeRunner(responses), fetch=counting)
    t = by_key(report.targets)
    assert report.ipv6 is True
    assert urls.count(youtube.MAPPING_URL) == 1 and urls.count(netflix.FAST_URL) == 1
    assert t[("anchor", "cloudflare", 6)].ip == "2606:4700:4700::1111"
    assert ("anchor", "bbc", 6) not in t  # no AAAA → unavailable, not pinged
    assert t[("cdn", "instagram", 6)].ip == "2001:db8::1"
    assert ("cdn", "youtube", 6) not in t  # no AAAA answer → no v6 target at all
    assert t[("cdn", "netflix", 6)].ip == "2001:db8:7::1"


def test_lookups_disabled(conn):
    _, report = run_discovery(
        conn, fetch=FakeFetch(fail=set(FakeFetch().pages)), settings=cfg(discovery_lookups=False)
    )
    t = by_key(report.targets)
    assert t[("cdn", "youtube", 4)].status == "approximate"
    assert ("cdn", "netflix", 4) not in t
    netflix_row = store.find_target(conn, "cdn", "netflix", 4)
    assert netflix_row.status == "unavailable" and netflix_row.active == 0


def test_switching_a_cdn_off_deactivates_it(conn):
    d, first = run_discovery(conn)
    assert ("cdn", "instagram", 4) in by_key(first.targets)
    report = d.run(conn, cfg(cdn_instagram=False), T0 + 1)
    assert ("cdn", "instagram", 4) not in by_key(report.targets)
    assert store.find_target(conn, "cdn", "instagram", 4).active == 0


def test_no_gateway_changes_nothing(conn):
    run_discovery(conn)
    offline = FakeRunner(
        {
            "route -n get default": CommandResult(
                1, "", "route: writing to routing socket: not in table"
            )
        }
    )
    report = discover.Discovery(offline, FakeFetch()).run(conn, cfg(), T0 + 1)
    assert report.gateway is None and "no default gateway" in report.warnings[0]
    assert len(report.targets) == 8  # previous targets left as they were
