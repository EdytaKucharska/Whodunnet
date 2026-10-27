"""Parser tests against real macOS 26 captures in tests/fixtures/macos (plan M1.3).

Files named provisional_* are hand-written stand-ins for cases the real capture didn't hit.
Every parser also gets a malformed input and must return ok=False (or Unparsed), never raise.
"""

from pathlib import Path

import pytest

from whodunnet.probes.parsers import (
    arp,
    dig,
    ifconfig,
    netstat,
    networkquality,
    networksetup,
    ping,
    pmset,
    route,
    scutil,
    system_profiler,
    traceroute,
)

FX = Path(__file__).resolve().parent / "fixtures" / "macos"


def fx(name: str) -> str:
    return (FX / name).read_text()


GARBAGE = ["", "\n", "not the output you were looking for", "{", "[]", "\x00\xff"]


# ---- ping -------------------------------------------------------------------------------------


def parse_all(text):
    return [r for r in (ping.parse_line(line) for line in text.splitlines()) if r is not None]


def test_ping_replies_and_summary():
    results = parse_all(fx("ping/gateway.txt"))
    assert results == [
        ping.Reply(0, 59.423),
        ping.Reply(1, 2.89),
        ping.Reply(2, 4.598),
        ping.Reply(3, 3.542),
        ping.Reply(4, 2.645),
    ]


def test_ping_timeouts():
    assert parse_all(fx("ping/timeouts.txt")) == [ping.Timeout(s) for s in range(4)]


def test_ping_streamed_lines_with_timestamp_prefix():
    # streaming_check.txt prefixes each line with "  0.168s  "; replies are still found
    replies = [r for r in parse_all(fx("ping/streaming_check.txt")) if isinstance(r, ping.Reply)]
    assert [r.seq for r in replies] == list(range(11))


def test_ping_wifi_probe_log_is_all_replies_or_timeouts():
    results = parse_all(fx("wifi_probe_check/with_probe_ping.txt"))
    assert len(results) == 355
    assert sum(isinstance(r, ping.Timeout) for r in results) == 1
    assert not [r for r in results if isinstance(r, ping.Unparsed)]


def test_ping_send_errors_provisional():
    results = parse_all(fx("ping/provisional_sendto_error.txt"))
    assert results == [
        ping.Reply(0, 14.102),
        ping.SendError("No route to host"),
        ping.Timeout(1),
        ping.SendError("Network is down"),
        ping.Timeout(2),
        ping.Reply(3, 13.021),
    ]


def test_ping_ping6_style_reply_and_unparsed():
    line = "16 bytes from 2606:4700:4700::1111: icmp_seq=7 hlim=58 time=12.5 ms"
    assert ping.parse_line(line) == ping.Reply(7, 12.5)
    assert ping.parse_line("ping6: sendmsg: No route to host") == ping.SendError("No route to host")
    assert ping.parse_line("something odd") == ping.Unparsed("something odd")
    assert ping.parse_line("   ") is None


# ---- route ------------------------------------------------------------------------------------


def test_route_default():
    info = route.parse_default(fx("route/default.txt"))
    assert (info.ok, info.gateway, info.interface) == (True, "192.168.1.1", "en0")


def test_route_get_ip_for_vpn_check():
    info = route.parse_route_get(fx("route/get_1.1.1.1.txt"))
    assert info.ok and info.interface == "en0"


def test_route_not_in_table():
    info = route.parse_route_get(fx("route/get_inet6.txt"))
    assert not info.ok and "not in table" in info.error


def test_route_default_without_gateway():
    text = "   route to: default\ndestination: default\n  interface: utun4\n"
    assert route.parse_default(text).ok is False


# ---- networksetup -----------------------------------------------------------------------------


def test_networksetup_ports_and_medium():
    result = networksetup.parse_ports(fx("networksetup/listallhardwareports.txt"))
    assert result.ok
    assert result.ports["en0"] == "Wi-Fi"
    assert networksetup.medium(result.ports["en0"]) == "wifi"
    assert networksetup.medium(result.ports["en7"]) == "wired"  # USB3.0 5K Graphic Docking
    assert networksetup.medium(result.ports["en4"]) == "wired"  # Ethernet Adapter (en4)
    assert networksetup.medium(result.ports["bridge0"]) == "other"  # Thunderbolt Bridge
    assert networksetup.medium(result.ports["en1"]) == "other"  # Thunderbolt 1
    assert networksetup.medium("iPhone USB") == "other"
    assert networksetup.medium(None) == "other"


# ---- system_profiler --------------------------------------------------------------------------


def test_system_profiler_current_network():
    r = system_profiler.parse_wifi(fx("system_profiler/wifi.json"), interface="en0")
    assert r.ok and r.associated
    assert (r.rssi_dbm, r.noise_dbm) == (-55, -96)
    assert (r.channel, r.band, r.width_mhz) == (100, "5", 80)
    assert r.tx_rate_mbps == 576.0
    assert r.phy_mode == "802.11ax"


def test_system_profiler_defaults_to_first_en_interface():
    assert system_profiler.parse_wifi(fx("system_profiler/wifi.json")).channel == 100


def test_system_profiler_not_associated_and_missing_interface():
    awdl = system_profiler.parse_wifi(fx("system_profiler/wifi.json"), interface="awdl0")
    assert awdl.ok and not awdl.associated and awdl.rssi_dbm is None
    missing = system_profiler.parse_wifi(fx("system_profiler/wifi.json"), interface="en9")
    assert not missing.ok


def test_system_profiler_band_mapping_and_partial_fields():
    doc = (
        '{"SPAirPortDataType":[{"spairport_airport_interfaces":[{"_name":"en0",'
        '"spairport_current_network_information":{"spairport_signal_noise":"-71 dBm / -90 dBm",'
        '"spairport_network_channel":"6 (2GHz)","spairport_network_rate":"144 Mbps"}}]}]}'
    )
    r = system_profiler.parse_wifi(doc, "en0")
    assert (r.band, r.channel, r.width_mhz, r.tx_rate_mbps, r.phy_mode) == (
        "2.4",
        6,
        None,
        144.0,
        None,
    )


# ---- scutil -----------------------------------------------------------------------------------


def test_scutil_primary_resolver_ignores_search_domain_and_mdns():
    r = scutil.parse_resolvers(fx("scutil/dns.txt"))
    assert r.ok and r.nameservers == ["192.168.1.1"]


def test_scutil_skips_resolver_with_domain_line():
    text = (
        "DNS configuration\n\nresolver #1\n  domain   : corp.example\n  nameserver[0] : 10.0.0.53\n"
        "\nresolver #2\n  nameserver[0] : 192.168.1.1\n  nameserver[1] : 1.1.1.1\n"
    )
    assert scutil.parse_resolvers(text).nameservers == ["192.168.1.1", "1.1.1.1"]


def test_scutil_hostname():
    assert scutil.parse_hostname(fx("scutil/localhostname.txt")).hostname == "redacted"
    assert not scutil.parse_hostname("").ok


# ---- dig --------------------------------------------------------------------------------------


def test_dig_cached():
    r = dig.parse(fx("dig/cached.txt"))
    assert (r.ok, r.rcode, r.ms, r.server) == (True, "NOERROR", 3.0, "192.168.1.1")


def test_dig_random_name_answered_noerror_by_router():
    r = dig.parse(fx("dig/nxdomain.txt"))
    assert (r.rcode, r.ms) == ("NOERROR", 17.0)


def test_dig_timeout():
    text = ";; connection timed out; no servers could be reached\n"
    assert dig.parse(text) == dig.DigResult(ok=False, error="timeout")
    assert dig.parse_short(text).ok is False


def test_dig_short_skips_cnames():
    assert dig.parse_short(fx("dig/short_a_bbc.txt")).ips == [
        f"203.0.113.{n}" for n in range(9, 15)
    ]
    assert dig.parse_short(fx("dig/short_aaaa_bbc.txt")).ips == []
    assert dig.parse_short(fx("dig/short_aaaa_instagram.txt")).ips == ["2001:db8::1"]


# ---- traceroute -------------------------------------------------------------------------------


def test_traceroute_hops():
    r = traceroute.parse(fx("traceroute/icmp_1.1.1.1_m20.txt"))
    assert r.ok
    assert [h.ttl for h in r.hops] == [1, 2, 3, 4, 5, 6]
    assert r.hops[0].ip == "192.168.1.1" and len(r.hops[0].rtts) == 3
    assert r.hops[1].ip == "203.0.113.17" and r.hops[1].rtts == [6.388, 5.877]  # leading '*'
    assert r.hops[2].ip is None and r.hops[2].rtts == []  # * * *
    assert r.hops[3].rtts == [26.503]
    assert r.hops[-1].ip == "1.1.1.1"


def test_traceroute_annotations_and_multiple_responders():
    text = " 3  10.0.0.1  4.1 ms !H  10.0.0.2  5.2 ms  *\n"
    hop = traceroute.parse(text).hops[0]
    assert hop.ip == "10.0.0.1" and hop.rtts == [4.1, 5.2]


# ---- networkQuality ---------------------------------------------------------------------------


def test_networkquality_run():
    r = networkquality.parse(fx("networkquality/run.json"))
    assert r.ok
    assert r.dl_mbps == pytest.approx(447.131328)
    assert r.ul_mbps == pytest.approx(142.73144)
    assert r.dl_rpm == pytest.approx(1159.9140625)
    assert r.ul_rpm == pytest.approx(513.7443237304688)
    assert r.rpm == r.ul_rpm  # the worse one
    assert r.base_rtt_ms == pytest.approx(12.9376, abs=1e-3)
    assert r.dl_bytes + r.ul_bytes == 573_369_117
    assert r.test_endpoint.endswith(".aaplimg.com")


def test_networkquality_combined_key_and_error():
    assert networkquality.parse('{"responsiveness": 900, "dl_throughput": 1e8}').rpm == 900
    err = networkquality.parse('{"error_code": 1, "error_description": "no network"}')
    assert (err.ok, err.error) == (False, "no network")


def test_networkquality_supports_max_runtime():
    assert networkquality.supports_max_runtime(fx("networkquality/help.txt"))
    assert not networkquality.supports_max_runtime("USAGE: networkQuality [-c]\n    -c: json")


# ---- pmset / arp / ifconfig / netstat ---------------------------------------------------------


def test_pmset():
    assert pmset.parse_batt(fx("pmset/batt.txt")) == pmset.PowerState(ok=True, on_battery=False)
    assert pmset.parse_batt("Now drawing from 'Battery Power'\n").on_battery is True


def test_arp():
    assert arp.parse_mac(fx("arp/gateway.txt")).mac == "aa:bb:cc:00:00:01"
    assert arp.parse_mac("? (10.0.0.1) at 3c:a6:2f:1:b:9e on en0").mac == "3c:a6:2f:01:0b:9e"
    assert not arp.parse_mac("? (192.168.1.1) at (incomplete) on en0 ifscope [ethernet]").ok


def test_ifconfig():
    r = ifconfig.parse(fx("ifconfig/ifconfig.txt"))
    assert r.ok
    assert r.interfaces["en0"].ipv4 == ["192.168.1.174"]
    assert r.interfaces["en0"].active is True
    assert not r.has_global_ipv6("en0")  # this connection has no IPv6
    assert r.is_active("awdl0")
    assert not r.is_active("en3")
    v6 = ifconfig.parse("en0: flags=8863<UP>\n\tinet6 2a00:1450::1 prefixlen 64 autoconf\n")
    assert v6.has_global_ipv6("en0")


def test_netstat():
    r = netstat.parse_ibn(fx("netstat/ibn.txt"))
    assert r.counters["en0"] == netstat.Counters(rx_bytes=5354053487, tx_bytes=2620163474)
    assert r.counters["utun0"] == netstat.Counters(rx_bytes=0, tx_bytes=100)  # no Address column
    assert "gif0" in r.counters  # trailing '*' stripped


# ---- robustness -------------------------------------------------------------------------------


@pytest.mark.parametrize("text", GARBAGE)
def test_every_parser_fails_softly(text):
    assert not route.parse_route_get(text).ok
    assert not route.parse_default(text).ok
    assert not networksetup.parse_ports(text).ok
    assert not system_profiler.parse_wifi(text).ok
    assert not scutil.parse_resolvers(text).ok
    assert not dig.parse(text).ok
    assert dig.parse_short(text).ips == []
    assert not traceroute.parse(text).ok
    assert not networkquality.parse(text).ok
    assert not pmset.parse_batt(text).ok
    assert not arp.parse_mac(text).ok
    assert not ifconfig.parse(text).ok
    assert not netstat.parse_ibn(text).ok
    for line in text.splitlines() or [text]:
        assert ping.parse_line(line) is None or isinstance(ping.parse_line(line), ping.Unparsed)
