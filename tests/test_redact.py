"""Tests for tools/redact.py (plan M0.5.2)."""

import importlib.util
import json
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[1] / "tools" / "redact.py"
_spec = importlib.util.spec_from_file_location("redact", _PATH)
redact = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(redact)


@pytest.fixture
def r():
    return redact.Redactor()


def test_public_ipv4_becomes_documentation_range_consistently(r):
    out = r.redact_text("from 86.12.34.56: icmp_seq=1\nfrom 86.12.34.56\nhop 81.2.3.4")
    lines = out.splitlines()
    assert "86.12.34.56" not in out and "81.2.3.4" not in out
    assert lines[0].startswith("from 203.0.113.1:")
    assert lines[1] == "from 203.0.113.1"
    assert lines[2] == "hop 203.0.113.2"


def test_private_ipv4_keeps_range_and_host_octet(r):
    out = r.redact_text("gateway: 192.168.7.1\nbroadcast 192.168.7.255\nother 10.4.5.9")
    assert "192.168.7." not in out
    gw, bc, other = (line.split()[-1] for line in out.splitlines())
    assert gw.startswith("192.168.") and gw.endswith(".1")
    assert bc.startswith("192.168.") and bc.endswith(".255")
    assert gw.rsplit(".", 1)[0] == bc.rsplit(".", 1)[0]  # same /24 stays the same /24
    assert other.startswith("10.99.") and other.endswith(".9")


def test_cgnat_stays_cgnat(r):
    out = r.redact_text(" 2  100.72.13.4  3.1 ms")
    ip = out.split()[1]
    assert ip.startswith("100.64.") and ip.endswith(".4")
    assert "100.72.13.4" not in out


@pytest.mark.parametrize(
    "text",
    [
        "1.1.1.1",
        "8.8.8.8",
        "127.0.0.1",
        "0.0.0.0",
        "255.255.255.0",
        "224.0.0.251",
        "192.0.2.1",
        "203.0.113.9",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
        "::1",
        "2001:db8::5",
        "ff02::fb",
    ],
)
def test_reference_and_special_addresses_are_kept(r, text):
    assert r.redact_text(f"x {text} y") == f"x {text} y"


def test_version_like_strings_are_not_ips(r):
    assert r.redact_text("ProductVersion: 15.0.1 build 1.2.3.4.5") == (
        "ProductVersion: 15.0.1 build 1.2.3.4.5"
    )


def test_ipv6_global_link_local_and_ula(r):
    out = r.redact_text(
        "inet6 2a00:23c5:1234:5600::abcd prefixlen 64\nfe80::1c2d:3e4f%en0\nfd12::7"
    )
    assert "2a00:23c5" not in out and "1c2d" not in out and "fd12::7" not in out
    assert "inet6 2001:db8::1 prefixlen 64" in out
    assert "fe80::1%en0" in out
    assert "fd00::1" in out


def test_times_are_not_mistaken_for_ipv6(r):
    assert r.redact_text("started 21:58:20 today") == "started 21:58:20 today"


def test_mac_addresses(r):
    out = r.redact_text("? (192.168.1.1) at 3c:a6:2f:1:b:9e on en0\nether 3C:A6:2F:01:0B:9E")
    assert "3c:a6" not in out.lower()
    assert "aa:bb:cc:00:00:01" in out
    assert r.redact_text("ff:ff:ff:ff:ff:ff") == "ff:ff:ff:ff:ff:ff"


def test_local_names_and_terms(r):
    r.terms = ["Smith-Family-WiFi", "SomeISP"]
    out = r.redact_text("Janes-MacBook-Air.local via someisp; joined smith-family-wifi")
    assert out == "example-mac.local via redacted; joined redacted"


def test_netflix_host_loses_isp_label(r):
    out = r.redact_text("https://ipv4-c012-man001-someisp-isp.1.oca.nflxvideo.net/speedtest")
    assert out == "https://ipv4-c001-pop001-isp-example.1.oca.nflxvideo.net/speedtest"


def _system_profiler_sample():
    return {
        "SPAirPortDataType": [
            {
                "spairport_airport_interfaces": [
                    {
                        "_name": "en0",
                        "spairport_wireless_mac_address": "3c:a6:2f:01:0b:9e",
                        "spairport_current_network_information": {
                            "_name": "Smith-Family-WiFi",
                            "spairport_network_channel": "149 (5GHz, 80MHz)",
                            "spairport_signal_noise": "-55 dBm / -92 dBm",
                        },
                        "spairport_airport_other_local_wireless_networks": [
                            {
                                "_name": "NeighbourNet",
                                "spairport_network_channel": "6 (2GHz, 20MHz)",
                            }
                        ],
                    }
                ],
                "spairport_software_information": {"spairport_serial_number": "C02XYZ"},
            }
        ]
    }


def test_system_profiler_json(tmp_path):
    src, dst = tmp_path / "captures", tmp_path / "fixtures"
    (src / "system_profiler").mkdir(parents=True)
    (src / "scutil").mkdir()
    (src / "system_profiler" / "wifi.json").write_text(json.dumps(_system_profiler_sample()))
    (src / "scutil" / "localhostname.txt").write_text("Janes-MacBook-Air\n")
    (src / "notes.txt").write_text("Connected to Smith-Family-WiFi on Janes-MacBook-Air\n")

    written = redact.redact_tree(src, dst, redact.Redactor())

    assert sorted(written) == ["notes.txt", "scutil/localhostname.txt", "system_profiler/wifi.json"]
    data = json.loads((dst / "system_profiler" / "wifi.json").read_text())  # still valid JSON
    iface = data["SPAirPortDataType"][0]["spairport_airport_interfaces"][0]
    assert iface["_name"] == "en0"
    assert iface["spairport_wireless_mac_address"] == "REDACTED"
    current = iface["spairport_current_network_information"]
    assert current["_name"] == "example-network"
    assert current["spairport_network_channel"] == "149 (5GHz, 80MHz)"  # data kept
    assert current["spairport_signal_noise"] == "-55 dBm / -92 dBm"
    neighbour = iface["spairport_airport_other_local_wireless_networks"][0]
    assert neighbour["_name"] == "neighbour-network-1"
    assert (
        data["SPAirPortDataType"][0]["spairport_software_information"]["spairport_serial_number"]
        == "REDACTED"
    )

    everything = "".join(p.read_text() for p in dst.rglob("*") if p.is_file())
    for secret in ["Smith-Family-WiFi", "NeighbourNet", "Janes-MacBook-Air", "C02XYZ", "3c:a6"]:
        assert secret not in everything


def test_cli_refuses_dst_inside_src(tmp_path, capsys):
    (tmp_path / "captures").mkdir()
    with pytest.raises(SystemExit):
        redact.main([str(tmp_path / "captures"), str(tmp_path / "captures" / "out")])
