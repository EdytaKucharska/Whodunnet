"""Evidence report model and HTML (plan M4.1, spec §8)."""

from __future__ import annotations

import json
import re
import time

import pytest

from tests import scenarios as sc
from whodunnet import config
from whodunnet.core import report, store
from whodunnet.core.models import TracerouteRow

CFG, _ = config.validate({})
SECTION_TITLES = [
    "1. Summary",
    "2. What the household experienced",
    "3. Evening vs daytime",
    "4. Where it breaks",
    "5. Speed &amp; responsiveness",
    "6. Already tried",
    "7. Wired vs WiFi",
    "8. Method &amp; limitations",
    "9. Your rights (UK)",
    "10. Appendix",
]
PRIVATE_IP = re.compile(
    r"\b(10|127)\.\d+\.\d+\.\d+|\b192\.168\.\d+\.\d+|\b172\.(1[6-9]|2\d|3[01])\."
)


@pytest.fixture(autouse=True)
def london(monkeypatch):
    monkeypatch.setenv("TZ", "Europe/London")
    time.tzset()
    yield
    monkeypatch.delenv("TZ")
    time.tzset()


@pytest.fixture
def conn():
    c = store.connect(":memory:")
    yield c
    c.close()


def hop(ttl, ip, *rtts):
    return {"ttl": ttl, "ip": ip, "rtts": list(rtts)}


# ---- hop labelling -------------------------------------------------------------------------------


def test_hops_with_a_known_edge_are_labelled_by_position():
    hops = [
        hop(1, "192.168.1.1", 3.0),
        hop(2, "203.0.113.17", 6.0),  # ISP edge
        hop(3, "10.20.0.1", 7.0),  # private inside the ISP
        hop(4, "203.0.7.9", 8.0),  # same /16 as the edge
        hop(5, None),
        hop(6, "198.51.100.5", 20.0, 22.0),
    ]
    out = report.label_hops(hops, "192.168.1.1", "203.0.113.17", False)
    assert [h["zone"] for h in out] == ["home", "isp", "isp", "isp", "isp", "beyond"]
    assert [h["shown"] for h in out] == [
        "home router",
        "203.0.113.17",
        "private address",
        "203.0.7.9",
        "no reply",
        "198.51.100.5",
    ]
    assert out[5]["rtt_ms"] == 21.0


def test_hops_before_the_edge_are_home_even_if_public():
    hops = [hop(1, "192.168.1.1", 3.0), hop(2, "198.51.100.1", 4.0), hop(3, "203.0.113.17", 6.0)]
    out = report.label_hops(hops, "192.168.1.1", "203.0.113.17", False)
    assert [(h["zone"], h["shown"]) for h in out] == [
        ("home", "home router"),
        ("home", "home device"),
        ("isp", "203.0.113.17"),
    ]


def test_hops_without_an_edge_use_the_gateway_and_double_nat():
    hops = [
        hop(1, "192.168.1.1", 3.0),
        hop(2, "192.168.0.1", 4.0),  # second home router (double NAT)
        hop(3, "100.64.0.1", 6.0),  # CGNAT: ISP, and never printed
        hop(4, "198.51.100.5", 20.0),
    ]
    out = report.label_hops(hops, "192.168.1.1", None, True)
    assert [h["zone"] for h in out] == ["home", "home", "isp", "beyond"]
    assert [h["shown"] for h in out] == [
        "home router",
        "home device",
        "private address",
        "198.51.100.5",
    ]
    single = report.label_hops(hops, "192.168.1.1", None, False)
    assert [h["zone"] for h in single] == ["home", "isp", "isp", "beyond"]


def test_masking_covers_private_cgnat_and_link_local_but_not_public():
    for ip in ("10.0.0.1", "172.20.1.1", "192.168.1.1", "100.64.3.4", "169.254.1.1", "fd00::1"):
        assert report.is_masked(ip), ip
    for ip in ("203.0.113.17", "1.1.1.1", "2606:4700:4700::1111", None, "not-an-ip"):
        assert not report.is_masked(ip), ip


def test_median_trace_by_destination_rtt():
    traces = [
        (3, [hop(1, "192.168.1.1", 3.0), hop(2, "1.1.1.1", 30.0)]),
        (1, [hop(1, "192.168.1.1", 3.0), hop(2, "1.1.1.1", 10.0)]),
        (2, [hop(1, "192.168.1.1", 3.0), hop(2, None)]),  # destination silent → last answer 3 ms
        (4, [hop(1, "192.168.1.1", 3.0), hop(2, "1.1.1.1", 20.0)]),
        (5, [hop(1, None)]),  # nothing answered: ignored
    ]
    ts, _hops = report.pick_median_trace(traces)
    assert ts == 1  # RTTs 3, 10, 20, 30 → lower median 10
    assert report.pick_median_trace([]) is None


# ---- full report ----------------------------------------------------------------------------------


def add_trace(s, ts, target, last_rtt):
    hops = [
        hop(1, "192.168.1.1", 3.0),
        hop(2, "203.0.113.17", 6.0),
        hop(3, "10.1.1.1", 7.0),
        hop(4, "198.51.100.30", last_rtt),
    ]
    store.insert_rows(s.conn, [TracerouteRow(ts, target.id, 1, None, json.dumps(hops), "wifi", 0)])


@pytest.fixture
def rich(conn):
    """8 days of evening congestion beyond the ISP, with every kind of extra data."""
    s = sc.new(conn, days=8)
    s.bad_when(sc.is_evening, sc.is_kind("anchor", "cdn"))
    s.add_wifi_readings()
    bbc, yt = s.target("bbc"), s.target("youtube")
    for d in range(8):
        day = s.start + d * sc.DAY
        s.add_nq(day + 12 * sc.HOUR, 20.0)
        s.add_nq(day + 21 * sc.HOUR + 30 * sc.MIN, 250.0)
        s.add_lag(day + 20 * sc.HOUR + 15 * sc.MIN)
        for i, rtt in enumerate((140.0, 150.0, 160.0)):
            add_trace(s, day + 20 * sc.HOUR + i * 20 * sc.MIN, bbc, rtt)
        add_trace(s, day + 12 * sc.HOUR, bbc, 18.0)
        add_trace(s, day + 21 * sc.HOUR, yt, 999.0)  # not the worst target: ignored
    s.add_event("router_change", s.start + 3 * sc.DAY + 12 * sc.HOUR, "new router")
    s.add_event("isp_contact", s.start + 7 * sc.DAY + 9 * sc.HOUR, "called support")
    return s.build()


def test_report_model_for_a_rich_scenario(conn, rich):
    m = report.build(conn, CFG, rich.start, rich.end)
    assert m["summary"]["verdict"] == "isp_upstream"
    assert m["from"] == "2026-10-01" and m["to"] == "2026-10-08"
    assert len(m["experienced"]) == 8
    assert all(x["status"] == "network_bad" for x in m["experienced"])
    up = next(r for r in m["layers"] if r["layer"] == "isp_upstream")
    assert up["evening_rate"] > 0.9 and up["daytime_rate"] == 0
    where = m["where"]
    assert where["worst"]["kind"] in ("anchor", "cdn") and where["worst"]["evening_rate"] > 0.9
    assert where["worst"]["name"] == "bbc"  # ties go to kind then name
    assert len(m["heatmap"]["days"]) == 8
    assert {s["slot"] for s in m["speed"]["slots"]} == {"12:00", "21:30"}
    assert m["speed"]["grades"] == {"A": 8, "D": 8}
    assert [e["kind"] for e in m["tried"]] == ["router_change", "isp_contact"]
    assert m["tried"][0]["compared"] and m["tried"][0]["rates"]["isp_upstream"]["after"] > 0.9
    assert not m["tried"][1]["compared"]  # too few evenings after it
    assert not m["wired"]["available"]
    assert len(m["appendix"]) == 8 and m["appendix"][0]["lag_moments"] == 1
    assert m["appendix"][0]["dl_mbps"] == 450.0
    assert m["appendix"][0]["grade"] == "D"  # A and D runs: the worse middle value
    assert m["rights"]["checked"] == report.RIGHTS_TEXT_CHECKED
    json.dumps(m)  # the model is JSON-able


def test_traceroute_selection_uses_the_worst_target(conn, rich):
    m = report.build(conn, CFG, rich.start, rich.end)
    where = m["where"]
    assert where["worst"]["name"] == "bbc"  # all far targets tie at 100%: kind, then name
    assert where["traces"] == 32  # bbc only; youtube's traces are ignored
    ev, dt = where["evening_trace"], where["daytime_trace"]
    assert ev["dest_rtt_ms"] == 150.0 and ev["candidates"] == 24
    assert dt["dest_rtt_ms"] == 18.0 and dt["candidates"] == 8
    assert [h["zone"] for h in ev["hops"]] == ["home", "isp", "isp", "beyond"]
    assert [h["shown"] for h in ev["hops"]][:3] == [
        "home router",
        "203.0.113.17",
        "private address",
    ]


def test_rendered_report_has_every_section_and_no_private_data(conn, rich):
    out = report.render(report.build(conn, CFG, rich.start, rich.end))
    for title in SECTION_TITLES:
        assert f"<h2>{title}" in out, title
    assert "Beyond your ISP&#x27;s network" in out
    assert "home router" in out and "203.0.113.17" in out
    assert not PRIVATE_IP.search(out), PRIVATE_IP.search(out)
    assert "<script" not in out and "http://" not in out and "https://" not in out
    assert report.RIGHTS_TEXT_CHECKED in out
    assert "@page { size: A4" in out


def test_report_renders_with_sparse_data(conn):
    s = sc.new(conn, days=1).build()
    m = report.build(conn, CFG, s.start, s.end)
    out = report.render(m)
    assert m["summary"]["verdict"] == "insufficient_data"
    for title in SECTION_TITLES:
        assert f"<h2>{title}" in out, title
    assert "No lag moments were marked" in out
    assert "No speed tests ran" in out
    assert "No traceroutes to this target" in out
    assert "No changes" in out
    assert "No evenings were measured on a wired adapter" in out


def test_report_renders_with_no_data_at_all(conn):
    start = sc.local_ms(2026, 10, 1)
    out = report.render(report.build(conn, CFG, start, start + 2 * sc.DAY))
    for title in SECTION_TITLES:
        assert f"<h2>{title}" in out, title
    assert "No reference or video targets were measured" in out


def test_report_is_deterministic_and_escapes_notes(conn):
    s = sc.new(conn, days=4)
    s.add_event("other", s.start + sc.DAY, "<b>router</b> & co")
    s.build()
    a = report.render(report.build(conn, CFG, s.start, s.end))
    b = report.render(report.build(conn, CFG, s.start, s.end))
    assert a == b
    assert "&lt;b&gt;router&lt;/b&gt; &amp; co" in a and "<b>router</b>" not in a


def test_wired_section_when_wired_evenings_exist(conn):
    s = sc.SCENARIOS["wifi_bad_plus_wired_evening"](conn)
    m = report.build(conn, CFG, s.start, s.end)
    assert m["wired"]["available"] and m["wired"]["evenings"]["wired"] == 1
    assert m["wired"]["check"] == "confirms_wifi"
    assert m["wired"]["bad_rate"]["wired"] < m["wired"]["bad_rate"]["wifi"]
    assert "the WiFi is the problem" in report.render(m)
