"""Findings, verdict selection and confidence (spec §6.5–6.8, plan M2.5)."""

from __future__ import annotations

import time

import pytest

from tests import scenarios as sc
from whodunnet import cli, config
from whodunnet.core import analysis, store
from whodunnet.core import thresholds as th

CFG, _ = config.validate({})


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


def analyse(conn, s):
    return analysis.analyse(conn, CFG, s.start, s.end)


# ---- every §11 scenario ------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(sc.SCENARIOS))
def test_scenario_verdicts(conn, name):
    s = sc.SCENARIOS[name](conn)
    v = analyse(conn, s)
    e = s.expected
    if "verdict" in e:
        assert v["verdict"] == e["verdict"]
    if "not_verdict" in e:
        assert v["verdict"] != e["not_verdict"]
    if "qualifier" in e:
        assert v["qualifier"] == e["qualifier"]
    if "confidence" in e:
        assert v["confidence"] == e["confidence"]
    if "address_family" in e:
        assert v["address_family"] == e["address_family"]
    if "not_measurable" in e:
        assert v["not_measurable"] == e["not_measurable"]
    assert v["summary"] and v["next_steps"]
    assert set(v) == {
        "verdict",
        "qualifier",
        "confidence",
        "address_family",
        "summary",
        "evidence",
        "secondary",
        "lag",
        "not_measurable",
        "next_steps",
        "coverage",
        "missing",
    }


def test_deterministic(conn):
    s = sc.wifi_bad_evenings(conn)
    assert analyse(conn, s) == analyse(conn, s)


# ---- §6.8 boundaries -----------------------------------------------------------------------------


def evening_minutes(s, n_minutes, days=None):
    """The first n evening minutes (from 19:00) of each listed day index."""
    days = range(s.days) if days is None else days
    minutes = set()
    for d in days:
        first = sc.local_ms(2026, 10, 1 + d, 19, 0)
        minutes.update(first + i * sc.MIN for i in range(n_minutes))
    return minutes


def upstream_case(conn, days, bad_minutes_per_evening, bad_days=None, daytime_minutes=0):
    s = sc.new(conn, days=days)
    bad = evening_minutes(s, bad_minutes_per_evening, bad_days)
    for d in range(days):
        first = sc.local_ms(2026, 10, 1 + d, 10, 0)
        bad.update(first + i * sc.MIN for i in range(daytime_minutes))
    s.bad_when(lambda m: m in bad, sc.is_kind("anchor", "cdn"))
    return analyse(conn, s.build())


def test_exactly_5_percent_shows_the_layer(conn):
    v = upstream_case(conn, 4, 12)  # 12 of 240 evening minutes = 5%
    assert (v["verdict"], v["qualifier"]) == ("isp_upstream", "evening")


def test_just_under_5_percent_does_not(conn):
    v = upstream_case(conn, 4, 11)
    assert v["verdict"] == "no_problem_found"


def test_exactly_3_evenings_is_an_evening_problem(conn):
    v = upstream_case(conn, 5, 30, bad_days=[1, 2, 3])
    assert (v["verdict"], v["qualifier"]) == ("isp_upstream", "evening")


def test_two_evenings_is_not(conn):
    v = upstream_case(conn, 5, 30, bad_days=[1, 2])
    assert v["verdict"] == "no_problem_found"


def test_exactly_2x_daytime_is_still_evening(conn):
    # evening 24/240 = 10%; daytime 18/360 = 5% → ratio exactly 2
    v = upstream_case(conn, 4, 24, daytime_minutes=18)
    assert (v["verdict"], v["qualifier"]) == ("isp_upstream", "evening")


def test_under_2x_daytime_is_all_day(conn):
    v = upstream_case(conn, 4, 24, daytime_minutes=19)  # 5.3% daytime → ratio < 2, shown daytime
    assert (v["verdict"], v["qualifier"]) == ("isp_upstream", "all_day")


def test_exactly_70_percent_of_evenings_is_high(conn):
    v = upstream_case(conn, 10, 30, bad_days=range(7))  # 7 of 10
    assert v["confidence"] == "high"


def test_60_percent_of_evenings_is_medium(conn):
    v = upstream_case(conn, 10, 30, bad_days=range(6))
    assert v["confidence"] == "medium"


def test_no_daytime_waives_2x_and_caps_medium(conn):
    s = sc.new(conn, days=8)
    s.gaps = [
        (s.start + d * sc.DAY + 7 * sc.HOUR, s.start + d * sc.DAY + 17 * sc.HOUR) for d in range(8)
    ]  # asleep 07:00–17:00 every day
    s.bad_when(sc.is_evening, sc.is_kind("anchor", "cdn"))
    v = analyse(conn, s.build())
    assert (v["verdict"], v["confidence"]) == ("isp_upstream", "medium")
    assert "No daytime data to compare" in v["missing"]


# ---- adjustments and other findings ------------------------------------------------------------


def test_bufferbloat_caps_isp_verdicts_and_adds_missing_line(conn):
    s = sc.new(conn, days=8)
    s.bad_when(sc.is_evening, sc.is_kind("anchor", "cdn"))
    for i in range(8):
        s.add_nq(s.start + i * sc.DAY + 12 * sc.HOUR, bufferbloat_ms=300.0)
    v = analyse(conn, s.build())
    assert (v["verdict"], v["confidence"]) == ("isp_upstream", "medium")
    assert any(m.startswith("Pause big downloads") for m in v["missing"])
    assert any(x["finding"] == "bufferbloat" for x in v["secondary"])


def test_bufferbloat_wired_label(conn):
    s = sc.new(conn, days=4)
    for i in range(6):
        s.add_nq(s.start + i * 12 * sc.HOUR + 3 * sc.HOUR, bufferbloat_ms=500.0, link="wired")
    v = analyse(conn, s.build())
    assert v["verdict"] == "bufferbloat" and "(home router or ISP shaper)" in v["summary"]


def test_lag_confirming_the_layer_raises_confidence(conn):
    s = sc.new(conn, days=4)  # 4 evenings → medium on its own
    s.bad_when(sc.is_evening, sc.is_kind("anchor", "cdn"))
    for d in range(4):
        for k in range(2):
            s.add_lag(sc.local_ms(2026, 10, 1 + d, 20, 10 * k))
    v = analyse(conn, s.build())
    assert (v["verdict"], v["confidence"]) == ("isp_upstream", "high")
    assert v["lag"]["lag_layer"] == "isp_upstream"


def test_lag_pointing_to_device_lowers_confidence(conn):
    s = sc.new(conn, days=8)
    s.bad_when(sc.is_evening, sc.is_kind("anchor", "cdn"))
    for d in range(6):
        s.add_lag(sc.local_ms(2026, 10, 1 + d, 12, 0))  # middays: network fine
    v = analyse(conn, s.build())
    assert (v["verdict"], v["confidence"]) == ("isp_upstream", "medium")
    assert any(x["finding"] == "device_or_app" for x in v["secondary"])


def test_wifi_both_bad_lowers_confidence(conn):
    s = sc.new(conn, days=8)
    wired_day = 7
    s.link = lambda m: "wired" if (m - s.start) // sc.DAY == wired_day else "wifi"
    s.bad_when(sc.is_evening, sc.is_kind("gateway", "anchor", "cdn"))
    v = analyse(conn, s.build())
    # 7 wifi evenings shown, wired evening bad too → high − 1
    assert (v["verdict"], v["confidence"]) == ("wifi", "medium")


def test_wifi_without_wired_evening_asks_for_one(conn):
    s = sc.wifi_bad_evenings(conn)
    v = analyse(conn, s)
    assert "One evening on a wired adapter would confirm the WiFi verdict" in v["missing"]


def test_lag_moments_with_no_data_are_unknown(conn):
    s = sc.new(conn, days=4)
    s.gaps = [(sc.local_ms(2026, 10, 2, 20, 0), sc.local_ms(2026, 10, 2, 21, 0))]
    s.add_lag(sc.local_ms(2026, 10, 2, 20, 30))
    v = analyse(conn, s.build())
    assert v["lag"]["unknown"] == 1
    assert "1 lag moments fell in periods with no data" in v["missing"]


def test_insufficient_data_missing_lines(conn):
    s = sc.insufficient_data(conn)
    v = analyse(conn, s)
    assert v["missing"][0] == "Need 3 more covered evenings"
    assert v["next_steps"] == ['Follow the "missing" list.']


def test_before_after_event_evidence(conn):
    s = sc.new(conn, days=8)
    change = sc.local_ms(2026, 10, 5, 12, 0)
    s.bad_when(lambda m: sc.is_evening(m) and m < change, sc.is_kind("anchor", "cdn"))
    s.add_event("router_change", change, "new router")
    v = analyse(conn, s.build())
    (ba,) = [e for e in v["evidence"] if e["metric"] == "before_after"]
    assert ba["rates"]["isp_upstream"]["before"] > 0.9
    assert ba["rates"]["isp_upstream"]["after"] == 0


def test_approximate_cdn_is_missing_line(conn):
    s = sc.new(conn, days=4)
    s.set_status("youtube", "approximate", "iad66s07")
    v = analyse(conn, s.build())
    assert "Couldn't find your Netflix/YouTube server" in v["missing"]


def test_shift_and_cap():
    assert analysis.shift("high", +1) == "high" and analysis.shift("low", -1) == "low"
    assert analysis.shift("medium", +1) == "high"
    assert analysis.cap("high", "medium") == "medium" and analysis.cap("low", "medium") == "low"
    assert th.PROBLEM_MIN_WINDOWS == 3 and th.LAYER_SHOWN_RATE == 0.05


# ---- status ------------------------------------------------------------------------------------


def test_status_prints_verdict(conn):
    s = sc.wifi_bad_evenings(conn)
    lines = cli.status_lines(conn, s.end, CFG)
    text = "\n".join(lines)
    assert "Verdict: wifi (evening) — confidence high" in text
    assert "→ Move closer to the router or use 5 GHz." in text
    assert "covered evenings" in text
