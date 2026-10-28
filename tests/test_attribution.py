"""Bad minutes (spec §6.3) and layer attribution (spec §6.4), plan M2.4."""

from __future__ import annotations

import time

import pytest

from tests import scenarios as sc
from whodunnet import config
from whodunnet.core import attribution as at
from whodunnet.core import baseline, coverage, store
from whodunnet.core.baseline import Baseline
from whodunnet.core.models import RollupRow

CFG, _ = config.validate({})
BASE = Baseline(p50_ms=10.0, jitter_ms=2.0, hours=8, edge_lost_median=0.0)


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


def row(lost=0, p95=12.0, jitter=2.0):
    return RollupRow(0, 1, 30, lost, 10.0, p95, p95, jitter, "wifi", 0)


# ---- §6.3 bad minute ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("r", "kind", "bad"),
    [
        (row(lost=1), "anchor", False),
        (row(lost=2), "anchor", True),
        (row(p95=50.0), "anchor", False),  # exactly baseline + 40
        (row(p95=50.1), "anchor", True),
        (row(jitter=17.0), "anchor", False),  # exactly baseline jitter + 15
        (row(jitter=17.1), "anchor", True),
        (row(lost=1), "isp_edge", False),
        (row(lost=2), "isp_edge", True),  # median 0 + 2
    ],
)
def test_is_bad_boundaries(r, kind, bad):
    assert at.is_bad(r, BASE, kind) is bad


def test_isp_edge_loss_uses_its_own_median():
    lossy_edge = Baseline(6.0, 1.0, 8, edge_lost_median=3.0)
    assert not at.is_bad(row(lost=4), lossy_edge, "isp_edge")
    assert at.is_bad(row(lost=5), lossy_edge, "isp_edge")
    assert at.is_bad(row(lost=2), lossy_edge, "anchor")  # the edge rule is the edge's only


def test_majority_definitions():
    assert not at.majority_bad([1, 2, 3], {1})  # exactly 1 bad: never a majority
    assert not at.majority_bad([1, 2, 3, 4], {1, 2})  # half is not more than half
    assert at.majority_bad([1, 2, 3, 4], {1, 2, 3})
    assert at.majority_bad([1, 2], {1, 2})
    assert not at.majority_bad([1], {1})  # needs ≥ 2 bad
    assert not at.majority_bad([], set()) and not at.majority_ok([], set())
    assert at.majority_ok([1, 2, 3], {1})


# ---- §6.4 table, one minute at a time ---------------------------------------------------------

EVAL = sc.local_ms(2026, 10, 2, 20, 0)  # day 2, 20:00 — baselines come from day 1–2 quiet hours


def run(conn, bad_names=(), link="wired_if_set", setup=None, minutes=(EVAL,), v6=False):
    """Two clean days; the named targets are bad in `minutes`. Returns the result at EVAL."""
    s = sc.new(conn, days=2, v6=v6)
    window = set(minutes)
    s.bad_when(lambda m: m in window, lambda t: t.name in bad_names)
    if link == "wired":
        s.link = lambda m: "wired"
    if setup:
        setup(s)
    s.build()
    cov = coverage.load(conn, s.start, s.end)
    bases = baseline.compute(cov, CFG, s.start, s.end)
    results = at.attribute(
        cov, bases, EVAL - 10 * sc.MIN, EVAL + sc.MIN, at.read_wifi(conn, s.start, s.end)
    )
    return s, {af: {r.minute: r for r in rs} for af, rs in results.items()}


def result_at(results, af=4, minute=EVAL):
    return results[af][minute]


ALL_DOWN = ("cloudflare", "google", "bbc", "youtube", "instagram", "netflix")
ANCHORS = ("cloudflare", "google", "bbc")


def test_row1_wifi(conn):
    _, res = run(conn, ("gateway", *ALL_DOWN))
    assert result_at(res).layer == "wifi"


def test_row1_home_network_on_wired(conn):
    _, res = run(conn, ("gateway", *ALL_DOWN), link="wired")
    assert result_at(res).layer == "home_network"


def test_row2_router_icmp_slow(conn):
    _, res = run(conn, ("gateway",))
    r = result_at(res)
    assert (r.layer, r.tags) == ("ok", ["router_icmp_slow"])


def test_row3_isp_network(conn):
    _, res = run(conn, ("isp_edge", *ALL_DOWN))
    assert result_at(res).layer == "isp_network"


def test_row4_isp_upstream(conn):
    _, res = run(conn, ALL_DOWN)
    r = result_at(res)
    assert (r.layer, r.tags) == ("isp_upstream", [])


def test_row4_edge_unknown_tag(conn):
    def no_edge(s):
        s.set_status("isp_edge", "unavailable", "not found")

    _, res = run(conn, ALL_DOWN, setup=no_edge)
    r = result_at(res)
    assert (r.layer, r.tags, r.edge_unknown) == ("isp_upstream", ["edge_unknown"], True)


def test_row5_general_internet_only(conn):
    _, res = run(conn, ANCHORS)
    r = result_at(res)
    assert (r.layer, r.tags) == ("isp_upstream", ["general_internet_only"])


def test_row6_video_path_two_cdns(conn):
    _, res = run(conn, ("youtube", "netflix"))
    r = result_at(res)
    assert (r.layer, r.tags) == ("video_path", ["netflix", "youtube"])


def test_row6_single_cdn_streak_of_three(conn):
    minutes = (EVAL - 2 * sc.MIN, EVAL - sc.MIN, EVAL)
    _, res = run(conn, ("youtube",), minutes=minutes)
    assert result_at(res, minute=EVAL - sc.MIN).layer == "ok"  # only 2 in a row yet
    r = result_at(res)
    assert (r.layer, r.tags) == ("video_path", ["youtube"])


def test_row6_streak_broken_by_a_gap(conn):
    minutes = (EVAL - 2 * sc.MIN, EVAL - sc.MIN, EVAL)

    def gap(s):
        s.gaps = [(EVAL - sc.MIN, EVAL)]

    _, res = run(conn, ("youtube",), minutes=minutes, setup=gap)
    assert result_at(res).layer == "ok"


def test_first_match_wins_gateway_rows_before_edge_rows(conn):
    _, res = run(conn, ("gateway", "isp_edge", *ALL_DOWN))
    assert result_at(res).layer == "wifi"  # row 1 beats row 3
    conn2 = store.connect(":memory:")
    _, res2 = run(conn2, ("gateway", "isp_edge"))
    r = result_at(res2)
    assert (r.layer, r.tags) == ("ok", ["router_icmp_slow"])  # row 2 beats row 7
    conn2.close()


def test_row7_isp_edge_icmp(conn):
    _, res = run(conn, ("isp_edge",))
    r = result_at(res)
    assert (r.layer, r.tags) == ("ok", ["isp_edge_icmp"])


def test_row8_one_bad_target_is_ok(conn):
    _, res = run(conn, ("google",))
    assert result_at(res).layer == "ok"


def test_row9_inconclusive(conn):
    # two anchors + one CDN bad: A majority bad, C majority OK → row 5… so make it mixed:
    # one anchor and one CDN bad = not a majority anywhere, two bad → row 8 fails → row 9
    _, res = run(conn, ("google", "instagram"))
    assert result_at(res).layer == "inconclusive"


def test_d_smaller_than_three_is_inconclusive(conn):
    def drop(s):
        for name in ("google", "bbc", "youtube", "instagram"):
            s.set_status(name, "unavailable", "test")

    _, res = run(conn, ("gateway", "cloudflare", "netflix"), setup=drop)
    r = result_at(res)
    assert (r.layer, r.d_size) == ("inconclusive", 2)


def test_blocked_gateway_skips_rows_1_and_2(conn):
    def blocked(s):
        s.blocked_gateway = lambda m: True

    _, res = run(conn, ALL_DOWN, setup=blocked)
    r = result_at(res)
    assert r.gateway_unknown and r.layer == "isp_upstream"


def test_empty_cdn_set_falls_through_rows_4_to_6(conn):
    def no_cdns(s):
        for name in ("youtube", "instagram", "netflix"):
            s.set_status(name, "unavailable", "test")

    _, res = run(conn, ANCHORS, setup=no_cdns)
    assert result_at(res).layer == "inconclusive"  # 3 bad of 3, but no C → row 9


def test_wifi_context_flags():
    readings = [
        at.WifiReading(1000, -55, -92, 149, "5"),
        at.WifiReading(2000, -75, -85, 6, "2.4"),
    ]
    assert at.wifi_context(readings, 1500) == []
    assert at.wifi_context(readings, 2500) == ["weak_signal", "low_snr", "band_2_4", "band_changed"]
    assert at.wifi_context([], 2500) == []


def test_wifi_minutes_carry_context(conn):
    def readings(s):
        s.add_wifi_readings(band="2.4", rssi=-75)

    _, res = run(conn, ("gateway", *ALL_DOWN), setup=readings)
    assert {"weak_signal", "band_2_4"} <= set(result_at(res).wifi_context)


def test_choose_family(conn):
    _, res = run(conn, v6=True)
    full = {af: list(rs.values()) for af, rs in res.items()}
    assert at.choose_family(full) == 6
    assert at.choose_family({4: full[4], 6: []}) == 4
    assert at.choose_family({4: [], 6: []}) == 4


# ---- scenarios -------------------------------------------------------------------------------


def evening_layers(conn, s, af=4):
    cov = coverage.load(conn, s.start, s.end)
    bases = baseline.compute(cov, CFG, s.start, s.end)
    results = at.attribute(cov, bases, s.start, s.end, at.read_wifi(conn, s.start, s.end))
    layers = [
        r.layer for r in results[af] if sc.is_evening(r.minute) and r.minute > s.start + sc.DAY
    ]
    return results, layers


@pytest.mark.parametrize(
    ("name", "layer"),
    [
        ("wifi_bad_evenings", "wifi"),
        ("wired_bad_evenings", "home_network"),
        ("isp_network_evenings", "isp_network"),
        ("isp_upstream_evenings", "isp_upstream"),
        ("video_path_evenings", "video_path"),
    ],
)
def test_scenario_evenings_attributed(conn, name, layer):
    s = sc.SCENARIOS[name](conn)
    _, layers = evening_layers(conn, s)
    assert layers.count(layer) / len(layers) > 0.9


def test_scenario_gateway_slow_only_is_never_wifi(conn):
    s = sc.gateway_slow_only(conn)
    _, layers = evening_layers(conn, s)
    assert "wifi" not in layers and layers.count("ok") / len(layers) > 0.9


def test_scenario_lossy_edge_is_never_isp_network(conn):
    s = sc.isp_edge_always_lossy(conn)
    results, _ = evening_layers(conn, s)
    assert all(r.layer != "isp_network" for r in results[4])


def test_scenario_ipv6(conn):
    s = sc.ipv6_bad_ipv4_clean(conn)
    results, layers6 = evening_layers(conn, s, af=6)
    assert at.choose_family(results) == 6
    assert layers6.count("isp_upstream") / len(layers6) > 0.9
    layers4 = [
        r.layer for r in results[4] if sc.is_evening(r.minute) and r.minute > s.start + sc.DAY
    ]
    assert layers4.count("ok") / len(layers4) > 0.9
