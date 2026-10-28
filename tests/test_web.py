"""Web server & JSON API (spec §7.1, §7.3; plan M3.1)."""

from __future__ import annotations

import http.client
import json
import time

import pytest

from tests import scenarios as sc
from whodunnet import config, paths
from whodunnet.core import analysis, store
from whodunnet.web import server as web

TOKEN = "t" * 32
HEADERS = {"X-Whodunnet": "1", "Content-Type": "application/json"}


@pytest.fixture(autouse=True)
def london(monkeypatch):
    monkeypatch.setenv("TZ", "Europe/London")
    time.tzset()
    yield
    monkeypatch.delenv("TZ")
    time.tzset()


@pytest.fixture
def site(tmp_path):
    """A running server on an ephemeral port over a built scenario database."""
    p = paths.resolve(tmp_path / "data", env={}, home=tmp_path / "home")
    p.data_dir.mkdir(parents=True)
    config.save_overrides(p.config, {"lan_token": TOKEN})
    conn = store.connect(p.db)
    s = sc.wifi_bad_evenings(conn)
    store.set_meta(conn, "local_hostname", "Example-Mac")
    store.set_meta(
        conn,
        "doctor_json",
        json.dumps([{"check": "power", "status": "ok", "message": "On charger", "fix": None}]),
    )
    conn.close()
    srv = web.WebServer(p, 0, lambda: "Example-Mac")
    srv.start(lan_access=False)
    yield srv, s, p
    srv.stop()


def request(srv, method, path, body=None, headers=None, host=None):
    c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=30)
    h = {"Host": host or f"127.0.0.1:{srv.port}", **(headers or {})}
    c.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
    r = c.getresponse()
    data = r.read()
    c.close()
    try:
        parsed = json.loads(data)
    except ValueError:
        parsed = data.decode()
    return r.status, parsed, dict(r.getheaders())


# ---- access rules: the pure function --------------------------------------------------------------


def access(
    method="GET",
    path="/api/verdict",
    host="127.0.0.1:8737",
    ip="127.0.0.1",
    headers=None,
    cookie=None,
    query=None,
    token=TOKEN,
):
    return web.check_access(
        method, path, query or {}, host, ip, headers or {}, cookie, token, 8737, "Example-Mac"
    )


def test_host_header_rules():
    assert access().allowed
    assert access(host="localhost:8737").allowed
    assert access(host="EXAMPLE-MAC.local:8737").allowed
    assert not access(host="evil.example:8737").allowed
    assert not access(host="127.0.0.1:9999").allowed
    assert not access(host=None).allowed


def test_loopback_writes_need_header_and_json():
    h = {"x-whodunnet": "1", "content-type": "application/json; charset=utf-8"}
    assert access("POST", "/api/lag", headers=h).allowed
    assert not access("POST", "/api/lag", headers={"content-type": "application/json"}).allowed
    assert not access(
        "POST", "/api/lag", headers={"x-whodunnet": "1", "content-type": "text/plain"}
    ).allowed
    assert not access("DELETE", "/api/events/1", headers={}).allowed


def test_phone_only_reaches_lag_with_the_token():
    phone = "192.168.1.50"
    lan_host = "Example-Mac.local:8737"
    assert not access(ip=phone, host=lan_host).allowed  # /api/verdict
    assert access("GET", "/lag", host=lan_host, ip=phone, query={"t": [TOKEN]}).allowed
    assert not access("GET", "/lag", host=lan_host, ip=phone, query={"t": ["wrong"]}).allowed
    assert not access("GET", "/lag", host=lan_host, ip=phone).allowed
    assert access("POST", "/api/lag", host=lan_host, ip=phone, cookie=TOKEN).allowed
    assert not access("POST", "/api/lag", host=lan_host, ip=phone, cookie="old").allowed
    assert not access("POST", "/api/lag", host=lan_host, ip=phone).allowed
    assert not access("GET", "/lag", host=lan_host, ip=phone, query={"t": [""]}, token=None).allowed
    assert access(ip=phone, host=lan_host).reason == web.INVALID_LINK


# ---- over HTTP -------------------------------------------------------------------------------


def test_wrong_host_is_403(site):
    srv, _, _ = site
    status, body, _ = request(srv, "GET", "/api/verdict", host="rebind.attacker:80")
    assert status == 403 and body == {"error": "Forbidden host"}


def test_post_without_header_is_403(site):
    srv, _, _ = site
    status, _, _ = request(srv, "POST", "/api/lag", {}, {"Content-Type": "application/json"})
    assert status == 403


def test_verdict_matches_analysis(site):
    srv, _s, _p = site
    status, body, headers = request(srv, "GET", "/api/verdict")
    assert status == 200 and body["verdict"] in analysis.NEXT_STEPS
    assert headers["Cache-Control"] == "no-store"
    _status2, body2, _ = request(srv, "GET", "/api/verdict")
    assert body2 == body  # served from the cache


def test_timeline_shapes_and_cap(site):
    srv, _s, _ = site
    start = sc.local_ms(2026, 10, 3, 18, 0)
    status, body, _ = request(srv, "GET", f"/api/timeline?from={start}&to={start + 4 * sc.HOUR}")
    assert status == 200
    assert {"targets", "rollups", "layers", "wifi", "events", "gaps", "excluded"} <= set(body)
    gateway = next(t for t in body["targets"] if t["kind"] == "gateway")
    minute, sent, _lost, _p50, _p95, _jitter = body["rollups"][str(gateway["id"])][0]
    assert minute == start and sent == 30
    layers = {m: layer for m, layer in body["layers"]}
    assert layers[sc.local_ms(2026, 10, 3, 20, 0)] == "wifi"
    status, body, _ = request(srv, "GET", f"/api/timeline?from=0&to={9 * 24 * 3600 * 1000}")
    assert status == 400 and "range too long" in body["error"]
    status, body, _ = request(srv, "GET", "/api/timeline?from=abc")
    assert status == 400


def test_heatmap(site):
    srv, s, _ = site
    q = f"from={s.start}&to={s.start + 3 * sc.DAY}"
    status, body, _ = request(srv, "GET", f"/api/heatmap?metric=layer_rate&{q}")
    assert status == 200 and body["hours"] == list(range(24))
    assert body["days"][:2] == ["2026-10-01", "2026-10-02"]
    row = body["values"][1]
    assert row[20] > 0.9 and row[12] == 0
    status, body, _ = request(srv, "GET", f"/api/heatmap?metric=loss&{q}")
    assert status == 200 and body["values"][1][20] > 0.05
    status, body, _ = request(srv, "GET", f"/api/heatmap?metric=nope&{q}")
    assert status == 400


def test_compare(site):
    srv, s, _ = site
    status, body, _ = request(srv, "GET", f"/api/compare?from={s.start}&to={s.end}")
    assert status == 200 and body["address_family"] == 4
    wifi = body["families"]["4"]["wifi"]
    assert wifi["evening_rate"] > 0.9 and wifi["daytime_rate"] == 0
    assert wifi["evenings_shown"] == wifi["evenings_covered"] == 8


def test_events_add_list_delete(site):
    srv, s, _ = site
    status, body, _ = request(
        srv,
        "POST",
        "/api/events",
        {"kind": "router_change", "note": "new router", "ts": s.start + 5},
        HEADERS,
    )
    assert status == 200 and body["source"] == "dashboard"
    event_id = body["id"]
    status, listed, _ = request(srv, "GET", f"/api/events?from={s.start}&to={s.end}")
    assert [e["id"] for e in listed] == [event_id]
    status, body, _ = request(srv, "POST", "/api/events", {"kind": "lag"}, HEADERS)
    assert status == 400  # lag is not a user event kind here
    status, body, _ = request(srv, "DELETE", f"/api/events/{event_id}", None, HEADERS)
    assert status == 200 and body == {"deleted": event_id}
    status, body, _ = request(srv, "DELETE", f"/api/events/{event_id}", None, HEADERS)
    assert status == 404


def test_system_events_cannot_be_deleted(site):
    srv, s, p = site
    conn = store.connect(p.db)
    system_id = store.add_event(conn, "system", "Gap 5 min", "auto", s.start)
    conn.close()
    status, _, _ = request(srv, "DELETE", f"/api/events/{system_id}", None, HEADERS)
    assert status == 404


def test_lag_from_dashboard(site):
    srv, _, p = site
    status, body, _ = request(srv, "POST", "/api/lag", {}, HEADERS)
    assert status == 200 and body["source"] == "dashboard"
    conn = store.connect(p.db)
    assert store.list_events(conn, 0, 10**15, kinds=["lag"])[0].source == "dashboard"
    conn.close()


def test_settings_get_and_regenerate_token(site):
    srv, _, p = site
    status, body, _ = request(srv, "GET", "/api/settings")
    assert status == 200 and body["lan_access"] is False and body["token_set"]
    assert body["phone_url"] == f"http://Example-Mac.local:{srv.port}/lag?t={TOKEN}"
    assert body["doctor"][0]["check"] == "power"
    status, body, _ = request(srv, "POST", "/api/settings", {"regenerate_token": True}, HEADERS)
    new_token = config.read_overrides(p.config)["lan_token"]
    assert new_token != TOKEN and new_token in body["phone_url"]
    status, body, _ = request(srv, "POST", "/api/settings", {"lan_access": "yes"}, HEADERS)
    assert status == 400


def test_settings_lan_toggle_rebinds(site):
    srv, _, p = site
    port = srv.port
    status, body, _ = request(srv, "POST", "/api/settings", {"lan_access": True}, HEADERS)
    assert status == 200 and body["lan_access"] is True
    deadline = time.monotonic() + 5
    while srv.bound_to != "0.0.0.0" and time.monotonic() < deadline:
        time.sleep(0.05)
    assert srv.bound_to == "0.0.0.0" and srv.port == port
    assert config.read_overrides(p.config)["lan_access"] is True
    status, _, _ = request(srv, "GET", "/api/settings")
    assert status == 200


def test_report_html(site):
    srv, _, _ = site
    status, body, headers = request(srv, "GET", "/api/report?from=2026-10-01&to=2026-10-08")
    assert status == 200
    assert headers["Content-Type"].startswith("text/html")
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert (
        'filename="whodunnet-report-2026-10-01-2026-10-08.html"' in headers["Content-Disposition"]
    )
    assert "<h2>1. Summary" in body and "Your WiFi" in body


@pytest.mark.parametrize(
    "query",
    [
        "",
        "?from=2026-10-01",
        "?from=yesterday&to=2026-10-08",
        "?from=2026-10-08&to=2026-10-01",
        "?from=2026-01-01&to=2026-10-08",
    ],
)
def test_report_bad_ranges_are_400(site, query):
    srv, _, _ = site
    status, body, _ = request(srv, "GET", "/api/report" + query)
    assert status == 400 and body["error"]


def test_report_is_not_reachable_from_the_lan():
    phone, lan_host = "192.168.1.50", "Example-Mac.local:8737"
    assert not access("GET", "/api/report", host=lan_host, ip=phone, cookie=TOKEN).allowed


def test_static_pages_and_traversal(site):
    srv, _, _ = site
    status, body, headers = request(srv, "GET", "/")
    assert status == 200 and "Whodunnet" in body and headers["Content-Type"].startswith("text/html")
    status, body, headers = request(srv, "GET", "/lag")
    assert status == 200 and "It's lagging now" in body
    assert "Set-Cookie" not in headers  # loopback needs no cookie
    status, _, _ = request(srv, "GET", "/../server.py")
    assert status == 404
    status, _, _ = request(srv, "GET", "/nope.html")
    assert status == 404


def test_bad_json_body(site):
    srv, _, _ = site
    c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
    c.request(
        "POST",
        "/api/events",
        body="{not json",
        headers={"Host": f"127.0.0.1:{srv.port}", **HEADERS},
    )
    r = c.getresponse()
    assert r.status == 400 and json.loads(r.read())["error"] == "body must be JSON"
    c.close()


def test_no_database_yet(tmp_path):
    p = paths.resolve(tmp_path / "empty", env={}, home=tmp_path / "home")
    p.data_dir.mkdir(parents=True)
    srv = web.WebServer(p, 0)
    srv.start(lan_access=False)
    try:
        status, body, _ = request(srv, "GET", "/api/verdict")
        assert status == 404 and body == {"error": "no data yet"}
    finally:
        srv.stop()


def test_collector_hook_starts_and_stop_stops(tmp_path):
    from tests.test_collector import (
        FakeFetch,
        FakePopen,
        PrefixRunner,
        Spawner,
        collector_responses,
    )
    from whodunnet.collector import main

    p = paths.resolve(tmp_path / "data", env={}, home=tmp_path / "home")
    cfg, _ = config.validate({"web_port": 18737})
    c = main.Collector(
        p,
        cfg,
        runner=PrefixRunner(collector_responses()),
        fetch=FakeFetch(),
        popen=FakePopen(),
        spawner=Spawner(),
        nudge=lambda gw: True,
        threaded=False,
    )
    c.web_hook = web.start_for_collector
    c.start()
    try:
        assert c.web is not None and c.web.port == 18737
        status, body, _ = request(c.web, "GET", "/api/settings", host=f"localhost:{c.web.port}")
        assert status == 200 and body["token_set"]
    finally:
        srv = c.web
        c.stop()
    assert c.web is None and srv.httpd is None


def test_static_files_load_nothing_external():
    # Spec §7.1: the dashboard works offline and never contacts third parties.
    import re
    from pathlib import Path

    static = Path(web.__file__).parent / "static"
    pattern = re.compile(r"(https?:)?//[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE)
    for f in static.iterdir():
        # URLs in JS comments (the vendored QR library's credits) are never fetched.
        lines = f.read_text(encoding="utf-8").splitlines()
        text = "\n".join(line for line in lines if not line.lstrip().startswith("//"))
        text = text.replace("http://www.w3.org/2000/svg", "")
        assert not pattern.search(text), f.name


def test_vendored_qr_library_is_unmodified():
    import hashlib
    import re
    from pathlib import Path

    text = (Path(web.__file__).parent / "static" / "qr.js").read_text(encoding="utf-8")
    header, body = text.split("\n\n", 1)
    (expected,) = re.findall(r"sha256 ([0-9a-f]{64})", header)
    assert hashlib.sha256(body.encode("utf-8")).hexdigest() == expected
    assert "MIT License" in header


def test_bucket_rollups_sums_and_maxes():
    from whodunnet.core.models import RollupRow

    def row(minute, target, sent, lost, p50, p95, jitter):
        return RollupRow(minute, target, sent, lost, p50, p95, None, jitter, None, 0)

    step = web.TIMELINE_LONG_STEP_MS
    rows = [
        row(0, 1, 60, 1, 10.0, 20.0, 1.0),
        row(60_000, 1, 60, 2, 20.0, 50.0, 3.0),
        row(60_000, 2, 60, 0, None, None, None),
        row(step, 1, 30, 0, 5.0, 8.0, 0.5),
    ]
    out = web.bucket_rollups(rows, step)
    assert out["1"] == [[0, 120, 3, 15.0, 50.0, 2.0], [step, 30, 0, 5.0, 8.0, 0.5]]
    assert out["2"] == [[0, 60, 0, None, None, None]]


def test_bucket_layers_keeps_the_most_severe():
    from whodunnet.core.attribution import MinuteResult

    step = web.TIMELINE_LONG_STEP_MS
    results = [
        MinuteResult(0, 4, "ok"),
        MinuteResult(60_000, 4, "isp_upstream"),
        MinuteResult(120_000, 4, "inconclusive"),
        MinuteResult(step, 4, "ok"),
        MinuteResult(step + 60_000, 4, "inconclusive"),
    ]
    assert web.bucket_layers(results, step) == [[0, "isp_upstream"], [step, "inconclusive"]]
