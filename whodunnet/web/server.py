"""The dashboard's web server and JSON API, run inside the collector (spec §7).

Stdlib only (`http.server.ThreadingHTTPServer`). Access rules (spec §7.1) live in the pure
`check_access` so they can be tested without sockets. Each GET opens a read-only connection;
each POST/DELETE opens a short-lived read-write one. All SQL is in `core/store` / `core/analysis`.
The web code never runs commands. The doctor summary comes from `meta.doctor_json`.
"""

from __future__ import annotations

import hmac
import json
import logging
import mimetypes
import sqlite3
import threading
import time
from dataclasses import dataclass
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

from whodunnet import config
from whodunnet.core import analysis, report, store
from whodunnet.core.models import USER_EVENT_KINDS
from whodunnet.paths import Paths

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"
VERDICT_DAYS = 14
TIMELINE_MAX_MS = 8 * 24 * 3600 * 1000
HEATMAP_MAX_MS = 31 * 24 * 3600 * 1000
VERDICT_CACHE_S = 60
COOKIE = "wd_token"
COOKIE_MAX_AGE = 31_536_000
HEATMAP_METRICS = ("layer_rate", "loss", "p95", "bufferbloat", "download")
PHONE_PATHS = {("GET", "/lag"), ("POST", "/api/lag")}
INVALID_LINK = "This link is invalid"
DAY_MS = 24 * 3600 * 1000
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'"  # the report has no scripts


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


# ---- access rules (spec §7.1) ---------------------------------------------------------------------


@dataclass(frozen=True)
class Access:
    allowed: bool
    status: int = 200
    reason: str = ""
    loopback: bool = True


def is_loopback(ip: str) -> bool:
    return ip.startswith("127.") or ip in ("::1", "::ffff:127.0.0.1")


def allowed_hosts(port: int, local_hostname: str | None) -> set[str]:
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    if local_hostname:
        hosts.add(f"{local_hostname}.local:{port}".lower())
    return hosts


def tokens_equal(given: str | None, token: str | None) -> bool:
    if not given or not token:
        return False
    return hmac.compare_digest(given.encode(), token.encode())


def check_access(
    method: str,
    path: str,
    query: dict[str, list[str]],
    host: str | None,
    client_ip: str,
    headers: dict[str, str],
    cookie_token: str | None,
    token: str | None,
    port: int,
    local_hostname: str | None,
) -> Access:
    if (host or "").lower() not in allowed_hosts(port, local_hostname):
        return Access(False, 403, "Forbidden host")
    if is_loopback(client_ip):
        if method != "GET":
            json_type = headers.get("content-type", "").split(";")[0].strip().lower()
            if headers.get("x-whodunnet") != "1" or json_type != "application/json":
                return Access(False, 403, "Missing X-Whodunnet header or JSON content type")
        return Access(True)
    # Non-loopback (the phone): only the lag page and the lag button, with the token.
    if (method, path) not in PHONE_PATHS:
        return Access(False, 403, INVALID_LINK, loopback=False)
    if method == "GET":
        given = (query.get("t") or [None])[0]
        if not tokens_equal(given, token):
            return Access(False, 403, INVALID_LINK, loopback=False)
    elif not tokens_equal(cookie_token, token):
        return Access(False, 403, INVALID_LINK, loopback=False)
    return Access(True, loopback=False)


# ---- the API ------------------------------------------------------------------------------------


def _int_param(query: dict[str, list[str]], name: str, default: int | None = None) -> int:
    values = query.get(name)
    if not values:
        if default is None:
            raise ApiError(400, f"missing parameter: {name}")
        return default
    try:
        return int(values[0])
    except ValueError:
        raise ApiError(400, f"{name} must be epoch milliseconds") from None


def _range(query, max_ms: int, default_ms: int) -> tuple[int, int]:
    now = int(time.time() * 1000) // 60_000 * 60_000
    end = _int_param(query, "to", now)
    start = _int_param(query, "from", end - default_ms)
    if start >= end:
        raise ApiError(400, "from must be before to")
    if end - start > max_ms:
        raise ApiError(400, f"range too long (max {max_ms // DAY_MS} days)")
    return start, end


TIMELINE_LONG_STEP_MS = 5 * 60_000  # ranges over a day are bucketed (keeps 7 days < 1 MB)
LAYER_SEVERITY = (
    "ok",
    "inconclusive",
    "video_path",
    "isp_upstream",
    "isp_network",
    "home_network",
    "wifi",
)


def bucket_rollups(rows, step: int) -> dict[str, list]:
    """[[bucket, sent, lost, p50 (mean), p95 (max), jitter (mean)], …] per target."""
    buckets: dict[tuple[int, int], list] = {}
    for r in rows:
        key = (r.target_id, r.minute // step * step)
        buckets.setdefault(key, []).append(r)
    out: dict[str, list] = {}
    for (target_id, start), group in sorted(buckets.items()):
        p50s = [g.p50_ms for g in group if g.p50_ms is not None]
        p95s = [g.p95_ms for g in group if g.p95_ms is not None]
        jitters = [g.jitter_ms for g in group if g.jitter_ms is not None]
        out.setdefault(str(target_id), []).append(
            [
                start,
                sum(g.sent for g in group),
                sum(g.lost for g in group),
                round(sum(p50s) / len(p50s), 2) if p50s else None,
                max(p95s) if p95s else None,
                round(sum(jitters) / len(jitters), 2) if jitters else None,
            ]
        )
    return out


def bucket_layers(results, step: int) -> list[list]:
    """[[bucket, layer], …]; a bucket shows its most severe layer (any problem beats ok)."""
    worst: dict[int, str] = {}
    for r in results:
        key = r.minute // step * step
        if key not in worst or LAYER_SEVERITY.index(r.layer) > LAYER_SEVERITY.index(worst[key]):
            worst[key] = r.layer
    return [[k, worst[k]] for k in sorted(worst)]


class Api:
    """Endpoint implementations. Each takes parsed inputs and returns a JSON-able value."""

    def __init__(
        self, paths: Paths, local_hostname: Callable[[], str | None], port: Callable[[], int]
    ):
        self.paths = paths
        self.local_hostname = local_hostname
        self.port = port
        self._verdict_cache: tuple[tuple, float, dict] | None = None
        self._lock = threading.Lock()

    # ---- helpers --------------------------------------------------------------------------

    def cfg(self) -> dict:
        cfg, _ = config.load(self.paths.config)
        return cfg

    def read(self) -> sqlite3.Connection:
        if not self.paths.db.exists():
            raise ApiError(404, "no data yet")
        return store.connect_readonly(self.paths.db)

    def write(self) -> sqlite3.Connection:
        return store.connect(self.paths.db)

    def token(self) -> str | None:
        return config.read_overrides(self.paths.config).get("lan_token")

    # ---- GET ------------------------------------------------------------------------------

    def verdict(self, query) -> dict:
        conn = self.read()
        try:
            key = (
                conn.execute("SELECT MAX(minute) FROM minute_rollup").fetchone()[0],
                conn.execute("SELECT MAX(id) FROM events").fetchone()[0],
            )
            with self._lock:
                cached = self._verdict_cache
                if cached and cached[0] == key and time.monotonic() - cached[1] < VERDICT_CACHE_S:
                    return cached[2]
            end = int(time.time() * 1000) // 60_000 * 60_000
            result = analysis.analyse(conn, self.cfg(), end - VERDICT_DAYS * DAY_MS, end)
        finally:
            conn.close()
        with self._lock:
            self._verdict_cache = (key, time.monotonic(), result)
        return result

    def timeline(self, query) -> dict:
        start, end = _range(query, TIMELINE_MAX_MS, DAY_MS)
        conn = self.read()
        try:
            cov, af, results = analysis.minute_layers(conn, self.cfg(), start, end)
            step = 60_000 if end - start <= DAY_MS else TIMELINE_LONG_STEP_MS
            rollups = bucket_rollups(store.read_rollups(conn, start, end), step)
            wifi = [
                [r["ts"], r["rssi_dbm"], r["band"], r["channel"]]
                for r in store.read_raw(conn, "wifi", start, end)
            ]
            events = [e.__dict__ for e in store.list_events(conn, start, end)]
            excluded = [
                [m, reason]
                for m in range(start // 60_000 * 60_000, end, 60_000)
                if cov.has_data(m) and (reason := cov.exclusion(m))
            ]
            targets = [
                {
                    "id": t.id,
                    "kind": t.kind,
                    "name": t.name,
                    "af": t.af,
                    "ip": t.ip,
                    "status": t.status,
                    "active": bool(t.active),
                }
                for t in store.list_targets(conn)
            ]
        finally:
            conn.close()
        return {
            "from": start,
            "to": end,
            "address_family": af,
            "targets": targets,
            "rollups": rollups,
            "step": step,
            "layers": bucket_layers(results.get(af, []), step),
            "wifi": wifi,
            "events": events,
            "gaps": [[a, b] for a, b in cov.gaps() if b > start],
            "excluded": excluded,
        }

    def heatmap(self, query) -> dict:
        metric = (query.get("metric") or ["layer_rate"])[0]
        if metric not in HEATMAP_METRICS:
            raise ApiError(400, "metric must be one of " + ", ".join(HEATMAP_METRICS))
        start, end = _range(query, HEATMAP_MAX_MS, 7 * DAY_MS)
        conn = self.read()
        try:
            cells: dict[tuple[str, int], list[float]] = {}

            def add(ms: int, value: float | None) -> None:
                if value is None:
                    return
                t = time.localtime(ms / 1000)
                cells.setdefault((time.strftime("%Y-%m-%d", t), t.tm_hour), []).append(value)

            if metric == "layer_rate":
                _cov, af, results = analysis.minute_layers(conn, self.cfg(), start, end)
                for r in results.get(af, []):
                    if r.layer != "inconclusive":
                        add(r.minute, 0.0 if r.layer == "ok" else 1.0)
            elif metric in ("loss", "p95"):
                downstream = {t.id for t in store.list_targets(conn) if t.kind in ("anchor", "cdn")}
                for r in store.read_rollups(conn, start, end):
                    if r.target_id not in downstream:
                        continue
                    if metric == "loss":
                        add(r.minute, r.lost / r.sent if r.sent else None)
                    else:
                        add(r.minute, r.p95_ms)
            else:
                column = "bufferbloat_ms" if metric == "bufferbloat" else "dl_mbps"
                for r in store.read_raw(conn, "nq", start, end):
                    if r["ok"]:
                        add(r["ts"], r[column])
        finally:
            conn.close()
        days = sorted({day for day, _ in cells})
        values = [
            [
                round(sum(v) / len(v), 4) if (v := cells.get((day, hour))) else None
                for hour in range(24)
            ]
            for day in days
        ]
        return {"metric": metric, "days": days, "hours": list(range(24)), "values": values}

    def compare(self, query) -> dict:
        start, end = _range(query, HEATMAP_MAX_MS, VERDICT_DAYS * DAY_MS)
        conn = self.read()
        try:
            return analysis.compare(conn, self.cfg(), start, end)
        finally:
            conn.close()

    def report(self, query) -> tuple[str, str]:
        """(HTML, filename) for inclusive local dates ?from=YYYY-MM-DD&to=YYYY-MM-DD."""
        date_from, date_to = (query.get(k, [None])[0] for k in ("from", "to"))
        try:
            start, end = report.parse_range(date_from, date_to)
        except ValueError as exc:
            raise ApiError(400, str(exc)) from None
        conn = self.read()
        try:
            html = report.render(report.build(conn, self.cfg(), start, end))
        finally:
            conn.close()
        return html, report.filename(date_from.strip(), date_to.strip())

    def events(self, query) -> list[dict]:
        start, end = _range(query, 10 * 365 * DAY_MS, 30 * DAY_MS)
        conn = self.read()
        try:
            return [e.__dict__ for e in store.list_events(conn, start, end)]
        finally:
            conn.close()

    def settings(self, query=None) -> dict:
        cfg = self.cfg()
        token = self.token()
        host = self.local_hostname()
        phone_url = f"http://{host}.local:{self.port()}/lag?t={token}" if host and token else None
        doctor: list = []
        if self.paths.db.exists():
            conn = store.connect_readonly(self.paths.db)
            try:
                raw = store.get_meta(conn, "doctor_json")
            finally:
                conn.close()
            try:
                doctor = json.loads(raw) if raw else []
            except ValueError:
                doctor = []
        return {
            "lan_access": cfg["lan_access"],
            "port": self.port(),
            "phone_url": phone_url,
            "token_set": bool(token),
            "doctor": doctor,
        }

    # ---- writes ---------------------------------------------------------------------------

    def add_event(self, body: dict) -> dict:
        kind = body.get("kind", "other")
        note = body.get("note", "")
        if kind not in USER_EVENT_KINDS:
            raise ApiError(400, "kind must be one of " + ", ".join(USER_EVENT_KINDS))
        if not isinstance(note, str) or len(note) > 500:
            raise ApiError(400, "note must be a string of at most 500 characters")
        ts = body.get("ts", int(time.time() * 1000))
        if isinstance(ts, bool) or not isinstance(ts, int):
            raise ApiError(400, "ts must be epoch milliseconds")
        conn = self.write()
        try:
            event_id = store.add_event(conn, kind, note, "dashboard", ts)
        finally:
            conn.close()
        return {"id": event_id, "ts": ts, "kind": kind, "note": note, "source": "dashboard"}

    def delete_event(self, event_id: int) -> dict:
        conn = self.write()
        try:
            if not store.delete_event(conn, event_id, user_only=True):
                raise ApiError(404, "no such event (only events you added can be deleted)")
        finally:
            conn.close()
        return {"deleted": event_id}

    def lag(self, source: str) -> dict:
        ts = int(time.time() * 1000)
        conn = self.write()
        try:
            event_id = store.add_event(conn, "lag", "", source, ts)
        finally:
            conn.close()
        return {"id": event_id, "ts": ts, "source": source}

    def update_settings(self, body: dict, on_rebind: Callable[[bool], None]) -> dict:
        overrides = config.read_overrides(self.paths.config)
        rebind = None
        if "lan_access" in body:
            if not isinstance(body["lan_access"], bool):
                raise ApiError(400, "lan_access must be true or false")
            if body["lan_access"] != bool(overrides.get("lan_access", False)):
                rebind = body["lan_access"]
            overrides["lan_access"] = body["lan_access"]
        if body.get("regenerate_token") is True:
            overrides["lan_token"] = config.new_token()
        elif "regenerate_token" in body and body["regenerate_token"] is not False:
            raise ApiError(400, "regenerate_token must be true or false")
        if not overrides.get("lan_token"):
            overrides["lan_token"] = config.new_token()
        config.save_overrides(self.paths.config, overrides)
        if rebind is not None:
            on_rebind(rebind)
        return self.settings()


# ---- HTTP plumbing ------------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    server_version = "Whodunnet"
    sys_version = ""
    web: WebServer  # set on the subclass created per server

    def log_message(self, fmt: str, *args: Any) -> None:
        log.debug("web: " + fmt, *args)

    # -- responses --

    def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, value: Any, extra: dict | None = None) -> None:
        self._send(status, json.dumps(value).encode(), "application/json; charset=utf-8", extra)

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    # -- dispatch --

    def _handle(self) -> None:
        parts = urlsplit(self.path)
        path, query = parts.path, parse_qs(parts.query)
        headers = {k.lower(): v for k, v in self.headers.items()}
        cookies = SimpleCookie(headers.get("cookie", ""))
        cookie_token = cookies[COOKIE].value if COOKIE in cookies else None
        token = self.web.api.token()
        access = check_access(
            self.command,
            path,
            query,
            headers.get("host"),
            self.client_address[0],
            headers,
            cookie_token,
            token,
            self.web.port,
            self.web.local_hostname(),
        )
        if not access.allowed:
            if not access.loopback and path == "/lag":
                self._send(403, INVALID_LINK.encode(), "text/plain; charset=utf-8")
            else:
                self._error(access.status, access.reason)
            return
        try:
            self._route(path, query, access, token)
        except ApiError as exc:
            self._error(exc.status, exc.message)
        except Exception:  # never let a request kill the server thread
            log.exception("web: %s %s failed", self.command, path)
            self._error(500, "internal error")

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length > 64_000:
            raise ApiError(400, "request too large")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            raise ApiError(400, "body must be JSON") from None
        if not isinstance(body, dict):
            raise ApiError(400, "body must be a JSON object")
        return body

    def _route(self, path: str, query, access: Access, token: str | None) -> None:
        api, method = self.web.api, self.command
        if method in ("GET", "HEAD"):
            routes = {
                "/api/verdict": api.verdict,
                "/api/timeline": api.timeline,
                "/api/heatmap": api.heatmap,
                "/api/compare": api.compare,
                "/api/events": api.events,
                "/api/settings": api.settings,
            }
            if path in routes:
                self._json(200, routes[path](query))
            elif path == "/api/report":
                html, name = api.report(query)
                self._send(
                    200,
                    html.encode(),
                    "text/html; charset=utf-8",
                    {
                        "Content-Security-Policy": REPORT_CSP,
                        "Content-Disposition": f'inline; filename="{name}"',
                    },
                )
            elif path == "/lag":
                extra = {}
                if not access.loopback and token:
                    extra["Set-Cookie"] = (
                        f"{COOKIE}={token}; HttpOnly; SameSite=Strict; Max-Age={COOKIE_MAX_AGE}; "
                        "Path=/"
                    )
                self._static("lag.html", extra)
            elif path == "/":
                self._static("index.html")
            else:
                self._static(path.lstrip("/"))
        elif method == "POST":
            body = self._body()
            if path == "/api/lag":
                self._json(200, api.lag("dashboard" if access.loopback else "phone"))
            elif path == "/api/events":
                self._json(200, api.add_event(body))
            elif path == "/api/settings":
                self._json(200, api.update_settings(body, self.web.schedule_rebind))
            else:
                raise ApiError(404, "not found")
        elif method == "DELETE" and path.startswith("/api/events/"):
            try:
                event_id = int(path.rsplit("/", 1)[1])
            except ValueError:
                raise ApiError(404, "not found") from None
            self._json(200, api.delete_event(event_id))
        else:
            raise ApiError(404, "not found")

    def _static(self, name: str, extra: dict | None = None) -> None:
        target = (STATIC_DIR / name).resolve()
        if STATIC_DIR not in target.parents or not target.is_file():
            raise ApiError(404, "not found")
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in ("application/javascript",):
            content_type += "; charset=utf-8"
        self._send(200, target.read_bytes(), content_type, extra)

    do_GET = do_HEAD = do_POST = do_DELETE = _handle


class WebServer:
    """Owns the listening socket and its thread; rebinds when LAN access is toggled."""

    def __init__(
        self,
        paths: Paths,
        port: int,
        local_hostname: Callable[[], str | None] = lambda: None,
    ) -> None:
        self.paths = paths
        self.requested_port = port
        self.port = port
        self.local_hostname = local_hostname
        self.api = Api(paths, local_hostname, lambda: self.port)
        self.httpd: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.bound_to: str | None = None
        self._lock = threading.Lock()

    def start(self, lan_access: bool) -> None:
        handler = type("Handler", (_Handler,), {"web": self})
        address = "0.0.0.0" if lan_access else "127.0.0.1"
        httpd = ThreadingHTTPServer((address, self.requested_port), handler)
        httpd.daemon_threads = True
        self.httpd, self.bound_to = httpd, address
        self.port = httpd.server_address[1]  # real port when 0 was requested (tests)
        self.thread = threading.Thread(
            target=httpd.serve_forever, kwargs={"poll_interval": 0.5}, name="web", daemon=True
        )
        self.thread.start()
        log.info("dashboard on http://%s:%s/", "127.0.0.1", self.port)

    def stop(self) -> None:
        with self._lock:
            httpd, self.httpd = self.httpd, None
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        if self.thread is not None:
            self.thread.join(5)

    def rebind(self, lan_access: bool) -> None:
        """Stop and listen again on the other address, keeping the same port."""
        self.requested_port = self.port
        self.stop()
        self.start(lan_access)

    def schedule_rebind(self, lan_access: bool) -> None:
        # The current request is answered first; then the server rebinds from another thread.
        threading.Timer(0.2, self.rebind, args=(lan_access,)).start()


def start_for_collector(collector) -> WebServer:
    """The collector's web hook: start the dashboard with the current config."""
    config.ensure_token(collector.paths.config)
    # Read once on the collector's thread (sqlite connections are per-thread); the collector
    # writes meta.local_hostname before it calls this hook.
    name = store.get_meta(collector.conn, "local_hostname") if collector.conn else None
    server = WebServer(collector.paths, collector.cfg["web_port"], lambda: name)
    server.start(collector.cfg["lan_access"])
    collector.web = server
    return server
