"""Evidence report (spec §8): a model built from the analysis, rendered as one self-contained HTML
page (inline CSS, no scripts, A4 print CSS) that the user prints to PDF and sends to their ISP.

`build(conn, cfg, start_ms, end_ms)` returns the model (plain dicts and lists, JSON-able);
`render(model)` turns it into HTML. Both are pure: the same data always gives the same report.

Privacy: the household's public IP is never collected. Home hops are shown as "home router" /
"home device"; private, CGNAT, link-local and ULA addresses anywhere are shown as "private
address", never as numbers. There is no SSID in the data.
"""

from __future__ import annotations

import html
import ipaddress
import json
import os
import sqlite3
import statistics
import time
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from whodunnet import __version__, timeutil
from whodunnet.core import analysis, baseline, store
from whodunnet.core import thresholds as th
from whodunnet.core.attribution import LAYERS
from whodunnet.core.coverage import DOWNSTREAM_KINDS, MINUTE_MS

MAX_DAYS = 62  # longest report range (CLI and dashboard)
RIGHTS_TEXT_CHECKED = "2026-10-04"  # when the UK rights text below was last checked
RIGHTS_TEXT = [
    (
        "Ofcom's voluntary Broadband Speeds Code of Practice: ISPs that have signed it must give you "
        "a minimum guaranteed download speed when you sign up. If your speed falls below it, they "
        "have 30 days to fix it; if they can't, you can leave without penalty. The evening download "
        "figures in section 5 are the relevant evidence."
    ),
    "Check whether your ISP has signed the code (Ofcom lists the signatories).",
    (
        "If a complaint isn't resolved after 8 weeks (or the ISP gives you a deadlock letter), you can "
        "take it to the ISP's alternative dispute resolution (ADR) scheme, free of charge."
    ),
]

VERDICT_TITLES = {
    "wifi": "Your WiFi",
    "home_network": "Your home network",
    "isp_network": "Inside your ISP's network",
    "isp_upstream": "Beyond your ISP's network",
    "video_path": "The route to video services",
    "bufferbloat": "Latency under load (bufferbloat)",
    "device_or_app": "The device or app, not the network",
    "no_problem_found": "No network problem found",
    "insufficient_data": "Not enough data yet",
}
QUALIFIER_WORDS = {
    "evening": "in the evenings",
    "all_day": "all day",
    "at_lag_moments": "at the moments you marked",
}
LAYER_TITLES = {
    "wifi": "WiFi (Mac ↔ router)",
    "home_network": "Home network",
    "isp_network": "ISP's own network",
    "isp_upstream": "Beyond the ISP",
    "video_path": "Route to video services",
}
EVENT_TITLES = {
    "router_change": "Router change",
    "package_change": "Package change",
    "isp_contact": "ISP contact",
    "other": "Note",
}
USER_EVENT_KINDS = tuple(EVENT_TITLES)
GRADE_ORDER = "ABCDF"
EXCLUSION_WORDS = {
    "nq": "during a speed test",
    "vpn": "on a VPN",
    "link_other": "on a network other than WiFi or wired",
    "local_load": "while this Mac was itself downloading or uploading heavily",
}
_MASKED_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",  # CGNAT (could be the household's own WAN address)
        "169.254.0.0/16",
        "127.0.0.0/8",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
    )
]


# ---- small helpers -------------------------------------------------------------------------------


def _addr(ip: str | None):
    if not ip:
        return None
    try:
        return ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return None


def is_masked(ip: str | None) -> bool:
    """Private, CGNAT, link-local, loopback or ULA: never printed in the report."""
    a = _addr(ip)
    return a is not None and any(a.version == n.version and a in n for n in _MASKED_NETS)


def _isp_internal(ip: str, edge_ip: str | None) -> bool:
    """Private/CGNAT, or in the same /16 as the ISP edge (IPv4)."""
    a = _addr(ip)
    if a is None:
        return False
    if is_masked(ip):
        return True
    e = _addr(edge_ip)
    if a.version == 4 and e is not None and e.version == 4:
        return a in ipaddress.ip_network(f"{e}/16", strict=False)
    return False


def _rtt(hop: dict) -> float | None:
    rtts = [r for r in hop.get("rtts") or [] if r is not None]
    return round(statistics.median(rtts), 1) if rtts else None


def _local_date(ms: int) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(ms / 1000))


def _local_time(ms: int) -> str:
    return time.strftime("%a %Y-%m-%d %H:%M", time.localtime(ms / 1000))


def _median(values: Sequence[float | None]) -> float | None:
    vs = [v for v in values if v is not None]
    return round(statistics.median(vs), 1) if vs else None


def _median_grade(grades: Sequence[str | None]) -> str | None:
    """Median grade; with an even count, the worse of the middle two (don't hide bad runs)."""
    ranks = sorted(GRADE_ORDER.index(g) for g in grades if g in GRADE_ORDER)
    return GRADE_ORDER[statistics.median_high(ranks)] if ranks else None


def _bad_share(results) -> float | None:
    judged = [r for r in results if r.layer != "inconclusive"]
    return round(sum(1 for r in judged if r.layer != "ok") / len(judged), 4) if judged else None


# ---- traceroutes (section 4) ---------------------------------------------------------------------


def label_hops(
    hops: Sequence[dict], gateway_ip: str | None, edge_ip: str | None, double_nat: bool
) -> list[dict]:
    """Label each hop home / isp / beyond by position (spec §8.4) and decide what to print.

    With a known ISP edge in the trace: hops before it are home; from it on, private, CGNAT and
    same-/16-as-edge hops are ISP, the rest beyond. Without one: the gateway (and a skipped
    double-NAT hop) is home, private/CGNAT hops after it ISP, the rest beyond. A hop that didn't
    reply takes the zone of the hop before it (ISP if that was home).
    """
    ips = [h.get("ip") for h in hops]
    edge_pos = ips.index(edge_ip) if edge_ip and edge_ip in ips else None
    if edge_pos is None:
        if gateway_ip and gateway_ip in ips:
            home_end = ips.index(gateway_ip) + 1
        else:
            home_end = 1 if ips and is_masked(ips[0]) else 0
        if double_nat and home_end < len(ips) and is_masked(ips[home_end]):
            home_end += 1
    else:
        home_end = edge_pos
    out = []
    zone = "home"
    for i, hop in enumerate(hops):
        ip = hop.get("ip")
        if i < home_end:
            zone = "home"
        elif ip is None:
            zone = "isp" if zone == "home" else zone
        elif edge_pos is not None:
            zone = "isp" if _isp_internal(ip, edge_ip) else "beyond"
        else:
            zone = "isp" if is_masked(ip) else "beyond"
        if ip is None:
            shown = "no reply"
        elif zone == "home":
            shown = "home router" if ip == gateway_ip else "home device"
        elif is_masked(ip):
            shown = "private address"
        else:
            shown = ip
        out.append({"ttl": hop.get("ttl"), "zone": zone, "shown": shown, "rtt_ms": _rtt(hop)})
    return out


def dest_rtt(hops: Sequence[dict]) -> float | None:
    """Destination RTT = the last hop that answered (the destination itself if it did)."""
    for hop in reversed(hops):
        rtt = _rtt(hop)
        if rtt is not None:
            return rtt
    return None


def pick_median_trace(traces: Sequence[tuple[int, list[dict]]]) -> tuple[int, list[dict]] | None:
    """The trace whose destination RTT is the (lower) median; ties go to the earliest."""
    scored = [(rtt, ts, hops) for ts, hops in traces if (rtt := dest_rtt(hops)) is not None]
    if not scored:
        return None
    scored.sort(key=lambda x: (x[0], x[1]))
    _rtt_ms, ts, hops = scored[(len(scored) - 1) // 2]
    return ts, hops


def _target_rates(windows_: Sequence[analysis.Window], target_ids: set[int]) -> dict[int, float]:
    hit: Counter = Counter()
    total = 0
    for w in windows_:
        for r in w.results:
            if r.layer == "inconclusive":
                continue
            total += 1
            for tid in set(r.bad) & target_ids:
                hit[tid] += 1
    return {tid: (hit[tid] / total if total else 0.0) for tid in target_ids}


def _where(conn: sqlite3.Connection, f: analysis.Facts, start: int, end: int) -> dict:
    targets = [t for t in f.cov.targets.values() if t.kind in DOWNSTREAM_KINDS and t.af == f.af]
    if not targets:
        return {"worst": None, "evening_trace": None, "daytime_trace": None, "traces": 0}
    ids = {t.id for t in targets}
    ev = _target_rates(f.covered_evenings, ids)
    dt = _target_rates([w for w in f.daytimes if w.covered], ids)
    worst = min(targets, key=lambda t: (-ev[t.id], t.kind, t.name))
    gateway = next((t for t in f.cov.targets.values() if t.kind == "gateway"), None)
    edge = next((t for t in f.cov.targets.values() if t.kind == "isp_edge" and t.af == 4), None)
    double_nat = store.get_meta(conn, "double_nat") == "1"

    rows = [
        r
        for r in store.read_raw(conn, "traceroute", start, end, target_id=worst.id)
        if r["ok"] and r["hops_json"]
    ]

    def pick(windows_: Sequence[analysis.Window]) -> dict | None:
        inside = [
            (r["ts"], json.loads(r["hops_json"]))
            for r in rows
            if any(w.start <= r["ts"] < w.end for w in windows_)
        ]
        chosen = pick_median_trace(inside)
        if chosen is None:
            return None
        ts, hops = chosen
        return {
            "ts": ts,
            "dest_rtt_ms": dest_rtt(hops),
            "candidates": len(inside),
            "hops": label_hops(
                hops, gateway.ip if gateway else None, edge.ip if edge else None, double_nat
            ),
        }

    return {
        "worst": {
            "name": worst.name,
            "kind": worst.kind,
            "evening_rate": round(ev[worst.id], 4),
            "daytime_rate": round(dt[worst.id], 4),
        },
        "evening_trace": pick(f.evenings),
        "daytime_trace": pick(f.daytimes),
        "traces": len(rows),
    }


# ---- the other sections --------------------------------------------------------------------------


def _layer_table(f: analysis.Facts) -> list[dict]:
    ev = f.covered_evenings
    dt = [w for w in f.daytimes if w.covered]
    return [
        {
            "layer": layer,
            "evening_rate": round(analysis.overall_rate(ev, layer), 4),
            "daytime_rate": round(analysis.overall_rate(dt, layer), 4),
            "evenings_shown": sum(1 for w in ev if w.rate(layer) >= th.LAYER_SHOWN_RATE),
            "evenings_covered": len(ev),
            "daytimes_shown": sum(1 for w in dt if w.rate(layer) >= th.LAYER_SHOWN_RATE),
            "daytimes_covered": len(dt),
        }
        for layer in LAYERS
    ]


def _heatmap(f: analysis.Facts) -> dict:
    cells: dict[tuple[str, int], list] = {}
    for r in f.results:
        t = time.localtime(r.minute / 1000)
        cells.setdefault((time.strftime("%Y-%m-%d", t), t.tm_hour), []).append(r)
    days = sorted({day for day, _hour in cells})
    return {
        "days": days,
        "values": [[_bad_share(cells.get((day, hour), [])) for hour in range(24)] for day in days],
    }


def _slot(ms: int, schedule: Sequence[str]) -> str:
    t = time.localtime(ms / 1000)
    minute = t.tm_hour * 60 + t.tm_min

    def distance(hhmm: str) -> int:
        h, m = (int(x) for x in hhmm.split(":"))
        d = abs(minute - (h * 60 + m))
        return min(d, 1440 - d)

    return min(schedule, key=lambda s: (distance(s), s))


def _speed(conn: sqlite3.Connection, cfg: dict, start: int, end: int) -> dict:
    rows = list(store.read_raw(conn, "nq", start, end))
    ok = [r for r in rows if r["ok"]]
    schedule = list(cfg["nq_schedule"])
    by_slot: dict[str, list] = {s: [] for s in schedule}
    for r in ok:
        by_slot[_slot(r["started_ts"] or r["ts"], schedule)].append(r)
    slots = [
        {
            "slot": s,
            "runs": len(rs),
            "dl_mbps": _median([r["dl_mbps"] for r in rs]),
            "ul_mbps": _median([r["ul_mbps"] for r in rs]),
            "bufferbloat_ms": _median([r["bufferbloat_ms"] for r in rs]),
            "grade": _median_grade([r["grade"] for r in rs]),
        }
        for s, rs in by_slot.items()
        if rs
    ]
    skipped = Counter(
        (r["error"] or "unknown").replace("skipped:", "") for r in rows if not r["ok"]
    )
    return {
        "runs": len(ok),
        "slots": slots,
        "grades": {g: n for g in GRADE_ORDER if (n := sum(1 for r in ok if r["grade"] == g))},
        "not_run": dict(sorted(skipped.items())),
    }


def _tried(conn: sqlite3.Connection, f: analysis.Facts, start: int, end: int) -> list[dict]:
    changes = {(c["event"], c["ts"]): c for c in f.changes}
    out = []
    for e in store.list_events(conn, start, end, kinds=list(USER_EVENT_KINDS)):
        change = changes.get((e.kind, e.ts))
        rates = None
        if change is not None:
            rates = {
                layer: v
                for layer, v in change["rates"].items()
                if v["before"] > 0 or v["after"] > 0
            }
        out.append(
            {
                "ts": e.ts,
                "kind": e.kind,
                "note": e.note,
                "compared": change is not None,
                "rates": rates,
            }
        )
    return out


def _wired(f: analysis.Facts) -> dict:
    groups: dict[str, list] = {"wired": [], "wifi": []}
    for w in f.covered_evenings:
        link = w.majority_link(f.cov)
        if link in groups:
            groups[link].append(w)
    return {
        "available": bool(groups["wired"]),
        "check": f.link_check,
        "evenings": {k: len(v) for k, v in groups.items()},
        "bad_rate": {k: _bad_share([r for w in v for r in w.results]) for k, v in groups.items()},
    }


def _method(f: analysis.Facts, cfg: dict, start: int, end: int) -> dict:
    minutes = range(start // MINUTE_MS * MINUTE_MS, end, MINUTE_MS)
    excluded = Counter(
        reason for m in minutes if f.cov.has_data(m) and (reason := f.cov.exclusion(m)) is not None
    )
    links = Counter(f.cov.link(m) for m in minutes if f.cov.covered(m))
    gap_ms = sum(min(b, end) - max(a, start) for a, b in f.cov.gaps() if b > start and a < end)
    targets = sorted(
        (t for t in f.cov.targets.values() if t.active),
        key=lambda t: (("gateway", "isp_edge", "anchor", "cdn").index(t.kind), t.name, t.af),
    )
    return {
        "ping_interval_s": cfg["ping_interval_s"],
        "trace_interval_min": cfg["trace_interval_s"] // 60,
        "nq_schedule": list(cfg["nq_schedule"]),
        "evening_window": list(cfg["evening_window"]),
        "daytime_window": list(cfg["daytime_window"]),
        "address_family": f.af,
        "targets": [
            {"kind": t.kind, "name": t.name, "af": t.af, "ip": None if is_masked(t.ip) else t.ip}
            for t in targets
        ],
        "excluded_minutes": dict(sorted(excluded.items())),
        "links": {str(k): v for k, v in sorted(links.items(), key=lambda kv: str(kv[0]))},
        "no_data_hours": round(gap_ms / 3_600_000, 1),
    }


def _appendix(conn: sqlite3.Connection, f: analysis.Facts, start: int, end: int) -> list[dict]:
    nq = [r for r in store.read_raw(conn, "nq", start, end) if r["ok"]]
    out = []
    for day in baseline.local_days(start, end):
        lo, hi = max(day, start), min(baseline.next_midnight(day), end)
        minutes = range(lo // MINUTE_MS * MINUTE_MS, hi, MINUTE_MS)
        covered = sum(1 for m in minutes if f.cov.covered(m))
        ev = [w for w in f.evenings if w.day == day and w.covered]
        dt = [w for w in f.daytimes if w.day == day and w.covered]
        runs = [r for r in nq if lo <= r["ts"] < hi]
        out.append(
            {
                "date": _local_date(day),
                "covered_pct": round(100 * covered / len(minutes)) if len(minutes) else 0,
                "evening_bad": _bad_share([r for w in ev for r in w.results]) if ev else None,
                "daytime_bad": _bad_share([r for w in dt for r in w.results]) if dt else None,
                "dl_mbps": _median([r["dl_mbps"] for r in runs]),
                "ul_mbps": _median([r["ul_mbps"] for r in runs]),
                "grade": _median_grade([r["grade"] for r in runs]),
                "lag_moments": sum(1 for ts, _k, _l in f.moments if lo <= ts < hi),
            }
        )
    return out


def parse_range(date_from: str | None, date_to: str | None) -> tuple[int, int]:
    """Inclusive local dates YYYY-MM-DD → [start_ms, end_ms). ValueError with a readable message."""
    if not date_from or not date_to:
        raise ValueError("give both dates, YYYY-MM-DD")
    start = timeutil.start_of_local_day(date_from)
    end = timeutil.end_of_local_day(date_to)
    if end <= start:
        raise ValueError("the start date must not be after the end date")
    if len(baseline.local_days(start, end)) > MAX_DAYS:
        raise ValueError(f"a report covers at most {MAX_DAYS} days")
    return start, end


def filename(date_from: str, date_to: str) -> str:
    return f"whodunnet-report-{date_from}-{date_to}.html"


def write(path: Path, text: str) -> Path:
    """Write atomically (temp file + rename) so a half-written report never replaces a good one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
    return path


def build(conn: sqlite3.Connection, cfg: dict, start_ms: int, end_ms: int) -> dict:
    """The report model for [start_ms, end_ms)."""
    f = analysis.facts(conn, cfg, start_ms, end_ms)
    verdict = analysis.verdict_from(f, cfg, start_ms, end_ms)
    return {
        "version": __version__,
        "from": verdict["coverage"]["from"],
        "to": verdict["coverage"]["to"],
        "summary": verdict,
        "experienced": [
            {"ts": ts, "status": kind, "layers": sorted(set(layers))}
            for ts, kind, layers in f.moments
        ],
        "layers": _layer_table(f),
        "heatmap": _heatmap(f),
        "where": _where(conn, f, start_ms, end_ms),
        "speed": _speed(conn, cfg, start_ms, end_ms),
        "tried": _tried(conn, f, start_ms, end_ms),
        "wired": _wired(f),
        "method": _method(f, cfg, start_ms, end_ms),
        "rights": {"text": RIGHTS_TEXT, "checked": RIGHTS_TEXT_CHECKED},
        "appendix": _appendix(conn, f, start_ms, end_ms),
    }


# ---- HTML ----------------------------------------------------------------------------------------

CSS = """
@page { size: A4; margin: 16mm 14mm; }
* { box-sizing: border-box; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { font: 10.5pt/1.45 -apple-system, "Helvetica Neue", Arial, sans-serif; color: #1d1d1f;
       margin: 0 auto; max-width: 190mm; padding: 12mm 4mm; background: #fff; }
h1 { font-size: 18pt; margin: 0 0 2mm; }
h2 { font-size: 13pt; margin: 7mm 0 2mm; border-bottom: 1px solid #d2d2d7; padding-bottom: 1mm;
     break-after: avoid; }
h3 { font-size: 11pt; margin: 4mm 0 1mm; break-after: avoid; }
p, li { margin: 1mm 0; }
.muted { color: #6e6e73; }
.verdict { font-size: 14pt; font-weight: 600; margin: 2mm 0; }
.badge { display: inline-block; padding: 0 2mm; border-radius: 3mm; font-size: 9pt;
         background: #e8e8ed; margin-left: 2mm; vertical-align: middle; font-weight: normal; }
table { border-collapse: collapse; width: 100%; margin: 2mm 0; font-size: 9.5pt; }
th, td { text-align: left; padding: 1mm 1.5mm; border-bottom: 1px solid #e5e5ea; }
th { font-weight: 600; background: #f5f5f7; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
tr { break-inside: avoid; }
.heat { width: auto; }
.heat td { padding: 0; width: 6mm; height: 4.2mm; border: 1px solid #fff; }
.heat th { font-weight: normal; background: none; font-size: 7.5pt; padding: 0 1mm;
           color: #6e6e73; border: 0; }
.zone-home { color: #6e6e73; }
.zone-isp { color: #b3261e; font-weight: 600; }
.zone-beyond { color: #5b2a86; }
@media print { body { padding: 0; } }
"""


def _e(value) -> str:
    return html.escape("" if value is None else str(value))


def _pct(x: float | None) -> str:
    return "–" if x is None else f"{round(x * 100)}%"


def _num(x: float | None, unit: str = "") -> str:
    return "–" if x is None else f"{x:g}{unit}"


def _heat_colour(x: float | None) -> str:
    if x is None:
        return "#ececf0"
    level = min(1.0, x / 0.5)  # green at 0, red at ≥ 50% bad minutes
    return f"hsl({round(120 * (1 - level))}, 70%, {round(88 - 30 * level)}%)"


def _table(head: Sequence[str], rows: Sequence[Sequence[str]], num_from: int = 1) -> str:
    """Rows hold already-escaped HTML; columns from `num_from` on are right-aligned numbers."""

    def cell(tag: str, i: int, v: str) -> str:
        cls = ' class="num"' if i >= num_from else ""
        return f"<{tag}{cls}>{v}</{tag}>"

    out = ["<table><thead><tr>"]
    out += [cell("th", i, _e(h)) for i, h in enumerate(head)]
    out.append("</tr></thead><tbody>")
    for row in rows:
        out.append("<tr>" + "".join(cell("td", i, v) for i, v in enumerate(row)) + "</tr>")
    out.append("</tbody></table>")
    return "".join(out)


def _bullets(title: str, items: Sequence[str]) -> str:
    if not items:
        return ""
    return f"<h3>{_e(title)}</h3><ul>" + "".join(f"<li>{_e(i)}</li>" for i in items) + "</ul>"


def _s_summary(m: dict) -> str:
    v = m["summary"]
    c = v["coverage"]
    return (
        "<section><h2>1. Summary</h2>"
        f'<p class="verdict">{_e(VERDICT_TITLES.get(v["verdict"], v["verdict"]))} '
        f"{_e(QUALIFIER_WORDS.get(v['qualifier'] or '', ''))}"
        f'<span class="badge">{_e(v["confidence"])} confidence</span></p>'
        f"<p>{_e(v['summary'])}</p>"
        f"<p class='muted'>{_e(m['from'])} to {_e(m['to'])}: {c['evenings_covered']} evenings "
        f"and {c['daytimes_covered']} daytimes with data; {c['evening_coverage_pct']}% of "
        f"evening time covered. IPv{v['address_family']} measurements.</p>"
        + _bullets("Evidence", [e["claim"] for e in v["evidence"]])
        + _bullets("Suggested next steps", v["next_steps"])
        + _bullets("What would make this more certain", v["missing"])
        + "</section>"
    )


def _s_experienced(m: dict) -> str:
    moments = m["experienced"]
    head = "<section><h2>2. What the household experienced</h2>"
    if not moments:
        return head + (
            '<p>No lag moments were marked in this period. (Pressing "It\'s lagging now" when '
            "a call or video stutters lets the report show what the network was doing at that "
            "moment.)</p></section>"
        )
    words = {
        "network_bad": "network slow",
        "network_ok": "network healthy",
        "unknown": "no data at the time",
    }
    rows = [
        [
            _e(_local_time(x["ts"])),
            _e(words[x["status"]]),
            _e(", ".join(LAYER_TITLES.get(layer, layer) for layer in x["layers"]) or "–"),
        ]
        for x in moments
    ]
    bad = sum(1 for x in moments if x["status"] == "network_bad")
    ok = sum(1 for x in moments if x["status"] == "network_ok")
    return (
        head + f"<p>{len(moments)} lag moments marked: the network was slow at {bad}, healthy at "
        f"{ok}, and there was no data for {len(moments) - bad - ok}.</p>"
        + _table(["When", "Network", "Where it was slow (± 2 min)"], rows, num_from=9)
        + "</section>"
    )


def _s_compare(m: dict) -> str:
    rows = [
        [
            _e(LAYER_TITLES[r["layer"]]),
            _pct(r["evening_rate"]),
            _pct(r["daytime_rate"]),
            f"{r['evenings_shown']} of {r['evenings_covered']}",
            f"{r['daytimes_shown']} of {r['daytimes_covered']}",
        ]
        for r in m["layers"]
    ]
    ev, dt = m["method"]["evening_window"], m["method"]["daytime_window"]
    heat = m["heatmap"]
    grid = ['<table class="heat"><tr><th></th>']
    grid += [f"<th>{h:02d}</th>" for h in range(24)]
    grid.append("</tr>")
    for day, values in zip(heat["days"], heat["values"]):
        grid.append(f"<tr><th>{_e(day[5:])}</th>")
        grid += [
            f'<td style="background:{_heat_colour(x)}" title="{_pct(x)}"></td>' for x in values
        ]
        grid.append("</tr>")
    grid.append("</table>")
    return (
        "<section><h2>3. Evening vs daytime</h2>"
        f"<p>Share of measured minutes that were bad, by where the problem was, in the evening "
        f"({_e(ev[0])}–{_e(ev[1])}) and the daytime ({_e(dt[0])}–{_e(dt[1])}).</p>"
        + _table(
            ["Where", "Evening", "Daytime", "Evenings showing it", "Daytimes showing it"], rows
        )
        + "<h3>Bad minutes by hour</h3>"
        + "<p class='muted'>Each square is one hour: green = fine, red = half or more of the "
        "minutes bad, grey = no data.</p>" + "".join(grid) + "</section>"
    )


def _trace_table(trace: dict) -> str:
    zones = {"home": "Home", "isp": "ISP", "beyond": "Beyond ISP"}
    rows = [
        [
            _e(h["ttl"]),
            f'<span class="zone-{h["zone"]}">{zones[h["zone"]]}</span>',
            _e(h["shown"]),
            _num(h["rtt_ms"], " ms"),
        ]
        for h in trace["hops"]
    ]
    return (
        f"<p class='muted'>{_e(_local_time(trace['ts']))} — destination round trip "
        f"{_num(trace['dest_rtt_ms'], ' ms')} (the median of {trace['candidates']} traceroutes in "
        "this window).</p>" + _table(["Hop", "Part", "Address", "Round trip"], rows, num_from=3)
    )


def _s_where(m: dict) -> str:
    v = m["summary"]
    w = m["where"]
    parts = ["<section><h2>4. Where it breaks</h2>"]
    if v["verdict"] in LAYER_TITLES:
        parts.append(f"<p>{_e(v['summary'])}</p>")
    parts.append(
        "<p>Whodunnet pings the home router, the first router inside the ISP, reference servers "
        "and the video services every few seconds. When only the far targets slow down, the "
        "problem is beyond the ISP's first router; when the ISP's router slows down too, it is "
        "inside the ISP; when the home router slows down, it is at home.</p>"
    )
    if w["worst"] is None:
        parts.append("<p>No reference or video targets were measured.</p></section>")
        return "".join(parts)
    worst = w["worst"]
    parts.append(
        f"<p>Worst-affected target: <b>{_e(worst['name'])}</b> — bad in "
        f"{_pct(worst['evening_rate'])} of evening minutes vs {_pct(worst['daytime_rate'])} in "
        "the daytime.</p>"
    )
    if not w["traces"]:
        parts.append("<p>No traceroutes to this target were recorded in this period.</p>")
    else:
        for key, title in (("evening_trace", "Evening route"), ("daytime_trace", "Daytime route")):
            parts.append(f"<h3>{title}</h3>")
            parts.append(_trace_table(w[key]) if w[key] else "<p>No traceroute in this window.</p>")
        parts.append(
            "<p class='muted'>Hops are labelled by position: before the ISP's first router = "
            "home (shown without addresses); from it on, the ISP's private addresses and its own "
            "address block = ISP; the rest = beyond the ISP. Private addresses are never "
            "printed.</p>"
        )
    parts.append("</section>")
    return "".join(parts)


def _s_speed(m: dict) -> str:
    s = m["speed"]
    parts = ["<section><h2>5. Speed &amp; responsiveness</h2>"]
    if not s["runs"]:
        parts.append("<p>No speed tests ran in this period.</p>")
    else:
        parts.append(
            f"<p>{s['runs']} speed tests (macOS <i>networkQuality</i>), grouped by scheduled "
            "time. Bufferbloat is how much latency rises while the line is busy; grade A is under "
            "30 ms, F is 400 ms or more.</p>"
        )
        rows = [
            [
                _e(x["slot"]),
                str(x["runs"]),
                _num(x["dl_mbps"]),
                _num(x["ul_mbps"]),
                _num(x["bufferbloat_ms"]),
                _e(x["grade"] or "–"),
            ]
            for x in s["slots"]
        ]
        parts.append(
            _table(
                ["Time", "Runs", "Download (Mbps)", "Upload (Mbps)", "Bufferbloat (ms)", "Grade"],
                rows,
            )
        )
        grades = ", ".join(f"{g}: {n}" for g, n in s["grades"].items())
        parts.append(f"<p>Grades: {_e(grades or '–')}.</p>")
    if s["not_run"]:
        skipped = ", ".join(f"{n} {reason}" for reason, n in s["not_run"].items())
        parts.append(f"<p class='muted'>Not run: {_e(skipped)}.</p>")
    parts.append("</section>")
    return "".join(parts)


def _s_tried(m: dict) -> str:
    parts = ["<section><h2>6. Already tried</h2>"]
    if not m["tried"]:
        parts.append("<p>No changes (router, package, ISP contact) were recorded.</p></section>")
        return "".join(parts)
    rows = []
    for e in m["tried"]:
        if not e["compared"]:
            effect = "not enough evenings before and after to compare"
        elif not e["rates"]:
            effect = "no bad evening minutes before or after"
        else:
            effect = "; ".join(
                f"{LAYER_TITLES[layer]}: {_pct(r['before'])} → {_pct(r['after'])}"
                for layer, r in e["rates"].items()
            )
        rows.append(
            [
                _e(_local_time(e["ts"])),
                _e(EVENT_TITLES.get(e["kind"], e["kind"])),
                _e(e["note"] or "–"),
                _e(effect),
            ]
        )
    parts.append(
        "<p>Bad evening minutes in the up to 7 covered evenings before and after each change.</p>"
    )
    parts.append(_table(["When", "What", "Note", "Evening bad minutes"], rows, num_from=9))
    parts.append("</section>")
    return "".join(parts)


def _s_wired(m: dict) -> str:
    w = m["wired"]
    head = "<section><h2>7. Wired vs WiFi</h2>"
    if not w["available"]:
        return head + (
            "<p>No evenings were measured on a wired adapter, so WiFi and the rest of the line "
            "can't be compared directly. One evening with an Ethernet adapter would settle "
            "it.</p></section>"
        )
    verdict = {
        "confirms_wifi": "Wired evenings were clean while WiFi evenings were bad: the WiFi is "
        "the problem.",
        "both_bad": "Wired evenings were bad too, so the problem isn't only the WiFi.",
    }.get(w["check"] or "", "Not enough evenings on each to draw a conclusion.")
    rows = [
        [link, str(w["evenings"][key]), _pct(w["bad_rate"][key])]
        for key, link in (("wired", "Wired"), ("wifi", "WiFi"))
    ]
    return (
        head
        + _table(["Connection", "Evenings", "Bad minutes"], rows)
        + f"<p>{_e(verdict)}</p></section>"
    )


def _s_method(m: dict) -> str:
    x = m["method"]
    kinds = {
        "gateway": "home router",
        "isp_edge": "ISP's first router",
        "anchor": "reference server",
        "cdn": "video service",
    }
    targets = "; ".join(
        (kinds[t["kind"]] if t["kind"] in ("gateway", "isp_edge") else f"{t['name']}")
        + (f" ({t['ip']})" if t["ip"] else "")
        for t in x["targets"]
        if t["af"] == x["address_family"] or t["kind"] == "gateway"
    )
    excluded = ", ".join(
        f"{n} minutes {EXCLUSION_WORDS.get(reason, reason)}"
        for reason, n in x["excluded_minutes"].items()
    )
    link_words = {"wifi": "WiFi", "wired": "a wired connection"}
    links = ", ".join(f"{v} minutes on {link_words.get(k, k)}" for k, v in x["links"].items())
    ev, dt = x["evening_window"], x["daytime_window"]
    items = [
        f"Every {x['ping_interval_s']} s, this Mac pings: {targets}.",
        (
            f"Traceroutes every {x['trace_interval_min']} minutes; speed tests at "
            f"{', '.join(x['nq_schedule'])}."
        ),
        (
            "A minute is bad for a target when 2 or more pings are lost, or its latency or jitter "
            "rises well above that target's own quiet-hours (02:00–06:00) level. Where the problem "
            "is comes from which targets are bad together."
        ),
        (
            f"Evening = {ev[0]}–{ev[1]}, daytime = {dt[0]}–{dt[1]}, local time. An evening counts "
            "when at least half its minutes have data."
        ),
        (
            f"Measured over: {links or 'no covered minutes'}. Measured from a laptop over WiFi — "
            "macOS WiFi has inherent short spikes, which is why single lost pings are ignored."
        ),
        "Minutes left out: " + (excluded or "none") + ".",
        (
            f"No data for {x['no_data_hours']:g} hours (Mac asleep, off or away). Gaps are never "
            "counted as outages."
        ),
        (
            "Other devices' traffic (TV, phones, consoles) is not visible; heavy household use can "
            "look like ISP congestion."
        ),
        f"Address family used for the verdict: IPv{x['address_family']}.",
    ]
    return (
        "<section><h2>8. Method &amp; limitations</h2><ul>"
        + "".join(f"<li>{_e(i)}</li>" for i in items)
        + "</ul></section>"
    )


def _s_rights(m: dict) -> str:
    r = m["rights"]
    return (
        "<section><h2>9. Your rights (UK)</h2>"
        + "".join(f"<p>{_e(p)}</p>" for p in r["text"])
        + f"<p class='muted'>This summary was last checked on {_e(r['checked'])}. It is not "
        "legal advice; check Ofcom's website for the current rules.</p></section>"
    )


def _s_appendix(m: dict) -> str:
    rows = [
        [
            _e(d["date"]),
            f"{d['covered_pct']}%",
            _pct(d["evening_bad"]),
            _pct(d["daytime_bad"]),
            _num(d["dl_mbps"]),
            _num(d["ul_mbps"]),
            _e(d["grade"] or "–"),
            str(d["lag_moments"]),
        ]
        for d in m["appendix"]
    ]
    head = [
        "Date",
        "Covered",
        "Evening bad",
        "Daytime bad",
        "Down (Mbps)",
        "Up (Mbps)",
        "Grade",
        "Lag moments",
    ]
    return "<section><h2>10. Appendix — day by day</h2>" + _table(head, rows) + "</section>"


SECTIONS = (
    _s_summary,
    _s_experienced,
    _s_compare,
    _s_where,
    _s_speed,
    _s_tried,
    _s_wired,
    _s_method,
    _s_rights,
    _s_appendix,
)


def render(m: dict) -> str:
    title = f"Whodunnet evidence report {m['from']} to {m['to']}"
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{_e(title)}</title><style>{CSS}</style></head><body>"
        f"<h1>Broadband evidence report</h1><p class='muted'>{_e(m['from'])} to "
        f"{_e(m['to'])} · measured with Whodunnet {_e(m['version'])} on this household's Mac"
        "</p>" + "".join(s(m) for s in SECTIONS) + "</body></html>\n"
    )
