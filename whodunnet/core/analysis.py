"""Findings, verdict selection, confidence and text (spec §6.5–6.7).

`analyse(conn, cfg, start_ms, end_ms)` returns the verdict dict of spec §6.7. It is pure: the same
data and range always give the same verdict. It loads coverage from 7 days before `start_ms`, so
the baselines have their look-back (§6.2).
"""

from __future__ import annotations

import sqlite3
import statistics
import time
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field

from whodunnet.core import attribution, baseline, coverage
from whodunnet.core import thresholds as th
from whodunnet.core.attribution import LAYERS, MinuteResult
from whodunnet.core.coverage import MINUTE_MS, Coverage

DAY_MS = 24 * 3600 * 1000
LEVELS = ("low", "medium", "high")
ISP_LAYERS = ("isp_network", "isp_upstream", "video_path")

NEXT_STEPS = {
    "wifi": [
        "Move closer to the router or use 5 GHz.",
        "Try a different WiFi channel.",
        "Do one evening on a wired adapter to confirm.",
    ],
    "home_network": [
        "Check the cable/adapter and any switch or mesh unit between the Mac and the router."
    ],
    "isp_network": [
        "Raise a fault with your ISP and attach the report — the slowdown is inside their network."
    ],
    "isp_upstream": [
        (
            "Raise a fault with your ISP and attach the report — their links to the wider internet "
            "are congested at peak times."
        )
    ],
    "video_path": [
        (
            "Raise it with your ISP, naming the affected services — their route to those video "
            "services is congested."
        )
    ],
    "bufferbloat": [
        'Turn on SQM / "Smart Queue" / QoS on the router if it has it.',
        "Pause big downloads and backups in the evening.",
    ],
    "device_or_app": [
        (
            "The network was healthy when you saw lag — check the device (updates, storage, "
            "low-power mode) or the app."
        )
    ],
    "no_problem_found": [
        "Keep collecting and keep marking lag moments — they're the best evidence."
    ],
    "insufficient_data": ['Follow the "missing" list.'],
}
LAYER_WORDS = {
    "wifi": "the WiFi between this Mac and your router",
    "home_network": "your home network (cable, adapter, switch or mesh)",
    "isp_network": "your ISP's own network",
    "isp_upstream": "beyond your ISP's network (their links to the wider internet)",
    "video_path": "the route to the video services",
}


# ---- windows ----------------------------------------------------------------------------------


def _local(day_ms: int, hhmm: str) -> int:
    t = time.localtime(day_ms / 1000)
    hours, minutes = (int(x) for x in hhmm.split(":"))
    return int(time.mktime((t.tm_year, t.tm_mon, t.tm_mday, hours, minutes, 0, 0, 0, -1)) * 1000)


@dataclass
class Window:
    day: int  # local midnight of the day it starts on
    start: int
    end: int
    minutes: list[int]
    covered: bool = False
    results: list[MinuteResult] = field(default_factory=list)

    def counts(self, layer: str) -> tuple[int, int]:
        """(minutes with this layer, covered non-inconclusive minutes)."""
        judged = [r for r in self.results if r.layer != "inconclusive"]
        return sum(1 for r in judged if r.layer == layer), len(judged)

    def rate(self, layer: str) -> float:
        hit, total = self.counts(layer)
        return hit / total if total else 0.0

    def majority_link(self, cov: Coverage) -> str | None:
        links = Counter(cov.link(r.minute) for r in self.results)
        return min(links.items(), key=lambda kv: (-kv[1], str(kv[0])))[0] if links else None


def windows(
    cov: Coverage, by_minute: dict[int, MinuteResult], start: int, end: int, span: Sequence[str]
) -> list[Window]:
    """One window per local day; it belongs to the date it starts on. Only whole windows inside
    the range count."""
    out = []
    for day in baseline.local_days(start, end):
        w_start, w_end = _local(day, span[0]), _local(day, span[1])
        if w_end <= w_start:  # wraps past midnight
            w_end = _local(baseline.next_midnight(day), span[1])
        if w_start < start or w_end > end:
            continue
        minutes = list(range(w_start, w_end, MINUTE_MS))
        w = Window(day, w_start, w_end, minutes)
        w.covered = cov.window_covered(minutes)
        w.results = [by_minute[m] for m in minutes if m in by_minute]
        out.append(w)
    return out


def overall_rate(ws: Sequence[Window], layer: str) -> float:
    hit = total = 0
    for w in ws:
        h, t = w.counts(layer)
        hit, total = hit + h, total + t
    return hit / total if total else 0.0


# ---- findings (spec §6.5) -----------------------------------------------------------------------


@dataclass
class LayerFinding:
    layer: str
    qualifier: str  # evening | all_day
    evening_rate: float
    daytime_rate: float
    evenings_shown: int
    evenings_covered: int
    daytimes_shown: int
    no_daytime: bool


def layer_findings(evenings: Sequence[Window], daytimes: Sequence[Window]) -> list[LayerFinding]:
    ev = [w for w in evenings if w.covered]
    dt = [w for w in daytimes if w.covered]
    out = []
    for layer in LAYERS:
        shown_ev = sum(1 for w in ev if w.rate(layer) >= th.LAYER_SHOWN_RATE)
        shown_dt = sum(1 for w in dt if w.rate(layer) >= th.LAYER_SHOWN_RATE)
        e_rate, d_rate = overall_rate(ev, layer), overall_rate(dt, layer)
        if shown_ev >= th.PROBLEM_MIN_WINDOWS and (not dt or e_rate >= th.EVENING_RATIO * d_rate):
            qualifier = "evening"
        elif shown_ev >= th.PROBLEM_MIN_WINDOWS and shown_dt >= th.PROBLEM_MIN_WINDOWS:
            qualifier = "all_day"
        else:
            continue
        out.append(
            LayerFinding(layer, qualifier, e_rate, d_rate, shown_ev, len(ev), shown_dt, not dt)
        )
    return out


def bufferbloat_finding(conn: sqlite3.Connection, start: int, end: int) -> dict | None:
    rows = conn.execute(
        "SELECT grade, bufferbloat_ms, link FROM nq WHERE ok = 1 AND ts >= ? AND ts < ?",
        (start, end),
    ).fetchall()
    if len(rows) < th.BUFFERBLOAT_MIN_RUNS:
        return None
    bad = [r for r in rows if r["grade"] in ("D", "F")]
    if len(bad) < th.BUFFERBLOAT_BAD_SHARE * len(rows):
        return None
    wired = bool(bad) and all(r["link"] == "wired" for r in bad)
    values = [r["bufferbloat_ms"] for r in rows if r["bufferbloat_ms"] is not None]
    return {
        "runs": len(rows),
        "bad_runs": len(bad),
        "median_bufferbloat_ms": statistics.median(values) if values else None,
        "grades": dict(sorted(Counter(r["grade"] for r in rows).items())),
        "label": "bufferbloat under load ("
        + ("home router or ISP shaper)" if wired else "home router, WiFi or ISP shaper)"),
    }


def lag_markers(
    conn: sqlite3.Connection, by_minute: dict[int, MinuteResult], start: int, end: int
) -> dict:
    moments = []
    events = conn.execute(
        "SELECT ts FROM events WHERE kind = 'lag' AND ts >= ? AND ts < ? ORDER BY ts", (start, end)
    ).fetchall()
    for (ts,) in events:
        lo, hi = ts - th.LAG_WINDOW_MS, ts + th.LAG_WINDOW_MS
        first = lo // MINUTE_MS * MINUTE_MS
        near = [by_minute[m] for m in range(first, hi + 1, MINUTE_MS) if m in by_minute]
        bad = [r.layer for r in near if r.layer not in ("ok", "inconclusive")]
        if bad:
            moments.append(("network_bad", bad))
        elif any(r.layer == "ok" for r in near):
            moments.append(("network_ok", []))
        else:
            moments.append(("unknown", []))
    known = [m for m in moments if m[0] != "unknown"]
    n_bad = sum(1 for m in known if m[0] == "network_bad")
    n_ok = len(known) - n_bad
    layers = Counter(layer for kind, ls in moments if kind == "network_bad" for layer in set(ls))
    lag_layer = min(layers.items(), key=lambda kv: (-kv[1], kv[0]))[0] if layers else None
    enough = len(known) >= th.LAG_MIN_KNOWN
    return {
        "known": len(known),
        "network_bad": n_bad,
        "network_ok": n_ok,
        "unknown": len(moments) - len(known),
        "lag_layer": lag_layer,
        "device_or_app": enough and n_ok >= th.DEVICE_OK_SHARE * len(known),
        "confirms_network": enough and n_bad > th.LAG_BAD_SHARE * len(known),
    }


def wired_vs_wifi(cov: Coverage, evenings: Sequence[Window]) -> str | None:
    """'confirms_wifi' | 'both_bad' | None (spec §6.5)."""
    by_link: dict[str, list[Window]] = {"wired": [], "wifi": []}
    for w in evenings:
        link = w.majority_link(cov) if w.covered else None
        if link in by_link:
            by_link[link].append(w)
    if not by_link["wired"] or len(by_link["wifi"]) < th.PROBLEM_MIN_WINDOWS:
        return None
    if overall_rate(by_link["wifi"], "wifi") < th.LAYER_SHOWN_RATE:
        return None
    judged = [r for w in by_link["wired"] for r in w.results if r.layer != "inconclusive"]
    wired_bad_rate = sum(1 for r in judged if r.layer != "ok") / len(judged) if judged else 0.0
    return "both_bad" if wired_bad_rate >= th.LAYER_SHOWN_RATE else "confirms_wifi"


def before_after(conn: sqlite3.Connection, evenings: Sequence[Window]) -> list[dict]:
    covered = [w for w in evenings if w.covered]
    out = []
    for kind, ts, note in conn.execute(
        "SELECT kind, ts, note FROM events WHERE kind IN ('router_change', 'package_change', "
        "'isp_contact') ORDER BY ts"
    ):
        before = [w for w in covered if w.end <= ts][-th.BEFORE_AFTER_MAX :]
        after = [w for w in covered if w.start >= ts][: th.BEFORE_AFTER_MAX]
        if len(before) < th.BEFORE_AFTER_MIN or len(after) < th.BEFORE_AFTER_MIN:
            continue
        rates = {
            layer: {
                "before": round(overall_rate(before, layer), 4),
                "after": round(overall_rate(after, layer), 4),
            }
            for layer in LAYERS
        }
        out.append({"event": kind, "ts": ts, "note": note, "rates": rates})
    return out


# ---- confidence (spec §6.6) ---------------------------------------------------------------------


def shift(level: str, by: int) -> str:
    return LEVELS[max(0, min(len(LEVELS) - 1, LEVELS.index(level) + by))]


def cap(level: str, at: str) -> str:
    return LEVELS[min(LEVELS.index(level), LEVELS.index(at))]


def layer_confidence(f: LayerFinding) -> str:
    share = f.evenings_shown / f.evenings_covered if f.evenings_covered else 0.0
    if f.evenings_covered >= th.HIGH_MIN_EVENINGS and share >= th.HIGH_SHOWN_SHARE:
        return "high"
    if f.evenings_covered >= th.PROBLEM_MIN_WINDOWS and share >= th.MEDIUM_SHOWN_SHARE:
        return "medium"
    return "low"


# ---- verdict ------------------------------------------------------------------------------------


def _pct(x: float) -> str:
    return f"{round(x * 100)}%"


def _span(window: Sequence[str]) -> str:
    return f"{window[0]}–{window[1]}"


@dataclass
class _Facts:
    """Everything the selection and the text need, computed once."""

    cov: Coverage
    af: int
    results: list[MinuteResult]
    evenings: list[Window]
    daytimes: list[Window]
    findings: list[LayerFinding]
    bloat: dict | None
    lag: dict
    link_check: str | None
    changes: list[dict]
    gateway_baseline: bool
    gateway_ever_blocked: bool
    not_measurable: list[str]

    @property
    def covered_evenings(self) -> list[Window]:
        return [w for w in self.evenings if w.covered]


def _facts(conn: sqlite3.Connection, cfg: dict, start: int, end: int) -> _Facts:
    cov = coverage.load(conn, start - th.BASELINE_LOOKBACK_DAYS * DAY_MS, end)
    bases = baseline.compute(cov, cfg, start, end)
    results = attribution.attribute(cov, bases, start, end, attribution.read_wifi(conn, start, end))
    af = attribution.choose_family(results)
    by_minute = {r.minute: r for r in results[af]}
    evenings = windows(cov, by_minute, start, end, cfg["evening_window"])
    daytimes = windows(cov, by_minute, start, end, cfg["daytime_window"])
    gid = cov.gateway_id
    gateway_baseline = gid is not None and any(
        v is not None for (tid, _day, _epoch), v in bases.items() if tid == gid
    )
    evening_minutes = [m for w in evenings if w.covered for m in w.minutes if cov.covered(m)]
    blocked = sum(1 for m in evening_minutes if cov.gateway_blocked(m))
    not_measurable = (
        ["wifi", "home_network"]
        if evening_minutes and blocked > th.NOT_MEASURABLE_BLOCKED_SHARE * len(evening_minutes)
        else []
    )
    return _Facts(
        cov=cov,
        af=af,
        results=results[af],
        evenings=evenings,
        daytimes=daytimes,
        findings=sorted(layer_findings(evenings, daytimes), key=lambda f: -f.evening_rate),
        bloat=bufferbloat_finding(conn, start, end),
        lag=lag_markers(conn, by_minute, start, end),
        link_check=wired_vs_wifi(cov, evenings),
        changes=before_after(conn, evenings),
        gateway_baseline=gateway_baseline,
        gateway_ever_blocked=any(start <= m < end for m in cov.blocked),
        not_measurable=not_measurable,
    )


def _select(f: _Facts) -> tuple[str, str | None, str, LayerFinding | None, str | None, list[str]]:
    """(verdict, qualifier, confidence, chosen layer finding, lag layer, extra notes)."""
    notes: list[str] = []
    evening = [x for x in f.findings if x.qualifier == "evening"]
    all_day = [x for x in f.findings if x.qualifier == "all_day"]
    n_ev = len(f.covered_evenings)
    if n_ev < th.PROBLEM_MIN_WINDOWS or (not f.gateway_baseline and not f.gateway_ever_blocked):
        return "insufficient_data", None, "low", None, None, notes
    if evening or all_day:
        chosen = (evening or all_day)[0]
        confidence = layer_confidence(chosen)
        if f.lag["confirms_network"] and f.lag["lag_layer"] == chosen.layer:
            confidence = shift(confidence, +1)
        if chosen.layer == "wifi" and f.link_check == "confirms_wifi":
            confidence = shift(confidence, +1)
            notes.append("confirms_wifi")
        elif chosen.layer == "wifi" and f.link_check == "both_bad":
            confidence = shift(confidence, -1)
            notes.append("both_bad")
        if f.lag["device_or_app"]:
            confidence = shift(confidence, -1)
            notes.append("lag_points_to_device")
        if chosen.layer in ISP_LAYERS and f.bloat:
            confidence = cap(confidence, "medium")
            notes.append("pause_downloads")
        if chosen.no_daytime:
            confidence = cap(confidence, "medium")
        return chosen.layer, chosen.qualifier, confidence, chosen, None, notes
    if f.lag["confirms_network"] and f.lag["lag_layer"]:
        return f.lag["lag_layer"], "at_lag_moments", "medium", None, f.lag["lag_layer"], notes
    if f.bloat:
        level = "high" if f.bloat["runs"] >= th.BUFFERBLOAT_HIGH_RUNS else "medium"
        return "bufferbloat", None, level, None, None, notes
    if f.lag["device_or_app"]:
        level = "high" if f.lag["known"] >= th.DEVICE_HIGH_KNOWN else "medium"
        return "device_or_app", None, level, None, None, notes
    if n_ev >= th.HIGH_MIN_EVENINGS:
        level = "high" if f.lag["known"] >= th.LAG_MIN_KNOWN else "medium"
    else:
        level = "low"
    return "no_problem_found", None, level, None, None, notes


def _missing(f: _Facts, verdict: str, chosen: LayerFinding | None, notes: list[str], end: int):
    missing = []
    n_ev = len(f.covered_evenings)
    goal = th.PROBLEM_MIN_WINDOWS if n_ev < th.PROBLEM_MIN_WINDOWS else th.HIGH_MIN_EVENINGS
    if n_ev < goal:
        missing.append(f"Need {goal - n_ev} more covered evenings")
    if f.lag["known"] < th.LAG_MIN_KNOWN:
        missing.append("Mark lag moments with the 'It's lagging now' button")
    all_minutes = [m for w in f.evenings for m in w.minutes]
    pct = (
        round(100 * sum(1 for m in all_minutes if f.cov.covered(m)) / len(all_minutes))
        if all_minutes
        else 0
    )
    if all_minutes and pct < th.EVENING_COVERAGE_TARGET_PCT:
        missing.append(
            f"{100 - pct}% of evening time had no data — keep the Mac awake, on charger, lid open"
        )
    if f.gateway_ever_blocked:
        missing.append("Your router doesn't answer Whodunnet — allow Local Network access")
    if any(
        t.kind == "cdn"
        and f.cov.discovery_status(t.id, end - MINUTE_MS) in ("unavailable", "approximate")
        for t in f.cov.targets.values()
    ):
        missing.append("Couldn't find your Netflix/YouTube server")
    if verdict == "wifi" and not any(w.majority_link(f.cov) == "wired" for w in f.covered_evenings):
        missing.append("One evening on a wired adapter would confirm the WiFi verdict")
    if chosen is not None and chosen.no_daytime:
        missing.append("No daytime data to compare")
    if "pause_downloads" in notes:
        missing.append(
            "Pause big downloads/backups (or enable SQM) for one evening to rule out home load"
        )
    if f.results:
        share = sum(1 for r in f.results if r.layer == "inconclusive") / len(f.results)
        if share > th.INCONCLUSIVE_MISSING_SHARE:
            missing.append(f"{_pct(share)} of minutes were inconclusive")
    if f.lag["unknown"]:
        missing.append(f"{f.lag['unknown']} lag moments fell in periods with no data")
    return missing, pct


def analyse(conn: sqlite3.Connection, cfg: dict, start_ms: int, end_ms: int) -> dict:
    f = _facts(conn, cfg, start_ms, end_ms)
    verdict, qualifier, confidence, chosen, lag_layer, notes = _select(f)
    ev_span, dt_span = _span(cfg["evening_window"]), _span(cfg["daytime_window"])

    evidence: list[dict] = []
    if chosen is not None:
        evidence.append(
            {
                "claim": (
                    f"{_pct(chosen.evening_rate)} of evening minutes ({ev_span}) were bad in "
                    f"{LAYER_WORDS[chosen.layer]}, vs {_pct(chosen.daytime_rate)} in the daytime "
                    f"({dt_span})."
                ),
                "metric": "layer_rate",
                "evening": round(chosen.evening_rate, 4),
                "daytime": round(chosen.daytime_rate, 4),
                "evenings_shown": chosen.evenings_shown,
                "evenings_covered": chosen.evenings_covered,
            }
        )
        when = "Evenings are" if qualifier == "evening" else "All day it is"
        summary = (
            f"{when} worse in {LAYER_WORDS[chosen.layer]}: {_pct(chosen.evening_rate)} bad "
            f"minutes {ev_span} vs {_pct(chosen.daytime_rate)} in the daytime."
        )
    elif qualifier == "at_lag_moments":
        summary = (
            f"Short slowdowns in {LAYER_WORDS[lag_layer]} matched {f.lag['network_bad']} of the "
            f"{f.lag['known']} lag moments you marked."
        )
    elif verdict == "bufferbloat":
        b = f.bloat
        summary = (
            f"Latency jumps when the line is busy: grade D or F on {b['bad_runs']} of {b['runs']} "
            f"speed tests ({b['label']})."
        )
        evidence.append(
            {
                "claim": summary,
                "metric": "bufferbloat",
                "runs": b["runs"],
                "bad_runs": b["bad_runs"],
                "median_bufferbloat_ms": b["median_bufferbloat_ms"],
                "grades": b["grades"],
            }
        )
    elif verdict == "device_or_app":
        summary = (
            f"The network was healthy at {f.lag['network_ok']} of {f.lag['known']} lag moments — "
            "the device or the app is the likelier cause."
        )
    elif verdict == "no_problem_found":
        summary = f"No network problem found over {len(f.covered_evenings)} covered evenings."
    else:
        summary = "Not enough data for a verdict yet."
    notes_text = {
        "confirms_wifi": "Wired evenings were clean, so the WiFi is the problem.",
        "both_bad": "Wired evenings were bad too, so it isn't only the WiFi.",
        "lag_points_to_device": "At most lag moments the network looked healthy.",
    }
    evidence.extend({"claim": notes_text[n], "metric": n} for n in notes if n in notes_text)
    evidence.extend(
        {"claim": f"Before/after {c['event']}", "metric": "before_after", **c} for c in f.changes
    )

    secondary = [
        {
            "finding": x.layer,
            "qualifier": x.qualifier,
            "detail": f"shown on {x.evenings_shown} of {x.evenings_covered} evenings",
        }
        for x in f.findings
        if x is not chosen
    ]
    if f.bloat and verdict != "bufferbloat":
        secondary.append(
            {
                "finding": "bufferbloat",
                "detail": f"grade D or F on {f.bloat['bad_runs']} of {f.bloat['runs']} runs",
            }
        )
    if f.lag["device_or_app"] and verdict != "device_or_app":
        secondary.append({"finding": "device_or_app", "detail": "network healthy at lag moments"})

    missing, evening_pct = _missing(f, verdict, chosen, notes, end_ms)
    fmt = "%Y-%m-%d"
    return {
        "verdict": verdict,
        "qualifier": qualifier,
        "confidence": confidence,
        "address_family": f.af,
        "summary": summary,
        "evidence": evidence,
        "secondary": secondary,
        "lag": {
            k: f.lag[k] for k in ("known", "network_bad", "network_ok", "unknown", "lag_layer")
        },
        "not_measurable": f.not_measurable,
        "next_steps": NEXT_STEPS[verdict],
        "coverage": {
            "from": time.strftime(fmt, time.localtime(start_ms / 1000)),
            "to": time.strftime(fmt, time.localtime((end_ms - 1) / 1000)),
            "evenings_covered": len(f.covered_evenings),
            "daytimes_covered": sum(1 for w in f.daytimes if w.covered),
            "evening_coverage_pct": evening_pct,
        },
        "missing": missing,
    }
