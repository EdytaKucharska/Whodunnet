"""Doctor checks shared by the CLI and the collector (spec §9; §5 `meta.doctor_json`).

Each check returns a `Check(check, status, message, fix)` with status ok | warn | fail | info.
The collector runs them at start and every 10 min and stores the list as JSON in
`meta.doctor_json`. That is what the dashboard shows (`web/` never runs commands). `cli doctor`
runs them directly (M1.8). A check that crashes becomes a `warn`, never an exception.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

import whodunnet
from whodunnet.core import store
from whodunnet.paths import Paths
from whodunnet.probes import power
from whodunnet.probes.parsers import ifconfig
from whodunnet.probes.runner import Runner, run_command

MIN_PYTHON = (3, 9)  # the collector runs on macOS's /usr/bin/python3
STATUSES = ("ok", "warn", "fail", "info")
HEARTBEAT_FRESH_MS = 30_000
GATEWAY_WINDOW_MS = 5 * 60_000
BLOCKED_WINDOW_MS = 10 * 60_000
MIN_FREE_BYTES = 1_000_000_000
FIREWALL = "/usr/libexec/ApplicationFirewall/socketfilterfw"

REQUIRED_COMMANDS = (
    "ping",
    "traceroute",
    "dig",
    "route",
    "networksetup",
    "system_profiler",
    "netstat",
    "pmset",
    "arp",
    "ifconfig",
    "scutil",
    "caffeinate",
    "launchctl",
)
OPTIONAL_COMMANDS = ("ping6", "traceroute6", "networkQuality")


@dataclass(frozen=True)
class Check:
    check: str
    status: str
    message: str
    fix: str | None = None


@dataclass
class Context:
    conn: sqlite3.Connection | None
    paths: Paths
    cfg: dict[str, Any]
    now_ms: int
    runner: Runner = run_command
    which: Callable[[str], str | None] = shutil.which
    link_medium: str | None = None
    vpn: int = 0
    collector: bool = False  # True when the collector itself runs the checks


# ---- individual checks ------------------------------------------------------------------------


def check_xcode(ctx: Context) -> Check:
    if ctx.runner(["xcode-select", "-p"], 10).ok:
        return Check("xcode_tools", "ok", "Command Line Tools are installed.")
    return Check(
        "xcode_tools",
        "fail",
        "Xcode Command Line Tools are not installed (needed for /usr/bin/python3).",
        "Run: xcode-select --install",
    )


def check_python(ctx: Context) -> Check:
    version = ".".join(str(v) for v in sys.version_info[:3])
    if tuple(sys.version_info[:2]) >= MIN_PYTHON:
        return Check("python", "ok", f"Python {version}.")
    return Check(
        "python", "fail", f"Python {version} is too old.", "Python 3.9 or newer is needed."
    )


def check_commands(ctx: Context) -> Check:
    missing = [c for c in REQUIRED_COMMANDS if not ctx.which(c)]
    if missing:
        return Check(
            "commands",
            "fail",
            "Missing commands: " + ", ".join(missing) + ".",
            "These ship with macOS; check PATH or the macOS version (13+).",
        )
    optional = [c for c in OPTIONAL_COMMANDS if not ctx.which(c)]
    if optional:
        return Check(
            "commands",
            "warn",
            "Missing: " + ", ".join(optional) + ". Related probes will be skipped.",
            "networkQuality needs macOS 12 or newer.",
        )
    return Check("commands", "ok", "All required commands are present.")


def _last_heartbeat(conn: sqlite3.Connection) -> int | None:
    row = conn.execute("SELECT MAX(ts) FROM heartbeat").fetchone()
    return row[0] if row else None


def check_collector(ctx: Context) -> Check:
    if ctx.collector:
        return Check("collector", "ok", "The collector is running.")
    last = _last_heartbeat(ctx.conn) if ctx.conn else None
    if last is not None and ctx.now_ms - last < HEARTBEAT_FRESH_MS:
        return Check("collector", "ok", "The collector is running.")
    age = "never" if last is None else f"{(ctx.now_ms - last) // 60_000} min ago"
    return Check(
        "collector",
        "fail",
        f"The collector is not running (last heartbeat: {age}).",
        "Run: python3 -m whodunnet install  (or `run --foreground` to test).",
    )


def _ping_counts(conn: sqlite3.Connection, target_id: int, since_ms: int) -> tuple[int, int]:
    row = conn.execute(
        "SELECT COUNT(*), COUNT(rtt_ms) FROM ping WHERE target_id = ? AND ts >= ?",
        (target_id, since_ms),
    ).fetchone()
    return row[0], row[1]


def check_gateway(ctx: Context) -> list[Check]:
    """Gateway reachable *from the agent* (its own pings), and Local Network blocking."""
    if ctx.conn is None:
        return [Check("gateway", "info", "No database yet.")]
    gateway = store.find_target(ctx.conn, "gateway", "gateway", 4)
    if gateway is None or not gateway.active:
        return [
            Check(
                "gateway",
                "warn",
                "No router (default gateway) found.",
                "Check that the Mac is connected to your home network.",
            )
        ]
    sent, replies = _ping_counts(ctx.conn, gateway.id, ctx.now_ms - GATEWAY_WINDOW_MS)
    if sent == 0:
        return [
            Check("gateway", "info", "No router pings stored yet (they appear within a minute).")
        ]
    if replies:
        return [
            Check(
                "gateway",
                "ok",
                f"The router answers the agent's pings ({replies}/{sent} in 5 min).",
            ),
            Check("local_network", "ok", "Local Network access works."),
        ]
    downstream = [
        t for t in store.list_targets(ctx.conn, active_only=True) if t.kind in ("anchor", "cdn")
    ]
    answering = sum(
        1 for t in downstream if _ping_counts(ctx.conn, t.id, ctx.now_ms - BLOCKED_WINDOW_MS)[1] > 0
    )
    if downstream and answering * 2 > len(downstream):
        return [
            Check("gateway", "fail", "The router never answers the agent, but the internet does."),
            Check(
                "local_network",
                "fail",
                "macOS Local Network privacy is probably blocking the collector.",
                "System Settings → Privacy & Security → Local Network → turn on python3 "
                "(or Python), then run: python3 -m whodunnet install",
            ),
        ]
    return [
        Check(
            "gateway",
            "warn",
            "Neither the router nor the internet answer right now.",
            "Check the WiFi connection.",
        )
    ]


def check_power(ctx: Context) -> Check:
    if power.on_battery(ctx.runner):
        return Check(
            "power",
            "warn",
            "On battery (or unknown): the Mac may sleep and speed tests are skipped.",
            "Keep the Mac on its charger during the evenings you want measured.",
        )
    return Check("power", "ok", "On charger: the collector keeps the Mac awake.")


def check_lid(ctx: Context) -> Check:
    return Check(
        "lid",
        "info",
        "A closed lid sleeps the Mac regardless of settings; gaps are shown as 'no data'.",
        "Leave the lid open (screen can turn off) in the evenings.",
    )


def check_double_nat(ctx: Context) -> Check:
    if ctx.conn is not None and store.get_meta(ctx.conn, "double_nat") == "1":
        return Check(
            "double_nat",
            "warn",
            "Possible double NAT: a second router sits between this Mac and the ISP router.",
            "If you have a mesh/extender in router mode, set it to bridge/access-point mode.",
        )
    return Check("double_nat", "ok", "No double NAT detected.")


def check_vpn(ctx: Context) -> Check:
    if ctx.vpn:
        return Check(
            "vpn",
            "warn",
            "A VPN is active: those minutes are excluded from the analysis.",
            "Turn the VPN off while measuring, if you can.",
        )
    return Check("vpn", "ok", "No VPN.")


def check_private_relay(ctx: Context) -> Check:
    return Check(
        "private_relay",
        "info",
        "iCloud Private Relay doesn't affect Whodunnet's probes.",
    )


def check_awdl(ctx: Context) -> Check:
    parsed = ifconfig.parse(ctx.runner(["ifconfig", "awdl0"], 5).output)
    if parsed.ok and parsed.is_active("awdl0"):
        return Check(
            "awdl",
            "info",
            "AWDL (AirDrop/Handoff) is active: it causes short WiFi latency spikes.",
            "Optional: turn AirDrop to 'Receiving Off' while measuring.",
        )
    return Check("awdl", "ok", "AWDL is not active.")


def check_wifi_band(ctx: Context) -> Check:
    if ctx.link_medium == "wired":
        return Check("wifi_band", "ok", "Connected by cable.")
    row = (
        ctx.conn.execute(
            "SELECT band FROM wifi WHERE ok = 1 AND band IS NOT NULL ORDER BY ts DESC LIMIT 1"
        ).fetchone()
        if ctx.conn
        else None
    )
    if row is None:
        return Check("wifi_band", "info", "No WiFi reading yet.")
    if row[0] == "2.4":
        return Check(
            "wifi_band",
            "warn",
            "The Mac is on 2.4 GHz WiFi, which is slower and more crowded.",
            "Move closer to the router or prefer the 5 GHz network.",
        )
    return Check("wifi_band", "ok", f"WiFi band: {row[0]} GHz.")


def check_firewall(ctx: Context) -> Check:
    result = ctx.runner([FIREWALL, "--getglobalstate"], 5)
    text = result.output.lower()
    if "enabled" in text or "state = 1" in text or "state = 2" in text:
        return Check(
            "firewall",
            "warn",
            "The macOS firewall is on: it will ask to allow incoming connections for python3.",
            "Click Allow when asked (needed only for the phone lag button).",
        )
    if "disabled" in text or "state = 0" in text:
        return Check("firewall", "ok", "The macOS firewall is off.")
    return Check("firewall", "info", "Couldn't read the firewall state.")


def check_disk(ctx: Context) -> Check:
    folder = ctx.paths.data_dir if ctx.paths.data_dir.exists() else Path.home()
    free = shutil.disk_usage(folder).free
    if free < MIN_FREE_BYTES:
        return Check(
            "disk",
            "warn",
            f"Only {free / 1e9:.1f} GB free.",
            "Free some space; the database grows ~40 MB/day (raw pings are pruned after 14 days).",
        )
    return Check("disk", "ok", f"{free / 1e9:.0f} GB free.")


def check_app_dir(ctx: Context) -> Check:
    here = Path(whodunnet.__file__).resolve().parent
    if ctx.paths.app_dir in here.parents:
        return Check("app_dir", "ok", "Running the installed copy.")
    return Check(
        "app_dir",
        "info",
        f"Running from {here.parent}, not the installed copy.",
        "`install` copies the app so launchd never runs it from Documents/Desktop.",
    )


def check_nq_data_use(ctx: Context) -> Check:
    if ctx.conn is None:
        return Check("nq_data_use", "info", "No speed tests yet.")
    rows = ctx.conn.execute(
        "SELECT raw_json FROM nq WHERE ok = 1 AND raw_json IS NOT NULL ORDER BY ts DESC LIMIT 10"
    ).fetchall()
    totals = []
    for (raw,) in rows:
        try:
            data = json.loads(raw)
            totals.append(
                float(data.get("dl_bytes_transferred", 0))
                + float(data.get("ul_bytes_transferred", 0))
            )
        except (ValueError, TypeError, AttributeError):
            continue
    if not totals:
        return Check("nq_data_use", "info", "No speed tests yet, so no data-use estimate.")
    per_run = sum(totals) / len(totals)
    per_day = per_run * len(ctx.cfg.get("nq_schedule", []))
    return Check(
        "nq_data_use",
        "info",
        f"Speed tests use ~{per_run / 1e9:.2f} GB each, ~{per_day / 1e9:.1f} GB/day.",
        "Remove times from nq_schedule in config.json to use less.",
    )


def check_targets(ctx: Context) -> Check:
    if ctx.conn is None:
        return Check("targets", "info", "No targets discovered yet.")
    targets = store.list_targets(ctx.conn, active_only=False)
    if not targets:
        return Check("targets", "info", "No targets discovered yet.")
    lines = [
        f"{t.kind}/{t.name}/v{t.af}: {t.ip or '-'} ({t.status}{'' if t.active else ', inactive'})"
        for t in targets
    ]
    return Check("targets", "info", "; ".join(lines))


CHECKS: Sequence[Callable[[Context], Check | list[Check]]] = (
    check_xcode,
    check_python,
    check_commands,
    check_collector,
    check_gateway,
    check_power,
    check_lid,
    check_double_nat,
    check_vpn,
    check_private_relay,
    check_awdl,
    check_wifi_band,
    check_firewall,
    check_disk,
    check_app_dir,
    check_nq_data_use,
    check_targets,
)


def run_checks(ctx: Context, checks: Sequence[Callable] = CHECKS) -> list[Check]:
    results: list[Check] = []
    for check in checks:
        try:
            out = check(ctx)
        except Exception as exc:  # noqa: BLE001 - doctor must report, not crash
            name = check.__name__.removeprefix("check_")
            results.append(Check(name, "warn", f"Check failed: {type(exc).__name__}: {exc}"))
            continue
        results.extend(out if isinstance(out, list) else [out])
    return results


def to_json(results: Sequence[Check]) -> str:
    return json.dumps([asdict(r) for r in results])


def store_results(conn: sqlite3.Connection, results: Sequence[Check]) -> None:
    store.set_meta(conn, "doctor_json", to_json(results))
