"""Command-line interface: `python3 -m whodunnet <command>` (spec §9).

Commands whose task hasn't landed yet are stubs that exit with status 2.
"""

from __future__ import annotations

import argparse
import csv
import logging
import logging.handlers
import os
import sqlite3
import sys
from pathlib import Path

from whodunnet import __version__, config, doctor, timeutil
from whodunnet import paths as paths_mod
from whodunnet.core import store

EVENT_KINDS = ["router_change", "package_change", "isp_contact", "other"]

# command -> (help text, task that implements it)
COMMANDS = {
    "install": ("Install and start the background collector.", "M1.8"),
    "uninstall": ("Stop and remove the background collector.", "M1.8"),
    "run": ("Run the collector (what launchd runs).", "M1.7/M1.8"),
    "status": ("Show collector state, coverage and the current verdict.", "M1.8/M2.5"),
    "doctor": ("Check the setup and explain how to fix problems.", "M1.8"),
    "dashboard": ("Open the local dashboard in the browser.", "M3.4"),
    "event": ("Record something that changed (router, package, ISP contact, note).", "M1.8"),
    "lag": ('Record "it\'s lagging now".', "M1.8"),
    "report": ("Write the evidence report for a date range.", "M4.2"),
    "export": ("Export data as CSV, one file per table.", "M1.8"),
    "purge": ("Delete data before a date.", "M1.8"),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m whodunnet",
        description="Find out who is to blame for evening internet lag.",
    )
    parser.add_argument("--version", action="version", version=f"whodunnet {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    subparsers = {}
    for name, (help_text, _task) in COMMANDS.items():
        p = sub.add_parser(name, help=help_text, description=help_text)
        p.add_argument(
            "--data-dir",
            metavar="DIR",
            help="Use DIR for the database, config, reports and logs (or set WHODUNNET_DATA_DIR).",
        )
        subparsers[name] = p

    subparsers["uninstall"].add_argument(
        "--purge", action="store_true", help="Also delete the database, config, reports and logs."
    )
    subparsers["run"].add_argument(
        "--foreground", action="store_true", help="Also log to the terminal."
    )
    subparsers["run"].add_argument(
        "--nq-now", action="store_true", help="Run one networkQuality test immediately."
    )
    subparsers["event"].add_argument("note", help="What happened.")
    subparsers["event"].add_argument("--kind", choices=EVENT_KINDS, default="other")
    subparsers["event"].add_argument("--at", metavar='"YYYY-MM-DD HH:MM"', help="Local time.")
    subparsers["report"].add_argument("--from", dest="date_from", required=True, metavar="DATE")
    subparsers["report"].add_argument("--to", dest="date_to", required=True, metavar="DATE")
    subparsers["report"].add_argument("-o", "--output", metavar="FILE")
    subparsers["export"].add_argument("--from", dest="date_from", metavar="DATE")
    subparsers["export"].add_argument("--to", dest="date_to", metavar="DATE")
    subparsers["export"].add_argument("-o", "--output", required=True, metavar="DIR")
    subparsers["purge"].add_argument("--before", required=True, metavar="DATE")
    subparsers["purge"].add_argument("--yes", action="store_true", help="Don't ask to confirm.")
    return parser


# ---- helpers ------------------------------------------------------------------------------------

EXPORT_TABLES = (
    "targets",
    "target_ips",
    "target_status",
    "ping",
    "minute_rollup",
    "wifi",
    "dns",
    "nq",
    "traceroute",
    "local_load",
    "events",
    "heartbeat",
)
# table -> time column used by --from/--to (None = exported whole)
TIME_COLUMN = {
    "targets": None,
    "target_ips": "from_ts",
    "target_status": "from_ts",
    "minute_rollup": "minute",
    "local_load": "minute",
}
STATUS_TABLES = (
    ("ping", "ts"),
    ("wifi", "ts"),
    ("dns", "ts"),
    ("traceroute", "ts"),
    ("nq", "ts"),
    ("local_load", "minute"),
)
SYMBOL = {"ok": "✓", "warn": "!", "fail": "✗", "info": "·"}


def _paths(args) -> paths_mod.Paths:
    return paths_mod.resolve(getattr(args, "data_dir", None))


def _explicit_data_dir(args) -> Path | None:
    value = getattr(args, "data_dir", None) or os.environ.get(paths_mod.ENV_DATA_DIR)
    return Path(value).expanduser().resolve() if value else None


def _load_config(paths: paths_mod.Paths) -> dict:
    cfg, warnings = config.load(paths.config)
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    return cfg


def _readonly(paths: paths_mod.Paths) -> sqlite3.Connection | None:
    return store.connect_readonly(paths.db) if paths.db.exists() else None


def _age(now_ms: int, ts: int | None) -> str:
    if ts is None:
        return "never"
    seconds = max(0, (now_ms - ts) // 1000)
    if seconds < 120:
        return f"{seconds} s ago"
    if seconds < 7200:
        return f"{seconds // 60} min ago"
    return f"{seconds // 3600} h ago"


def setup_logging(paths: paths_mod.Paths, foreground: bool) -> None:
    paths.logs.mkdir(parents=True, exist_ok=True)
    handlers: list[logging.Handler] = [
        logging.handlers.RotatingFileHandler(
            paths.collector_log, maxBytes=1_000_000, backupCount=4, encoding="utf-8"
        )
    ]
    if foreground:
        handlers.append(logging.StreamHandler(sys.stderr))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


# ---- commands -----------------------------------------------------------------------------------


def cmd_install(args) -> int:
    from whodunnet import agent

    return agent.install(_paths(args), _explicit_data_dir(args))


def cmd_uninstall(args) -> int:
    from whodunnet import agent

    return agent.uninstall(_paths(args), purge=args.purge)


def cmd_run(args) -> int:
    from whodunnet.collector.main import Collector

    paths = _paths(args)
    paths_mod.ensure_dirs(paths)
    setup_logging(paths, args.foreground)
    try:
        cfg = _load_config(paths)
    except config.ConfigError as exc:
        logging.getLogger("whodunnet").error("%s", exc)
        print(exc, file=sys.stderr)
        return 1
    collector = Collector(paths, cfg)
    collector.install_signal_handlers()
    collector.run(nq_now=args.nq_now)
    return 0


def status_lines(conn: sqlite3.Connection | None, now_ms: int) -> list[str]:
    if conn is None:
        return ["Collector: no data yet. Start it with `python3 -m whodunnet install`."]
    last = conn.execute("SELECT MAX(ts) FROM heartbeat").fetchone()[0]
    running = last is not None and now_ms - last < doctor.HEARTBEAT_FRESH_MS
    lines = [
        f"Collector: {'running' if running else 'NOT running'} (last heartbeat {_age(now_ms, last)})"
    ]
    for table, column in STATUS_TABLES:
        ts = conn.execute(f"SELECT MAX({column}) FROM {table}").fetchone()[0]
        lines.append(f"  {table:<11} last sample {_age(now_ms, ts)}")
    day_ago = now_ms - timeutil.DAY_MS
    beats = conn.execute("SELECT COUNT(*) FROM heartbeat WHERE ts >= ?", (day_ago,)).fetchone()[0]
    uptime = min(100, round(beats * 10_000 * 100 / timeutil.DAY_MS))
    lines.append(f"Coverage (last 24 h, collector up): {uptime}%")
    lines.append("Verdict: not available yet (the analysis arrives in a later update).")
    return lines


def cmd_status(args) -> int:
    conn = _readonly(_paths(args))
    try:
        print("\n".join(status_lines(conn, timeutil.now_ms())))
    finally:
        if conn is not None:
            conn.close()
    return 0


def cmd_doctor(args) -> int:
    from whodunnet.probes.link import current_link

    paths = _paths(args)
    try:
        cfg = _load_config(paths)
    except config.ConfigError as exc:
        print(f"✗ {exc}")
        cfg, _ = config.validate({})
    conn = _readonly(paths)
    link = current_link()
    try:
        ctx = doctor.Context(
            conn=conn,
            paths=paths,
            cfg=cfg,
            now_ms=timeutil.now_ms(),
            link_medium=link.medium,
            vpn=link.vpn,
        )
        results = doctor.run_checks(ctx)
    finally:
        if conn is not None:
            conn.close()
    for r in results:
        print(f"{SYMBOL.get(r.status, '?')} {r.check}: {r.message}")
        if r.fix and r.status in ("warn", "fail"):
            print(f"    fix: {r.fix}")
    return 1 if any(r.status == "fail" for r in results) else 0


def _add_event(args, kind: str, note: str, ts: int) -> int:
    paths = _paths(args)
    conn = store.connect(paths.db)
    try:
        store.add_event(conn, kind, note, "cli", ts)
    finally:
        conn.close()
    return 0


def cmd_event(args) -> int:
    try:
        ts = timeutil.parse_local_datetime(args.at) if args.at else timeutil.now_ms()
    except ValueError as exc:
        print(f"--at: {exc}", file=sys.stderr)
        return 2
    _add_event(args, args.kind, args.note, ts)
    print(f"Recorded {args.kind} event.")
    return 0


def cmd_lag(args) -> int:
    _add_event(args, "lag", "", timeutil.now_ms())
    print("Recorded: it's lagging now.")
    return 0


def export_tables(
    conn: sqlite3.Connection, out_dir: Path, start_ms: int | None, end_ms: int | None
) -> dict[str, int]:
    out_dir.mkdir(parents=True, exist_ok=True)
    counts = {}
    for table in EXPORT_TABLES:
        column = TIME_COLUMN.get(table, "ts")
        sql, params = f"SELECT * FROM {table}", []
        if column and (start_ms is not None or end_ms is not None):
            clauses = []
            if start_ms is not None:
                clauses.append(f"{column} >= ?")
                params.append(start_ms)
            if end_ms is not None:
                clauses.append(f"{column} < ?")
                params.append(end_ms)
            sql += " WHERE " + " AND ".join(clauses)
        cur = conn.execute(sql, params)
        with open(out_dir / f"{table}.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([d[0] for d in cur.description])
            n = 0
            for row in cur:
                writer.writerow(list(row))
                n += 1
        counts[table] = n
    return counts


def cmd_export(args) -> int:
    paths = _paths(args)
    try:
        start = timeutil.start_of_local_day(args.date_from) if args.date_from else None
        end = timeutil.end_of_local_day(args.date_to) if args.date_to else None
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    conn = _readonly(paths)
    if conn is None:
        print("No data yet.", file=sys.stderr)
        return 1
    try:
        counts = export_tables(conn, Path(args.output), start, end)
    finally:
        conn.close()
    print(f"Wrote {len(counts)} CSV files to {args.output} ({sum(counts.values())} rows).")
    return 0


def cmd_purge(args) -> int:
    try:
        before = timeutil.start_of_local_day(args.before)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    if not args.yes:
        try:
            answer = input(f"Delete all measurements before {args.before}? [y/N] ")
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            print("Nothing deleted.")
            return 1
    conn = store.connect(_paths(args).db)
    try:
        deleted = store.purge_before(conn, before)
    finally:
        conn.close()
    print(f"Deleted {sum(deleted.values())} rows before {args.before}.")
    return 0


HANDLERS = {
    "install": cmd_install,
    "uninstall": cmd_uninstall,
    "run": cmd_run,
    "status": cmd_status,
    "doctor": cmd_doctor,
    "event": cmd_event,
    "lag": cmd_lag,
    "export": cmd_export,
    "purge": cmd_purge,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = HANDLERS.get(args.command)
    if handler is None:
        task = COMMANDS[args.command][1]
        print(f"`{args.command}` is not implemented yet (task {task}).", file=sys.stderr)
        return 2
    return handler(args)
