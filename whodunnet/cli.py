"""Command-line interface: `python3 -m whodunnet <command>` (spec §9).

Every command is a stub until its task lands; stubs exit with status 2.
"""

from __future__ import annotations

import argparse
import sys

from whodunnet import __version__

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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    task = COMMANDS[args.command][1]
    print(f"`{args.command}` is not implemented yet (task {task}).", file=sys.stderr)
    return 2
