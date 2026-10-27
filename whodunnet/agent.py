"""`install` / `uninstall`: copy the app, write config and the LaunchAgent, (un)load it (spec §9).

macOS-specific actions go through an injectable runner, so tests never call launchctl.
"""

from __future__ import annotations

import os
import secrets
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from string import Template
from xml.sax.saxutils import escape

import whodunnet
from whodunnet import config
from whodunnet.core import store
from whodunnet.paths import AGENT_LABEL, Paths, ensure_dirs
from whodunnet.probes.runner import Runner, run_command

SYSTEM_PYTHON = "/usr/bin/python3"
TEMPLATE = Path(whodunnet.__file__).resolve().parent / "launchd" / f"{AGENT_LABEL}.plist.template"
PACKAGE_DIR = Path(whodunnet.__file__).resolve().parent

EXPLANATION = """\
Whodunnet will run in the background on this Mac and measure your connection 24/7:
  - pings (one small packet every 2 s) to your router, your ISP's first router, a few
    reference servers and the YouTube, Instagram and Netflix servers your Mac is sent to
  - WiFi signal every 5 min, DNS every minute, traceroutes every 20 min
  - a speed/lag-under-load test (networkQuality) 8 times a day, ~0.6 GB each (~4.6 GB/day)
Everything stays on this Mac. Nothing is uploaded anywhere.
"""
LOOKUP_QUESTION = (
    "Allow looking up which YouTube and Netflix servers you use?\n"
    "(one request to Google and to fast.com every 30 min) [Y/n] "
)
AFTER_INSTALL = """\
Installed and started.
  - If macOS asks to allow python3 to find devices on your local network: click Allow.
    (Without it the router can't be measured.)
  - If you see "Background Items Added", keep Whodunnet / python3 enabled in
    System Settings → General → Login Items.
  - Check the setup any time: python3 -m whodunnet doctor
"""


def domain_target() -> str:
    return f"gui/{os.getuid()}"


def service_target() -> str:
    return f"{domain_target()}/{AGENT_LABEL}"


def program_arguments(data_dir: Path | None) -> list[str]:
    args = [SYSTEM_PYTHON, "-m", "whodunnet", "run"]
    if data_dir is not None:
        args += ["--data-dir", str(data_dir)]
    return args


def render_plist(paths: Paths, data_dir: Path | None) -> str:
    """The LaunchAgent plist. `data_dir` is the --data-dir to pass through (None = default)."""
    arguments = "\n".join(f"\t\t<string>{escape(a)}</string>" for a in program_arguments(data_dir))
    return Template(TEMPLATE.read_text()).substitute(
        label=AGENT_LABEL,
        program_arguments=arguments,
        app_dir=escape(str(paths.app_dir)),
        out_log=escape(str(paths.launchd_out_log)),
        err_log=escape(str(paths.launchd_err_log)),
    )


def copy_package(app_dir: Path, source: Path = PACKAGE_DIR) -> Path:
    """Replace app_dir/whodunnet with a fresh copy of the running package."""
    target = app_dir / "whodunnet"
    if target.exists():
        shutil.rmtree(target)
    app_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return target


def _ask_yes(question: str, ask: Callable[[str], str]) -> bool:
    try:
        answer = ask(question)
    except EOFError:
        return True  # not interactive: the default
    return answer.strip().lower() not in ("n", "no")


def prerequisites(runner: Runner) -> list[str]:
    problems = []
    if sys.platform != "darwin":
        problems.append("Whodunnet's collector runs on macOS only.")
    if not runner(["xcode-select", "-p"], 10).ok:
        problems.append("Xcode Command Line Tools are missing: run `xcode-select --install`.")
    if not Path(SYSTEM_PYTHON).exists():
        problems.append(f"{SYSTEM_PYTHON} not found (it comes with the Command Line Tools).")
    return problems


def install(
    paths: Paths,
    data_dir: Path | None,
    runner: Runner = run_command,
    ask: Callable[[str], str] = input,
    out: Callable[[str], None] = print,
    check_prerequisites: bool = True,
) -> int:
    if check_prerequisites:
        problems = prerequisites(runner)
        if problems:
            for problem in problems:
                out(f"✗ {problem}")
            return 1
    out(EXPLANATION)
    lookups = _ask_yes(LOOKUP_QUESTION, ask)

    copy_package(paths.app_dir)
    ensure_dirs(paths)
    overrides = config.read_overrides(paths.config)
    overrides["discovery_lookups"] = lookups
    config.save_overrides(paths.config, overrides)
    config.ensure_token(paths.config)
    conn = store.connect(paths.db)
    try:
        if not store.get_meta(conn, "install_salt"):
            store.set_meta(conn, "install_salt", secrets.token_hex(16))
    finally:
        conn.close()

    runner(["launchctl", "bootout", service_target()], 30)  # not loaded yet is fine
    paths.launch_agent.parent.mkdir(parents=True, exist_ok=True)
    paths.launch_agent.write_text(render_plist(paths, data_dir))
    result = runner(["launchctl", "bootstrap", domain_target(), str(paths.launch_agent)], 30)
    if not result.ok:
        out(f"✗ launchctl bootstrap failed: {result.output.strip()}")
        out(f"  Logs: {paths.logs}")
        return 1
    out(AFTER_INSTALL)
    return 0


def _remove(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def uninstall(
    paths: Paths,
    purge: bool = False,
    runner: Runner = run_command,
    out: Callable[[str], None] = print,
) -> int:
    runner(["launchctl", "bootout", service_target()], 30)
    _remove(paths.launch_agent)
    _remove(paths.app_dir)
    out("Stopped and removed the background collector.")
    if purge:
        for path in (
            paths.db,
            Path(f"{paths.db}-wal"),
            Path(f"{paths.db}-shm"),
            paths.config,
            paths.reports,
            paths.logs,
        ):
            _remove(path)
        for folder in (paths.data_dir,):
            if folder.exists() and not any(folder.iterdir()):
                folder.rmdir()
        out("Deleted the database, config, reports and logs.")
    else:
        out(f"Your data is kept in {paths.data_dir} (use --purge to delete it).")
    return 0
