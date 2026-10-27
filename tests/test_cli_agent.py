"""CLI commands, local-time parsing and install/uninstall (plan M1.8)."""

from __future__ import annotations

import csv
import os
import plistlib
import time

import pytest

from whodunnet import agent, cli, config, doctor, paths, timeutil
from whodunnet.core import store
from whodunnet.core.models import PingRow
from whodunnet.probes.runner import CommandResult

T0 = 1_793_000_000_000


@pytest.fixture
def london(monkeypatch):
    monkeypatch.setenv("TZ", "Europe/London")
    time.tzset()
    yield
    monkeypatch.delenv("TZ")
    time.tzset()


@pytest.fixture
def p(tmp_path):
    return paths.resolve(tmp_path / "data", env={}, home=tmp_path / "home")


def run_cli(p, *args):
    return cli.main([*args, "--data-dir", str(p.data_dir)])


# ---- time parsing ---------------------------------------------------------------------------------


def test_local_datetime_and_days_respect_dst(london):
    assert timeutil.parse_local_datetime("2026-07-01 20:15") == 1782933300000  # BST = UTC+1
    assert timeutil.parse_local_datetime("2026-12-01 20:15") == 1796156100000  # GMT
    start = timeutil.start_of_local_day("2026-10-25")  # clocks go back: a 25-hour day
    assert timeutil.end_of_local_day("2026-10-25") - start == 25 * 3600 * 1000
    assert timeutil.end_of_local_day("2026-12-31") == timeutil.start_of_local_day("2027-01-01")


@pytest.mark.parametrize("bad", ["2026-13-01 10:00", "27/10/2026 20:00", "2026-10-27"])
def test_bad_datetime(bad):
    with pytest.raises(ValueError, match="YYYY-MM-DD HH:MM"):
        timeutil.parse_local_datetime(bad)


# ---- plist & install ------------------------------------------------------------------------------


def test_render_plist_is_valid_and_complete(p):
    data = plistlib.loads(agent.render_plist(p, None).encode())
    assert data["Label"] == "app.whodunnet.collector"
    assert data["ProgramArguments"] == ["/usr/bin/python3", "-m", "whodunnet", "run"]
    assert data["WorkingDirectory"] == str(p.app_dir)
    assert data["EnvironmentVariables"] == {"PYTHONPATH": str(p.app_dir)}
    assert data["RunAtLoad"] is True and data["KeepAlive"] is True
    assert data["ThrottleInterval"] == 30 and data["ProcessType"] == "Standard"
    assert data["StandardOutPath"] == str(p.logs / "launchd.out.log")
    assert data["StandardErrorPath"] == str(p.logs / "launchd.err.log")


def test_render_plist_passes_data_dir_and_escapes(tmp_path):
    odd = tmp_path / "R&D <data>"
    q = paths.resolve(odd, env={}, home=tmp_path / "home")
    data = plistlib.loads(agent.render_plist(q, odd).encode())
    assert data["ProgramArguments"][-2:] == ["--data-dir", str(odd)]
    assert data["StandardOutPath"] == str(odd / "logs" / "launchd.out.log")


def test_copy_package_skips_bytecode_and_replaces(tmp_path):
    app = tmp_path / "app"
    target = agent.copy_package(app)
    assert (target / "cli.py").exists()
    assert (target / "launchd" / "app.whodunnet.collector.plist.template").exists()
    assert not list(target.rglob("__pycache__"))
    (target / "stale.py").write_text("x = 1\n")
    agent.copy_package(app)
    assert not (target / "stale.py").exists()


class Recorder:
    def __init__(self, fail=()):
        self.calls, self.fail = [], set(fail)

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        if argv[1] in self.fail:
            return CommandResult(5, "", "Bootstrap failed: 5: Input/output error")
        return CommandResult(0, "", "")


def test_install_writes_everything_and_bootstraps(p, monkeypatch):
    runner, out = Recorder(), []
    rc = agent.install(
        p, None, runner=runner, ask=lambda q: "n", out=out.append, check_prerequisites=False
    )
    assert rc == 0
    assert (p.app_dir / "whodunnet" / "cli.py").exists()
    overrides = config.read_overrides(p.config)
    assert overrides["discovery_lookups"] is False
    assert len(overrides["lan_token"]) >= 16
    conn = store.connect(p.db)
    assert store.get_meta(conn, "install_salt")
    conn.close()
    assert p.launch_agent.exists()
    assert [c[:2] for c in runner.calls] == [["launchctl", "bootout"], ["launchctl", "bootstrap"]]
    assert runner.calls[0][2].endswith("/app.whodunnet.collector")
    assert runner.calls[1][3] == str(p.launch_agent)
    assert any("Local network" in line or "local network" in line for line in out)


def test_install_keeps_salt_and_token_on_reinstall(p):
    agent.install(
        p, None, runner=Recorder(), ask=lambda q: "", out=lambda s: None, check_prerequisites=False
    )
    token = config.read_overrides(p.config)["lan_token"]
    conn = store.connect(p.db)
    salt = store.get_meta(conn, "install_salt")
    conn.close()
    agent.install(
        p, None, runner=Recorder(), ask=lambda q: "y", out=lambda s: None, check_prerequisites=False
    )
    assert config.read_overrides(p.config)["lan_token"] == token
    assert config.read_overrides(p.config)["discovery_lookups"] is True
    conn = store.connect(p.db)
    assert store.get_meta(conn, "install_salt") == salt
    conn.close()


def test_install_non_interactive_defaults_to_lookups(p):
    def eof(q):
        raise EOFError

    agent.install(
        p, None, runner=Recorder(), ask=eof, out=lambda s: None, check_prerequisites=False
    )
    assert config.read_overrides(p.config)["discovery_lookups"] is True


def test_install_reports_bootstrap_failure(p):
    out = []
    rc = agent.install(
        p,
        None,
        runner=Recorder(fail={"bootstrap"}),
        ask=lambda q: "",
        out=out.append,
        check_prerequisites=False,
    )
    assert rc == 1 and any("bootstrap failed" in line for line in out)


def test_install_prerequisites(p, monkeypatch):
    monkeypatch.setattr(agent.sys, "platform", "linux")
    out = []
    rc = agent.install(p, None, runner=Recorder(fail={"-p"}), ask=lambda q: "", out=out.append)
    assert rc == 1 and any("macOS only" in line for line in out)
    assert not p.app_dir.exists()


def test_uninstall_keeps_data_unless_purge(p):
    agent.install(
        p, None, runner=Recorder(), ask=lambda q: "", out=lambda s: None, check_prerequisites=False
    )
    p.logs.mkdir(parents=True, exist_ok=True)
    (p.logs / "collector.log").write_text("x")
    runner = Recorder()
    agent.uninstall(p, purge=False, runner=runner, out=lambda s: None)
    assert runner.calls[0][:2] == ["launchctl", "bootout"]
    assert not p.launch_agent.exists() and not p.app_dir.exists()
    assert p.db.exists() and p.config.exists()
    agent.uninstall(p, purge=True, runner=Recorder(), out=lambda s: None)
    assert not p.db.exists() and not p.config.exists() and not p.logs.exists()


# ---- event, lag, export, purge, status, doctor ----------------------------------------------------


def events(p):
    conn = store.connect(p.db)
    rows = store.list_events(conn, 0, 10**15)
    conn.close()
    return rows


def test_event_with_local_time(p, london, capsys):
    assert (
        run_cli(
            p, "event", "New router fitted", "--kind", "router_change", "--at", "2026-07-01 20:15"
        )
        == 0
    )
    (e,) = events(p)
    assert (e.kind, e.note, e.source, e.ts) == (
        "router_change",
        "New router fitted",
        "cli",
        1782933300000,
    )


def test_event_defaults_and_bad_at(p, capsys):
    before = timeutil.now_ms()
    assert run_cli(p, "event", "called ISP") == 0
    (e,) = events(p)
    assert e.kind == "other" and e.ts >= before
    assert run_cli(p, "event", "x", "--at", "tomorrow") == 2
    assert "YYYY-MM-DD HH:MM" in capsys.readouterr().err


def test_lag(p, capsys):
    assert run_cli(p, "lag") == 0
    (e,) = events(p)
    assert (e.kind, e.source) == ("lag", "cli")


def seed(p):
    conn = store.connect(p.db)
    tid = store.upsert_target(conn, "anchor", "cloudflare", 4, None, "1.1.1.1", "ok", T0)
    store.insert_rows(conn, [PingRow(T0, tid, 0, 10.0), PingRow(T0 + 86_400_000, tid, 1, None)])
    store.insert_heartbeat(conn, T0)
    store.record_gateway_mac(conn, "abcdef0123456789", T0)
    store.set_meta(conn, "local_hostname", "Example-Mac")
    conn.close()
    return tid


def read_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def test_export_writes_one_csv_per_table_without_private_tables(p, tmp_path, capsys):
    seed(p)
    out = tmp_path / "export"
    assert run_cli(p, "export", "-o", str(out)) == 0
    assert sorted(f.stem for f in out.iterdir()) == sorted(cli.EXPORT_TABLES)
    assert not (out / "gateway_mac.csv").exists() and not (out / "meta.csv").exists()
    pings = read_csv(out / "ping.csv")
    assert [r["seq"] for r in pings] == ["0", "1"]
    assert pings[1]["rtt_ms"] == ""
    assert read_csv(out / "targets.csv")[0]["name"] == "cloudflare"


def test_export_date_range(p, tmp_path):
    seed(p)
    out = tmp_path / "e"
    day = time.strftime("%Y-%m-%d", time.localtime(T0 / 1000))
    assert run_cli(p, "export", "--from", day, "--to", day, "-o", str(out)) == 0
    assert [r["seq"] for r in read_csv(out / "ping.csv")] == ["0"]
    assert len(read_csv(out / "targets.csv")) == 1  # targets exported whole


def test_export_without_db(p, tmp_path):
    assert run_cli(p, "export", "-o", str(tmp_path / "e")) == 1


def test_purge_confirms_and_deletes(p, monkeypatch, capsys):
    seed(p)
    cut = time.strftime("%Y-%m-%d", time.localtime((T0 + 86_400_000) / 1000))
    monkeypatch.setattr("builtins.input", lambda q: "n")
    assert run_cli(p, "purge", "--before", cut) == 1
    assert run_cli(p, "purge", "--before", cut, "--yes") == 0
    conn = store.connect(p.db)
    assert [r["seq"] for r in conn.execute("SELECT seq FROM ping")] == [1]
    conn.close()


def test_status_without_and_with_data(p, capsys):
    assert run_cli(p, "status") == 0
    assert "no data yet" in capsys.readouterr().out
    conn = store.connect(p.db)
    store.insert_heartbeat(conn, timeutil.now_ms() - 3000)
    conn.close()
    assert run_cli(p, "status") == 0
    out = capsys.readouterr().out
    assert "Collector: running" in out and "ping" in out and "Verdict" in out


def test_status_lines_not_running():
    conn = store.connect(":memory:")
    store.insert_heartbeat(conn, T0)
    lines = cli.status_lines(conn, T0 + 10 * 60_000)
    assert lines[0].startswith("Collector: NOT running (last heartbeat 10 min ago)")


def test_doctor_prints_fixes_and_exit_code(p, monkeypatch, capsys):
    from whodunnet.probes import link

    monkeypatch.setattr(
        link, "current_link", lambda runner=None: link.LinkState(None, None, "wifi", 0)
    )
    monkeypatch.setattr(
        doctor,
        "run_checks",
        lambda ctx: [
            doctor.Check("a", "ok", "fine"),
            doctor.Check("b", "fail", "broken", "do this"),
        ],
    )
    assert run_cli(p, "doctor") == 1
    out = capsys.readouterr().out
    assert "✓ a: fine" in out and "✗ b: broken" in out and "fix: do this" in out
    monkeypatch.setattr(doctor, "run_checks", lambda ctx: [doctor.Check("a", "warn", "hmm")])
    assert run_cli(p, "doctor") == 0


def test_run_with_invalid_config_exits_1(p, capsys):
    p.data_dir.mkdir(parents=True)
    p.config.write_text('{"ping_interval_s": "fast"}')
    assert run_cli(p, "run") == 1
    assert "ping_interval_s" in capsys.readouterr().err
    assert p.collector_log.exists()


def test_explicit_data_dir_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv(paths.ENV_DATA_DIR, str(tmp_path / "x"))
    args = cli.build_parser().parse_args(["install"])
    assert cli._explicit_data_dir(args) == (tmp_path / "x").resolve()
    monkeypatch.delenv(paths.ENV_DATA_DIR)
    assert cli._explicit_data_dir(args) is None
    assert os.environ.get(paths.ENV_DATA_DIR) is None
