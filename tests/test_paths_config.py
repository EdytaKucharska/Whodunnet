"""Tests for whodunnet/paths.py and whodunnet/config.py (plan M1.1)."""

import json
from pathlib import Path

import pytest

from whodunnet import config, paths


def test_default_paths_follow_macos_conventions(tmp_path):
    p = paths.resolve(env={}, home=tmp_path)
    support = tmp_path / "Library" / "Application Support" / "Whodunnet"
    assert p.db == support / "whodunnet.db"
    assert p.config == support / "config.json"
    assert p.reports == support / "reports"
    assert p.logs == tmp_path / "Library" / "Logs" / "Whodunnet"
    assert p.collector_log.name == "collector.log"
    assert p.launch_agent == tmp_path / "Library/LaunchAgents/app.whodunnet.collector.plist"


def test_data_dir_relocates_db_config_reports_logs(tmp_path):
    p = paths.resolve(data_dir=tmp_path / "dev", env={}, home=tmp_path)
    base = (tmp_path / "dev").resolve()
    assert (p.db, p.config, p.reports, p.logs) == (
        base / "whodunnet.db",
        base / "config.json",
        base / "reports",
        base / "logs",
    )
    # app code and the LaunchAgent stay in their standard places
    assert p.app_dir == tmp_path / "Library/Application Support/Whodunnet/app"


def test_env_var_used_when_no_flag_and_flag_wins(tmp_path):
    env = {paths.ENV_DATA_DIR: str(tmp_path / "from-env")}
    assert paths.resolve(env=env, home=tmp_path).data_dir == (tmp_path / "from-env").resolve()
    flag = paths.resolve(data_dir=tmp_path / "flag", env=env, home=tmp_path)
    assert flag.data_dir == (tmp_path / "flag").resolve()


def test_ensure_dirs(tmp_path):
    p = paths.resolve(data_dir=tmp_path / "d", env={}, home=tmp_path)
    paths.ensure_dirs(p)
    assert p.data_dir.is_dir() and p.reports.is_dir() and p.logs.is_dir()


def test_missing_config_gives_defaults(tmp_path):
    cfg, warnings = config.load(tmp_path / "config.json")
    assert cfg == config.DEFAULTS and warnings == []
    assert cfg is not config.DEFAULTS  # a copy, safe to mutate


def test_overrides_merge_and_unknown_keys_warn(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"web_port": 9000, "colour": "blue"}))
    cfg, warnings = config.load(path)
    assert cfg["web_port"] == 9000
    assert cfg["ping_interval_s"] == 2
    assert warnings == ['config.json: unknown key "colour" ignored']


@pytest.mark.parametrize(
    "key, value",
    [
        ("web_port", 80),
        ("web_port", "8737"),
        ("lan_access", "yes"),
        ("ping_interval_s", True),
        ("ipv6", "on"),
        ("nq_schedule", ["25:00"]),
        ("nq_schedule", []),
        ("evening_window", ["19:00"]),
        ("anchors", {}),
        ("anchors", {"x": ""}),
        ("lan_token", "short"),
        ("raw_ping_retention_days", 0),
    ],
)
def test_invalid_values_name_the_key(tmp_path, key, value):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({key: value}))
    with pytest.raises(config.ConfigError, match=f'"{key}"'):
        config.load(path)


def test_bad_json_and_non_object(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{ not json")
    with pytest.raises(config.ConfigError, match="not valid JSON"):
        config.load(path)
    path.write_text("[1, 2]")
    with pytest.raises(config.ConfigError, match="JSON object"):
        config.load(path)


def test_defaults_are_valid():
    cfg, warnings = config.validate(dict(config.DEFAULTS))
    assert cfg == config.DEFAULTS and warnings == []


def test_ensure_token_generates_once_and_keeps_other_keys(tmp_path):
    path = tmp_path / "sub" / "config.json"
    path.parent.mkdir()
    path.write_text(json.dumps({"web_port": 9000}))
    token = config.ensure_token(path)
    assert len(token) >= 16
    assert config.ensure_token(path) == token  # stable
    saved = json.loads(path.read_text())
    assert saved == {"web_port": 9000, "lan_token": token}
    assert not list(path.parent.glob(".config-*"))  # no temp files left behind


def test_save_overrides_rejects_invalid_and_leaves_file_untouched(tmp_path):
    path = tmp_path / "config.json"
    config.save_overrides(path, {"web_port": 9000})
    with pytest.raises(config.ConfigError):
        config.save_overrides(path, {"web_port": 1})
    assert json.loads(Path(path).read_text()) == {"web_port": 9000}
