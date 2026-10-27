"""Smoke tests: every module imports (catches Python 3.9 syntax errors) and the CLI is wired."""

import importlib
import pkgutil
import subprocess
import sys

import pytest

import whodunnet
from whodunnet import cli


def all_modules():
    names = ["whodunnet"]
    for info in pkgutil.walk_packages(whodunnet.__path__, prefix="whodunnet."):
        if info.name != "whodunnet.__main__":
            names.append(info.name)
    return names


@pytest.mark.parametrize("name", all_modules())
def test_module_imports(name):
    importlib.import_module(name)


def test_help_lists_every_command():
    out = subprocess.run(
        [sys.executable, "-m", "whodunnet", "--help"], capture_output=True, text=True, check=True
    ).stdout
    for command in cli.COMMANDS:
        assert command in out


@pytest.mark.parametrize("command", ["status", "doctor", "lag"])
def test_stub_commands_exit_2(command, capsys):
    assert cli.main([command]) == 2
    assert "not implemented yet" in capsys.readouterr().err


def test_every_command_accepts_data_dir():
    parser = cli.build_parser()
    required = {
        "event": ["note"],
        "report": ["--from", "2026-10-01", "--to", "2026-10-07"],
        "export": ["-o", "out"],
        "purge": ["--before", "2026-10-01"],
    }
    for command in cli.COMMANDS:
        args = parser.parse_args([command, "--data-dir", "x", *required.get(command, [])])
        assert args.data_dir == "x"
