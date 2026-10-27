"""Filesystem locations and --data-dir handling (spec §2.1).

Default locations follow macOS conventions. `--data-dir DIR` or `WHODUNNET_DATA_DIR` moves the
database, config, reports and logs together under DIR; the installed app code and the
LaunchAgent plist always stay in their standard places.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

ENV_DATA_DIR = "WHODUNNET_DATA_DIR"
AGENT_LABEL = "app.whodunnet.collector"


@dataclass(frozen=True)
class Paths:
    data_dir: Path
    db: Path
    config: Path
    reports: Path
    logs: Path
    app_dir: Path
    launch_agent: Path

    @property
    def collector_log(self) -> Path:
        return self.logs / "collector.log"

    @property
    def launchd_out_log(self) -> Path:
        return self.logs / "launchd.out.log"

    @property
    def launchd_err_log(self) -> Path:
        return self.logs / "launchd.err.log"


def resolve(
    data_dir: str | os.PathLike | None = None,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> Paths:
    """Work out every location. An explicit data_dir wins over the environment variable."""
    env = os.environ if env is None else env
    home = Path.home() if home is None else Path(home)
    support = home / "Library" / "Application Support" / "Whodunnet"
    app_dir = support / "app"
    launch_agent = home / "Library" / "LaunchAgents" / f"{AGENT_LABEL}.plist"

    override = data_dir or env.get(ENV_DATA_DIR) or None
    if override:
        base = Path(override).expanduser().resolve()
        return Paths(
            data_dir=base,
            db=base / "whodunnet.db",
            config=base / "config.json",
            reports=base / "reports",
            logs=base / "logs",
            app_dir=app_dir,
            launch_agent=launch_agent,
        )
    return Paths(
        data_dir=support,
        db=support / "whodunnet.db",
        config=support / "config.json",
        reports=support / "reports",
        logs=home / "Library" / "Logs" / "Whodunnet",
        app_dir=app_dir,
        launch_agent=launch_agent,
    )


def ensure_dirs(paths: Paths) -> None:
    """Create the data, reports and log folders if they don't exist."""
    for folder in (paths.data_dir, paths.reports, paths.logs):
        folder.mkdir(parents=True, exist_ok=True)
