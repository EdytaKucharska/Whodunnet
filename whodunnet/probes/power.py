"""Battery state and keeping the Mac awake (spec §2, §4.4)."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from typing import Callable

from whodunnet.probes.parsers import pmset
from whodunnet.probes.runner import Runner, run_command, spawn


def on_battery(runner: Runner = run_command) -> bool:
    """True on battery. Unknown power state counts as battery (be conservative: skip nq)."""
    state = pmset.parse_batt(runner(["pmset", "-g", "batt"], 5).output)
    return True if state.on_battery is None else state.on_battery


class Caffeinate:
    """Holds `caffeinate -i -w <pid>` (prevent idle sleep while <pid> lives) while on charger."""

    def __init__(self, spawner: Callable[[Sequence[str]], subprocess.Popen] = spawn) -> None:
        self._spawn = spawner
        self._proc: subprocess.Popen | None = None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self, pid: int) -> None:
        if not self.running:
            self._proc = self._spawn(["caffeinate", "-i", "-w", str(pid)])

    def stop(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None or proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
