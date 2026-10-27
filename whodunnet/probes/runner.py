"""The only place Whodunnet starts processes or makes HTTP requests (spec §3.1, §4).

Probes receive a `runner` (and, for discovery, a `fetch`) so tests can substitute fakes that
return captured fixture text. Nothing here raises for ordinary failures.
"""

from __future__ import annotations

import subprocess
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Callable

from whodunnet import __version__

# Deliberately anonymous: no repo URL, user or machine details are sent to fast.com / Google.
USER_AGENT = f"whodunnet/{__version__}"


@dataclass(frozen=True)
class CommandResult:
    rc: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out

    @property
    def output(self) -> str:
        """stdout followed by stderr (some macOS tools report results on stderr)."""
        return self.stdout + self.stderr


Runner = Callable[[Sequence[str], float], CommandResult]
Fetch = Callable[[str, float], str]


def _text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def run_command(argv: Sequence[str], timeout: float = 15.0) -> CommandResult:
    """Run a command and capture its output. Missing binary → rc 127; timeout → timed_out."""
    try:
        proc = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return CommandResult(127, "", f"{argv[0]}: command not found")
    except subprocess.TimeoutExpired as exc:
        return CommandResult(-1, _text(exc.stdout), _text(exc.stderr), timed_out=True)
    except OSError as exc:
        return CommandResult(126, "", f"{argv[0]}: {exc}")
    return CommandResult(proc.returncode, proc.stdout, proc.stderr)


def spawn(argv: Sequence[str]) -> subprocess.Popen:
    """Start a long-running background process (caffeinate, ping streams). Output discarded."""
    return subprocess.Popen(
        list(argv), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL
    )


def http_get(url: str, timeout: float) -> str:
    """GET a URL and return the body as text (max 1 MB). Raises on any failure."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read(1_000_000).decode("utf-8", "replace")
