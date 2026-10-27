"""Netflix Open Connect target via fast.com (spec §4.1).

The API answer contains the household's public IP, so the body is never stored or logged;
only server host names leave this module. Any failure → status "unavailable".
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

from whodunnet.probes.runner import Fetch, http_get

FAST_URL = "https://fast.com/"
API_URL = "https://api.fast.com/netflix/speedtest/v2?https=true&token={token}&urlCount=5"
_APP_JS = re.compile(r'src="(/app-[A-Za-z0-9._-]+\.js)"')
_TOKEN = re.compile(r'token:"([A-Za-z0-9]+)"')


@dataclass(frozen=True)
class NetflixResult:
    status: str  # ok | unavailable
    reason: str | None
    host_v4: str | None = None
    host_v6: str | None = None


def _unavailable(reason: str) -> NetflixResult:
    return NetflixResult(status="unavailable", reason=reason)


def lookup(
    fetch: Fetch = http_get,
    budget_s: float = 10.0,
    clock: Callable[[], float] = time.monotonic,
) -> NetflixResult:
    deadline = clock() + budget_s

    def remaining() -> float:
        left = deadline - clock()
        if left <= 0:
            raise TimeoutError("fast.com lookup took too long")
        return left

    try:
        page = fetch(FAST_URL, remaining())
        script = _APP_JS.search(page)
        if not script:
            return _unavailable("fast.com page format changed (no app script)")
        token = _TOKEN.search(fetch("https://fast.com" + script.group(1), remaining()))
        if not token:
            return _unavailable("fast.com token not found")
        data = json.loads(fetch(API_URL.format(token=token.group(1)), remaining()))
        targets = data.get("targets", []) if isinstance(data, dict) else []
        hosts = [
            urlparse(t["url"]).hostname
            for t in targets
            if isinstance(t, dict) and isinstance(t.get("url"), str)
        ]
    except Exception as exc:  # noqa: BLE001 — never include the message: may hold token/body
        return _unavailable(f"fast.com lookup failed ({type(exc).__name__})")

    hosts = [h for h in hosts if h]
    v4 = next((h for h in hosts if h.startswith("ipv4-")), None)
    v6 = next((h for h in hosts if h.startswith("ipv6-")), None)
    if v4 and not v6:
        v6 = "ipv6-" + v4[len("ipv4-") :]
    elif v6 and not v4:
        v4 = "ipv4-" + v6[len("ipv6-") :]
    if not v4 and not v6:
        return _unavailable("no Netflix servers in the fast.com answer")
    return NetflixResult(status="ok", reason=None, host_v4=v4, host_v6=v6)
