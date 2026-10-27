"""YouTube target (spec §4.1).

v0: Google's report_mapping returns a POP name (e.g. "iad66s07"), not a pingable cache host,
so the target is the redirector with status "approximate" and the POP name as the reason.
The client IP and subnet in the answer are never stored or logged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from whodunnet.probes.runner import Fetch, http_get

REDIRECTOR = "redirector.googlevideo.com"
MAPPING_URL = "https://redirector.googlevideo.com/report_mapping?di=no"
_POP = re.compile(r"=>\s*([a-z]{3}\d+[a-z]+\d+)\b")


@dataclass(frozen=True)
class YoutubeResult:
    host: str
    status: str
    reason: str


def lookup(fetch: Fetch = http_get, timeout: float = 10.0) -> YoutubeResult:
    try:
        text = fetch(MAPPING_URL, timeout)
    except Exception as exc:  # noqa: BLE001 — any failure just means "not available"
        return YoutubeResult(
            REDIRECTOR, "approximate", f"report_mapping failed ({type(exc).__name__})"
        )
    m = _POP.search(text)
    reason = f"Google POP {m.group(1)}" if m else "report_mapping format not recognised"
    return YoutubeResult(REDIRECTOR, "approximate", reason)
