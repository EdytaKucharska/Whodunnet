"""Parse one line of `ping` / `ping6` output (spec §4.2).

parse_line returns Reply, Timeout, SendError, Unparsed, or None for header/summary/blank lines.
It never raises. Pairing outcomes with sequence numbers is the stream's job (probes/ping.py).
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Reply:
    seq: int
    rtt_ms: float


@dataclass(frozen=True)
class Timeout:
    seq: int


@dataclass(frozen=True)
class SendError:
    reason: str  # e.g. "No route to host"


@dataclass(frozen=True)
class Unparsed:
    line: str


_REPLY = re.compile(r"\bicmp_seq=(\d+)\b.*?\btime=([\d.]+) ms")
_TIMEOUT = re.compile(r"^Request timeout for icmp_seq (\d+)")
_SEND_ERROR = re.compile(r"^ping6?: (?:sendto|sendmsg): (.+)$")
_IGNORED = re.compile(r"^(PING6? |--- .* statistics ---|\d+ packets transmitted|round-trip )")


def parse_line(line: str) -> Reply | Timeout | SendError | Unparsed | None:
    text = line.strip()
    if not text or _IGNORED.match(text):
        return None
    m = _REPLY.search(text)
    if m:
        return Reply(seq=int(m.group(1)), rtt_ms=float(m.group(2)))
    m = _TIMEOUT.match(text)
    if m:
        return Timeout(seq=int(m.group(1)))
    m = _SEND_ERROR.match(text)
    if m:
        return SendError(reason=m.group(1).strip())
    return Unparsed(line=text)
