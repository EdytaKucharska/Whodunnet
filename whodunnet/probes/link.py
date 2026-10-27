"""Link medium and VPN detection (spec §4.7)."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from whodunnet.probes.parsers import networksetup, route
from whodunnet.probes.runner import Runner, run_command

VPN_PREFIXES = ("utun", "ipsec", "ppp")
_V4_PROBE = "1.1.1.1"
_V6_PROBE = "2606:4700:4700::1111"


@dataclass(frozen=True)
class LinkState:
    interface: str | None  # default-route interface, e.g. "en0"
    gateway: str | None
    medium: str  # wifi | wired | other
    vpn: int  # 1 if traffic to the internet goes through a tunnel


def current_link(runner: Runner = run_command) -> LinkState:
    default = route.parse_default(runner(["route", "-n", "get", "default"], 5).output)
    interface = default.interface
    ports = networksetup.parse_ports(runner(["networksetup", "-listallhardwareports"], 10).output)
    medium = networksetup.medium(ports.ports.get(interface)) if interface else "other"

    vpn = 0
    for argv in (["route", "-n", "get", _V4_PROBE], ["route", "-n", "get", "-inet6", _V6_PROBE]):
        info = route.parse_route_get(runner(argv, 5).output)
        if info.ok and info.interface and info.interface.startswith(VPN_PREFIXES):
            vpn = 1
    return LinkState(
        interface=interface,
        gateway=default.gateway if default.ok else None,
        medium=medium,
        vpn=vpn,
    )


class LinkCache:
    """current_link() at most every `ttl` seconds (spec §4.7: refreshed every 10 s)."""

    def __init__(
        self,
        runner: Runner = run_command,
        clock: Callable[[], float] = time.monotonic,
        ttl: float = 10.0,
    ) -> None:
        self._runner, self._clock, self._ttl = runner, clock, ttl
        self._state: LinkState | None = None
        self._at = 0.0

    def peek(self) -> LinkState | None:
        """The last state without refreshing: cheap and safe to call from reader threads."""
        return self._state

    def get(self, force: bool = False) -> LinkState:
        now = self._clock()
        if force or self._state is None or now - self._at >= self._ttl:
            self._state = current_link(self._runner)
            self._at = now
        return self._state
