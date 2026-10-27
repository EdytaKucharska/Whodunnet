"""WiFi readings via `system_profiler SPAirPortDataType -json` (spec §4.3), every 5 min.

The probe takes ~11 s and disturbs latency while it runs, so it records `started_ts` as well as
`ts`. core/rollup.py drops ping samples sent around it. SSID and BSSID are never stored.
"""

from __future__ import annotations

from typing import Callable

from whodunnet.core.models import WifiRow
from whodunnet.probes.parsers import system_profiler
from whodunnet.probes.runner import Runner, run_command

TIMEOUT_S = 15
ARGV = ["system_profiler", "SPAirPortDataType", "-json"]


def read_wifi(
    interface: str | None,
    medium: str | None,
    clock: Callable[[], int],
    runner: Runner = run_command,
) -> WifiRow:
    """One reading. `interface` is used only when the default route is WiFi (`medium`);
    otherwise the first WiFi interface is read, so the WiFi context is still recorded."""
    started = clock()
    result = runner(ARGV, TIMEOUT_S)
    ended = clock()
    if result.timed_out:
        return WifiRow(ts=ended, started_ts=started, ok=0, error="timeout")
    reading = system_profiler.parse_wifi(result.stdout, interface if medium == "wifi" else None)
    if not reading.ok:
        return WifiRow(ts=ended, started_ts=started, ok=0, error=reading.error)
    return WifiRow(
        ts=ended,
        started_ts=started,
        ok=1,
        rssi_dbm=reading.rssi_dbm,
        noise_dbm=reading.noise_dbm,
        channel=reading.channel,
        band=reading.band,
        width_mhz=reading.width_mhz,
        tx_rate_mbps=reading.tx_rate_mbps,
        phy_mode=reading.phy_mode,
    )
