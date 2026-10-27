"""Parse `system_profiler SPAirPortDataType -json` for the current WiFi link (spec §4.3).

Reads only signal, noise, channel/band/width, rate and PHY mode. Never returns network names
or hardware addresses. Not associated → ok=True with every field None.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

_SIGNAL_NOISE = re.compile(r"(-?\d+)\s*dBm\s*/\s*(-?\d+)\s*dBm")
_CHANNEL = re.compile(r"^\s*(\d+)\s*\(\s*(\d+)\s*GHz(?:\s*,\s*(\d+)\s*MHz)?\s*\)")
_BANDS = {"2": "2.4", "5": "5", "6": "6"}


@dataclass(frozen=True)
class WifiReading:
    ok: bool
    error: str | None = None
    associated: bool = False
    rssi_dbm: int | None = None
    noise_dbm: int | None = None
    channel: int | None = None
    band: str | None = None
    width_mhz: int | None = None
    tx_rate_mbps: float | None = None
    phy_mode: str | None = None


def _number(value) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        m = re.match(r"\s*([\d.]+)", value)
        return float(m.group(1)) if m else None
    return None


def parse_wifi(json_text: str, interface: str | None = None) -> WifiReading:
    """interface: the default-route WiFi device (e.g. "en0"); None = first WiFi interface."""
    try:
        data = json.loads(json_text)
        interfaces = data["SPAirPortDataType"][0]["spairport_airport_interfaces"]
    except (ValueError, KeyError, IndexError, TypeError):
        return WifiReading(ok=False, error="unexpected system_profiler output")
    if not isinstance(interfaces, list):
        return WifiReading(ok=False, error="unexpected system_profiler output")

    chosen = None
    for entry in interfaces:
        if not isinstance(entry, dict):
            continue
        if interface is not None and entry.get("_name") == interface:
            chosen = entry
            break
        if interface is None and entry.get("_name", "").startswith("en"):
            chosen = entry
            break
    if chosen is None:
        return WifiReading(ok=False, error=f"WiFi interface {interface or 'en*'} not found")

    current = chosen.get("spairport_current_network_information")
    if not isinstance(current, dict) or "spairport_signal_noise" not in current:
        return WifiReading(ok=True, associated=False)

    rssi = noise = channel = width = None
    band = None
    m = _SIGNAL_NOISE.search(str(current.get("spairport_signal_noise", "")))
    if m:
        rssi, noise = int(m.group(1)), int(m.group(2))
    m = _CHANNEL.match(str(current.get("spairport_network_channel", "")))
    if m:
        channel = int(m.group(1))
        band = _BANDS.get(m.group(2))
        width = int(m.group(3)) if m.group(3) else None
    phy = current.get("spairport_network_phymode")
    return WifiReading(
        ok=True,
        associated=True,
        rssi_dbm=rssi,
        noise_dbm=noise,
        channel=channel,
        band=band,
        width_mhz=width,
        tx_rate_mbps=_number(current.get("spairport_network_rate")),
        phy_mode=phy if isinstance(phy, str) else None,
    )
