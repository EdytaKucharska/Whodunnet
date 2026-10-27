"""Parse `networkQuality -c` JSON and `networkQuality -h` (spec §4.4).

Verified on macOS 26 (plan §8): with -s there is no combined `responsiveness` key, only
dl_/ul_responsiveness. Throughput is in bits/s; base_rtt in ms.
"""

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class NqResult:
    ok: bool
    error: str | None = None
    dl_mbps: float | None = None
    ul_mbps: float | None = None
    dl_rpm: float | None = None
    ul_rpm: float | None = None
    rpm: float | None = None  # the worse (lower) of what's available
    base_rtt_ms: float | None = None
    dl_bytes: int | None = None
    ul_bytes: int | None = None
    test_endpoint: str | None = None
    os_version: str | None = None


def _num(data: dict, key: str) -> float | None:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def parse(json_text: str) -> NqResult:
    try:
        data = json.loads(json_text)
    except ValueError:
        return NqResult(ok=False, error="networkQuality output is not JSON")
    if not isinstance(data, dict):
        return NqResult(ok=False, error="unexpected networkQuality output")
    if "error_code" in data or "error_domain" in data:
        return NqResult(
            ok=False, error=str(data.get("error_description") or "networkQuality error")
        )

    dl_bps, ul_bps = _num(data, "dl_throughput"), _num(data, "ul_throughput")
    dl_rpm, ul_rpm = _num(data, "dl_responsiveness"), _num(data, "ul_responsiveness")
    candidates = [r for r in (dl_rpm, ul_rpm, _num(data, "responsiveness")) if r]
    if dl_bps is None and ul_bps is None and not candidates:
        return NqResult(ok=False, error="networkQuality output has no results")
    dl_bytes, ul_bytes = _num(data, "dl_bytes_transferred"), _num(data, "ul_bytes_transferred")
    endpoint, os_version = data.get("test_endpoint"), data.get("os_version")
    return NqResult(
        ok=True,
        dl_mbps=dl_bps / 1e6 if dl_bps is not None else None,
        ul_mbps=ul_bps / 1e6 if ul_bps is not None else None,
        dl_rpm=dl_rpm,
        ul_rpm=ul_rpm,
        rpm=min(candidates) if candidates else None,
        base_rtt_ms=_num(data, "base_rtt"),
        dl_bytes=int(dl_bytes) if dl_bytes is not None else None,
        ul_bytes=int(ul_bytes) if ul_bytes is not None else None,
        test_endpoint=endpoint if isinstance(endpoint, str) else None,
        os_version=os_version if isinstance(os_version, str) else None,
    )


def supports_max_runtime(help_text: str) -> bool:
    """True if `networkQuality -h` lists the -M (maximum runtime) option."""
    return any(line.strip().startswith("-M") for line in help_text.splitlines())
