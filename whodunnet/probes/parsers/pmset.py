"""Parse `pmset -g batt` (spec §4.4: skip networkQuality on battery)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PowerState:
    ok: bool
    error: str | None = None
    on_battery: bool | None = None  # None = unknown; callers treat unknown as battery


def parse_batt(text: str) -> PowerState:
    if "'AC Power'" in text:
        return PowerState(ok=True, on_battery=False)
    if "'Battery Power'" in text:
        return PowerState(ok=True, on_battery=True)
    return PowerState(ok=False, error="unknown power source")
