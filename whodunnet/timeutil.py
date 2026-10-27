"""Local-time parsing for CLI arguments (spec §9: local dates use the Mac's time zone).

`time.mktime` converts local wall-clock fields to epoch seconds using the system time zone, DST
included, which is exactly what "local date" means here.
"""

from __future__ import annotations

import time

DAY_MS = 24 * 3600 * 1000


def now_ms() -> int:
    return int(time.time() * 1000)


def _mktime_ms(fields: time.struct_time, add_days: int = 0) -> int:
    local = (
        fields.tm_year,
        fields.tm_mon,
        fields.tm_mday + add_days,  # mktime normalises day overflow
        fields.tm_hour,
        fields.tm_min,
        0,
        0,
        0,
        -1,  # let the C library decide whether DST applies
    )
    return int(time.mktime(local) * 1000)


def parse_local_datetime(text: str) -> int:
    """'YYYY-MM-DD HH:MM' (local) → epoch ms. Raises ValueError with a readable message."""
    try:
        return _mktime_ms(time.strptime(text.strip(), "%Y-%m-%d %H:%M"))
    except ValueError:
        raise ValueError(f'expected "YYYY-MM-DD HH:MM", got {text!r}') from None


def _parse_date(text: str) -> time.struct_time:
    try:
        return time.strptime(text.strip(), "%Y-%m-%d")
    except ValueError:
        raise ValueError(f"expected YYYY-MM-DD, got {text!r}") from None


def start_of_local_day(text: str) -> int:
    return _mktime_ms(_parse_date(text))


def end_of_local_day(text: str) -> int:
    """Exclusive end: local midnight at the start of the next day (CLI date ranges are inclusive)."""
    return _mktime_ms(_parse_date(text), add_days=1)
