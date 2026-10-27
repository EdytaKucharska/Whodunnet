"""Config loading, defaults and validation (spec §2.2).

`config.json` holds only the keys the user wants to change; everything else comes from
DEFAULTS. Unknown keys produce a warning, invalid values raise ConfigError naming the key.
"""

from __future__ import annotations

import copy
import json
import os
import re
import secrets
import tempfile
from pathlib import Path
from typing import Any, Callable

DEFAULTS: dict[str, Any] = {
    "anchors": {"cloudflare": "1.1.1.1", "google": "8.8.8.8", "bbc": "www.bbc.co.uk"},
    "anchors_v6": {
        "cloudflare": "2606:4700:4700::1111",
        "google": "2001:4860:4860::8888",
        "bbc": "www.bbc.co.uk",
    },
    "cdn_youtube": True,
    "cdn_instagram": True,
    "cdn_netflix": True,
    "discovery_lookups": True,
    "ipv6": "auto",
    "ping_interval_s": 2,
    "wifi_interval_s": 300,
    "dns_interval_s": 60,
    "trace_interval_s": 1200,
    "discover_interval_s": 1800,
    "nq_schedule": ["04:00", "10:00", "12:00", "14:00", "19:30", "20:30", "21:30", "22:30"],
    "evening_window": ["19:00", "23:00"],
    "daytime_window": ["10:00", "16:00"],
    "quiet_window": ["02:00", "06:00"],
    "web_port": 8737,
    "lan_access": False,
    "lan_token": None,
    "raw_ping_retention_days": 14,
}

_HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


class ConfigError(ValueError):
    """config.json is unreadable or has an invalid value."""


def _bool(v: Any) -> str | None:
    return None if isinstance(v, bool) else "must be true or false"


def _int_range(lo: int, hi: int) -> Callable[[Any], str | None]:
    def check(v: Any) -> str | None:
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            return f"must be a whole number from {lo} to {hi}"
        return None

    return check


def _hosts(v: Any) -> str | None:
    if not isinstance(v, dict) or not v:
        return "must be a non-empty object of name -> host"
    for name, host in v.items():
        if not isinstance(host, str) or not host.strip() or not name.strip():
            return "every name and host must be a non-empty string"
    return None


def _hhmm_list(v: Any) -> str | None:
    if (
        not isinstance(v, list)
        or not v
        or not all(isinstance(t, str) and _HHMM.match(t) for t in v)
    ):
        return 'must be a list of "HH:MM" times'
    return None


def _window(v: Any) -> str | None:
    if _hhmm_list(v) is not None or len(v) != 2:
        return 'must be ["HH:MM", "HH:MM"] (start, end)'
    return None


def _choice(*options: str) -> Callable[[Any], str | None]:
    def check(v: Any) -> str | None:
        return None if v in options else "must be one of " + ", ".join(f'"{o}"' for o in options)

    return check


def _token(v: Any) -> str | None:
    if v is None or (isinstance(v, str) and len(v) >= 16):
        return None
    return "must be a string of at least 16 characters"


VALIDATORS: dict[str, Callable[[Any], str | None]] = {
    "anchors": _hosts,
    "anchors_v6": _hosts,
    "cdn_youtube": _bool,
    "cdn_instagram": _bool,
    "cdn_netflix": _bool,
    "discovery_lookups": _bool,
    "ipv6": _choice("auto", "off"),
    "ping_interval_s": _int_range(1, 60),
    "wifi_interval_s": _int_range(60, 3600),
    "dns_interval_s": _int_range(10, 3600),
    "trace_interval_s": _int_range(60, 86400),
    "discover_interval_s": _int_range(60, 86400),
    "nq_schedule": _hhmm_list,
    "evening_window": _window,
    "daytime_window": _window,
    "quiet_window": _window,
    "web_port": _int_range(1024, 65535),
    "lan_access": _bool,
    "lan_token": _token,
    "raw_ping_retention_days": _int_range(1, 3650),
}
assert set(VALIDATORS) == set(DEFAULTS)


def validate(overrides: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Merge overrides onto DEFAULTS. Returns (config, warnings); raises ConfigError."""
    cfg = copy.deepcopy(DEFAULTS)
    warnings: list[str] = []
    for key, value in overrides.items():
        if key not in VALIDATORS:
            warnings.append(f'config.json: unknown key "{key}" ignored')
            continue
        problem = VALIDATORS[key](value)
        if problem:
            raise ConfigError(f'config.json: "{key}" {problem} (got {value!r})')
        cfg[key] = value
    return cfg, warnings


def read_overrides(path: Path) -> dict[str, Any]:
    try:
        text = Path(path).read_text()
    except FileNotFoundError:
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"config.json is not valid JSON (line {exc.lineno}, column {exc.colno})"
        ) from None
    if not isinstance(data, dict):
        raise ConfigError("config.json must contain a JSON object")
    return data


def load(path: Path) -> tuple[dict[str, Any], list[str]]:
    """Read config.json merged onto DEFAULTS. A missing file means all defaults."""
    return validate(read_overrides(path))


def new_token() -> str:
    return secrets.token_urlsafe(24)


def save_overrides(path: Path, overrides: dict[str, Any]) -> None:
    """Validate and write config.json atomically (temp file + rename)."""
    validate(overrides)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".config-", suffix=".json", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(overrides, f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def ensure_token(path: Path) -> str:
    """Return the LAN token, generating and saving one if config.json has none."""
    overrides = read_overrides(path)
    if not overrides.get("lan_token"):
        overrides["lan_token"] = new_token()
        save_overrides(path, overrides)
    return overrides["lan_token"]
