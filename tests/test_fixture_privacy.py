"""Guard: committed macOS fixtures must stay redacted (spec §10, plan M0.5).

Fails if a fixture contains a public IPv4 address outside the documentation ranges and the
reference anchors, or a MAC address that isn't one of the redactor's placeholders.
"""

import ipaddress
import re
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "macos"
ALLOWED_PUBLIC = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"}
DOC_NETS = [ipaddress.ip_network(n) for n in ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]]
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\w)")
MAC_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,2}:){5}[0-9A-Fa-f]{1,2}(?![\w:])")
SAFE_MACS = {"0:0:0:0:0:0", "ff:ff:ff:ff:ff:ff"}


def fixture_files():
    return sorted(p for p in FIXTURES.rglob("*") if p.is_file())


@pytest.mark.parametrize("path", fixture_files(), ids=lambda p: str(p.relative_to(FIXTURES)))
def test_fixture_is_redacted(path):
    text = path.read_text(errors="replace")
    leaks = []
    for m in IPV4_RE.finditer(text):
        try:
            ip = ipaddress.IPv4Address(m.group())
        except ValueError:
            continue
        if ip.is_global and m.group() not in ALLOWED_PUBLIC and not any(ip in n for n in DOC_NETS):
            leaks.append(m.group())
    for m in MAC_RE.finditer(text):
        mac = m.group().lower()
        if not mac.startswith("aa:bb:cc:") and mac not in SAFE_MACS:
            leaks.append(mac)
    assert not leaks, f"unredacted values in {path.name}: {sorted(set(leaks))}"
