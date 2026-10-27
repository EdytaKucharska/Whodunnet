#!/usr/bin/env python3
"""Redact captured macOS command output before it is committed as test fixtures.

Usage:
    python3 tools/redact.py captures/ tests/fixtures/macos/ [--term WORD ...]

Walks SRC, writes a redacted copy of every text file to DST (same relative paths) and prints a
summary. Structure and numbers are preserved so parsers can still be tested against the output.

What is replaced (plan M0.5.2):
- public IPv4 -> 203.0.113.N, public IPv6 -> 2001:db8::N (same input -> same output within a run)
- private / CGNAT IPv4 -> same range, fake network part, host octet kept (so .1 and .255 survive)
- link-local / ULA IPv6 -> fe80::N / fd00::N (zone such as %en0 kept)
- MAC addresses -> aa:bb:cc:00:00:NN
- WiFi network names (current and neighbouring), serial numbers, UUIDs in system_profiler JSON
- the Mac's LocalHostName and any `*.local` name -> example-mac
- the ISP label inside Netflix server names (…oca.nflxvideo.net)
- every --term (e.g. your ISP or WiFi name), case-insensitive

Kept as-is: loopback, unspecified, broadcast, multicast, documentation ranges, and the public
reference anchors the tool pings (1.1.1.1, 8.8.8.8 and their IPv6 equivalents).

Always grep the output for your real public IP, WiFi name, router MAC and Mac name before
committing.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections import Counter
from pathlib import Path

KEEP_IPS = {
    ipaddress.ip_address(a)
    for a in [
        "1.1.1.1",
        "1.0.0.1",
        "8.8.8.8",
        "8.8.4.4",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
    ]
}
DOC_NETS = [
    ipaddress.ip_network(n)
    for n in ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"]
]
CGNAT = ipaddress.ip_network("100.64.0.0/10")
PRIVATE_V4 = [ipaddress.ip_network(n) for n in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]]

IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\w)")
IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%[\w.]+)?(?![\w:])")
MAC_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,2}:){5}[0-9A-Fa-f]{1,2}(?![\w:])")
LOCAL_NAME_RE = re.compile(r"\b[\w-]+\.local\b")
NETFLIX_RE = re.compile(r"\b(ipv[46])-c(\d+)-([a-z]+\d+)-[\w-]+?\.(\d+\.)?oca\.nflxvideo\.net\b")

# system_profiler JSON keys whose values identify the network, the machine or the person.
SENSITIVE_KEY_RE = re.compile(r"(ssid|bssid|serial|uuid|mac_address|udid)", re.IGNORECASE)
NETWORK_LIST_KEYS = {
    "spairport_airport_other_local_wireless_networks",
    "spairport_airport_local_wireless_networks",
}
CURRENT_NETWORK_KEY = "spairport_current_network_information"


class Redactor:
    def __init__(self, terms: list[str] | None = None) -> None:
        self.terms: list[str] = [t for t in (terms or []) if t.strip()]
        self.maps: dict[str, dict[str, str]] = {}
        self.counts: Counter[str] = Counter()

    # ---- consistent fake values -------------------------------------------------------------

    def _fake(self, category: str, original: str, make, count: bool = True) -> str:
        table = self.maps.setdefault(category, {})
        if original not in table:
            table[original] = make(len(table) + 1)
        if count:
            self.counts[category] += 1
        return table[original]

    def _fake_v4_public(self, n: int) -> str:
        blocks = ["203.0.113", "198.51.100", "192.0.2"]
        block, host = divmod(n - 1, 254)
        return f"{blocks[block % len(blocks)]}.{host + 1}"

    def _fake_v4_network(self, ip: ipaddress.IPv4Address, prefix: str, category: str) -> str:
        """Fake the /24 network part but keep the host octet (gateway .1, broadcast .255)."""
        octets = str(ip).split(".")
        net24 = ".".join(octets[:3])
        fake_net = self._fake(
            category + "_net", net24, lambda n: f"{prefix}.{n % 256}", count=False
        )
        self.counts[category] += 1
        return f"{fake_net}.{octets[3]}"

    # ---- text rules -------------------------------------------------------------------------

    def _ipv4(self, m: re.Match) -> str:
        text = m.group(0)
        try:
            ip = ipaddress.IPv4Address(text)
        except ValueError:
            return text
        if (
            ip in KEEP_IPS
            or ip.is_loopback
            or ip.is_unspecified
            or ip.is_multicast
            or ip.is_link_local
            or str(ip) == "255.255.255.255"
            or text.startswith("255.")
            or any(ip in n for n in DOC_NETS)
        ):
            return text
        if ip in CGNAT:
            return self._fake_v4_network(ip, "100.64", "ipv4_cgnat")
        if any(ip in n for n in PRIVATE_V4):
            first = str(ip).split(".")[0]
            prefix = {"10": "10.99", "172": "172.16", "192": "192.168"}[first]
            return self._fake_v4_network(ip, prefix, "ipv4_private")
        return self._fake("ipv4_public", text, self._fake_v4_public)

    def _ipv6(self, m: re.Match) -> str:
        text = m.group(0)
        addr, _, zone = text.partition("%")
        try:
            ip = ipaddress.IPv6Address(addr)
        except ValueError:
            return text
        zone = f"%{zone}" if zone else ""
        if (
            ip in KEEP_IPS
            or ip.is_loopback
            or ip.is_unspecified
            or ip.is_multicast
            or any(ip in n for n in DOC_NETS)
        ):
            return text
        if ip.is_link_local:
            return self._fake("ipv6_link_local", addr, lambda n: f"fe80::{n:x}") + zone
        if ip in ipaddress.ip_network("fc00::/7"):
            return self._fake("ipv6_ula", addr, lambda n: f"fd00::{n:x}") + zone
        return self._fake("ipv6_public", addr, lambda n: f"2001:db8::{n:x}") + zone

    def _mac(self, m: re.Match) -> str:
        text = m.group(0)
        if text.lower() in {"ff:ff:ff:ff:ff:ff", "0:0:0:0:0:0"}:
            return text
        return self._fake(
            "mac", text.lower(), lambda n: f"aa:bb:cc:00:{n // 256:02x}:{n % 256:02x}"
        )

    def _netflix(self, m: re.Match) -> str:
        family, _cluster, _pop = m.group(1), m.group(2), m.group(3)
        self.counts["netflix_host"] += 1
        return f"{family}-c001-pop001-isp-example.1.oca.nflxvideo.net"

    def redact_text(self, text: str) -> str:
        for term in sorted(self.terms, key=len, reverse=True):
            text, n = re.subn(re.escape(term), "redacted", text, flags=re.IGNORECASE)
            self.counts["term"] += n
        text = NETFLIX_RE.sub(self._netflix, text)
        text = MAC_RE.sub(self._mac, text)
        text = IPV6_RE.sub(self._ipv6, text)
        text = IPV4_RE.sub(self._ipv4, text)
        text, n = LOCAL_NAME_RE.subn("example-mac.local", text)
        self.counts["local_name"] += n
        return text

    # ---- JSON rules -------------------------------------------------------------------------

    def redact_json(self, value, key: str = "", parent: str = ""):
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                out[k] = self.redact_json(v, k, key)
            return out
        if isinstance(value, list):
            if key in NETWORK_LIST_KEYS:
                return [self._redact_network(item, i + 1) for i, item in enumerate(value)]
            return [self.redact_json(v, key, parent) for v in value]
        if isinstance(value, str):
            if SENSITIVE_KEY_RE.search(key):
                self.counts["json_sensitive"] += 1
                return "REDACTED"
            if key == "_name" and parent == CURRENT_NETWORK_KEY:
                self.counts["wifi_name"] += 1
                return "example-network"
            return self.redact_text(value)
        return value

    def _redact_network(self, item, n: int):
        if isinstance(item, dict):
            item = self.redact_json(item, "", "")
            if "_name" in item:
                item["_name"] = f"neighbour-network-{n}"
                self.counts["wifi_name"] += 1
        return item

    # ---- discovery of sensitive terms -------------------------------------------------------

    def learn_terms(self, src: Path) -> None:
        """Pick up names that must be scrubbed everywhere: LocalHostName and WiFi network names."""
        hostname_file = src / "scutil" / "localhostname.txt"
        if hostname_file.is_file():
            name = hostname_file.read_text(errors="replace").strip()
            if name:
                self.terms.append(name)
        for path in src.rglob("*.json"):
            try:
                data = json.loads(path.read_text(errors="replace"))
            except ValueError:
                continue
            self.terms.extend(_wifi_names(data))
        self.terms = sorted({t for t in self.terms if len(t) >= 3})


def _wifi_names(value, key: str = "") -> list[str]:
    names: list[str] = []
    if isinstance(value, dict):
        if key == CURRENT_NETWORK_KEY and isinstance(value.get("_name"), str):
            names.append(value["_name"])
        for k, v in value.items():
            names.extend(_wifi_names(v, k))
    elif isinstance(value, list):
        for item in value:
            if (
                key in NETWORK_LIST_KEYS
                and isinstance(item, dict)
                and isinstance(item.get("_name"), str)
            ):
                names.append(item["_name"])
            names.extend(_wifi_names(item, key))
    return names


def redact_tree(src: Path, dst: Path, redactor: Redactor) -> list[str]:
    """Redact every file under src into dst. Returns the relative paths written."""
    redactor.learn_terms(src)
    written: list[str] = []
    for path in sorted(p for p in src.rglob("*") if p.is_file()):
        rel = path.relative_to(src)
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            print(f"skipping binary file {rel}", file=sys.stderr)
            continue
        if path.suffix == ".json":
            try:
                out = json.dumps(redactor.redact_json(json.loads(text)), indent=2) + "\n"
            except ValueError:
                out = redactor.redact_text(text)
        else:
            out = redactor.redact_text(text)
        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(out)
        written.append(str(rel))
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("src", type=Path, help="Folder with raw captures (e.g. captures/).")
    parser.add_argument("dst", type=Path, help="Output folder (e.g. tests/fixtures/macos/).")
    parser.add_argument(
        "--term",
        action="append",
        default=[],
        help="Extra word to scrub everywhere, e.g. your ISP or WiFi name. Repeatable.",
    )
    args = parser.parse_args(argv)
    src, dst = args.src.resolve(), args.dst.resolve()
    if not src.is_dir():
        parser.error(f"{args.src} is not a folder")
    if dst == src or src in dst.parents:
        parser.error("dst must not be inside src")

    redactor = Redactor(args.term)
    written = redact_tree(src, dst, redactor)
    print(f"Wrote {len(written)} redacted files to {args.dst}")
    for category, count in sorted(redactor.counts.items()):
        if count:
            print(f"  {category:18} {count}")
    print(f"  scrubbed terms     {len(redactor.terms)} (auto-detected names + --term)")
    print("\nBefore committing, grep the output for your real public IP, WiFi name,")
    print("router MAC and Mac name. Nothing should match.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
