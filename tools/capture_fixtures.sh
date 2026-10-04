#!/bin/bash
# Capture real macOS command output for Whodunnet's parser tests (plan M0.5.1).
#
# Run on the Mac, from the repo root, connected to your home WiFi:
#     bash tools/capture_fixtures.sh            # full run, ~30 min (includes a 20-min WiFi-probe test)
#     bash tools/capture_fixtures.sh --quick    # skips the 20-min WiFi-probe test, ~5 min
#
# Writes raw output to captures/<command>/<case>.txt|json and captures/MANIFEST.txt.
# captures/ is git-ignored and contains private data (IPs, MACs, network names).
# NEVER commit it. Redact first:
#     python3 tools/redact.py captures tests/fixtures/macos --term "<your ISP name>"
# No sudo needed. Every step records failures and carries on.
#
# Compatible with the bash 3.2 that ships with macOS.

set -u

QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

if [ "$(uname -s)" != "Darwin" ]; then
  echo "This script must run on macOS." >&2
  exit 1
fi

OUT="captures"
mkdir -p "$OUT"
MANIFEST="$OUT/MANIFEST.txt"
: > "$MANIFEST"

log() { printf '%s\n' "$*" | tee -a "$MANIFEST"; }

# run <dir> <file> <command...>: save stdout+stderr, record exit code and duration.
run() {
  local dir="$1" file="$2"
  shift 2
  mkdir -p "$OUT/$dir"
  local start end rc
  start=$(python3 -c 'import time; print(time.time())')
  "$@" > "$OUT/$dir/$file" 2>&1
  rc=$?
  end=$(python3 -c 'import time; print(time.time())')
  log "$(printf '%-40s rc=%-3s %5.1fs  %s' "$dir/$file" "$rc" \
    "$(python3 -c "print($end - $start)")" "$*")"
}

log "Whodunnet fixture capture"
log "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
sw_vers >> "$MANIFEST" 2>&1
log ""

echo "== Network basics"
run sw_vers sw_vers.txt sw_vers
run route default.txt route -n get default
run route get_1.1.1.1.txt route -n get 1.1.1.1
run route get_inet6.txt route -n get -inet6 2606:4700:4700::1111
run networksetup listallhardwareports.txt networksetup -listallhardwareports
run ifconfig ifconfig.txt ifconfig
run ifconfig awdl0.txt ifconfig awdl0
run netstat ibn.txt netstat -ibn
run scutil dns.txt scutil --dns
run scutil localhostname.txt scutil --get LocalHostName
run firewall globalstate.txt /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
run pmset batt.txt pmset -g batt

GATEWAY=$(route -n get default 2>/dev/null | awk '/gateway:/ {print $2}')
IFACE=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')
log "gateway: ${GATEWAY:-unknown}  interface: ${IFACE:-unknown}"
if [ -n "$GATEWAY" ]; then
  run arp gateway.txt arp -n "$GATEWAY"
fi

# First resolver in the main "DNS configuration" section without a "domain :" line.
RESOLVER=$(scutil --dns 2>/dev/null | python3 -c '
import re, sys
text = sys.stdin.read().split("DNS configuration (for scoped queries)")[0]
for block in re.split(r"\nresolver #\d+", text)[1:]:
    if re.search(r"^\s*domain\s*:", block, re.M):
        continue
    m = re.search(r"nameserver\[0\]\s*:\s*(\S+)", block)
    if m:
        print(m.group(1)); break
')
log "resolver: ${RESOLVER:-unknown}"
HAS_V6=0
if ifconfig "${IFACE:-en0}" 2>/dev/null | grep -Eq 'inet6 [23][0-9a-f]{3}:'; then HAS_V6=1; fi
log "global IPv6: $HAS_V6"

echo "== WiFi (system_profiler)"
run system_profiler wifi.json system_profiler SPAirPortDataType -json

echo "== DNS"
if [ -n "$RESOLVER" ]; then
  RANDOM_LABEL=$(python3 -c 'import secrets, string; print("".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(12)))')
  run dig cached.txt dig +tries=1 +time=2 "@$RESOLVER" www.google.com
  run dig nxdomain.txt dig +tries=1 +time=2 "@$RESOLVER" "$RANDOM_LABEL.example.com"
  run dig short_a_instagram.txt dig +short A "@$RESOLVER" scontent.cdninstagram.com
  run dig short_aaaa_instagram.txt dig +short AAAA "@$RESOLVER" scontent.cdninstagram.com
  run dig short_a_bbc.txt dig +short A "@$RESOLVER" www.bbc.co.uk
  run dig short_aaaa_bbc.txt dig +short AAAA "@$RESOLVER" www.bbc.co.uk
fi

echo "== Ping"
[ -n "$GATEWAY" ] && run ping gateway.txt ping -n -c 5 -i 2 "$GATEWAY"
run ping timeouts.txt ping -n -c 5 -i 2 192.0.2.1
if [ "$HAS_V6" = 1 ]; then
  run ping ping6_anchor.txt ping6 -n -c 5 -i 2 2606:4700:4700::1111
  run ping ping6_timeouts.txt ping6 -n -c 5 -i 2 2001:db8::1
fi

echo "== Ping streaming check (20 s): are lines delivered promptly through a pipe?"
mkdir -p "$OUT/ping"
python3 - "$OUT/ping/streaming_check.txt" <<'PY'
import subprocess, sys, time
out = open(sys.argv[1], "w")
proc = subprocess.Popen(["ping", "-n", "-i", "2", "1.1.1.1"], stdout=subprocess.PIPE, text=True)
start = time.monotonic()
try:
    for line in proc.stdout:
        out.write(f"{time.monotonic() - start:7.3f}s  {line}")
        if time.monotonic() - start > 20:
            break
finally:
    proc.terminate()
out.write("\n# If the timestamps step by ~2 s, piping works. Bursts mean ping buffers -> use a pty.\n")
PY
log "ping/streaming_check.txt (see timestamps)"

echo
echo "== Ping with WiFi switched off (sendto errors)"
echo "When you press Enter, ping runs for 30 s. Turn WiFi OFF for ~10 s, then back ON."
read -r -p "Press Enter to start (or type s + Enter to skip): " ANSWER
if [ "${ANSWER:-}" != "s" ]; then
  run ping sendto_error.txt ping -n -c 15 -i 2 1.1.1.1
  echo "Make sure WiFi is back on. Waiting 15 s for it to reconnect..."
  sleep 15
fi

echo "== Traceroute"
run traceroute icmp_1.1.1.1_m20.txt traceroute -I -n -q 3 -w 1 -m 20 1.1.1.1
run traceroute icmp_1.1.1.1_m8.txt traceroute -I -n -q 3 -w 1 -m 8 1.1.1.1
if [ "$HAS_V6" = 1 ]; then
  run traceroute traceroute6_anchor.txt traceroute6 -I -n -q 3 -w 1 -m 20 2606:4700:4700::1111
fi

echo "== networkQuality (~20-60 s, transfers ~1 GB on a fast line)"
run networkquality help.txt networkQuality -h
if networkQuality -h 2>&1 | grep -q -- '-M'; then
  run networkquality run.json networkQuality -c -s -M 20
else
  run networkquality run.json networkQuality -c -s
fi

echo "== Video-service discovery"
run youtube report_mapping.txt curl -s --max-time 10 'https://redirector.googlevideo.com/report_mapping?di=no'
mkdir -p "$OUT/netflix"
python3 - "$OUT/netflix/fast_shape.json" <<'PY'
# Save only the SHAPE of the fast.com answer: keys and server host names. Never client.ip.
import json, re, sys, urllib.request
from urllib.parse import urlparse
result = {"steps": []}
try:
    page = urllib.request.urlopen("https://fast.com/", timeout=10).read().decode()
    script = re.search(r'src="(/app-[^"]+\.js)"', page).group(1)
    result["steps"].append({"app_js_found": True})
    js = urllib.request.urlopen("https://fast.com" + script, timeout=10).read().decode()
    token = re.search(r'token:"([^"]+)"', js).group(1)
    result["steps"].append({"token_found": True, "token_length": len(token)})
    api = f"https://api.fast.com/netflix/speedtest/v2?https=true&token={token}&urlCount=5"
    data = json.loads(urllib.request.urlopen(api, timeout=10).read().decode())
    result["top_level_keys"] = sorted(data)
    result["client_keys"] = sorted(data.get("client", {}))  # keys only, no values
    result["target_hosts"] = [urlparse(t["url"]).hostname for t in data.get("targets", [])]
    result["target_keys"] = sorted(data["targets"][0]) if data.get("targets") else []
except Exception as exc:  # record the failure, it is useful too
    result["error"] = f"{type(exc).__name__}: {exc}"
json.dump(result, open(sys.argv[1], "w"), indent=2)
PY
log "netflix/fast_shape.json"

if [ "$QUICK" = 0 ] && [ -n "$GATEWAY" ]; then
  echo "== WiFi-probe spike check: 10 min pinging the router WITH system_profiler every 60 s,"
  echo "   then 10 min WITHOUT. Leave the Mac alone (on charger, lid open)."
  mkdir -p "$OUT/wifi_probe_check"
  ping -n -i 2 "$GATEWAY" > "$OUT/wifi_probe_check/with_probe_ping.txt" 2>&1 &
  PING_PID=$!
  : > "$OUT/wifi_probe_check/probe_times.txt"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    date +%s >> "$OUT/wifi_probe_check/probe_times.txt"
    system_profiler SPAirPortDataType -json > /dev/null 2>&1
    sleep 60
  done
  kill "$PING_PID" 2>/dev/null
  ping -n -i 2 "$GATEWAY" > "$OUT/wifi_probe_check/without_probe_ping.txt" 2>&1 &
  PING_PID=$!
  sleep 600
  kill "$PING_PID" 2>/dev/null
  log "wifi_probe_check/ (compare RTT spikes with probe_times.txt)"
fi

echo
log "Done. Raw captures are in $OUT/ (git-ignored; contains private data)."
echo
echo "Next:"
echo "  python3 tools/redact.py captures tests/fixtures/macos --term \"<your ISP name>\""
echo "  then grep tests/fixtures/macos for your public IP, WiFi name, router MAC and Mac name,"
echo "  and only then commit tests/fixtures/macos/. Never commit captures/."
