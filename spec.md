# Whodunnet — Spec (v0 / MVP)

> Implements [`intent.md`](./intent.md). Precedence on conflict: **intent → spec → plan**. If this spec contradicts the intent, fix the spec.
> The build plan is in [`plan.md`](./plan.md). Terms are defined in the [Glossary](#16-glossary).

**Status:** reviewed (3 review rounds — see plan §9). Values marked _(initial)_ are starting points, calibrated after the first real week (plan "Calibrate"). Assumptions about macOS behaviour marked _(verify M0.5)_ must be confirmed against real captures before the code depending on them is "done"; each has a stated fallback.

---

## 1. Goals for v0

1. Run unattended on a Mac laptop over WiFi for 1–2 weeks and collect continuous connection data.
2. Attribute each covered minute to a **layer** — WiFi/home network, ISP network, ISP upstream, video path — or none.
3. Turn that into a **verdict** (with confidence, evidence, next steps and what's missing), shown in a local dashboard and an evidence report.
4. Record "**it's lagging right now**" moments (from the Mac, or from an iPhone on the same WiFi) so the verdict can answer "was the network bad when it lagged?".

## 2. Constraints & decisions

| Decision | Choice | Why |
|---|---|---|
| Platform | macOS 13+ | Origin case; `networkQuality` built in. |
| Language | Python 3.9+, **standard library only** at runtime | Runs on `/usr/bin/python3` (Xcode Command Line Tools). No installs beyond CLT. |
| Storage | SQLite, WAL mode | One local file; collector writes while the dashboard reads. |
| Process model | **One long-running collector process** (launchd user agent) that runs the probes **and** serves the web dashboard | The phone lag button must work 24/7, so the web server must always be up. |
| Keeping awake | On charger: collector holds `caffeinate -i -w <pid>`. On battery: caffeinate released, probes continue, `networkQuality` skipped. | 24/7 on charger (decision log). Lid must stay open — a closed lid sleeps regardless. |
| Dashboard | stdlib `http.server`, static HTML/JS, no build step, no external requests | Offline, private. |
| Config | JSON (`config.json`) | `tomllib` needs 3.11. |
| Dev tooling | `pytest`, `ruff` (`target-version = "py39"`, line length 100, default rules); CI on `ubuntu-latest` | Parsers and analysis are pure → testable off-Mac. |

### 2.1 Locations

| What | Path |
|---|---|
| Installed app code | `~/Library/Application Support/Whodunnet/app/` (copied by `install`; never run from the repo — avoids macOS folder-privacy prompts if the repo is in Documents/Desktop) |
| Database | `~/Library/Application Support/Whodunnet/whodunnet.db` |
| Config | `~/Library/Application Support/Whodunnet/config.json` |
| Reports (default output) | `~/Library/Application Support/Whodunnet/reports/` |
| Logs | `~/Library/Logs/Whodunnet/collector.log` (rotating, 5 × 1 MB); launchd's own stdout/stderr → `launchd.out.log` / `launchd.err.log` in the same folder |
| LaunchAgent | `~/Library/LaunchAgents/app.whodunnet.collector.plist` |

`--data-dir DIR` (accepted after any subcommand) or env `WHODUNNET_DATA_DIR` relocates **db, config, reports and logs** together (`DIR/whodunnet.db`, `DIR/config.json`, `DIR/reports/`, `DIR/logs/`); every command honours it. The repo `.gitignore` blocks `.venv/ .devdata/ *.db *.sqlite* reports/ captures/ whodunnet-report-*.html`.

### 2.2 Configuration (`config.json`)

Defaults live in `whodunnet/config.py` (`DEFAULTS`). Missing file → defaults. Unknown keys → warning. Invalid values → error naming the key. Config is read at collector start and on `POST /api/settings`; other changes need a collector restart.

| Key | Default | Meaning |
|---|---|---|
| `anchors` | `{"cloudflare": "1.1.1.1", "google": "8.8.8.8", "bbc": "www.bbc.co.uk"}` | Reference hosts (name → IP or hostname). |
| `anchors_v6` | `{"cloudflare": "2606:4700:4700::1111", "google": "2001:4860:4860::8888", "bbc": "www.bbc.co.uk"}` | IPv6 anchors (hostnames resolved for AAAA). |
| `cdn_youtube` / `cdn_instagram` / `cdn_netflix` | `true` / `true` / `true` | Which video services to measure (§4.1). |
| `discovery_lookups` | `true` | Allow the YouTube/Netflix HTTP lookups (§4.1). `false` → YouTube uses its approximate host, Netflix is `unavailable`. |
| `ipv6` | `"auto"` | `auto` = add IPv6 targets if the Mac has a global IPv6 address; `off`. |
| `ping_interval_s` | `2` | Ping cadence. |
| `wifi_interval_s` / `dns_interval_s` | `60` / `60` | |
| `trace_interval_s` | `1200` | Traceroute cadence. |
| `discover_interval_s` | `1800` | Discovery cadence. |
| `nq_schedule` | `["04:00","10:00","12:00","14:00","19:30","20:30","21:30","22:30"]` | Local times for `networkQuality`: 1 overnight reference, 3 daytime, 4 evening. |
| `evening_window` / `daytime_window` / `quiet_window` | `["19:00","23:00"]` / `["10:00","16:00"]` / `["02:00","06:00"]` | Local `[start, end)`. |
| `web_port` | `8737` | Dashboard port. |
| `lan_access` | `false` | Expose the phone lag page on the LAN (§7.1). |
| `lan_token` | generated at install | `secrets.token_urlsafe(24)`. |
| `raw_ping_retention_days` | `14` | |

Thresholds are **not** config — they live in `whodunnet/core/thresholds.py` (§6.9).

## 3. Architecture

```
  collector process (launchd agent, always running)
  ├─ probes: ping streams (continuous) · wifi (60 s) · dns (60 s) · local load (60 s)
  │          · traceroute (20 min) · networkQuality (8 slots/day) · discovery (30 min + on wake/route change)
  ├─ heartbeat (10 s) · rollup (every minute) · prune (daily)
  └─ web server (127.0.0.1, or 0.0.0.0 if lan_access)  ──►  dashboard · JSON API · phone /lag page
                │ writes                                     │ reads (+ small writes: events, settings)
                ▼                                            ▼
        SQLite: raw tables ──► minute_rollup ──► core/analysis (pure) ──► verdict · report
```

### 3.1 Package layout

```
whodunnet/
  __init__.py  __main__.py      # `python3 -m whodunnet <command>`
  cli.py  config.py  paths.py
  doctor.py      # doctor checks; used by `cli.py doctor` and by the collector (→ meta.doctor_json)
  core/          # NO subprocess, NO macOS imports — reusable by a future native app
    models.py      # dataclasses for rows and results
    schema.py      # DDL + forward-only migrations
    store.py       # read/write helpers (the only place SQL lives)
    rollup.py      # raw ping → minute_rollup
    coverage.py    # covered minutes, gaps, exclusions, derived target status
    baseline.py
    analysis.py    # attribution, findings, verdict, text templates
    thresholds.py  # every numeric threshold, one constant each
    report.py      # report model → self-contained HTML
  probes/        # macOS-specific: run commands; parsing delegated to parsers/
    runner.py      # run_command(argv, timeout) → (rc, stdout, stderr); the only subprocess entry point
    ping.py wifi.py dns.py nq.py trace.py link.py load.py discover.py youtube.py netflix.py power.py
    parsers/       # PURE: text → result dataclass with ok/error. Never raise.
      ping.py route.py traceroute.py system_profiler.py scutil.py dig.py ifconfig.py
      networkquality.py networksetup.py netstat.py pmset.py arp.py
  collector/
    main.py        # process entry: starts probes, scheduler, web server
    scheduler.py   # tick scheduler with injectable clock
  web/
    server.py      # handlers; DB access via core/store only
    static/        # index.html app.js styles.css lag.html qr.js (vendored, MIT)
  launchd/app.whodunnet.collector.plist.template
tools/
  capture_fixtures.sh  redact.py
tests/
  fixtures/macos/<command>/<case>.(txt|json)
  scenarios.py   # synthetic datasets for analysis tests (§11)
  test_*.py
```

## 4. Probes

Common rules:

- Every row records `ts` (UTC epoch **ms**) and, where listed in §5, `link` (`wifi` / `wired` / `other`) and `vpn` (0/1) from §4.7.
- A failed probe writes its row with `ok = 0` and a short `error`; it never raises out of the probe. The collector loop must never die because a probe failed.
- All commands go through `probes/runner.py` with a timeout.
- **Target hostname resolution** uses `dig +short A|AAAA @<primary resolver>` (§4.5), keeping IP lines only (CNAME lines skipped) — the same answer the TV and phones get, unaffected by iCloud Private Relay. If that `dig` fails and the resolver is a LAN/link-local address (e.g. Local Network privacy blocking it), fall back to `socket.getaddrinfo` and mark the target `approximate`.

### 4.1 Targets & discovery (`discover.py`) — at start, every 30 min, on wake, and when the default route changes

A **target** is a logical thing we ping, identified by `(kind, name, af)`. Its IP may change; its identity does not.

| kind | name | af | How it's found |
|---|---|---|---|
| `gateway` | `gateway` | 4 | `route -n get default` → `gateway:`. |
| `isp_edge` | `isp_edge` | 4 | Rule below. |
| `anchor` | config key | 4 / 6 | `anchors` / `anchors_v6` config. |
| `cdn` | `youtube` | 4 / 6 | YouTube rule below. |
| `cdn` | `instagram` | 4 / 6 | `scontent.cdninstagram.com` (approximate by nature — see §14). |
| `cdn` | `netflix` | 4 / 6 | Netflix rule below. |

**ISP edge.** From `traceroute -I -n -q 3 -w 1 -m 8 1.1.1.1`:
- The edge is the **first responding hop after the gateway**, if it is within **2 TTLs** of the gateway and is not the destination. Otherwise `isp_edge` is unknown (not pinged).
- A private (RFC1918) hop after the gateway whose RTT is within **1 ms** of the gateway's is a second home router: skip it and set `meta.double_nat = 1` (`doctor` says "possible double NAT"). Otherwise a private hop is ISP-internal and can be the edge. _(verify M0.5)_
- First discovery with no known edge → adopt immediately. Afterwards a different edge IP is adopted only after it is seen in **2 consecutive** discoveries.

**YouTube (`youtube.py`).** `GET https://redirector.googlevideo.com/report_mapping?di=no` returns the household's mapped Google cache (a POP/node name). Convert to the `rr1---sn-<node>.googlevideo.com` host and resolve it _(verify M0.5: exact response format and conversion)_. Fallback: `redirector.googlevideo.com` with status `approximate`.

**Netflix (`netflix.py`).** Fetch `https://fast.com/`, find the referenced `app-*.js`, extract `token:"…"`, call `https://api.fast.com/netflix/speedtest/v2?https=true&token=<t>&urlCount=5`, and take the hostnames of `targets[].url`. Prefer an `ipv4-…` host for af 4 and an `ipv6-…` host for af 6; if only one family is returned, derive the other by swapping the prefix (same server) _(verify M0.5)_. Total timeout 10 s. **Never store or log the response body** (it contains the household's public IP). Failure → status `unavailable` with reason. Never substitute `www.netflix.com` (AWS, not where video comes from).

YouTube and Netflix lookups only run when `discovery_lookups` is true.

**IPv6.** If `ipv6 = auto` and `ifconfig <default iface>` shows a global IPv6 address (in `2000::/3`), add af 6 targets: `anchors_v6` plus each CDN that has an AAAA answer. Pinged with `ping6`. Gateway and ISP edge are IPv4 only.

**Sticky IPs.** A hostname target keeps its current IP while that IP is in the `dig` answer set (CDN DNS rotates; switching every 30 min would reset baselines). It switches when the IP has been absent from the answer set in **2 consecutive** discoveries — unless it is still answering pings, in which case it switches only once it also stops answering (≥ 10 consecutive lost while the gateway answers). On a switch: update `targets.ip`, append to `target_ips`; if the new IP is in a different `/24` (IPv4) or `/48` (IPv6), set `targets.baseline_epoch_ms = now` (§6.2).

**Discovery status.** Each discovery records a target's status — `ok`, `approximate` (fallback host) or `unavailable` (not found; not pinged) — in `target_status` whenever it changes. `blocked` and `unresponsive` are **not** recorded; they are derived at read time (§6.1).

**Router change detection.** Hash the gateway MAC from `arp -n <gateway>` as SHA-256(`meta.install_salt` + MAC), first 16 hex chars; store in `gateway_mac` when it changes. Gateway IP **or** MAC-hash change → automatic `system` event "Router changed?" (replacement routers usually keep the same IP). An ISP edge change (after the 2-run rule) → `system` event too.

### 4.2 Ping (`ping.py`) — continuous

- One long-lived subprocess per active target: `ping -n -i 2 <ip>` / `ping6 -n -i 2 <ip>`. No root needed for 2 s intervals.
- Read stdout line by line. If lines arrive in bursts when piped (buffering), run the process under a pseudo-terminal (`pty`). _(verify M0.5)_
- `parsers/ping.py` parses one line → `Reply(seq, rtt_ms)` · `Timeout(seq)` · `SendError(reason)` (`ping: sendto: No route to host` / `Host is down` / `Network is down`) · `None` (header/summary) · `Unparsed(line)` (logged, ignored).
- **Outcomes per seq.** The stream keeps outcomes in memory for **10 s** after the seq was sent, then flushes them (batch insert every 5 s). Within that window the **last outcome wins** — a late reply replaces its timeout (stored as received, RTT > 2000 ms). Replies arriving after flush are logged and dropped.
- **`SendError` creates no row**; its reason is attached as `error` to the next timeout/loss row of that stream.
- **Sequence gaps** (seq jumps with no outcome lines) are loss rows, one per missing seq, with `ts` interpolated between the surrounding lines — **unless** a sleep/heartbeat gap (§4.8) overlaps that period, in which case they are dropped (no data). Seq arithmetic is modulo 65536. Gap rules never apply across a process restart (seq restarts at 0). macOS `ping6` may print no timeout lines at all _(verify M0.5)_ — the gap rule covers that.
- `ts` of a row = send time (reply: read time − RTT; timeout: read time − 2 s), so the outcome lands in the minute it was sent.
- Each outcome is one row (`rtt_ms` NULL = lost), so `sent` = row count.
- Restart on process exit, on target IP change, after wake, and every 24 h.
- **Local Network privacy (macOS 15+).** Background agents need user permission to send to LAN addresses (including the router's DNS). At start the collector **sends one UDP datagram** to the gateway (a DNS query to port 53) to trigger the permission prompt _(verify M1.8 on macOS 15: whether this triggers the prompt, and whether Settings lists it as "python3" or "Python")_. It keeps running whether or not access is granted. Blocked detection is derived at read time (§6.1); while blocked, `doctor`, the dashboard and `missing` explain how to allow it.
- Cost: ~8–14 targets × 1 small packet / 2 s — negligible.

### 4.3 WiFi (`wifi.py`) — every 60 s

- `system_profiler SPAirPortDataType -json`, timeout 15 s. (The old `airport` CLI is non-functional since macOS 14.4.)
- Expected shape _(verify M0.5)_: `SPAirPortDataType[0].spairport_airport_interfaces[*]`; use the entry whose `_name` equals the default-route WiFi device. Its `spairport_current_network_information` has:
  - `spairport_signal_noise`: `"-55 dBm / -92 dBm"` → `rssi_dbm`, `noise_dbm`
  - `spairport_network_channel`: `"149 (5GHz, 80MHz)"` → `channel`, `band` (`2GHz` → `2.4`, `5GHz` → `5`, `6GHz` → `6`), `width_mhz`
  - `spairport_network_rate` → `tx_rate_mbps`; `spairport_network_phymode` → `phy_mode`
- Not associated / no current-network block → `ok = 1`, all fields NULL. Missing fields → NULL, never a crash. SSID/BSSID are **never** stored. A channel or band change between consecutive readings is treated as a likely roam/band switch.
- `snr_db` is derived at read time (`rssi − noise`).
- Running `system_profiler` may itself trigger a WiFi scan and spike latency _(verify M0.5: gateway p95 with the probe on vs off, 10 min each)_. If confirmed, `core/rollup.py` drops ping samples sent within `[wifi.started_ts − 3 s, wifi.ts + 3 s]` (thresholds flag `DROP_PINGS_AROUND_WIFI_PROBE`); minutes are not excluded.

### 4.4 Load / bufferbloat (`nq.py`) — 8 slots per day

- Command: `networkQuality -c -s -M 20` (JSON, sequential download then upload, max 20 s). If `-M` is unsupported (checked once via `networkQuality -h`), run without it. _(verify M0.5)_
- Parse (`parsers/networkquality.py`), tolerating missing/renamed keys: `dl_throughput`, `ul_throughput` (**bits/s** → store Mbps), `responsiveness` (RPM; also `dl_responsiveness`/`ul_responsiveness` if present), `base_rtt` (ms). Store raw JSON and macOS version.
- Derived: `loaded_ms = 60000 / rpm` (worse of dl/ul if both present) — an **approximation** of latency under load (includes some connection-setup time). `bufferbloat_ms = loaded_ms − base_rtt`.
- Grade from `bufferbloat_ms` _(initial)_: **A < 30, B < 60, C < 200, D < 400, F ≥ 400**.
- **Schedule:** `nq_schedule` slots (04:00 overnight reference; 10:00, 12:00, 14:00 daytime; 19:30, 20:30, 21:30, 22:30 evening). A slot fires once, within 5 min of its time; a slot missed because the Mac was asleep is not retried.
- **Skip** if on battery (or battery state unknown), or if a `lag` event was recorded in the previous 2 minutes. Skipped runs are rows with `ok = 0`, `error = "skipped:<reason>"`.
- `started_ts` / `ended_ts` stored; minutes overlapping a successful run ±30 s are excluded (§6.1).
- Data use: ~1 GB per run on a fast line → **~8 GB/day** (`doctor` shows the estimate from actual throughput × duration).

### 4.5 DNS (`dns.py`) — every 60 s

- **Primary resolver:** in `scutil --dns`, the first `resolver #N` in the `DNS configuration` section (not "for scoped queries") that has a `nameserver[0]` and **no `domain :` line** (`search domain` lines are ignored). IPv6 link-local resolvers (`fe80::…%en0`) are supported.
- Two timed lookups, each `dig +tries=1 +time=2 @<resolver> <name>`:
  - `cached`: `www.google.com`.
  - `nxdomain`: random 12-char label under `example.com`. Many resolvers answer this from cache (aggressive NSEC caching), so it does **not** claim to measure recursion — it is a second resolver-health sample.
- Parser returns `ms` and `rcode` (or timeout). The probe sets `ok = 1` if an answer arrived with NOERROR or NXDOMAIN. If the resolver is a LAN/link-local address and `dig` fails with a send error or timeout, the row records `error = "lan_unreachable"`; whether that was Local Network blocking is decided at read time (§6.1).
- DNS results are shown in the dashboard and report as context; they do not feed layer attribution in v0.

### 4.6 Traceroute (`trace.py`) — every 20 min

- `traceroute -I -n -q 3 -w 1 -m 20 <ip>` / `traceroute6 -I -n -q 3 -w 1 -m 20 <ip>` (ICMP echo probes; macOS `traceroute` is setuid, no sudo) _(verify M0.5)_.
- Targets: every active anchor and CDN, **sequentially**, budget 90 s per round (unfinished targets go first next round).
- Stored as JSON hops `[{"ttl": 1, "ip": "…" | null, "rtts": [..]}]`. Trailing `*` hops = destination doesn't answer probes — not loss.
- Used by the report (§8). **Interpretation rule:** a hop with high latency/loss that does **not** carry through to later hops is that router de-prioritising probes, not a problem.

### 4.7 Link (`link.py`) — refreshed every 10 s and on route change

- Medium: `route -n get default` → `interface`; `networksetup -listallhardwareports` maps interface → hardware port. `wifi` if the port is "Wi-Fi"/"AirPort"; `other` for "iPhone USB", "Bluetooth PAN", "Thunderbolt Bridge"; otherwise `wired`.
- VPN: `vpn = 1` if the interface from `route -n get 1.1.1.1` (or `route -n get -inet6 2606:4700:4700::1111`) is `utun*`, `ipsec*` or `ppp*` — this also catches VPNs that install `0/1` + `128/1` routes instead of replacing the default. iCloud Private Relay doesn't affect probes; `doctor` always mentions it as info.

### 4.8 Heartbeat, sleep & gaps (`collector/main.py`)

- Heartbeat row every 10 s.
- **Sleep detection:** each tick compare `time.time()` and `time.monotonic()` deltas (monotonic stops during sleep on macOS). Wall clock ahead of monotonic by > 30 s → the Mac slept: write a `system` event "Gap N min (asleep/stopped)", rerun discovery, restart ping streams.
- **Gaps are derived from `heartbeat`** at read time: any interval > 30 s without a heartbeat. Gaps are "no data", never "outage".

### 4.9 Local load (`load.py`) — every 60 s

- `netstat -ibn` → byte counters of the default interface; store the Mac's own throughput over the last minute in `local_load`. Minutes where the Mac itself moved a lot of data are excluded (§6.1) — otherwise the Mac's own downloads/backups would look like ISP congestion. (Other devices' traffic is invisible to Whodunnet; see §14.)

## 5. Data model (SQLite)

```sql
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
  -- schema_version, install_salt, local_hostname, macos_version, double_nat,
  -- doctor_json: collector runs the doctor checks at start and every 10 min →
  --   JSON list of {check, status: ok|warn|fail|info, message, fix}

CREATE TABLE targets (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,            -- gateway | isp_edge | anchor | cdn
  name TEXT NOT NULL,            -- gateway | isp_edge | cloudflare | youtube | ...
  af INTEGER NOT NULL,           -- 4 | 6
  host TEXT,                     -- hostname if any
  ip TEXT,                       -- current IP
  status TEXT NOT NULL,          -- cache of latest discovery status: ok | approximate | unavailable
  active INTEGER NOT NULL,       -- 1 if currently pinged
  baseline_epoch_ms INTEGER,     -- baseline uses data from here on (§4.1 sticky IPs)
  first_seen INTEGER, last_seen INTEGER,
  UNIQUE (kind, name, af));
CREATE TABLE target_ips    (target_id INTEGER, ip TEXT, from_ts INTEGER);
CREATE TABLE target_status (target_id INTEGER, status TEXT, reason TEXT, from_ts INTEGER);
CREATE TABLE gateway_mac   (ts INTEGER, mac_hash TEXT);

CREATE TABLE ping (ts INTEGER, target_id INTEGER, seq INTEGER, rtt_ms REAL,   -- rtt NULL = lost
                   error TEXT, link TEXT, vpn INTEGER);
CREATE TABLE wifi (ts INTEGER, started_ts INTEGER, ok INTEGER, error TEXT,
                   rssi_dbm INTEGER, noise_dbm INTEGER, channel INTEGER, band TEXT,
                   width_mhz INTEGER, tx_rate_mbps REAL, phy_mode TEXT);
CREATE TABLE dns  (ts INTEGER, ok INTEGER, error TEXT, resolver TEXT,
                   query_kind TEXT,              -- cached | nxdomain
                   ms REAL, rcode TEXT, link TEXT, vpn INTEGER);
CREATE TABLE nq   (ts INTEGER, started_ts INTEGER, ended_ts INTEGER, ok INTEGER, error TEXT,
                   dl_mbps REAL, ul_mbps REAL, rpm INTEGER, base_rtt_ms REAL, loaded_ms REAL,
                   bufferbloat_ms REAL, grade TEXT, macos_version TEXT, raw_json TEXT,
                   link TEXT, vpn INTEGER);
CREATE TABLE traceroute (ts INTEGER, target_id INTEGER, ok INTEGER, error TEXT,
                   hops_json TEXT, link TEXT, vpn INTEGER);
CREATE TABLE local_load (minute INTEGER PRIMARY KEY, rx_mbps REAL, tx_mbps REAL);
CREATE TABLE heartbeat (ts INTEGER);
CREATE TABLE events (id INTEGER PRIMARY KEY, ts INTEGER, kind TEXT, note TEXT, source TEXT);
  -- kind:   router_change | package_change | isp_contact | lag | system | other   (UI shows other as "Note")
  -- source: dashboard | cli | phone | auto
CREATE TABLE minute_rollup (
  minute INTEGER,                -- ts_ms // 60000 * 60000 (UTC)
  target_id INTEGER, sent INTEGER, lost INTEGER,
  p50_ms REAL, p95_ms REAL, max_ms REAL, jitter_ms REAL,
  link TEXT, vpn INTEGER,        -- majority value among the minute's samples
  PRIMARY KEY (minute, target_id));
```

- Index on `ts` for every raw table.
- **Rollup rules (`core/rollup.py`):** a minute is rolled up once `now > minute_end + 15 s`; each run re-rolls the last 10 minutes (`INSERT OR REPLACE`). Percentiles: **nearest-rank** over non-NULL RTTs. `jitter_ms` = mean absolute difference between **consecutive received** RTTs (a loss breaks the pair; as used by common speed tests — not the RFC 3550 smoothed estimator). A minute with 0 replies has NULL p50/p95/jitter.
- **Size:** ~8–14 targets × 43,200 rows/day ≈ 350–600k rows/day ≈ 30–50 MB/day. Raw `ping` pruned after `raw_ping_retention_days` (14) → ~0.5–0.7 GB steady state. Everything else kept until `purge --before` or `uninstall --purge`.
- **Never stored:** SSID, BSSID, clear MAC addresses, the household's public IP, YouTube/fast.com response bodies.
- Schema version in `meta.schema_version`; forward-only migrations in `core/schema.py`.
- **Connections:** the collector holds one read-write connection. The web server opens a read-only connection per GET and a short-lived read-write connection (`busy_timeout = 5000`) per POST/DELETE, via `core/store` functions.

## 6. Analysis & verdict (`core/`)

Pure functions. Entry point: `analyse(conn, cfg, start_ms, end_ms) -> Verdict` (`cfg` = loaded config, for windows). `status` and the dashboard use the **last 14 days**; the report uses its own range. Same input ⇒ same output. Local-time windows use the Mac's system time zone; windows are half-open `[start, end)`; an evening belongs to the local date it starts on.

### 6.1 Coverage, exclusions & derived status (`coverage.py`)

- A minute is **covered** if it has ≥ 3 heartbeats, the gateway has a rollup row, and it is not **excluded**.
- A minute's `link` and `vpn` are taken from the gateway's rollup row.
- **Excluded** minutes: overlapping a successful nq run ±30 s (skipped runs don't count); `vpn = 1`; `link = other`; `local_load` rx or tx > `LOCAL_LOAD_MBPS` _(initial: 20)_.
- **Derived status (read time, per minute):**
  - **Gateway blocked** — from the first of ≥ 10 consecutive minutes where the gateway lost every ping while > 50% of downstream targets (anchors + CDNs of both families, ignoring baselines) had < 2 lost, until the gateway's next reply. Blocked minutes stay covered, but §6.4 rows 1–2 are skipped (the gateway is "unknown") and `wifi`/`home_network` are reported as *not measurable* for those minutes.
  - **Target unresponsive** — a downstream or ISP-edge target with > 50% loss across its first 10 rolled-up minutes after `first_seen` (or after an IP switch) while the gateway lost < 2 pings in those minutes → excluded from analysis until its IP changes.
  - Discovery status (`ok`/`approximate`/`unavailable`) at a minute = latest `target_status` row at or before it.
- A window (an evening, a daytime, an hour) is **covered** if ≥ 50% of its minutes are covered.
- **Denominators:** coverage percentages use all minutes of the window. **Layer rates** use covered, non-`inconclusive` minutes of the evaluated address family.

### 6.2 Baseline (`baseline.py`) — computed inside `analyse`, nothing stored

For each target and each local day `d` in the range:

1. Look-back = the 7 days ending at the end of `d`, starting no earlier than the start of the target's current **baseline epoch**. Epoch boundaries are the `target_ips.from_ts` rows whose IP is in a different /24 (/48) from the previous IP (`targets.baseline_epoch_ms` caches the latest). Minutes before a boundary are judged with the previous epoch's baseline.
2. Candidate hours = hours with ≥ 45 covered minutes in which the target has a rollup row.
3. Prefer candidate hours inside `quiet_window`. If fewer than 4: use the 25% of candidate hours with the lowest **hourly p95 summed across all targets** (hourly p95 = p95 of that target's minute `p95_ms` values in the hour).
4. Baseline = median `p50_ms`, and baseline jitter = median `jitter_ms`, over those hours' minutes.
5. A target needs ≥ 4 baseline hours; otherwise it has no baseline that day and is excluded from attribution (counts as "no data" for §6.4).

### 6.3 Bad minute _(initial)_

For a target with a baseline in a covered minute, **bad** if any of:

- **≥ 2 lost** pings in the minute (one isolated loss is normal background noise). For the **ISP edge only**: lost ≥ its median lost-per-minute over that day's §6.2 baseline hours + 2 (rate-limited routers drop pings constantly);
- `p95_ms` > baseline + **40 ms**;
- `jitter_ms` > baseline jitter + **15 ms**.

### 6.4 Layer attribution — per covered minute, per address family

Definitions (gateway and ISP edge are shared by both families):

- `D` = downstream targets of this family (anchors + CDNs) that have data and a baseline, and are not `unavailable`/unresponsive. `A` = anchors in D; `C` = CDNs in D.
- "**majority of X bad**" = X is non-empty, more than half of X's members are bad, **and at least 2** are bad. "**X majority OK**" = X is non-empty and not "majority of X bad".
- The gateway counts as **unknown** if it is blocked or has no baseline; the ISP edge counts as unknown if not found, unresponsive or without baseline.

Check first: if `|D| < 3` → `inconclusive`. Then evaluate top-down; **first match wins**:

| # | Condition | Layer | Tag |
|---|---|---|---|
| 1 | gateway bad **and** majority of D bad | `wifi` (`home_network` if `link = wired`) | WiFi context (below) |
| 2 | gateway bad, D majority OK | `ok` | `router_icmp_slow` (router answers pings slowly but forwards fine) |
| 3 | ISP edge bad **and** majority of D bad | `isp_network` | |
| 4 | majority of A bad **and** majority of C bad | `isp_upstream` | `edge_unknown` if ISP edge unknown |
| 5 | majority of A bad, C majority OK | `isp_upstream` | `general_internet_only` (video caches fine) |
| 6 | A majority OK, and (≥ 2 CDNs bad **or** the same CDN bad in this and the previous 2 covered, consecutive minutes) | `video_path` | names of bad CDNs |
| 7 | ISP edge bad, D majority OK | `ok` | `isp_edge_icmp` (ICMP de-prioritisation) |
| 8 | no target in D bad, or exactly one bad and row 6 not met | `ok` | |
| 9 | anything else | `inconclusive` | |

Rows 1–2 are skipped while the gateway is unknown; rows 3 and 7 while the ISP edge is unknown. Rows 4–6 need both A and C non-empty (otherwise fall through).

**WiFi context** for `wifi` minutes, from the latest wifi reading at or before the minute end: `weak_signal` (RSSI < −70 dBm), `low_snr` (SNR < 20 dB), `band_2_4` (on 2.4 GHz), `band_changed` (channel/band changed vs the previous reading). Reported as shares, e.g. "62% of WiFi-bad minutes were on 2.4 GHz".

**Address family.** Attribution runs for af 4 and af 6 separately. The verdict uses **af 6** if af 6 had `|D| ≥ 3` in ≥ 50% of covered minutes (video apps prefer IPv6); otherwise af 4. The other family is reported alongside as evidence.

### 6.5 Findings

**Layer problem** (per layer: `wifi`, `home_network`, `isp_network`, `isp_upstream`, `video_path`):

- A covered evening **shows** the layer if its layer rate ≥ **5%**. Same for a covered daytime.
- **Evening problem:** shown on ≥ **3** covered evenings **and** overall evening rate ≥ **2×** overall daytime rate. If there are **no covered daytimes**, the 2× test is waived, confidence is capped at medium, and `missing` gets "No daytime data to compare".
- **All-day problem:** not an evening problem, but shown on ≥ 3 covered evenings **and** on ≥ 3 covered daytimes.
- Strength = overall evening layer rate.

**Bufferbloat under load:** ≥ **6** successful nq runs in range, and grade **D or F** on ≥ **30%** of them. Labelled "bufferbloat under load (home router, WiFi or ISP shaper)"; if the bad runs were on `link = wired`, "(home router or ISP shaper)". Median `bufferbloat_ms` and the grade distribution are evidence.

**Lag markers:** for each `lag` event, look at the covered minutes in `[t − 2 min, t + 2 min]`:
- **network-bad** — any of them has a layer other than `ok`/`inconclusive`;
- **network-ok** — none is bad and at least one is `ok`;
- **unknown** — none covered, or all covered ones `inconclusive` (counted in `missing`).

Derived:
- **Device or app:** ≥ **5** known (non-unknown) moments and ≥ **70%** network-ok.
- **Lag confirms network:** ≥ 5 known moments and > **50%** network-bad. The **lag layer** = the layer most often bad at network-bad moments.

**Wired vs WiFi** (if ≥ 1 covered wired evening and ≥ 3 covered WiFi evenings):
- An evening's link = the majority `link` of its covered minutes (from the gateway's rollup rows).
- Per link, the **network-bad rate** = share of covered, non-inconclusive evening minutes whose layer is not `ok`. A link is **bad** if that rate ≥ 5%, otherwise **clean**.
- **Confirms wifi:** WiFi evenings' `wifi` layer rate ≥ 5% and wired is clean.
- **Both bad:** WiFi evenings' `wifi` layer rate ≥ 5% and wired is bad.

**Before / after events:** for each `router_change`, `package_change` and `isp_contact` event, compare layer evening rates over covered evenings before vs after it (up to 7 each side; needs ≥ 2 each side).

### 6.6 Verdict selection

Ordered — the first match is the **primary** verdict; every other finding that holds goes into `secondary`:

1. `insufficient_data` — < 3 covered evenings, or (no gateway baseline **and** the gateway was never blocked).
2. Among layers with an **evening problem**, the one with the highest evening rate → that layer, qualifier `evening`.
3. The same for an **all-day problem** → qualifier `all_day`.
4. **Lag confirms network** → the lag layer, qualifier `at_lag_moments` (short bursts that coincide with lag but don't reach 5% of evenings).
5. `bufferbloat`.
6. `device_or_app`.
7. `no_problem_found`.

**Confidence**

| Verdict | High | Medium | Low |
|---|---|---|---|
| Layer (`evening` / `all_day`) | ≥ 7 covered evenings and shown on ≥ 70% of them | ≥ 3 covered evenings and shown on ≥ 50% | otherwise |
| Layer (`at_lag_moments`) | — | ≥ 5 known lag moments | — |
| `bufferbloat` | ≥ 20 runs | ≥ 6 runs | — |
| `device_or_app` | ≥ 10 known lag moments | ≥ 5 | — |
| `no_problem_found` | ≥ 7 covered evenings, ≥ 5 known lag moments | ≥ 7 covered evenings | ≥ 3 covered evenings |
| `insufficient_data` | — | — | always |

Adjustments (applied in order, never above high or below low):
- **+1** for a layer verdict with qualifier `evening` or `all_day` if lag confirms network **and** the lag layer equals the verdict layer. (Never applied to `at_lag_moments`, whose confidence is fixed at medium.)
- **+1** for `wifi` if wired-vs-WiFi "confirms wifi"; **−1** if "both bad".
- **−1** for a layer verdict if lag markers point to `device_or_app`; add an evidence note.
- `isp_network` / `isp_upstream` / `video_path` are **capped at medium** while the bufferbloat finding also holds (home load could be the cause); `missing` gets "Pause big downloads/backups (or enable SQM) for one evening to rule out home load".
- Capped at medium when the "no daytime" rule of §6.5 applied.

**`missing`** — every applicable line, in this order:
- "Need N more covered evenings" (to reach 3, then 7).
- "Mark lag moments with the 'It's lagging now' button" (if < 5 known moments).
- "X% of evening time had no data — keep the Mac awake, on charger, lid open" (evening coverage < 80%).
- "Your router doesn't answer Whodunnet — allow Local Network access" (gateway blocked in range).
- "Couldn't find your Netflix/YouTube server" (any CDN `unavailable` or `approximate`).
- "One evening on a wired adapter would confirm the WiFi verdict" (primary `wifi`, no wired evening).
- "No daytime data to compare".
- "Pause big downloads/backups … to rule out home load" (see caps).
- "N% of minutes were inconclusive" (> 10%).
- "N lag moments fell in periods with no data" (any unknown).

**Next steps (fixed text per primary verdict)**

| Verdict | Next steps |
|---|---|
| `wifi` | Move closer to the router or use 5 GHz; try a different WiFi channel; do one evening on a wired adapter to confirm. |
| `home_network` | Check the cable/adapter and any switch or mesh unit between the Mac and the router. |
| `isp_network` | Raise a fault with your ISP and attach the report — the slowdown is inside their network. |
| `isp_upstream` | Raise a fault with your ISP and attach the report — their links to the wider internet are congested at peak times. |
| `video_path` | Raise it with your ISP, naming the affected services — their route to those video services is congested. |
| `bufferbloat` | Turn on SQM / "Smart Queue" / QoS on the router if it has it; pause big downloads and backups in the evening. |
| `device_or_app` | The network was healthy when you saw lag — check the device (updates, storage, low-power mode) or the app. |
| `no_problem_found` | Keep collecting and keep marking lag moments — they're the best evidence. |
| `insufficient_data` | Follow the "missing" list. |

### 6.7 Verdict object

```json
{
  "verdict": "isp_upstream",
  "qualifier": "evening",
  "confidence": "medium",
  "address_family": 6,
  "summary": "Evenings are worse beyond your ISP's network: 12% bad minutes 19:00–23:00 vs 1% in the daytime.",
  "evidence": [ { "claim": "...", "metric": "layer_rate", "evening": 0.12, "daytime": 0.01, "evenings_shown": 5, "evenings_covered": 6 } ],
  "secondary": [ { "finding": "bufferbloat", "detail": "grade D or F on 4 of 9 runs" } ],
  "lag": { "known": 6, "network_bad": 5, "network_ok": 1, "unknown": 1, "lag_layer": "isp_upstream" },
  "not_measurable": [ "wifi" ],
  "next_steps": [ "..." ],
  "coverage": { "from": "2026-10-04", "to": "2026-10-11", "evenings_covered": 6, "evening_coverage_pct": 86 },
  "missing": [ "..." ]
}
```

`qualifier` ∈ `evening | all_day | at_lag_moments | null`. `not_measurable` lists `wifi` and `home_network` when the gateway was blocked in > 50% of covered evening minutes. `summary`, `evidence[].claim`, `next_steps` and `missing` are plain English from templates in `core/analysis.py`.

### 6.8 Determinism & tests

Every rule in §6 has a unit test. Every threshold boundary (exactly 5%, exactly 2×, exactly 3 evenings, exactly 2 lost pings, exactly 70%) has a test on each side.

### 6.9 Thresholds

Every numeric threshold in §4.1 (ISP edge TTL distance, double-NAT RTT), §4.4 (grades), §6.1 (blocked/unresponsive/local load), §6.2–6.6 lives in `core/thresholds.py` as a named constant with a comment pointing to its spec section. Changing one requires updating this spec, a test pinning the new behaviour, and a Decisions log entry — all in the same PR.

## 7. Web (`web/`, served by the collector)

### 7.1 Binding & access

- Default: bind `127.0.0.1:<web_port>`.
- `lan_access = true`: bind `0.0.0.0:<web_port>`.
- **Every request:** `Host` must be `127.0.0.1:<port>`, `localhost:<port>` or `<LocalHostName>.local:<port>` (compared case-insensitively); otherwise 403 (blocks DNS rebinding).
- **Loopback requests** get the full dashboard and API. Every non-GET loopback request must carry `X-Whodunnet: 1` and `Content-Type: application/json`, otherwise 403 (blocks cross-site POSTs from other web pages).
- **Non-loopback requests** (phone) may only reach `GET /lag` and `POST /api/lag`:
  - `GET /lag?t=<token>` with a valid token → the lag page, and sets cookie `wd_token=<token>; HttpOnly; SameSite=Strict; Max-Age=31536000`. No redirect — the token stays in the URL so "Add to Home Screen" keeps it (home-screen web apps have their own cookie jar).
  - `POST /api/lag` requires the cookie to equal the current token (regenerating the token invalidates old links).
  - Anything else, or a wrong token → 403 "This link is invalid". Token comparison is constant-time.
- `doctor` warns if the macOS Application Firewall is on (`/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate`) — it will ask to allow incoming connections for python3.

### 7.2 Views (loopback only)

| View | Content |
|---|---|
| **Verdict** (home) | Verdict card (summary, qualifier, confidence, next steps, missing, not measurable) · coverage · **"It's lagging now"** button |
| **Timeline** | 24 h / 7 d: per-layer strip, RTT & loss per target, WiFi RSSI/band, events & lag markers overlaid, gaps and excluded minutes shaded |
| **Heatmap** | Day × hour; metric: layer rate, loss, p95, bufferbloat, download Mbps |
| **Evening vs daytime** | Per-layer table behind the verdict, per address family |
| **Events** | Add (Router change, Package change, ISP contact, Note) / list / delete |
| **Report** | Date range → generate and open the report |
| **Settings** | LAN access on/off (writes config atomically, rebinds the server), phone link + QR code + "Add to Home Screen" steps, regenerate token, data-use estimate, doctor summary (read from `meta.doctor_json` — `web/` never runs commands) |

All views work at phone width. The phone `/lag` page is one big button and a confirmation. No request leaves the machine.

### 7.3 API (JSON; loopback only except `POST /api/lag`)

| Method & path | Purpose |
|---|---|
| `GET /api/verdict` | Verdict object (§6.7), last 14 days |
| `GET /api/timeline?from&to` | Rollups per target, layer per minute, wifi, events, gaps |
| `GET /api/heatmap?metric&from&to` | Day × hour matrix |
| `GET /api/compare?from&to` | Evening vs daytime per layer and family |
| `GET /api/events?from&to` · `POST /api/events` · `DELETE /api/events/<id>` | Events (user kinds only: `router_change`, `package_change`, `isp_contact`, `other`) |
| `POST /api/lag` | Add a `lag` event (`source` = `dashboard` or `phone`) |
| `GET /api/report?from&to` | Generated report HTML |
| `GET /api/settings` · `POST /api/settings` | LAN access, token regeneration |

`from`/`to` are UTC epoch ms everywhere except `/api/report`, which takes local dates `YYYY-MM-DD` (inclusive) like the CLI. Errors: `{"error": "..."}` with 400/403/404. Exact request/response shapes are defined in M3.1 and recorded here in the same PR. The phone link is `http://<meta.local_hostname>.local:<port>/lag?t=<token>` (`local_hostname` from `scutil --get LocalHostName`, written by the collector).

## 8. Evidence report (`core/report.py`)

Single self-contained HTML (inline CSS/SVG), A4 print CSS → the user prints to PDF. Default output `reports/whodunnet-report-<from>-<to>.html` in the data dir.

1. **Summary** — verdict, qualifier, confidence, date range, coverage.
2. **What the household experienced** — lag moments with times and network status at each.
3. **Evening vs daytime** — per-layer table + heatmap of layer rate.
4. **Where it breaks** — layer attribution. Traceroute excerpts for the **worst-affected target** (the downstream target with the highest evening bad-minute rate): the evening traceroute and the daytime traceroute whose destination RTT is the median of their respective windows (destination RTT = last responding hop if the destination doesn't answer). Hops are labelled by **position**: before the ISP edge = **home**; from the ISP edge on, private, CGNAT and same-/16-as-edge hops = **ISP**; the rest = **beyond ISP**. If no ISP edge is known: the gateway (and a skipped double-NAT hop) = home; private/CGNAT hops after it = ISP; the rest = beyond ISP.
5. **Speed & responsiveness** — nq results by slot; grade distribution.
6. **Already tried** — events timeline with before/after evening rates (§6.5).
7. **Wired vs WiFi** — if available.
8. **Method & limitations** — what was measured, how often, thresholds, exclusions; "measured from a laptop over WiFi — macOS WiFi has inherent short spikes"; "other devices' traffic is not visible"; address families.
9. **Your rights (UK)** — short fixed text: Ofcom's voluntary broadband speeds code, under which signatory ISPs give a minimum guaranteed **download speed** and must fix a shortfall within 30 days or let you leave without penalty (the evening `networkQuality` download figures are the relevant evidence); check whether your ISP is a signatory; you can escalate to an ADR scheme after 8 weeks. Shows `RIGHTS_TEXT_CHECKED` (a constant in `core/report.py`, initially `2026-10-04`).
10. **Appendix** — daily table: date, covered %, evening and daytime layer rates, nq median down/up/grade, lag moments.

Privacy: the household public IP is never collected, so it never appears. Home hops are shown as "home router" / "home device", without IPs. ISP and beyond-ISP hop IPs are shown (that's the evidence). No SSID.

## 9. CLI

All commands: `python3 -m whodunnet <command>`; all accept `--data-dir` (or `WHODUNNET_DATA_DIR`). Local dates/times in arguments use the Mac's time zone.

| Command | Does |
|---|---|
| `install` | Prerequisite checks; explain what is measured and the outbound traffic; ask whether to allow YouTube/Netflix server lookups (sets `discovery_lookups`, default yes); copy the package to the app dir; create the log dir; write config (token) and `meta.install_salt`; `bootout` any already-loaded agent; render the plist (`/usr/bin/python3 -m whodunnet run [--data-dir …]`, `RunAtLoad`, `KeepAlive`, `ThrottleInterval 30`, `ProcessType Standard`, `WorkingDirectory` + `PYTHONPATH` = app dir, stdout/stderr → `launchd.out.log`/`launchd.err.log` in the log dir, i.e. `DIR/logs/` under `--data-dir`); `launchctl bootstrap gui/$(id -u) <plist>`; tell the user to approve the Local Network prompt and keep the "Background Items Added" item enabled. |
| `uninstall [--purge]` | `launchctl bootout gui/$(id -u)/app.whodunnet.collector`; remove plist and app dir; `--purge` also deletes db, config, reports, logs. |
| `run [--foreground] [--nq-now]` | The collector (what launchd runs). `--foreground` also logs to the terminal. `--nq-now` runs one nq immediately. |
| `status` | Running? (last heartbeat < 30 s ago), last sample age per probe, coverage, verdict summary. |
| `doctor` | Checks, each with a fix: `xcode-select -p`; Python ≥ 3.9; required commands present; collector running; **gateway reachable from the agent** (recent gateway rollups in the DB, not a Terminal ping); Local Network blocked; on charger; lid advice; possible double NAT (`meta.double_nat`); VPN; Private Relay (always info); AWDL active (`ifconfig awdl0`; info: AirDrop/Handoff cause short spikes); WiFi band; firewall; disk space; app dir location; nq data-use estimate; **discovered targets** (kind/name/af/ip/status). |
| `dashboard` | Open `http://127.0.0.1:<port>/` (served by the collector; if it isn't running, say so and suggest `run --foreground`). |
| `event "<note>" [--kind router_change\|package_change\|isp_contact\|other] [--at "YYYY-MM-DD HH:MM"]` | Add an event; defaults: kind `other`, time now. |
| `lag` | Add a `lag` event now (`source = cli`). |
| `report --from YYYY-MM-DD --to YYYY-MM-DD [-o FILE]` | Write the report (default in the data dir's `reports/`). Dates inclusive. |
| `export [--from] [--to] -o DIR` | One CSV per table: `targets, target_ips, target_status, ping, minute_rollup, wifi, dns, nq, traceroute, local_load, events, heartbeat`. (`gateway_mac` and `meta` are not exported — privacy.) |
| `purge --before YYYY-MM-DD` | Delete raw and rollup data before a date. |

## 10. Privacy & safety

- Outbound traffic is only: probe packets (ping/traceroute/dig), `networkQuality` (Apple's test servers), and — if `discovery_lookups` — HTTP lookups to YouTube's redirector and fast.com. No telemetry, no update checks.
- Never stored: SSID, BSSID, clear MAC addresses, the household public IP, discovery response bodies. The gateway MAC is stored only as a salted hash.
- Web server: loopback-only unless `lan_access`; Host-header and custom-header checks; on the LAN only the lag page, token-protected.
- Read-only with respect to the system: never changes network, WiFi or router settings. No `sudo`.

## 11. Testing

- **Parsers:** fixture tests for every parser in §3.1 — including ping `sendto` errors, late replies, seq wrap, ping6 output; `system_profiler` with missing fields / not associated / several interfaces; `networkQuality` with and without per-direction keys. Fixtures come from `tools/capture_fixtures.sh` + `tools/redact.py` (plan M0.5). Required: the founder's macOS version; others added when available. Until real fixtures exist, parsers may merge against hand-written `provisional_*` fixtures; a parser task is **done** only when real fixtures pass.
- **Ping stream:** fake process feeding lines — late reply inside/outside the 10 s hold, `sendto` + timeout = one loss, seq gap with and without an overlapping sleep gap, seq wrap, restart.
- **Rollup & coverage:** synthetic streams → expected sent/lost/p50/p95/jitter; gaps; each exclusion; blocked and unresponsive derivation.
- **Analysis:** `tests/scenarios.py` writes `targets`, `target_ips`, `target_status`, `minute_rollup`, `heartbeat`, `wifi`, `nq`, `local_load`, `traceroute` and `events` rows directly (no raw pings). Expected results:

| Scenario | Verdict | Qualifier | Confidence |
|---|---|---|---|
| WiFi bad evenings (gateway + downstream), 8 evenings | `wifi` | evening | high |
| WiFi bad on 4 WiFi evenings + 1 clean wired evening | `wifi` | evening | high (medium +1) |
| Same on wired link | `home_network` | evening | high |
| ISP edge + downstream bad evenings, 8 evenings | `isp_network` | evening | high |
| Anchors + CDNs bad evenings, edge fine, 4 evenings | `isp_upstream` | evening | medium |
| Only ≥ 2 CDNs bad evenings, 8 evenings | `video_path` | evening | high |
| Layer bad evenings and daytimes equally | that layer | all_day | per table |
| Short bursts at ≥ 5 lag moments only | that layer | at_lag_moments | medium |
| nq grade D/F on 40% of 10 runs, pings clean | `bufferbloat` | — | medium |
| Clean network, 6 lag moments all ok | `device_or_app` | — | medium |
| Clean network, 8 evenings, no lag moments | `no_problem_found` | — | medium |
| < 24 h of data | `insufficient_data` | — | low |
| Gateway slow only (router slow path) | not `wifi` | — | — |
| Gateway blocked, upstream bad evenings | `isp_upstream`, `wifi` not measurable | evening | per table |
| ISP edge lossy all the time, downstream clean | not `isp_network` | — | — |
| Single flaky CDN | `no_problem_found` | — | — |
| Bad minutes only during nq runs / Mac's own load | `no_problem_found` | — | — |
| Long sleep gaps, clean otherwise | `no_problem_found`, gaps not counted as loss | — | — |
| IPv6 bad, IPv4 clean, v6 targets present | layer (af 6) | evening | per table |

- **Web:** Host-header and custom-header checks; token flows; non-loopback restrictions.
- **CI:** GitHub Actions, `ubuntu-latest`, Python 3.9 and 3.12: `ruff check`, `ruff format --check`, `pytest`. Probes are not run in CI.

## 12. Milestones (summary — tasks in `plan.md`)

| # | Deliverable |
|---|---|
| M0 | Scaffold, CI, README |
| M0.5 | Real macOS fixtures + verification of every _(verify M0.5)_ item |
| M1 | Collector: probes, storage, discovery, CLI `install/uninstall/run/status/doctor/event/lag/export/purge` |
| M2 | Rollup, coverage, baseline, attribution, findings, verdict |
| M3 | Web server, dashboard, Settings, phone lag page |
| M4 | Evidence report, CLI `report` |
| — | Calibrate thresholds on the first real week |

## 13. Out of scope for v0

Native macOS app, native iPhone app (the v0 phone lag marker is a web page), plug-in probe, Windows/Linux, cloud sync, accounts, automatic router changes, video-style CDN download test (candidate v0.2), multi-household comparison, measuring other devices' traffic.

## 14. Known limitations

- Measured from a laptop over WiFi: the Mac's own WiFi (power save, AWDL, scans) adds short spikes. Mitigated by requiring downstream confirmation for `wifi` and by optional wired evenings.
- ICMP is not video traffic; routers and CDNs may treat it differently. §6.4 rows 2 and 7 and the unresponsive rule cover the known cases.
- Other devices' traffic (TV, phones, consoles) is invisible; heavy household use can look like ISP congestion. Mitigated by the bufferbloat cap and the "pause big downloads" check.
- `networkQuality` measures to Apple's servers, not video CDNs.
- Instagram's target is its general CDN hostname, not necessarily the household's exact cache. The YouTube/Netflix discovery endpoints are unofficial and may change; targets then degrade to `approximate`/`unavailable`.

## 15. Decisions log

| Date | Decision | Why |
|---|---|---|
| 2026-10-04 | Collect **24/7 while on charger**; on battery continue without caffeinate and skip nq. | Best evidence; analysis handles gaps. |
| 2026-10-04 | `networkQuality` **8 runs/day** (1 overnight, 3 daytime, 4 evening), `-s -M 20`. | Evening-vs-daytime comparison at ~8 GB/day instead of ~70 GB/day at every 20 min. |
| 2026-10-04 | **Phone "lagging now" marker in v0** (opt-in LAN, token, lag page only). | Most direct answer to "is it the phone?". |
| 2026-10-04 | Default video targets **YouTube, Instagram, Netflix**; YouTube via `report_mapping`, Netflix via fast.com. | What the household uses; DNS alone doesn't find the real video caches. |
| 2026-10-04 | Evening 19:00–23:00, daytime 10:00–16:00, quiet 02:00–06:00. | Matches when lag is noticed; revisit at calibration. |
| 2026-10-04 | The collector also serves the web app. | The phone button needs an always-on server. |
| 2026-10-04 | `wifi` requires gateway **and** downstream bad; loss needs ≥ 2 lost pings/min; majorities need ≥ 2 bad targets. | Avoid false WiFi/ISP verdicts from router slow-path pings, background loss and single flaky hosts. |
| 2026-10-04 | IPv6 targets measured when available; verdict prefers IPv6 when it has enough targets. | Video apps prefer IPv6; IPv4 may take a different (CGNAT) path. |
| 2026-10-04 | Exclude minutes with heavy traffic from the Mac itself; cap ISP verdicts at medium while bufferbloat holds. | Household load must not be blamed on the ISP. |
| 2026-10-04 | Blocked/unresponsive derived at read time; discovery status kept as history. | Analysis must know what was true at each minute. |

## 16. Glossary

| Term | Meaning here |
|---|---|
| **Gateway** | The home router — first hop from the Mac. |
| **ISP edge** | The first responding router after the home network, within 2 hops of the gateway — the first router inside the ISP. |
| **CGNAT** | Carrier-grade NAT; ISP-internal addresses in `100.64.0.0/10`. |
| **Double NAT** | A second home router (e.g. a mesh system) behind the ISP router. |
| **Anchor** | A stable, well-connected public host (e.g. `1.1.1.1`) standing for "the internet in general". |
| **CDN / video path** | The servers video actually streams from (YouTube/Netflix caches, Instagram's CDN). |
| **Downstream (D)** | Anchors + CDNs — everything beyond the ISP edge that we ping. |
| **Upstream / peering** | The ISP's links to the rest of the internet; congestion shows on a majority of anchors and CDNs while the ISP edge looks fine. The intent's "ISP peering / video services" = `isp_upstream` + `video_path`. |
| **Target** | A logical thing we ping, identified by kind + name + address family; its IP can change. |
| **Address family (af)** | IPv4 (4) or IPv6 (6). |
| **RTT** | Round-trip time of one ping, in ms. |
| **p50 / p95** | Median / 95th-percentile RTT in a minute (nearest-rank). With ~30 samples, p95 ≈ the second-highest. |
| **Jitter** | Mean absolute difference between consecutive received RTTs. |
| **Packet loss** | Pings with no reply. |
| **Slow path / ICMP de-prioritisation** | Routers answer pings *to themselves* at low priority; slow replies from a hop don't mean traffic *through* it is slow. |
| **Bufferbloat** | Latency rising sharply when the line is busy because a device queues too much traffic. |
| **RPM** | "Round-trips per minute" from `networkQuality`; `60000 / RPM` ≈ latency under load in ms. |
| **Baseline** | A target's normal RTT and jitter, from the quietest hours (§6.2). |
| **Covered minute / window** | A minute with data that isn't excluded / a window with ≥ 50% covered minutes (§6.1). |
| **Excluded minute** | A minute deliberately ignored: during a speed test, on VPN, on an `other` link, or while the Mac itself was moving lots of data. |
| **Blocked gateway** | macOS Local Network privacy stopping Whodunnet reaching the router (§4.2, §6.1). |
| **Gap** | A period with no heartbeat (Mac asleep or collector stopped). "No data", never "outage". |
| **Bad minute** | A target breaching the §6.3 thresholds in a minute. |
| **Layer** | Where a minute is attributed (§6.4): `wifi`, `home_network`, `isp_network`, `isp_upstream`, `video_path`, `ok`, `inconclusive`. |
| **Evening / all-day problem** | §6.5. |
| **Lag moment** | A `lag` event — someone pressed "It's lagging now". |
