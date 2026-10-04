# Whodunnet — Spec (v0 / MVP)

> Implements [`intent.md`](./intent.md). Where this spec and the intent disagree, the intent wins and this spec gets fixed.

**Status:** draft for review. Thresholds marked _(initial)_ are starting points to be calibrated against real data — not truths.

---

## 1. Goals for v0

1. Run unattended on a Mac laptop over WiFi for 1–2 weeks and collect continuous connection data.
2. Attribute bad periods to a **layer**: WiFi, ISP network, beyond the ISP (peering / CDN), home bufferbloat — or none.
3. Show it in a local dashboard and export an evidence report.
4. Let the user mark "**it's lagging right now**" moments (from the Mac, or from an iPhone on the same WiFi) so the verdict can answer "was the network bad when it lagged?".

## 2. Constraints & decisions

| Decision | Choice | Why |
|---|---|---|
| Platform | macOS 13+ (Ventura or later) | Origin case; `networkQuality` is built in (macOS 12+). |
| Language | Python 3.9+, **standard library only** at runtime | Runs on the system `python3` that ships with Xcode Command Line Tools — nothing to install. Keeps the core portable to a future native app. |
| Storage | SQLite (stdlib `sqlite3`) | Single local file, no server. |
| Scheduling | `launchd` user agent (`~/Library/LaunchAgents`) | Starts at login, restarted if it crashes. |
| Keeping awake | Collector holds a `caffeinate -i -w <pid>` assertion | Prevents idle sleep while collecting. Lid must stay open (closed lid sleeps regardless — documented). |
| Dashboard | stdlib `http.server` + static HTML/JS, no build step, no CDN | Works offline, nothing leaves the machine. Charts drawn with vanilla JS (canvas/SVG). |
| Config | JSON file | `tomllib` needs Python 3.11; JSON keeps us on stdlib 3.9. |
| Dev tooling | `pytest` (dev only), GitHub Actions on `ubuntu-latest` | Parsers and analysis are pure functions → testable off-Mac. |

**Locations**

- Data: `~/Library/Application Support/Whodunnet/whodunnet.db`
- Config: `~/Library/Application Support/Whodunnet/config.json`
- Logs: `~/Library/Logs/Whodunnet/collector.log`
- LaunchAgent: `~/Library/LaunchAgents/app.whodunnet.collector.plist`

Nothing in these paths is ever inside the repo. `.gitignore` additionally blocks `*.db`, `*.sqlite`, `reports/`, `captures/`.

## 3. Architecture

```
            ┌───────────────────────── collector (long-running process) ─────────────────────────┐
            │  probes/                                                                            │
            │   ping_stream ×N ─┐   wifi (1 min) ─┐   dns (1 min) ─┐   nq (sched) ─┐  trace (20m) │
            │                   └───────────┬─────┴────────────────┴───────────────┴──────┬───────┘
            │                          store.write()                         rollup (every minute)
            └──────────────────────────────┼──────────────────────────────────────────────┼──────┘
                                           ▼                                              ▼
                                    SQLite: raw tables  ───────────────────────►  minute_rollup
                                                                                        │
                    core/analysis (pure functions: rollups → layer health → verdict)    │
                                                                                        ▼
                     web/server (localhost)  ── dashboard · events · lag marker · report export
```

Package layout:

```
whodunnet/
  cli.py                 # entry point: `python3 -m whodunnet <command>`
  config.py
  core/                  # NO macOS / IO dependencies — reusable by a future native app
    schema.py            # SQL DDL + migrations
    store.py             # read/write helpers
    rollup.py            # raw → per-minute aggregates
    baseline.py          # per-target "normal" levels
    analysis.py          # layer health, peak vs off-peak, verdict
    report.py            # report data model → HTML
  probes/                # macOS-specific: run commands, parse output
    ping.py  wifi.py  dns.py  nq.py  trace.py  link.py  discover.py
    parsers/             # pure parsing functions, unit-tested with fixtures
  collector/
    runner.py            # scheduler loop, sleep/wake detection, caffeinate
  web/
    server.py
    static/              # index.html, app.js, styles.css
  launchd/
    app.whodunnet.collector.plist.template
tests/
  fixtures/              # captured & redacted command outputs
  test_parsers_*.py  test_rollup.py  test_analysis_*.py
```

## 4. Probes

All probes record `ts` (UTC, epoch ms) and the active **link** (§4.6). Every probe that fails records the failure — a failed probe is data, not an exception.

### 4.1 Target discovery (`discover.py`) — at start, every 30 min, and on network change

| Target kind | How it's found |
|---|---|
| `gateway` | `route -n get default` → `gateway:` |
| `isp_edge` | `traceroute -n -q 1 -w 1 -m 6 1.1.1.1` → first hop **after** the gateway that responds. (May be CGNAT `100.64.0.0/10` — still counts as ISP.) |
| `anchor` | Configurable; defaults `1.1.1.1`, `8.8.8.8`, `www.bbc.co.uk` (resolved once per discovery). |
| `cdn` | Configurable; defaults `scontent.cdninstagram.com`, `redirector.googlevideo.com`. Resolved at discovery time so we follow the CDN node the household actually uses. |

If the gateway or ISP edge changes, a `system` event is recorded automatically (e.g. new router).

### 4.2 Ping (`ping.py`) — continuous

- One long-lived `ping -i 2 -n <ip>` subprocess per target (2 s interval needs no root on macOS).
- Parse streamed lines:
  - `64 bytes from …: icmp_seq=N ttl=… time=X ms` → `rtt_ms = X`
  - `Request timeout for icmp_seq N` → `rtt_ms = NULL` (lost)
- Gaps in `icmp_seq` are also treated as loss.
- Subprocess restarted on exit or on target change.
- Cost: ~4–6 targets × 1 packet / 2 s — negligible.

### 4.3 WiFi (`wifi.py`) — every 60 s

- Source: `system_profiler SPAirPortDataType -json` (no sudo; the `airport` CLI was removed in macOS 14.4).
- Recorded: `rssi_dbm`, `noise_dbm`, `snr_db` (derived), `channel`, `band` (2.4/5/6 GHz), `channel_width_mhz`, `tx_rate_mbps`, `phy_mode`.
- **Not recorded:** SSID, BSSID (privacy; also redacted by macOS without Location permission). Instead a `bssid_hash` is computed **only if** available, to detect roaming between access points/bands without storing the identifier.
- Parsing is defensive: the JSON shape varies by macOS version; missing fields → `NULL`, never a crash.

### 4.4 DNS (`dns.py`) — every 60 s

- Resolver(s) from `scutil --dns` (first `nameserver[0]` of the primary resolver).
- Two timed lookups with `dig +tries=1 +time=2 @<resolver>`:
  - `cached`: a popular name (e.g. `www.google.com`) → resolver responsiveness.
  - `uncached`: `<random>.whodunnet-probe.<configured domain>`-style random label under a well-known domain → forces recursion.
- Recorded: `query_kind`, `ms`, `ok`, `rcode`.

### 4.5 Load / bufferbloat (`nq.py`) — scheduled, see note

- `networkQuality -c` (JSON output). Recorded: `dl_mbps`, `ul_mbps`, `responsiveness_rpm`, `base_rtt_ms`, plus raw JSON (keys differ across macOS versions).
- Derived: `bufferbloat_ms` = loaded latency − base RTT (from RPM: `60000 / rpm`), and a grade A–F _(initial)_: A < 5 ms, B < 30, C < 60, D < 200, F ≥ 200.
- **Data-use warning:** on a fast full-fibre line a single run can transfer ~1 GB+. Default schedule: **every 60 min, plus every 30 min between 18:00–24:00** (~30 runs/day). Configurable; skipped while on battery or if the user is mid-lag-marker (so we don't cause the lag we're measuring).

### 4.6 Link (`link.py`) — on every probe write (cached, refreshed every 10 s)

- Default-route interface from `route -n get default` → `interface:`; medium (`wifi` / `wired` / `other`) from `networksetup -listallhardwareports`.
- VPN / iCloud Private Relay detection (`utun` default route, or known relay behaviour) → flagged, because it distorts traceroutes and latency attribution. `doctor` warns.

### 4.7 Traceroute (`trace.py`) — every 20 min, per `anchor` + `cdn` target

- `traceroute -n -q 3 -w 2 -m 20 <ip>`; stored as JSON hops `[{"ttl":1,"ip":"…","rtts":[…]}, …]`.
- Used to (a) refresh `isp_edge`, (b) locate where latency increases (inside ISP vs after the ISP's border) in the report.
- Interpretation rule: a hop with high latency/loss **that does not carry through to later hops** is ICMP de-prioritisation, not a problem. Only increases that persist to the destination count.

### 4.8 Sleep / gap detection (`collector/runner.py`)

- Heartbeat row every 10 s. A heartbeat gap > 30 s ⇒ `gap` (Mac asleep, collector stopped, lid closed).
- Gaps are **"no data"**, never "outage". Analysis excludes them and the report states coverage (e.g. "evenings covered: 86%").

## 5. Data model (SQLite)

```sql
CREATE TABLE meta        (key TEXT PRIMARY KEY, value TEXT);            -- schema_version, install_id
CREATE TABLE targets     (id INTEGER PRIMARY KEY, kind TEXT, host TEXT, ip TEXT,
                          first_seen INTEGER, last_seen INTEGER);        -- kind: gateway|isp_edge|anchor|cdn
CREATE TABLE ping        (ts INTEGER, target_id INTEGER, seq INTEGER, rtt_ms REAL, link TEXT);
CREATE TABLE wifi        (ts INTEGER, rssi_dbm INTEGER, noise_dbm INTEGER, channel INTEGER, band TEXT,
                          width_mhz INTEGER, tx_rate_mbps REAL, phy_mode TEXT, bssid_hash TEXT);
CREATE TABLE dns         (ts INTEGER, resolver TEXT, query_kind TEXT, ms REAL, ok INTEGER, rcode TEXT, link TEXT);
CREATE TABLE nq          (ts INTEGER, dl_mbps REAL, ul_mbps REAL, rpm INTEGER, base_rtt_ms REAL,
                          bufferbloat_ms REAL, grade TEXT, raw_json TEXT, link TEXT);
CREATE TABLE traceroute  (ts INTEGER, target_id INTEGER, hops_json TEXT, link TEXT);
CREATE TABLE heartbeat   (ts INTEGER);
CREATE TABLE events      (id INTEGER PRIMARY KEY, ts INTEGER, kind TEXT, note TEXT, source TEXT);
                          -- kind: router_change|package_change|isp_contact|lag|system|other
                          -- source: dashboard|cli|phone|auto
CREATE TABLE minute_rollup (minute INTEGER, target_id INTEGER, sent INTEGER, lost INTEGER,
                          p50_ms REAL, p95_ms REAL, max_ms REAL, jitter_ms REAL, link TEXT,
                          PRIMARY KEY (minute, target_id));
```

- Indexes on `ts` for every raw table.
- `jitter_ms` = mean absolute difference between consecutive RTTs (RFC 3550-style).
- **Retention:** raw `ping` 14 days; everything else and all rollups kept until the user deletes. ~170k ping rows/day ≈ <10 MB/day.
- Schema versioned via `meta.schema_version`; forward-only migrations in `schema.py`.

## 6. Analysis & verdict (`core/analysis.py`)

Pure functions over rollups + events. Same input ⇒ same output. No IO.

### 6.1 Baseline

Per target, baseline = median of `p50_ms` over the **quietest** 25% of covered hours in the last 7 days (typically overnight/mid-morning). Needs ≥ 24 h of coverage; otherwise verdict is `insufficient_data`.

### 6.2 Bad minute _(initial thresholds)_

A minute is **bad** for a target if any of:

- loss ≥ 2% (≥ 1 lost of 30)
- `p95_ms` > baseline + 40 ms
- `jitter_ms` > 15 ms

### 6.3 Layer attribution — per minute

Evaluated top-down; first match wins:

| Condition (same minute) | Layer |
|---|---|
| `gateway` bad | **wifi** (or `lan` if link is wired) |
| `gateway` OK, `isp_edge` bad **and** ≥1 anchor/cdn bad | **isp_network** |
| `gateway` + `isp_edge` OK, majority of anchors **and** cdns bad | **isp_upstream** (ISP backhaul/peering) |
| only `cdn` targets bad, anchors OK | **video_path** (ISP ↔ video services) |
| a single anchor/cdn bad | ignored (that remote host's problem) |
| none bad | **ok** |

WiFi readings attach context: a wifi-layer minute with RSSI < −70 dBm, SNR < 20 dB, a band change to 2.4 GHz, or a roam is labelled with the likely reason.

### 6.4 Bufferbloat

From `nq`: median `bufferbloat_ms` in the window; grade ≤ C on ≥ 30% of runs ⇒ **bufferbloat** finding (independent of the per-minute layers — it's a "when loaded" problem, not an idle one).

### 6.5 Peak vs off-peak

- Windows: **evening** 19:00–23:00 local, **daytime** 10:00–16:00 local (configurable).
- Per layer: % bad minutes in evening vs daytime, across covered days.
- **Evening problem** if evening bad-rate ≥ 5% **and** ≥ 2× daytime **and** seen on ≥ 3 distinct evenings.

### 6.6 Lag markers

For every `lag` event: the layer status for ±2 minutes around it.

- Network bad at most lag moments ⇒ supports the network verdict.
- Network **ok** at ≥ 70% of ≥ 5 lag moments ⇒ **device_or_app** finding ("the network was healthy when you saw lag").

### 6.7 Verdict

```json
{
  "verdict": "isp_upstream | isp_network | video_path | wifi | bufferbloat | device_or_app | no_problem_found | insufficient_data",
  "confidence": "high | medium | low",
  "summary": "Plain-English one-liner",
  "evidence": [ { "claim": "...", "metric": "...", "evening": 0.12, "daytime": 0.01 } ],
  "secondary": [ "bufferbloat" ],
  "next_steps": [ "..." ],
  "coverage": { "days": 9, "evenings_covered_pct": 86, "lag_markers": 7 },
  "missing": [ "Run at least 3 more evenings for high confidence" ]
}
```

- **Primary** = layer with the highest evening bad-rate that qualifies as an evening problem. Other qualifying findings go in `secondary`.
- **Confidence:** high = ≥ 7 covered evenings and consistent across ≥ 70% of them; medium = ≥ 3; low = otherwise.
- **Next steps** are fixed per verdict, e.g. `wifi` → "move to 5 GHz / change channel / try a wired test"; `isp_upstream` → "raise a fault with your ISP; attach the report"; `bufferbloat` → "enable SQM/Smart Queue on the router if available"; `device_or_app` → "the network was fine during lag — check the device/app".

## 7. Dashboard (`web/`)

Served on `http://127.0.0.1:8737` by default.

| View | Content |
|---|---|
| **Verdict** (home) | Verdict card (summary, confidence, next steps, what's missing) · coverage · big "**It's lagging now**" button |
| **Timeline** | Last 24 h / 7 d: per-layer health strip, RTT & loss for gateway / ISP edge / anchors / CDNs, WiFi RSSI/band, events & lag markers overlaid, gaps shaded |
| **Heatmap** | Day × hour grid; metric selector (bad-minute %, loss, p95, bufferbloat, download Mbps) |
| **Evening vs daytime** | Table per layer, with the numbers behind the verdict |
| **Events** | Add / list / delete events (router change, package change, ISP contact, note) |
| **Report** | Pick a date range → generate report (§8) |

JSON API (`/api/verdict`, `/api/timeline?from&to`, `/api/heatmap?metric`, `/api/events`, `POST /api/events`, `POST /api/lag`) — same shapes a future native app will consume.

**iPhone lag marker (opt-in):** `config.lan_access = true` binds to the LAN and requires a token: `http://<mac>.local:8737/lag?t=<token>`. The dashboard shows a QR code + instructions for an iOS Shortcut / home-screen bookmark, so "it's lagging" can be tapped from the phone that's lagging. Off by default.

## 8. Evidence report (`core/report.py`)

Single self-contained HTML file (inline CSS/SVG) → user prints to PDF from the browser.

1. **Summary** — verdict, confidence, date range, coverage.
2. **What the household experienced** — lag markers with times.
3. **Evening vs daytime** — table + heatmap.
4. **Where it breaks** — layer attribution; representative evening vs daytime traceroute excerpts showing where latency rises.
5. **Speed & responsiveness** — `networkQuality` by hour.
6. **Already tried** — events timeline (e.g. "router replaced 12 Sep — problem persisted").
7. **Method** — what was measured, how often, thresholds used, limitations (WiFi-connected probe, gaps).
8. **Appendix** — daily tables.

Privacy in the report: public IPs of the household are masked by default (`86.x.x.x`); ISP hop IPs are shown (that's the evidence). SSID never appears.

## 9. CLI

```
python3 -m whodunnet install        # write config, LaunchAgent, start collector
python3 -m whodunnet uninstall      # stop + remove LaunchAgent (keeps data unless --purge)
python3 -m whodunnet status         # running?, coverage, last sample per probe, current verdict
python3 -m whodunnet doctor         # check commands exist, permissions, VPN/Private Relay, battery, lid advice
python3 -m whodunnet dashboard      # start web server + open browser
python3 -m whodunnet event "Router replaced" --kind router_change [--at "2026-09-12 18:00"]
python3 -m whodunnet lag            # mark "lagging now"
python3 -m whodunnet report --from 2026-10-01 --to 2026-10-14 [-o report.html]
python3 -m whodunnet export --csv   # raw data out
```

## 10. Privacy & safety

- No network calls except the probes themselves. No telemetry, no update checks.
- No SSID/BSSID stored. Household public IP masked in reports.
- Web server on `127.0.0.1` unless `lan_access` is explicitly enabled (then token-protected).
- Read-only with respect to the system: never changes network, WiFi, or router settings. No `sudo`.

## 11. Testing

- **Parsers:** fixture-based tests for every command output (`ping` lines, `system_profiler` JSON for macOS 13/14/15, `networkQuality -c` variants, `traceroute`, `dig`, `route`, `scutil`). Fixtures are captured on a real Mac via `doctor --capture` and **redacted** before committing.
- **Rollup:** synthetic RTT streams → expected p50/p95/jitter/loss.
- **Analysis:** synthetic scenario datasets, one per verdict — WiFi-only spikes, ISP-edge evening congestion, upstream/peering, CDN-only, bufferbloat, clean network + lag markers (→ `device_or_app`), sparse data (→ `insufficient_data`), gaps not counted as outages.
- **CI:** GitHub Actions, `ubuntu-latest`, Python 3.9 and 3.12, `pytest` + `ruff`. (Probes are not run in CI — they need macOS.)
- **Manual acceptance on the Mac:** `doctor` clean → 24 h run → `status` shows coverage ≥ 90% while awake.

## 12. Milestones

| # | Deliverable | Done when |
|---|---|---|
| M1 | Probes + collector + storage + `install`/`status`/`doctor` | Runs 24 h on the Mac; all tables filling; gaps recorded on sleep |
| M2 | Rollups + baseline + analysis + verdict (`status` prints it) | All scenario tests pass |
| M3 | Dashboard + events + lag marker (incl. opt-in iPhone) | Can view timeline/heatmap, add events, tap lag from phone |
| M4 | Evidence report | Generates a readable report for a ≥ 7-day range |
| — | Calibrate thresholds on the first real week | Thresholds updated with data, change documented |

## 13. Out of scope for v0

Native app, iPhone app, plug-in probe, Windows/Linux, cloud sync, accounts, automatic router changes, video-style CDN download test (candidate for v0.2), multi-household comparison.

## 14. Open questions for review

1. **Monitoring hours** — collect 24/7 (needs the Mac awake, lid open, on charger), or 17:00–24:00 plus a daytime baseline window? _Proposal: 24/7 when on charger; the verdict copes with gaps._
2. **`networkQuality` frequency** — hourly + every 30 min in the evening (~30 GB/day on a gigabit line). Acceptable, or lower (e.g. 4 evening + 4 daytime runs/day)?
3. **iPhone lag marker** — include in v0 (opt-in LAN access) or postpone?
4. **Default CDN targets** — Instagram + YouTube proposed. Add Netflix / BBC iPlayer / Disney+ — whichever the household actually uses for TV?
5. **Evening window** — 19:00–23:00 right, or is the lag earlier/later?
