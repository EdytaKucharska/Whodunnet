# Whodunnet — Build Plan (v0)

> How we build v0, task by task. Read [`intent.md`](./intent.md) (why) and [`spec.md`](./spec.md) (what/how) first; terms are in the [spec glossary](./spec.md#16-glossary).
> **Precedence on conflict:** intent → spec → plan. If this plan contradicts the spec, the spec wins — fix the plan in the same PR.

---

## 0. Read this first

- **What we're building:** a background tool for a Mac laptop that measures the home connection 24/7 and tells the household *who's to blame* for evening video lag — WiFi, the ISP, the ISP's links to video services, home bufferbloat, or the device/app — with an evidence report for the ISP.
- **Shape:** one Python package (`whodunnet/`), standard library only at runtime, one long-running **collector** process (started by `launchd`) that runs the probes, writes SQLite, and serves the local web dashboard.
- **Two halves:**
  - **Mac-only:** `probes/` and `collector/` run macOS commands (`ping`, `traceroute`, `system_profiler`, `networkQuality`, `dig`, …). Only `probes/runner.py` calls `subprocess`.
  - **Portable:** `core/` (storage, rollups, analysis, report) and `web/`. Runs and is tested on any OS.
- **Tests never run macOS commands.** Parsers are pure functions tested against real outputs captured once on a Mac (M0.5). Analysis is tested against synthetic scenarios (M2.0).
- **First milestone that matters to the user:** M2 — after ≥ 3 evenings of collection, `python3 -m whodunnet status` prints a verdict.
- **Biggest risk:** the spec's assumptions about macOS command output (marked _(verify M0.5)_). M0.5 exists to confirm them before parser work is called done.

## 1. Dev setup

| Need | For |
|---|---|
| macOS 13+ with Xcode Command Line Tools (`xcode-select --install`) | Running probes/collector, M0.5 capture, `install`. |
| Any OS with Python 3.9+ | Everything in `core/`, `web/`, parser tests, analysis tests. |

```bash
git clone git@github.com:EdytaKucharska/Whodunnet.git && cd Whodunnet
# (or HTTPS: git clone https://github.com/EdytaKucharska/Whodunnet.git)
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt      # pytest, ruff — dev only; runtime has NO dependencies
pytest                                   # all tests
ruff check . && ruff format --check .    # lint + format
python3 -m whodunnet --help              # CLI (stubs from M0.1)
```

On a Mac, run the collector in the foreground without installing the LaunchAgent (from M1.8):

```bash
python3 -m whodunnet run --foreground --data-dir ./.devdata     # Ctrl-C to stop
python3 -m whodunnet status --data-dir ./.devdata
```

`.devdata/` is git-ignored. Note: on macOS 15+, a process started from Terminal is exempt from the Local Network permission; the installed agent is not (spec §4.2) — always test gateway pings via `install` too.

## 2. Conventions (apply to every task)

1. **Stdlib only at runtime.** Dev tools live in `requirements-dev.txt`.
2. **Python 3.9 compatible.** No `match`, no `X | Y` unions at runtime (use `Optional[...]` / `from __future__ import annotations`), no `tomllib`, no `zoneinfo` needed (local time = system time zone via `datetime.fromtimestamp`). CI runs 3.9 and 3.12.
3. **Boundaries.** `core/` and `web/` never import `probes/` or `collector/` and never call `subprocess`. Only `probes/runner.py` calls `subprocess`.
4. **Parsers are pure:** `parse_x(text: str) -> ResultDataclass` with `ok: bool` and `error: Optional[str]` plus the parsed fields; they never raise. Exception: `parsers/ping.parse_line` returns `Reply`, `Timeout`, `SendError`, `None` (header/summary) or `Unparsed` (spec §4.2).
5. **Probe failures are data.** A failed probe writes its row with `ok = 0` and `error` (ping: `rtt_ms` NULL + `error`). The collector loop never dies because a probe failed.
6. **Time.** Store UTC epoch **milliseconds** (`int`). Local time is used only in `core/analysis.py`, `core/coverage.py`, `core/baseline.py`, `core/report.py` (windows, days), `collector/scheduler.py` (nq slots), `cli.py` (date/time arguments) and the UI. Every time-dependent function takes `now_ms` / a clock argument — no hidden `time.time()` in `core/`.
7. **Privacy.** Never store SSID/BSSID/clear MACs/household public IP/discovery response bodies. Never commit `.db` files, `captures/`, or unredacted output. Fixtures go through `tools/redact.py`.
8. **Single sources of truth.** Config defaults: `config.py` → `DEFAULTS` (spec §2.2). Thresholds: `core/thresholds.py` (spec §6.9). Schema: `core/schema.py` (spec §5). SQL lives only in `core/store.py` (and `schema.py`).
9. **Workflow.** One task (or a tight pair) per PR, branch `task/<ID>-short-name`, draft PR to `main`, CI green before review. The PR description lists the task ID and its acceptance criteria as a checklist. If behaviour must deviate from the spec, update the spec in the same PR.
10. **Logging.** Stdlib `logging`, one logger per module, rotating file in the log dir (spec §2.1). No `print` outside `cli.py`.

## 3. Repository layout

As in spec §3.1, plus at the repo root: `README.md intent.md spec.md plan.md pyproject.toml requirements-dev.txt .gitignore .github/workflows/ci.yml`. `pyproject.toml` holds ruff and pytest config only (no packaging needed — the app is run with `python3 -m whodunnet` from the repo in dev, or from the app dir after `install`).

## 4. Tasks

Format: **ID — title** · *depends on* — what · ✅ acceptance · 🧪 tests.

### M0 — Scaffold

**M0.1 — Repo skeleton & CI** · *none*
- Create the spec §3.1 tree with empty modules (one-line docstrings), `pyproject.toml` (ruff: `target-version = "py39"`, `line-length = 100`, default rules; pytest: `testpaths = ["tests"]`), `requirements-dev.txt` (`pytest`, `ruff`), `.gitignore` (`.venv/ .devdata/ *.db *.sqlite* reports/ captures/ whodunnet-report-*.html __pycache__/ .pytest_cache/`), `.github/workflows/ci.yml` (ubuntu-latest; Python 3.9 + 3.12; `ruff check .`, `ruff format --check .`, `pytest`).
- `cli.py` with `argparse` subcommands from spec §9 (each subparser accepts `--data-dir`); each prints "not implemented yet" and exits 2.
- ✅ `python3 -m whodunnet --help` lists all commands. CI green.
- 🧪 smoke test that imports every module (catches 3.9 syntax errors).

**M0.2 — README** · *M0.1*
- What it is, status, doc map, privacy summary, prerequisites (macOS 13+, Xcode CLT, lid open on charger), link to plan §1.
- ✅ A newcomer gets from clone to green `pytest` using only the README.

### M0.5 — Real macOS fixtures & assumption checks (main risk)

**M0.5.1 — Capture script** · *M0.1*
`tools/capture_fixtures.sh` (no sudo) saves raw output to `captures/<command>/<case>.txt|json` plus `captures/MANIFEST.txt` (macOS version, date):
- `sw_vers`; `route -n get default`; `route -n get 1.1.1.1`; `networksetup -listallhardwareports`; `ifconfig` (IPv6 + `awdl0`); `netstat -ibn`; `arp -n <gateway>`; `scutil --dns`; `scutil --get LocalHostName`; `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate`
- `system_profiler SPAirPortDataType -json` (also time how long it takes)
- `dig +tries=1 +time=2 @<resolver> www.google.com` and `… <random>.example.com`; `dig +short A` and `dig +short AAAA` for `scontent.cdninstagram.com` and `www.bbc.co.uk`
- `ping -n -c 5 -i 2 <gateway>`; `ping -n -c 5 -i 2 192.0.2.1` (guaranteed timeouts); `ping6 -n -c 5 -i 2 2606:4700:4700::1111` and `ping6 -n -c 5 -i 2 2001:db8::1` (if IPv6 — does ping6 print timeouts?)
- **Send errors:** `ping -n -i 2 1.1.1.1` while WiFi is switched off for ~10 s → `ping/sendto_error.txt`
- **Streaming check:** `ping -n -i 2 1.1.1.1` piped through a timestamping reader for 20 s → shows whether lines arrive promptly when piped (spec §4.2)
- `traceroute -I -n -q 3 -w 1 -m 20 1.1.1.1`, `traceroute -I -n -q 3 -w 1 -m 8 1.1.1.1`, and `traceroute6 -I -n -q 3 -w 1 -m 20 2606:4700:4700::1111` (if IPv6)
- `networkQuality -h`; `networkQuality -c -s -M 20` (or without `-M` if unsupported)
- `pmset -g batt`
- `curl -s 'https://redirector.googlevideo.com/report_mapping?di=no'` (YouTube mapping format); fast.com: fetch `https://fast.com/`, locate `app-*.js`, extract the token, call the API with `urlCount=5` — save only the **shape** (keys + host names), never `client.ip`
- **WiFi-probe spike check:** 10 min of gateway pings with `system_profiler` every 60 s, then 10 min without; save both ping logs.
- ✅ Runs on macOS 13+ in < 30 min; prints a reminder not to commit `captures/`.

**M0.5.2 — Redactor** · *M0.5.1*
- `tools/redact.py captures/ tests/fixtures/macos/`: public IPv4/IPv6 → documentation ranges (`203.0.113.x`, `2001:db8::x`) consistently (same input → same output within a run); private IPs → stable fake private IPs; CGNAT stays CGNAT-shaped (`100.64.x.x`); MAC addresses, SSID/BSSID, hostnames, LocalHostName, serial numbers → placeholders. Structure and numbers preserved.
- ✅ The founder greps `tests/fixtures/` for their real public IP, SSID, router MAC and Mac name → nothing.
- 🧪 unit tests on synthetic input for each rule.

**M0.5.3 — Founder captures; team verifies assumptions** · *M0.5.2* · **owner: founder (capture), any dev (verification)**
- Run capture → redact → review → commit `tests/fixtures/macos/`.
- Go through every _(verify M0.5)_ in the spec and record the result in the §8 "Verification results" table of this plan (assumption · confirmed/changed · fixture). If an assumption is wrong, update the spec in the same PR (e.g. `-M` unsupported, field names differ, YouTube mapping endpoint gone, ping needs a pty, wifi probe causes spikes → enable the §6.1 exclusion).
- ✅ Fixtures exist for every command above; every _(verify M0.5)_ item has a recorded result.

### M1 — Collect

**M1.1 — Paths & config** · *M0.1*
- `paths.py`: all locations from spec §2.1; `--data-dir` / `WHODUNNET_DATA_DIR` relocates db, config, reports and logs (spec §2.1).
- `config.py`: `DEFAULTS` exactly as spec §2.2; load/merge/validate; `lan_token` generated with `secrets.token_urlsafe(24)` when missing.
- ✅ Bad JSON → error naming the key; missing file → defaults; unknown key → warning.
- 🧪 load/merge/validate; env/flag override.

**M1.2 — Schema, store, models** · *M1.1*
- `core/schema.py` (spec §5 DDL + indexes, `migrate(conn)` idempotent, sets `schema_version`), `core/store.py` (open with WAL; batched `insert_*`; `upsert_target` keyed on `(kind, name, af)`; `switch_target_ip` (appends `target_ips`, resets `baseline_epoch_ms` on /24 (/48) change); `record_target_status` (appends `target_status` only on change); events CRUD; range readers; `prune_raw_ping`, `purge_before`; read-only and read-write connection helpers with `busy_timeout`), `core/models.py` (dataclasses).
- ✅ Fresh DB migrates idempotently; a reader works while a writer writes (WAL).
- 🧪 every store function on a temp DB; `upsert_target` IP-change cases.

**M1.3 — Parsers** · *M1.1; real fixtures from M0.5.3 for "done"* — one parser per PR is fine; start with `provisional_*` fixtures (spec §11).

| Module | Function → returns |
|---|---|
| `ping.py` | `parse_line(line)` → `Reply(seq, rtt_ms)` / `Timeout(seq)` / `SendError(reason)` / `None` / `Unparsed(line)` |
| `route.py` | `parse_default(text)` → `gateway`, `interface` |
| `networksetup.py` | `parse_ports(text)` → `{device: port}`; `medium(port)` → `wifi`/`wired`/`other` (spec §4.7) |
| `system_profiler.py` | `parse_wifi(json_text)` → `WifiReading` (spec §4.3; NULLs for missing) |
| `scutil.py` | `parse_resolvers(text)` → primary resolver per spec §4.5; `parse_hostname(text)` |
| `ifconfig.py` | `parse(text)` → per interface: global IPv6 present (`2000::/3`), `awdl0` active |
| `netstat.py` | `parse_ibn(text)` → byte counters per interface |
| `dig.py` | `parse(text)` → `ms`, `rcode` (or timeout); `parse_short(text)` → IPs (CNAME lines skipped) |
| `traceroute.py` | `parse(text)` → `[Hop(ttl, ip, rtts)]` |
| `networkquality.py` | `parse(json_text)` → `dl_mbps`, `ul_mbps`, `rpm`, `dl_rpm`, `ul_rpm`, `base_rtt_ms`; `supports_max_runtime(help_text)` |
| `pmset.py` | `parse_batt(text)` → `PowerState(on_battery: Optional[bool])`; unknown → treat as battery |
| `arp.py` | `parse_mac(text)` → `MacResult(mac: Optional[str])` (salted-hashed by caller) |
| `route.py` (also) | `parse_route_get(text)` → interface for a destination (VPN check) |

- ✅ Every real fixture parses; one malformed case per parser returns `ok=False`, never raises.
- 🧪 per-parser fixture tests.

**M1.4 — Runner, link, discovery, video-service lookups** · *M1.2, M1.3*
- `probes/runner.py`: `run_command(argv, timeout)`; tests inject a fake runner.
- `probes/link.py` (spec §4.7 incl. VPN via `route -n get 1.1.1.1`), `probes/power.py` (`on_battery`, caffeinate start/stop), `probes/load.py` (spec §4.9 → `local_load`).
- `probes/discover.py` (spec §4.1): gateway; ISP edge (≤ 2 TTLs, double-NAT rule → `meta.double_nat`, adopt-first then 2-consecutive rule); anchors (v4/v6) and CDN resolution via `dig @resolver` with sticky IPs and the `getaddrinfo` fallback when `dig` to a LAN/link-local resolver fails; IPv6 targets; router-change detection (gateway IP or salted MAC hash); `target_status` history; `system` events.
- `probes/youtube.py` (v0 per spec §4.1: report_mapping POP name recorded as the reason, target = redirector with status `approximate`), `probes/netflix.py` (fast.com flow, `urlCount=5`, prefer ipv4-/ipv6- hosts, prefix swap, 10 s timeout, never log body). Both use `urllib.request` and honour `cdn_*` and `discovery_lookups`.
- Discovery keeps its run-to-run state (ISP-edge candidate, sticky-IP absence counts) in memory; after a restart the current edge is simply adopted again.
- ✅ Unit tests on the real captures; the on-Mac check (a foreground run populates `targets` / `target_status`) happens once `run --foreground` exists (M1.7/M1.8); `doctor` shows them once M1.8 lands.
- 🧪 discovery with stubbed runner (double NAT, private ISP-internal hop, CGNAT edge, edge > 2 TTLs, flapping edge, sticky IP rotation, router MAC change); youtube/netflix with stubbed HTTP (success, token missing, API error, single-family answer).

**M1.5 — Ping streams** · *M1.2, M1.4*
- `probes/ping.py` per spec §4.2: one process per active target; reader thread; 10 s hold with last-outcome-wins; `SendError` attached to the next loss; seq-gap loss unless a sleep/heartbeat gap overlaps; modulo 65536; `ts` = send time; restart on exit / IP change / wake / every 24 h; batch insert every 5 s; pty mode if M0.5 showed buffering; startup UDP datagram to the gateway (Local Network prompt).
- ✅ 1 h foreground run: ~1,800 rows per target; losses recorded when WiFi is toggled off for 30 s; no orphan `ping` processes after Ctrl-C or `kill`.
- 🧪 the ping-stream cases in spec §11.
- Note: `PingStreams` is wired into the collector in M1.7 (`write()` every 5 s, `still_answering` → `Discovery`, `nudge_local_network` at start, `restart_all` on wake); the 1 h foreground acceptance run happens once `run --foreground` exists (M1.7/M1.8).

**M1.6 — Periodic probes** · *M1.2, M1.4*
- `wifi.py` (5 min, 15 s timeout, records `started_ts`, picks the default-route WiFi interface), `dns.py` (60 s; `cached` + `nxdomain`; `error = "lan_unreachable"` rule), `load.py` (60 s), `trace.py` (20 min, sequential, 90 s budget, `-I`), `nq.py` (slots, `-c -s -M 20`, skip rules incl. unknown battery state, records skipped runs).
- ✅ In a 1 h foreground run each table receives rows at the expected cadence; `run --nq-now` produces an nq row.
- 🧪 nq slot logic with a fake clock: fires once per slot within 5 min; missed slot not retried; skip on battery; skip after recent lag event.
- Note: the probes are plain functions/classes with an injected runner and clock; the collector (M1.7) calls them on their intervals, and `run --nq-now` (M1.8) calls `NqRunner.run_now`. A slot is also not re-fired after a collector restart (an `nq` row already exists in its window).

**M1.7 — Collector main, scheduler, sleep** · *M1.5, M1.6*
- `collector/scheduler.py`: 1 s tick scheduler with injectable clock.
- `collector/main.py`: start everything; heartbeat every 10 s; hooks for rollup (M2.1) and web server (M3.1) — no-ops until those land; daily prune; caffeinate on charger only; sleep detection via `time.time()` vs `time.monotonic()` (spec §4.8) → `system` gap event, rediscover, restart pings; route-change watch (10 s) → rediscover; SIGTERM → graceful stop; writes `meta.local_hostname` and `meta.macos_version`; runs the doctor checks at start and every 10 min → `meta.doctor_json` (spec §5) — so the doctor check functions live in a module the collector and `cli.py` share (`whodunnet/doctor.py`).
- ✅ Close the lid 5 min → gap event; collector resumes on wake without restart; unplug charger → caffeinate released, pings continue.
- 🧪 scheduler and sleep detection with a fake clock.
- Note: slow probes (discovery, WiFi, DNS, load, traceroute, nq, doctor, prune, rollup hook) run one at a time on a worker thread with its own SQLite connection, so the 10 s heartbeat is never delayed; heartbeat, ping writes, link refresh and caffeinate stay on the main thread. Until rollups exist (M2.1) the doctor's gateway/Local Network checks read the last minutes of raw pings. `cli run` is wired in M1.8.

**M1.8 — CLI & LaunchAgent** · *M1.7*
- Implement spec §9 commands except `dashboard` (M3.4) and `report` (M4.2): `install`, `uninstall`, `run`, `status` (verdict line arrives in M2.5), `doctor`, `event`, `lag`, `export`, `purge`.
- `install` exactly per spec §9 (copy package to app dir, `meta.install_salt`, bootout-then-bootstrap, plist from `launchd/…template` with `/usr/bin/python3`, `--data-dir` passed through, `ThrottleInterval 30`, `ProcessType Standard`, `launchd.out.log`/`launchd.err.log`).
- ✅ On the Mac (macOS 15 if available): fresh `install` → Local Network prompt appears (record whether the startup datagram triggered it and how Settings names it — update spec §4.2) → after approval the gateway receives pings **from the agent**; collector survives logout/login and `kill -9` (relaunched); `uninstall` leaves nothing running; `doctor` shows every check from spec §9 with a fix.
- 🧪 plist rendering; argument parsing; `doctor` with stubbed checks; `event --at` local-time parsing; `export` writes one CSV per table.
- Note: `install`/`uninstall` live in `whodunnet/agent.py` (launchctl via the injectable runner), local-time parsing in `whodunnet/timeutil.py` (`time.mktime`, DST-correct). `status` prints collector uptime coverage until M2.2/M2.5 add real coverage and the verdict. `purge` asks to confirm (`--yes` skips).

**M1 exit:** 24 h `install`ed run on the founder's Mac — all tables filling, gap events on sleep, `status` shows coverage, `doctor` clean (or every warning explained).

### M2 — Analyse (portable; can start once M1.2 lands, in parallel with M1.3+)

**M2.0 — Scenario generator** · *M1.2*
- `tests/scenarios.py` writes `targets`, `target_ips`, `target_status`, `minute_rollup`, `heartbeat`, `wifi`, `nq`, `local_load`, `traceroute` and `events` rows directly (seeded, deterministic, up to 10 days) for every scenario in the spec §11 table.
- ✅ Each scenario is one function call, < 1 s to build.
- Note: scenarios write `minute_rollup` as tuples and tests use in-memory databases; the 14-target IPv6 scenario uses 7 days to stay under 1 s. `store` row inserts no longer use `dataclasses.astuple` (deep copies; ~7× slower). Expected results live on each scenario (`s.expected`) and are asserted once the analysis lands (M2.5).

**M2.1 — Rollup** · *M1.2* — `core/rollup.py` per spec §5 rollup rules (closed minutes, re-roll last 10, nearest-rank, jitter on consecutive replies, majority link/vpn); wire into the collector hook. 🧪 hand-computed small streams incl. all-lost minute. Note: the WiFi-probe sample drop (spec §4.3) is done here too, and each run also catches up minutes not rolled since the last run (≤ 24 h), so a long worker delay never leaves holes.

**M2.2 — Coverage, exclusions & derived status** · *M2.1* — `core/coverage.py` per spec §6.1 (covered minute/window, gaps from heartbeat, exclusions: nq ±30 s, vpn, `link = other`, local load; derived gateway-blocked and target-unresponsive; discovery status at a minute). Optional wifi-probe sample drop lives in `rollup.py` (spec §4.3). 🧪 each exclusion; blocked and unresponsive derivation; window 50% boundary. Note: `coverage.load(conn, start, end)` reads a range once and answers every per-minute question from memory; unresponsive epochs start at each `target_ips.from_ts` (any IP change ends one), and "gateway lost < 2 pings in those minutes" is the total over the 10 minutes. Thresholds live in `core/thresholds.py`.

**M2.3 — Baseline** · *M2.2* — `core/baseline.py` per spec §6.2 (per local day, 7-day look-back, baseline RTT + jitter). 🧪 quiet-window path, fallback path, `baseline_epoch_ms` reset mid-range, < 4 hours → none, ISP-edge quiet-hour loss. Note: `baseline.compute(cov, cfg, start, end)` needs a Coverage loaded from 7 days before `start`; lookups go through `Baselines.get(target_id, minute)` (local day + epoch of that minute). The fallback takes ceil(25%) of candidate hours, so ≥ 4 hours means ≥ 13 candidates when the quiet window is thin.

**M2.4 — Bad minutes & attribution** · *M2.3* — spec §6.3–6.4 incl. majority definitions, unknown gateway/edge, per-family evaluation, family choice, WiFi context. 🧪 one test per row of the §6.4 table; loss 1 vs 2; |D| < 3; majority with exactly 1 bad; empty A or C; gateway blocked. Note: `attribution.attribute(cov, baselines, start, end, wifi_readings)` returns per-minute results per family; "p95 > baseline + 40 ms" compares against the baseline p50 (§6.2 defines the baseline as the median p50); the row-6 streak counts consecutive *covered, adjacent* minutes (a gap breaks it).

**M2.5 — Findings, verdict, status** · *M2.4* — spec §6.5–6.7 (evening/all-day problem, no-daytime rule, bufferbloat, lag markers, wired vs WiFi, before/after events, selection order incl. `at_lag_moments`, confidence + adjustments + caps, `missing`, next steps, text templates); `status` prints summary + confidence + missing. Note: `analysis.analyse(conn, cfg, start, end)` returns the §6.7 dict; `status` analyses the last 14 days. The "single flaky CDN" scenario is isolated bad minutes (one CDN bad for 3+ minutes in a row is a legitimate `video_path` signal by §6.4 row 6).
- ✅ Every scenario in the spec §11 table yields its expected verdict, qualifier and confidence; boundary tests per spec §6.8.

**M2 exit:** all scenario tests pass; on the founder's ≥ 3-evening dataset `status` prints a verdict whose numbers survive a manual spot-check against `export` CSVs.

### M3 — Dashboard

**M3.1 — Web server & API** · *M2.5* — `web/server.py` (`ThreadingHTTPServer`) started by the collector hook; access rules per spec §7.1 (Host check, `X-Whodunnet` header on non-GET, non-loopback restrictions); endpoints per spec §7.3; GET = read-only connection, POST/DELETE = short-lived read-write connection (spec §5); settings written atomically (temp file + rename); JSON errors. **Define the exact request/response JSON shapes and record them in spec §7.3 in the same PR.** 🧪 every endpoint against a scenario DB; wrong Host → 403; POST without `X-Whodunnet` → 403; non-loopback `/api/verdict` → 403. Note: `web/server.py` keeps the §7.1 rules in a pure `check_access`; `cli run` sets the collector's `web_hook` (collector tests run without a server); `index.html` is a minimal verdict page until M3.2.

**M3.2 — Views** · *M3.1* — `static/` vanilla HTML/JS/CSS (spec §7.2): Verdict, Timeline, Heatmap, Evening vs daytime, Events, Report, Settings. Phone-width layout. Note: timelines over 1 day are bucketed to 5-minute steps server-side (`step` in the response, spec §7.3) so 7 days stays ~1 MB; DOM is built with textContent only (no innerHTML); a test checks the static files reference no external hosts; verdict wording in `analysis.LAYER_WORDS` was made plain-English for the dashboard; the Report view shows the 501 message until M4.2.
- ✅ Each view renders from a scenario DB in Safari and Chrome; DevTools shows no requests except to the local server.

**M3.3 — Phone lag page & LAN access** · *M3.1* — `lag.html`; token/cookie flow exactly per spec §7.1 (cookie value = token, `Max-Age` 1 year, no redirect); Settings toggles `lan_access` (writes config, rebinds server), shows `http://<LocalHostName>.local:<port>/lag?t=…` + QR (`qr.js`, vendored MIT) + "Add to Home Screen" steps; regenerate token.
- ✅ From an iPhone on the same WiFi: open link → tap → `lag` event (source `phone`) appears on the Mac timeline within 5 s. With `lan_access=false` the phone can't connect; with a wrong token → 403.
- 🧪 token required / wrong / right; cookie set; regenerated token invalidates old cookie; only `/lag` + `POST /api/lag` reachable from non-loopback.

**M3.4 — CLI `dashboard`** · *M3.1* — opens the browser (spec §9).

### M4 — Evidence report

**M4.1 — Report builder** · *M2.5* — `core/report.py` → self-contained HTML with the 10 sections of spec §8 (worst-affected target, traceroute selection, positional hop labelling, before/after, UK rights text with `RIGHTS_TEXT_CHECKED`); A4 print CSS.
**M4.2 — CLI & dashboard hook** · *M4.1, M3.2* — `report --from --to [-o]`; `GET /api/report`; Report view.
- ✅ For a 7-day scenario DB the founder judges the report readable by a non-technical person and it prints cleanly to PDF.
- 🧪 every section present; renders with sparse data, zero lag moments, no traceroutes; no private IP or SSID in output.

### Calibrate — after the first real week

1. `python3 -m whodunnet export -o ./.devdata/week1` (inside the git-ignored `.devdata/`).
2. Compare bad minutes and layers against lag moments and the household's experience; check `inconclusive` share, `router_icmp_slow` and `isp_edge_icmp` rates, bufferbloat grades.
3. Any threshold change: edit `core/thresholds.py` **and** the matching spec section (spec §6.9 lists where thresholds live), add a test pinning the new behaviour, add a spec Decisions log entry — same PR.

## 5. Order & parallelisation

```
M0.1 ─┬─ M0.2
      ├─ M0.5.1 ─ M0.5.2 ─ M0.5.3 (founder on Mac + verification) ───────┐ (real fixtures → parsers "done")
      └─ M1.1 ─ M1.2 ─┬─ M1.3 (provisional fixtures first) ─ M1.4 ─┬─ M1.5 ─┐
                      │                                             └─ M1.6 ─┴─ M1.7 ─ M1.8
                      └─ M2.0 ─ M2.1 ─ M2.2 ─ M2.3 ─ M2.4 ─ M2.5 ─┬─ M3.1 ─┬─ M3.2 ─┐
                                                                    │        ├─ M3.3  ├─ M4.2
                                                                    │        └─ M3.4  │
                                                                    └─ M4.1 ──────────┘
```

- Two tracks from day one: **Mac track** (M0.5 → M1.3–M1.8) and **portable track** (M1.2 → M2 → M3/M4).
- Get M1.8 installed on the founder's Mac as early as possible — the verdict needs ≥ 3 covered evenings, ideally 7, and data collected before M2 lands is fully usable.

## 6. Definition of done

**Per task:** acceptance criteria met · tests added and green in CI on 3.9 and 3.12 · `ruff` clean · no private data in the diff · spec updated in the same PR if behaviour deviates.

**v0 done when:**
- The collector has run ≥ 7 days on the founder's Mac with ≥ 80% evening coverage.
- `status` and the dashboard show a verdict with confidence, evidence and next steps.
- The iPhone lag button works.
- A report for that week has been generated and the founder would send it to the ISP.

## 7. Risks & mitigations

| Risk | Mitigation |
|---|---|
| macOS output differs from spec assumptions | M0.5 capture + verification table before parsers are "done"; defensive parsers; `doctor` flags unknown formats. |
| Local Network privacy blocks the agent's gateway pings (macOS 15+) | Startup UDP connect triggers the prompt; `blocked` status never becomes a WiFi verdict; `doctor` + `missing` explain the fix; acceptance test on macOS 15. |
| Mac sleeps / lid closed → thin evening data | caffeinate on charger; coverage everywhere; `missing` tells the user. |
| Measurements cause lag | Pings are tiny; nq limited to 8 slots, skipped after a lag marker, its minutes excluded. |
| Router/ISP ICMP slow path → false wifi/ISP blame | Attribution requires downstream confirmation (spec §6.4 rows 1–3, 7); ISP-edge loss judged against its own quiet-hour loss. |
| Household's own heavy use looks like ISP congestion | Mac's own load excluded; ISP verdicts capped at medium while bufferbloat holds; "pause big downloads" check. |
| Web dashboard reachable by other web pages (CSRF / DNS rebinding) | Host-header check + custom header on writes (spec §7.1). |
| ICMP-silent targets | `unresponsive` status, excluded. |
| IPv4 vs IPv6 paths differ | Per-family attribution; verdict prefers IPv6. |
| YouTube/Netflix discovery endpoints change | Degrade to `approximate`/`unavailable`; other targets unaffected. |
| Thresholds wrong for this connection | All in `core/thresholds.py`; Calibrate step. |
| Public repo leaks household data | `.gitignore`, redactor, founder grep check, privacy line in definition of done. |
| Data use (~4.6 GB/day measured) on a capped plan | `doctor` shows the estimate; `nq_schedule` is configurable. |

## 8. Verification results (filled in by M0.5.3)

Captured 2026-10-27 on the founder's Mac: **macOS 26.6.2**, WiFi (5 GHz, 80 MHz, 802.11ax, −55 dBm), UK full fibre, **no IPv6**, router is also the DNS resolver. All fixtures in `tests/fixtures/macos/`, redacted with `tools/redact.py` and independently re-scanned before commit.

| Spec assumption | Result | Fixture |
|---|---|---|
| §4.2 ping lines arrive promptly through a pipe (else use a pty) | ✅ Confirmed: one line every ~2 s through a pipe → no pty needed. | `ping/streaming_check.txt` |
| §4.2 timeout line format | ✅ `Request timeout for icmp_seq N`. With `-c`, the last timeout isn't printed before exit (irrelevant for continuous pings). | `ping/timeouts.txt` |
| §4.2 `ping: sendto:` error lines | ⚠️ Not captured — no errors appeared during the WiFi-off step. Keep a `provisional_` fixture; recapture later if convenient. | `ping/wifi_off_attempt_no_errors.txt` (clean run) |
| §4.2 `ping6` timeout lines / §4.1 Netflix prefix swap | ➖ Not testable: no IPv6 on this connection (`route -n get -inet6` → "not in table"). | `route/get_inet6.txt` |
| §4.1 ISP edge / double NAT | ✅ Hop 1 router, **hop 2 public** at ~5 ms = ISP edge; no CGNAT, no double NAT; hop 3 silent (`* * *`), destination at hop 6. Rule as specified works. | `traceroute/*.txt` |
| §4.3 `system_profiler` shape | ✅ As specified (signal/noise string, channel string with band + width). `spairport_network_rate` is a number; no BSSID field; runtime **11.3 s**. | `system_profiler/wifi.json` |
| §4.3 WiFi probe disturbs latency | ❌→ changed: router pings > 50 ms 14.7% during the probe vs 4.3% outside (p95 98 vs 48 ms). Probe moved to every 5 min, pings around it dropped. | `wifi_probe_check/` |
| §4.4 `networkQuality -M` and JSON keys | ✅ `-M 20` works (runtime 20.3 s). ⚠️ With `-s` there is no combined `responsiveness`; keys are `dl_responsiveness`/`ul_responsiveness`, throughput in bits/s, `base_rtt` in ms. Spec updated. | `networkquality/*.txt|json` |
| §4.4 data use | Changed: 0.57 GB per run (447 down / 143 up Mbps over WiFi) → ~4.6 GB/day. | `networkquality/run.json` |
| §4.1 YouTube `report_mapping` | ⚠️ Format is `<client-ip> => <pop> (<subnet>)`, e.g. `iad66s07` — a POP name, not an `sn-` node. v0 uses the approximate redirector target. | `youtube/report_mapping.txt` |
| §4.1 fast.com flow | ✅ Token found; answer has `client{asn,ip,location}` and 5 IPv4 `targets[{location,name,url}]`. | `netflix/fast_shape.json` |
| §4.5 resolver rule | ✅ Resolver #1 has a `search domain[0]` line but no `domain :` line → correctly chosen (the router). | `scutil/dns.txt` |
| §4.5 `nxdomain` probe | Note: the router answered **NOERROR + SOA** (not NXDOMAIN) for the random name — still `ok` under the spec rule. | `dig/nxdomain.txt` |
| §4.1 `dig +short` | ✅ CNAME lines appear before the IPs (BBC) → skip non-IP lines as specified. | `dig/short_*.txt` |
| §4.7 VPN check | ✅ `utun0`–`utun5` exist with no VPN; default route is `en0` → `vpn = 0`. | `ifconfig/ifconfig.txt`, `route/*.txt` |
| §4.7 port names | Changed: dock and adapters appear as "Ethernet Adapter (enN)" / "USB3.0 5K Graphic Docking" (wired); "Thunderbolt 1/2/3" are bridge members → `other`. | `networksetup/listallhardwareports.txt` |
| §9 doctor: AWDL, firewall, battery | ✅ `awdl0` active; firewall disabled; `pmset` says "Now drawing from 'AC Power'". | `ifconfig/awdl0.txt`, `firewall/`, `pmset/` |
| §4.2 Local Network prompt for the agent | ➖ Can only be checked after `install` (M1.8, macOS 15+ incl. 26). | — |

**Calibration note (for the Calibrate step):** even without the probe, ~4% of router pings exceed 50 ms (macOS WiFi power-save/AWDL). With ~30 pings a minute, the gateway's p95 will often clear "baseline + 40 ms". That's why §6.4 requires downstream confirmation for `wifi`; expect many `router_icmp_slow` tags and revisit the gateway thresholds after week 1.

## 9. Doc review log

| Round | Reviewers | Blocking found | Changes |
|---|---|---|---|
| 1 | Newcomer · macOS/networking expert · cross-doc consistency | 11 · 2 · consistency: 48 items + 10 uncovered intent promises | Spec rewritten: target identity, exhaustive attribution table with downstream confirmation, verdict precedence + confidence + `missing` + next steps for every verdict, coverage/baseline definitions, gap vs loss rules, failure columns, collector serves web, token scope, Local Network privacy, YouTube/Netflix discovery, IPv6, nq flags/grades/exclusion, loss threshold, DNS/traceroute/Private Relay corrections, config table, CLI table, report sections (UK rights, before/after, wired vs WiFi). Intent aligned (24/7 on charger, nq schedule, phone marker in v0, privacy wording, all-day problems, WiFi definition). Plan rewritten to match. |
| 2 | Newcomer · expert + consistency | 9 · 17 | Target status history + read-time blocked/unresponsive; blocked gateway → rows 1–2 skipped, wifi "not measurable", DNS fallback; Mac's own load excluded + ISP-verdict cap under bufferbloat; majority = > half and ≥ 2; empty-set and IPv6 family rules; wifi-probe exclusion at sample level; per-day baseline with jitter baseline; sticky CDN IPs; ping `sendto`/late-reply/gap rules; lag-moment classification exhaustive + `at_lag_moments` verdict; rate denominators; VPN via `route get 1.1.1.1`; ISP edge ≤ 2 TTLs + positional hop labels; wired ≥ 1 evening; Host/CSRF protection; web write connections; report output path; resolver rule; expected-results table for scenarios; plan capture list, parsers, sequencing. |
| 3 | Combined (newcomer + technical + consistency) | 4 | `at_lag_moments` confidence fixed at medium; probes use write-time `lan_unreachable` instead of read-time "blocked"; doctor results stored in `meta.doctor_json` for the web view; wired-vs-WiFi rules defined + scenario; plus 8 nice fixes (baseline epochs from `target_ips`, sticky-IP wording, ISP-edge loss baseline, minute link/vpn source, hop labels without an ISP edge, `not_measurable` rule, case-insensitive Host, launchd log paths). All round-3 fixes applied verbatim as proposed; reviewer found every other cross-doc item consistent and every _(verify M0.5)_ item has a fallback. |
