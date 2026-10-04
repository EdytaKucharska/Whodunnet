# Whodunnet — Intent

> When the internet "goes bad in the evening", find out **who done it**: your WiFi, your ISP, or your devices — and give you the evidence.

## The problem

Video starts lagging in the evening — Instagram, YouTube, streaming, sometimes the TV. A one-off speed test looks fine, the ISP says "reboot the router" or "upgrade your package", and you're left guessing.

The origin case:

- UK full-fibre (FTTP) connection on an altnet ISP.
- Lag appears mostly in the evenings, mainly on video.
- The problem **persisted after a new ISP router and a faster package** — so it is not the old router, and not a lack of raw bandwidth.
- Suspected causes, most to least likely: ISP backhaul/peering congestion at peak time → WiFi congestion (neighbours are busiest in the evening) → home bufferbloat → the devices themselves.

A short speed test cannot tell these apart. Measuring continuously, over days, can.

## What Whodunnet does

Runs quietly in the background, measures the connection continuously, and turns the data into a **verdict** and an **evidence report**.

### It answers

1. **Is there actually a problem, and when?** Hour-of-day × day heatmaps; evening vs daytime comparison.
2. **Whose fault is it?**
   - **WiFi** — latency/loss to the home router itself spikes, or WiFi signal/noise/band degrades.
   - **ISP network** — router is clean, but latency/loss to the ISP's first hops rises at peak time.
   - **ISP peering / video services** — ISP network is clean, but the path to video CDNs (Instagram, YouTube, Netflix…) degrades.
   - **Home bufferbloat** — latency balloons only when the line is loaded.
   - **Nothing network-side** — the connection is healthy while the lag happens → it's the device or the app.
3. **What should I do about it?** A plain next step per verdict (change WiFi band/channel, enable SQM, raise a fault with the ISP, etc.).

### It measures

| Interval | Measurement | Why |
|---|---|---|
| ~2 s | Ping to home router | WiFi / LAN health |
| ~2 s | Ping to ISP first hop + public anchors (e.g. 1.1.1.1, a UK site) | ISP & internet latency, jitter, loss |
| 1 min | WiFi RSSI, noise, channel, band (2.4/5/6 GHz), link rate | Did WiFi cause this spike? |
| 1 min | DNS resolution time | Slow app start-up |
| ~20 min | Throughput + responsiveness under load (macOS `networkQuality`) | Speed and bufferbloat by hour |
| ~20 min | Traceroute to major video CDNs | Where along the path the delay builds up |

Every sample is tagged with the connection type (WiFi / wired), so an occasional wired test (USB-C Ethernet adapter) settles the WiFi question directly.

### Events log

Users record things that changed — "router replaced", "package upgraded", "ISP contacted", "ticket #123". Events appear on the timeline and in the report, so the evidence shows e.g. *"problem persisted after router replacement"*.

### Evidence report

An exportable report (HTML → PDF) for raising a complaint with the ISP: date range, evening vs daytime figures, verdict with supporting data, traceroute excerpts, and the events timeline. Written so a non-technical person can send it and an ISP support engineer can't dismiss it.

## Principles

- **Verdict over charts.** Charts support the answer; they are not the answer.
- **Honest about uncertainty.** If the data doesn't support a verdict yet, say "not enough evidence" and what's missing.
- **Light touch.** Measurements must not cause the lag they're measuring — throughput tests are short and infrequent.
- **Private by default.** All data stays local. Network names, IP addresses, and traceroutes are never committed, uploaded, or sent anywhere without explicit user action.
- **Simple first.** Ship the smallest thing that answers "whodunnit?" for one household, then generalise.

## Scope

### MVP (v0) — the origin case

- macOS only, running on a laptop over WiFi (no always-on wired device available).
- Python collector run by `launchd`, keeps the Mac awake during monitoring hours.
- SQLite storage, local-only.
- Local web dashboard: heatmap, evening vs daytime, verdict, events log.
- Evidence report export.
- Data format and verdict logic kept separate from the collector, so a future native app can reuse them.

### Product path (later)

1. **v1 — native macOS menu-bar app.** Same core, polished onboarding, one-click ISP report.
2. **v2 — iPhone companion.** Compare phone-on-WiFi vs Mac at the same moment; settle "is it the phone?".
3. **v3 — plug-in probe.** A cheap always-on device for households without a Mac.

UK-first: the report should reference Ofcom's broadband consumer guidance (e.g. the voluntary minimum-guaranteed-speed code, for ISPs that are signatories) where relevant.

## Non-goals (for now)

- Not a one-off speed test.
- Not a router/firmware replacement or network management tool.
- No cloud backend, accounts, or telemetry.
- Not Windows/Linux in the MVP.
- No automatic changes to the user's network or router settings.

## Success looks like

- After ~1 week of collection, the origin household gets a clear, evidence-backed answer to "whose fault is the evening lag?".
- If it's the ISP, the report is strong enough to get a fault escalated (not just "reboot your router").
- If it's WiFi or the devices, the user knows the specific fix to try.
