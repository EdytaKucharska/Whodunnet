# Whodunnet

When the internet goes bad in the evening, find out **who done it**: your WiFi, your ISP, the ISP's links to video services, your router under load, or your devices. Whodunnet measures your connection continuously in the background and turns that into a verdict and an evidence report you can send to your ISP.

**Status:** pre-alpha. Design docs only, no code yet.

## Docs

| Read | For |
|---|---|
| [`intent.md`](./intent.md) | Why this exists, what it must answer, principles, scope. |
| [`spec.md`](./spec.md) | How v0 works: probes, data model, verdict logic, dashboard, report, glossary. |
| [`plan.md`](./plan.md) | How we build it: dev setup, conventions, tasks with acceptance criteria, order. |

If the docs disagree: intent → spec → plan, in that order of precedence.

## v0 at a glance

- macOS 13+ laptop with Xcode Command Line Tools (for `python3`); standard library only — no other installs.
- Runs 24/7 while the Mac is on its charger with the lid open (started by `launchd`).
- All data stays on your Mac (SQLite). No accounts, no cloud, no telemetry.
- Local dashboard, an "It's lagging now" button (also from your iPhone, opt-in), and an exportable report.

## Privacy

Your network name, MAC addresses and public IP are never stored, and no measurement data is ever committed to this repo. The only outbound traffic is the measurement itself (see [spec §10](./spec.md#10-privacy--safety)).

## Development

See [`plan.md` §1 Dev setup](./plan.md#1-dev-setup).

## License

MIT
