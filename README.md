# Whodunnet

When the internet goes bad in the evening, find out **who done it**: your WiFi, your ISP, the ISP's links to video services, your router under load, or your devices. Whodunnet measures your connection continuously in the background and turns that into a verdict and an evidence report you can send to your ISP.

**Status:** pre-alpha. Design docs and project scaffold (M0); every CLI command is still a stub.

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

Prerequisites: Python 3.9+ on any OS for the portable code and tests; macOS 13+ with Xcode Command Line Tools (`xcode-select --install`) to run the collector or capture fixtures.

```bash
git clone git@github.com:EdytaKucharska/Whodunnet.git && cd Whodunnet
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt     # pytest + ruff, dev only
pytest
ruff check . && ruff format --check .
python3 -m whodunnet --help
```

Full setup, conventions and the task list: [`plan.md`](./plan.md#1-dev-setup).

### Capturing real macOS output (task M0.5 — on the Mac)

```bash
bash tools/capture_fixtures.sh            # ~30 min; add --quick to skip the 20-min WiFi-probe test
python3 tools/redact.py captures tests/fixtures/macos --term "<your ISP name>"
```

`captures/` holds private data and is git-ignored — never commit it. Check `tests/fixtures/macos/` for your public IP, WiFi name, router MAC and Mac name before committing it.

## License

MIT
