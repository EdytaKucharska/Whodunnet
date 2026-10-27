"""Continuous ping streams: one long-lived `ping` / `ping6` process per active target (spec §4.2).

There are three layers, so the rules can be tested without processes or threads:

- `PingStream` is pure. It turns parsed lines, plus the time each was read, into PingRows. It
  applies the 10 s hold with last-outcome-wins, attaches SendErrors and fills sequence gaps.
- `PingProcess` owns one subprocess and a reader thread that feeds a PingStream.
- `PingStreams` keeps one PingProcess per active target. It restarts a process when it exits,
  when its target's IP changes, after wake, and every 24 h. The collector calls `write()` every 5 s.
"""

from __future__ import annotations

import logging
import socket
import sqlite3
import subprocess
import threading
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Callable, Optional

from whodunnet.core import store
from whodunnet.core.models import PingRow, Target
from whodunnet.probes.parsers.ping import Reply, SendError, Timeout, Unparsed, parse_line

log = logging.getLogger(__name__)

HOLD_MS = 10_000  # outcomes stay editable this long after their send time
SEQ_MOD = 65536
MAX_AGE_MS = 24 * 3600 * 1000  # restart every 24 h
RESTART_BACKOFF_MS = 10_000  # minimum time between restarts of a process that keeps exiting
ANSWERING_WITHIN_MS = 60_000

Clock = Callable[[], int]  # wall clock, epoch ms
# -> (link, vpn). Called from reader threads, so it must be cheap and never run commands.
LinkContext = Callable[[], tuple[Optional[str], int]]
# (start_ms, end_ms) -> True if a sleep/heartbeat gap overlaps that period
GapCheck = Callable[[int, int], bool]
Popen = Callable[[Sequence[str]], subprocess.Popen]


def wall_ms() -> int:
    return int(time.time() * 1000)


def ping_argv(ip: str, af: int, interval_s: int = 2) -> list[str]:
    return ["ping6" if af == 6 else "ping", "-n", "-i", str(interval_s), ip]


def _no_link() -> tuple[str | None, int]:
    return None, 0


def link_context_from(cache) -> LinkContext:
    """(medium, vpn) from a LinkCache's last state; the collector refreshes the cache itself."""

    def context() -> tuple[str | None, int]:
        state = cache.peek()
        return (state.medium, state.vpn) if state is not None else (None, 0)

    return context


def _no_gap(start_ms: int, end_ms: int) -> bool:
    return False


@dataclass
class _Pending:
    seq: int  # as printed (0..65535)
    ts: int
    rtt_ms: float | None
    error: str | None
    link: str | None
    vpn: int


class PingStream:
    """Outcome bookkeeping for one ping process. Not thread-safe; PingProcess locks around it."""

    def __init__(
        self,
        target_id: int,
        interval_s: int = 2,
        link_context: LinkContext = _no_link,
        in_gap: GapCheck = _no_gap,
    ) -> None:
        self.target_id = target_id
        self.interval_ms = interval_s * 1000
        self.link_context = link_context
        self.in_gap = in_gap
        self._pending: dict[int, _Pending] = {}  # unwrapped seq -> outcome
        self._high: int | None = None  # highest unwrapped seq with an outcome
        self._high_ts: int | None = None  # send time of that outcome
        self._send_error: str | None = None
        self.last_reply_ms: int | None = None  # read time of the latest reply
        self.dropped_late = 0
        self.unparsed = 0

    def _unwrap(self, seq: int) -> int:
        """Map a printed seq (mod 65536) to the unwrapped number closest to the highest seen."""
        if self._high is None:
            return seq
        base = self._high - (self._high % SEQ_MOD)
        candidates = (base - SEQ_MOD + seq, base + seq, base + SEQ_MOD + seq)
        return min(candidates, key=lambda u: abs(u - self._high))

    def feed(self, line: str, read_ms: int) -> None:
        parsed = parse_line(line)
        if parsed is None:
            return
        if isinstance(parsed, Unparsed):
            self.unparsed += 1
            log.debug("ping target %s: unparsed line %r", self.target_id, parsed.line)
        elif isinstance(parsed, SendError):
            self._send_error = parsed.reason  # attached to the next loss row
        elif isinstance(parsed, Reply):
            self.last_reply_ms = read_ms
            self._outcome(parsed.seq, read_ms - round(parsed.rtt_ms), parsed.rtt_ms)
        elif isinstance(parsed, Timeout):
            self._outcome(parsed.seq, read_ms - self.interval_ms, None)

    def _row_context(self) -> tuple[str | None, int]:
        try:
            return self.link_context()
        except Exception:
            log.exception("ping target %s: link context failed", self.target_id)
            return None, 0

    def _take_error(self) -> str | None:
        error, self._send_error = self._send_error, None
        return error

    def _outcome(self, seq: int, ts: int, rtt_ms: float | None) -> None:
        u = self._unwrap(seq)
        if self._high is not None and u <= self._high:
            existing = self._pending.get(u)
            if existing is None:
                self.dropped_late += 1
                log.debug(
                    "ping target %s: seq %s arrived after flush, dropped", self.target_id, seq
                )
                return
            # Last outcome wins. A late reply carries its true send time (read time - RTT).
            if rtt_ms is not None:
                existing.ts, existing.rtt_ms, existing.error = ts, rtt_ms, None
            else:
                existing.rtt_ms = None
                existing.error = self._take_error() or existing.error
            return
        link, vpn = self._row_context()
        if self._high is not None and u > self._high + 1:
            self._fill_gap(u, ts, link, vpn)
        error = None if rtt_ms is not None else self._take_error()
        self._pending[u] = _Pending(seq % SEQ_MOD, ts, rtt_ms, error, link, vpn)
        self._high, self._high_ts = u, ts

    def _fill_gap(self, high: int, high_ts: int, link: str | None, vpn: int) -> None:
        """Seqs between the last outcome and `high` printed nothing: one loss row each, with
        interpolated send times, unless a sleep/heartbeat gap overlaps that period."""
        assert self._high is not None and self._high_ts is not None
        low, low_ts = self._high, self._high_ts
        if self.in_gap(low_ts, high_ts):
            return
        steps = high - low
        for i in range(1, steps):
            ts = low_ts + (high_ts - low_ts) * i // steps
            self._pending[low + i] = _Pending(
                (low + i) % SEQ_MOD, ts, None, self._take_error(), link, vpn
            )

    def flush(self, now_ms: int, everything: bool = False) -> list[PingRow]:
        """Rows whose hold has expired, in seq order (all of them when the process goes away)."""
        done = [u for u, p in self._pending.items() if everything or p.ts + HOLD_MS <= now_ms]
        rows = []
        for u in sorted(done):
            p = self._pending.pop(u)
            rows.append(PingRow(p.ts, self.target_id, p.seq, p.rtt_ms, p.error, p.link, p.vpn))
        return rows

    @property
    def pending_count(self) -> int:
        return len(self._pending)


def default_popen(argv: Sequence[str]) -> subprocess.Popen:
    """stderr is merged into stdout so `ping: sendto:` lines stay in order with the timeouts."""
    return subprocess.Popen(
        list(argv),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        errors="replace",
        bufsize=1,
    )


class PingProcess:
    """One `ping` subprocess plus the reader thread that feeds its PingStream."""

    def __init__(
        self,
        target: Target,
        interval_s: int = 2,
        clock: Clock = wall_ms,
        popen: Popen = default_popen,
        link_context: LinkContext = _no_link,
        in_gap: GapCheck = _no_gap,
    ) -> None:
        if not target.ip:
            raise ValueError(f"target {target.id} has no IP to ping")
        self.target = target
        self.clock = clock
        self.stream = PingStream(target.id, interval_s, link_context, in_gap)
        self.lock = threading.Lock()
        self.started_ms = clock()
        self.argv = ping_argv(target.ip, target.af, interval_s)
        self.proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._exited = threading.Event()
        try:
            self.proc = popen(self.argv)
        except OSError as exc:
            log.warning("could not start %s: %s", self.argv[0], exc)
            self._exited.set()
            return
        self._thread = threading.Thread(target=self._read, name=f"ping-{target.id}", daemon=True)
        self._thread.start()

    @property
    def ip(self) -> str | None:
        return self.target.ip

    def _read(self) -> None:
        try:
            assert self.proc is not None and self.proc.stdout is not None
            for line in self.proc.stdout:
                with self.lock:
                    self.stream.feed(line, self.clock())
        except (OSError, ValueError) as exc:  # pipe closed under us during stop()
            log.debug("ping target %s reader stopped: %s", self.target.id, exc)
        finally:
            self._exited.set()

    @property
    def exited(self) -> bool:
        return self._exited.is_set()

    def flush(self, now_ms: int, everything: bool = False) -> list[PingRow]:
        with self.lock:
            return self.stream.flush(now_ms, everything)

    def answering(self, now_ms: int, within_ms: int = ANSWERING_WITHIN_MS) -> bool:
        with self.lock:
            last = self.stream.last_reply_ms
        return last is not None and now_ms - last <= within_ms

    def stop(self, timeout_s: float = 2.0) -> None:
        """Terminate the process (kill it if it lingers) and wait for the reader to finish."""
        proc = self.proc
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=timeout_s)
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=timeout_s)
        if proc is not None and proc.stdout is not None:
            try:
                proc.stdout.close()
            except OSError:
                pass


class PingStreams:
    """One PingProcess per active target that has an IP, restarted per spec §4.2."""

    def __init__(
        self,
        interval_s: int = 2,
        clock: Clock = wall_ms,
        popen: Popen = default_popen,
        link_context: LinkContext = _no_link,
        in_gap: GapCheck = _no_gap,
    ) -> None:
        self.interval_s = interval_s
        self.clock = clock
        self.popen = popen
        self.link_context = link_context
        self.in_gap = in_gap
        self._procs: dict[int, PingProcess] = {}
        self._carry: list[PingRow] = []  # rows from stopped processes, returned by next collect()

    def _start(self, target: Target) -> None:
        self._procs[target.id] = PingProcess(
            target, self.interval_s, self.clock, self.popen, self.link_context, self.in_gap
        )

    def _stop(self, target_id: int) -> Target | None:
        proc = self._procs.pop(target_id, None)
        if proc is None:
            return None
        proc.stop()
        self._carry.extend(proc.flush(self.clock(), everything=True))
        return proc.target

    def _restart(self, target_id: int) -> None:
        target = self._stop(target_id)
        if target is not None:
            self._start(target)

    def sync(self, targets: Iterable[Target]) -> None:
        """Match processes to the active targets: start new, stop removed, restart on IP change."""
        wanted = {t.id: t for t in targets if t.active and t.ip}
        for target_id in list(self._procs):
            if target_id not in wanted:
                self._stop(target_id)
        for target_id, target in wanted.items():
            proc = self._procs.get(target_id)
            if proc is not None and (proc.ip != target.ip or proc.target.af != target.af):
                self._stop(target_id)
                proc = None
            if proc is None:
                self._start(target)
            else:
                proc.target = target

    def sync_from_db(self, conn: sqlite3.Connection) -> None:
        self.sync(store.list_targets(conn, active_only=True))

    def tick(self) -> None:
        """Restart processes that exited (at most once per backoff period) or are 24 h old."""
        now = self.clock()
        for target_id, proc in list(self._procs.items()):
            age = now - proc.started_ms
            if proc.exited and age >= RESTART_BACKOFF_MS:
                log.info("ping for target %s exited; restarting", target_id)
                self._restart(target_id)
            elif age >= MAX_AGE_MS:
                self._restart(target_id)

    def restart_all(self) -> None:
        """After wake: fresh processes, so the gap rule never spans the sleep."""
        for target_id in list(self._procs):
            self._restart(target_id)

    def collect(self) -> list[PingRow]:
        now = self.clock()
        rows, self._carry = self._carry, []
        for proc in self._procs.values():
            rows.extend(proc.flush(now))
        return rows

    def write(self, conn: sqlite3.Connection) -> int:
        """Batch insert of every row whose hold expired (the collector calls this every 5 s)."""
        rows = self.collect()
        if rows:
            store.insert_rows(conn, rows)
        return len(rows)

    def still_answering(self, target_id: int) -> bool:
        """Discovery hook: a sticky IP is kept while its stream still gets replies."""
        proc = self._procs.get(target_id)
        return proc is not None and proc.answering(self.clock())

    def stop_all(self) -> list[PingRow]:
        """Graceful stop: end every process and return all remaining rows for the caller to insert."""
        for target_id in list(self._procs):
            self._stop(target_id)
        rows, self._carry = self._carry, []
        return rows

    @property
    def running(self) -> dict[int, PingProcess]:
        return dict(self._procs)


def _dns_query(name: str = "whodunnet.invalid") -> bytes:
    header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # id, RD, one question
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return header + labels + b"\x00\x00\x01\x00\x01"  # QTYPE A, QCLASS IN


def nudge_local_network(gateway: str | None, sock_factory=socket.socket) -> bool:
    """Send one UDP DNS query to the gateway so macOS 15+ shows the Local Network prompt.

    The answer is ignored and the collector keeps running whether or not access is granted.
    Never raises.
    """
    if not gateway:
        return False
    family = socket.AF_INET6 if ":" in gateway else socket.AF_INET
    try:
        sock = sock_factory(family, socket.SOCK_DGRAM)
        try:
            sock.settimeout(1.0)
            sock.sendto(_dns_query(), (gateway, 53))
        finally:
            sock.close()
    except OSError as exc:
        log.info("local network nudge to the gateway failed: %s", exc)
        return False
    return True
