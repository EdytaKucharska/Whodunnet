"""Ping stream rules (spec §4.2, §11 "Ping stream") plus process management."""

from __future__ import annotations

import queue
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import ClassVar

import pytest

from whodunnet.core import store
from whodunnet.core.models import Target
from whodunnet.probes import ping
from whodunnet.probes.link import LinkState
from whodunnet.probes.ping import HOLD_MS, PingStream, PingStreams

FIXTURES = Path(__file__).parent / "fixtures" / "macos" / "ping"
T0 = 1_700_000_000_000


def reply(seq: int, ms: float = 10.0) -> str:
    return f"64 bytes from 192.0.2.9: icmp_seq={seq} ttl=58 time={ms:.3f} ms\n"


def timeout(seq: int) -> str:
    return f"Request timeout for icmp_seq {seq}\n"


def feed_all(stream: PingStream, lines: list[tuple[str, int]]) -> None:
    for line, read_ms in lines:
        stream.feed(line, read_ms)


# ---- PingStream (pure) -----------------------------------------------------------------------


def test_replies_become_rows_with_send_time():
    s = PingStream(target_id=7)
    s.feed("PING 192.0.2.9 (192.0.2.9): 56 data bytes\n", T0)
    s.feed(reply(0, 12.4), T0 + 12)
    s.feed(reply(1, 9.6), T0 + 2010)
    rows = s.flush(T0 + 60_000)
    assert [(r.seq, r.rtt_ms, r.ts, r.target_id) for r in rows] == [
        (0, 12.4, T0, 7),
        (1, 9.6, T0 + 2000, 7),
    ]
    assert all(r.error is None for r in rows)


def test_timeout_ts_is_read_time_minus_interval():
    s = PingStream(target_id=1)
    s.feed(reply(0), T0 + 10)
    s.feed(timeout(1), T0 + 4000)  # printed when seq 2 is sent
    rows = s.flush(T0 + 60_000)
    assert rows[1].seq == 1 and rows[1].rtt_ms is None and rows[1].ts == T0 + 2000


def test_hold_keeps_rows_until_10s_after_send():
    s = PingStream(target_id=1)
    s.feed(reply(0), T0 + 10)  # sent at T0
    assert s.flush(T0 + HOLD_MS - 1) == []
    assert [r.seq for r in s.flush(T0 + HOLD_MS)] == [0]
    assert s.flush(T0 + 60_000) == []


def test_late_reply_inside_hold_replaces_timeout():
    s = PingStream(target_id=1)
    s.feed(reply(0), T0 + 10)
    s.feed(timeout(1), T0 + 4000)
    s.feed(reply(1, 3500.0), T0 + 2000 + 3500)  # late reply for seq 1, still inside the hold
    rows = s.flush(T0 + 60_000)
    assert len(rows) == 2
    assert rows[1].seq == 1 and rows[1].rtt_ms == 3500.0 and rows[1].ts == T0 + 2000
    assert rows[1].error is None


def test_late_reply_after_flush_is_dropped():
    s = PingStream(target_id=1)
    s.feed(reply(0), T0 + 10)
    s.feed(timeout(1), T0 + 4000)
    flushed = s.flush(T0 + 2000 + HOLD_MS)
    assert [(r.seq, r.rtt_ms) for r in flushed] == [(0, 10.0), (1, None)]
    s.feed(reply(1, 12_000.0), T0 + 14_000)
    assert s.dropped_late == 1
    assert s.flush(T0 + 60_000) == []


def test_sendto_error_is_attached_to_next_loss_and_creates_no_row():
    s = PingStream(target_id=1)
    text = (FIXTURES / "provisional_sendto_error.txt").read_text().splitlines(keepends=True)
    for i, line in enumerate(text):
        s.feed(line, T0 + i * 2000)
    rows = s.flush(T0 + 60_000)
    assert [(r.seq, r.rtt_ms is None, r.error) for r in rows] == [
        (0, False, None),
        (1, True, "No route to host"),
        (2, True, "Network is down"),
        (3, False, None),
    ]


def test_sendto_error_with_no_following_loss_is_not_carried_to_a_reply():
    s = PingStream(target_id=1)
    s.feed(reply(0), T0)
    s.feed("ping: sendto: Host is down\n", T0 + 1000)
    s.feed(reply(1), T0 + 2010)
    s.feed(timeout(2), T0 + 6000)
    rows = s.flush(T0 + 60_000)
    assert [r.error for r in rows] == [None, None, "Host is down"]


def test_seq_gap_becomes_loss_rows_with_interpolated_ts():
    s = PingStream(target_id=1)
    s.feed(reply(0), T0 + 10)  # sent T0
    s.feed(reply(4), T0 + 8010)  # sent T0 + 8000; seqs 1-3 printed nothing (ping6 case)
    rows = s.flush(T0 + 60_000)
    assert [(r.seq, r.rtt_ms, r.ts) for r in rows] == [
        (0, 10.0, T0),
        (1, None, T0 + 2000),
        (2, None, T0 + 4000),
        (3, None, T0 + 6000),
        (4, 10.0, T0 + 8000),
    ]


def test_seq_gap_overlapping_sleep_gap_is_dropped():
    seen = []

    def in_gap(start, end):
        seen.append((start, end))
        return True

    s = PingStream(target_id=1, in_gap=in_gap)
    s.feed(reply(0), T0 + 10)
    s.feed(reply(50), T0 + 600_010)
    rows = s.flush(T0 + 700_000)
    assert [r.seq for r in rows] == [0, 50]
    assert seen == [(T0, T0 + 600_000)]


def test_gap_rows_get_pending_send_error_first():
    s = PingStream(target_id=1)
    s.feed(reply(0), T0)
    s.feed("ping: sendto: No route to host\n", T0 + 1000)
    s.feed(reply(3), T0 + 6000)
    rows = s.flush(T0 + 60_000)
    assert [(r.seq, r.error) for r in rows] == [
        (0, None),
        (1, "No route to host"),
        (2, None),
        (3, None),
    ]


def test_seq_wraps_modulo_65536():
    s = PingStream(target_id=1)
    s.feed(reply(65534), T0)
    s.feed(reply(65535), T0 + 2000)
    s.feed(reply(1), T0 + 6000)  # 0 missing across the wrap
    rows = s.flush(T0 + 60_000)
    assert [(r.seq, r.rtt_ms is None) for r in rows] == [
        (65534, False),
        (65535, False),
        (0, True),
        (1, False),
    ]


def test_late_reply_across_wrap_updates_existing_row():
    s = PingStream(target_id=1)
    s.feed(reply(65535), T0)
    s.feed(timeout(0), T0 + 4000)  # seq 0 sent at T0 + 2000
    s.feed(reply(1), T0 + 4010)
    s.feed(reply(0, 2500.0), T0 + 4500)
    rows = s.flush(T0 + 60_000)
    assert [(r.seq, r.rtt_ms) for r in rows] == [(65535, 10.0), (0, 2500.0), (1, 10.0)]


def test_unparsed_lines_are_counted_and_ignored():
    s = PingStream(target_id=1)
    s.feed("something macOS printed that we don't know\n", T0)
    s.feed("--- 192.0.2.9 ping statistics ---\n", T0)
    assert s.unparsed == 1 and s.pending_count == 0


def test_link_context_is_recorded_per_row():
    state = {"v": ("wifi", 0)}
    s = PingStream(target_id=1, link_context=lambda: state["v"])
    s.feed(reply(0), T0)
    state["v"] = ("wired", 1)
    s.feed(reply(1), T0 + 2000)
    rows = s.flush(T0 + 60_000)
    assert [(r.link, r.vpn) for r in rows] == [("wifi", 0), ("wired", 1)]


def test_link_context_failure_never_loses_outcome():
    def broken():
        raise RuntimeError("boom")

    s = PingStream(target_id=1, link_context=broken)
    s.feed(reply(0), T0)
    rows = s.flush(T0 + 60_000)
    assert len(rows) == 1 and rows[0].link is None and rows[0].vpn == 0


def test_real_fixtures_produce_one_row_per_seq():
    for name in ("gateway.txt", "timeouts.txt", "wifi_off_attempt_no_errors.txt"):
        s = PingStream(target_id=1)
        lines = (FIXTURES / name).read_text().splitlines(keepends=True)
        for i, line in enumerate(lines):
            s.feed(line, T0 + i * 2000)
        rows = s.flush(T0 + 10**9, everything=True)
        seqs = [r.seq for r in rows]
        assert seqs == list(range(len(seqs))), name
        assert s.unparsed == 0, name


def test_flush_everything_returns_rows_still_in_hold():
    s = PingStream(target_id=1)
    s.feed(reply(0), T0)
    assert s.flush(T0, everything=True)[0].seq == 0


def test_link_context_from_cache_peek():
    class Cache:
        def __init__(self):
            self.state = None

        def peek(self):
            return self.state

    cache = Cache()
    context = ping.link_context_from(cache)
    assert context() == (None, 0)
    cache.state = LinkState("en0", "192.168.1.1", "wifi", 1)
    assert context() == ("wifi", 1)


# ---- processes (fake Popen) ------------------------------------------------------------------


class FakeProc:
    """Popen stand-in: lines pushed by the test come out of stdout; terminate ends it."""

    def __init__(self, argv):
        self.argv = list(argv)
        self._lines: queue.Queue = queue.Queue()
        self.returncode = None
        self.terminated = False
        self.stdout = self

    def push(self, line: str) -> None:
        self._lines.put(line)

    def exit(self, code: int = 2) -> None:
        self.returncode = code
        self._lines.put(None)

    def __iter__(self):
        return self

    def __next__(self):
        line = self._lines.get(timeout=5)
        if line is None:
            raise StopIteration
        return line

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.exit(-15)

    def kill(self):
        self.exit(-9)

    def wait(self, timeout=None):
        return self.returncode

    def close(self):
        pass


class FakePopen:
    def __init__(self):
        self.procs: list[FakeProc] = []

    def __call__(self, argv):
        proc = FakeProc(argv)
        self.procs.append(proc)
        return proc


class Clock:
    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now


def target(id_, ip="192.0.2.9", af=4, active=1):
    return Target(id_, "anchor", f"t{id_}", af, None, ip, "ok", active, None, T0, T0)


def wait_until(cond, timeout_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.01)
    return False


def test_ping_argv():
    assert ping.ping_argv("192.0.2.9", 4) == ["ping", "-n", "-i", "2", "192.0.2.9"]
    assert ping.ping_argv("2001:db8::1", 6) == ["ping6", "-n", "-i", "2", "2001:db8::1"]


def test_sync_starts_one_process_per_active_target_with_ip():
    popen, clock = FakePopen(), Clock()
    streams = PingStreams(clock=clock, popen=popen)
    streams.sync([target(1), target(2, ip=None), target(3, active=0), target(4, "2001:db8::1", 6)])
    assert sorted(streams.running) == [1, 4]
    assert sorted(p.argv[0] for p in popen.procs) == ["ping", "ping6"]
    streams.stop_all()


def test_rows_flow_from_process_to_collect():
    popen, clock = FakePopen(), Clock()
    streams = PingStreams(clock=clock, popen=popen)
    streams.sync([target(1)])
    proc = popen.procs[0]
    proc.push(reply(0, 5.0))
    assert wait_until(lambda: streams.running[1].stream.pending_count == 1)
    assert streams.collect() == []  # still in hold
    clock.now += HOLD_MS + 100
    rows = streams.collect()
    assert [(r.target_id, r.seq) for r in rows] == [(1, 0)]
    assert streams.still_answering(1)
    clock.now += 120_000
    assert not streams.still_answering(1)
    assert not streams.still_answering(99)
    streams.stop_all()


def test_ip_change_restarts_and_flushes_old_rows():
    popen, clock = FakePopen(), Clock()
    streams = PingStreams(clock=clock, popen=popen)
    streams.sync([target(1)])
    popen.procs[0].push(reply(0))
    assert wait_until(lambda: streams.running[1].stream.pending_count == 1)
    streams.sync([target(1, ip="192.0.2.10")])
    assert popen.procs[0].terminated
    assert popen.procs[1].argv[-1] == "192.0.2.10"
    rows = streams.collect()  # the old process's row comes out even though its hold hadn't expired
    assert [r.seq for r in rows] == [0]
    streams.stop_all()


def test_removed_target_is_stopped():
    popen, clock = FakePopen(), Clock()
    streams = PingStreams(clock=clock, popen=popen)
    streams.sync([target(1), target(2)])
    streams.sync([target(2)])
    assert sorted(streams.running) == [2]
    assert popen.procs[0].terminated and not popen.procs[1].terminated
    streams.stop_all()


def test_unchanged_target_is_not_restarted():
    popen, clock = FakePopen(), Clock()
    streams = PingStreams(clock=clock, popen=popen)
    streams.sync([target(1)])
    streams.sync([target(1)])
    assert len(popen.procs) == 1
    streams.stop_all()


def test_exited_process_restarts_after_backoff():
    popen, clock = FakePopen(), Clock()
    streams = PingStreams(clock=clock, popen=popen)
    streams.sync([target(1)])
    popen.procs[0].exit(2)
    assert wait_until(lambda: streams.running[1].exited)
    streams.tick()
    assert len(popen.procs) == 1  # within backoff: no busy restart loop
    clock.now += ping.RESTART_BACKOFF_MS
    streams.tick()
    assert len(popen.procs) == 2
    streams.stop_all()


def test_restart_every_24_hours_and_new_stream_has_no_gap_rule():
    popen, clock = FakePopen(), Clock()
    streams = PingStreams(clock=clock, popen=popen)
    streams.sync([target(1)])
    popen.procs[0].push(reply(40_000))
    assert wait_until(lambda: streams.running[1].stream.pending_count == 1)
    clock.now += ping.MAX_AGE_MS
    streams.tick()
    assert len(popen.procs) == 2 and popen.procs[0].terminated
    popen.procs[1].push(reply(0))  # seq restarts at 0: no gap/late handling against old seqs
    assert wait_until(lambda: streams.running[1].stream.pending_count == 1)
    rows = streams.stop_all()
    assert sorted(r.seq for r in rows) == [0, 40_000]


def test_restart_all_after_wake():
    popen, clock = FakePopen(), Clock()
    streams = PingStreams(clock=clock, popen=popen)
    streams.sync([target(1), target(2)])
    streams.restart_all()
    assert len(popen.procs) == 4
    assert all(p.terminated for p in popen.procs[:2])
    streams.stop_all()


def test_write_inserts_batch(tmp_path):
    conn = store.connect(tmp_path / "w.db")
    target_id = store.upsert_target(conn, "anchor", "cloudflare", 4, None, "1.1.1.1", "ok", T0)
    popen, clock = FakePopen(), Clock()
    streams = PingStreams(clock=clock, popen=popen)
    streams.sync_from_db(conn)
    popen.procs[0].push(reply(0))
    popen.procs[0].push(timeout(1))
    assert wait_until(lambda: streams.running[target_id].stream.pending_count == 2)
    clock.now += 60_000
    assert streams.write(conn) == 2
    rows = store.read_raw(conn, "ping", T0 - 10**6, T0 + 10**9)
    assert sorted((r["seq"], r["rtt_ms"]) for r in rows) == [(0, 10.0), (1, None)]
    streams.stop_all()


def test_popen_failure_marks_exited_and_retries_later():
    clock = Clock()

    def failing(argv):
        raise FileNotFoundError("ping")

    streams = PingStreams(clock=clock, popen=failing)
    streams.sync([target(1)])
    assert streams.running[1].exited
    clock.now += ping.RESTART_BACKOFF_MS
    streams.tick()  # retries without raising
    assert streams.running[1].exited
    assert streams.stop_all() == []


# ---- real subprocess: reader thread and no orphans -----------------------------------------


FAKE_PING = """
import sys, time
print("PING 192.0.2.9 (192.0.2.9): 56 data bytes", flush=True)
print("64 bytes from 192.0.2.9: icmp_seq=0 ttl=58 time=1.000 ms", flush=True)
print("ping: sendto: No route to host", file=sys.stderr, flush=True)
print("Request timeout for icmp_seq 1", flush=True)
time.sleep(60)
"""


def test_real_process_lines_stream_in_order_and_stop_leaves_no_orphan():
    def popen(argv):
        return ping.default_popen([sys.executable, "-c", FAKE_PING])

    streams = PingStreams(popen=popen)
    streams.sync([target(1)])
    proc = streams.running[1]
    assert wait_until(lambda: proc.stream.pending_count == 2, 10)
    rows = streams.stop_all()
    assert [(r.seq, r.error) for r in rows] == [(0, None), (1, "No route to host")]
    assert proc.proc.poll() is not None
    assert not proc._thread.is_alive()


def test_stop_kills_a_process_that_ignores_sigterm():
    script = (
        "import signal, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "print('ready', flush=True)\n"
        "time.sleep(60)\n"
    )
    p = ping.PingProcess(
        target(1), popen=lambda argv: ping.default_popen([sys.executable, "-c", script])
    )
    assert wait_until(lambda: p.stream.unparsed == 1, 10)
    started = time.monotonic()
    p.stop(timeout_s=0.5)
    assert p.proc.poll() is not None
    assert time.monotonic() - started < 5


# ---- Local Network nudge ---------------------------------------------------------------------


class FakeSocket:
    sent: ClassVar[list] = []

    def __init__(self, family, kind):
        self.family, self.kind = family, kind

    def settimeout(self, t):
        pass

    def sendto(self, data, addr):
        FakeSocket.sent.append((self.family, data, addr))

    def close(self):
        pass


def test_nudge_sends_one_dns_query_to_gateway():
    FakeSocket.sent = []
    assert ping.nudge_local_network("192.168.1.1", FakeSocket)
    ((family, data, addr),) = FakeSocket.sent
    assert family == socket.AF_INET and addr == ("192.168.1.1", 53)
    assert data[4:6] == b"\x00\x01" and data.endswith(b"\x00\x01\x00\x01")
    assert ping.nudge_local_network("fe80::1%en0", FakeSocket)
    assert FakeSocket.sent[-1][0] == socket.AF_INET6


def test_nudge_never_raises():
    def broken(family, kind):
        raise PermissionError("blocked")

    assert ping.nudge_local_network("192.168.1.1", broken) is False
    assert ping.nudge_local_network(None) is False


def test_nudge_real_socket_to_loopback():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.settimeout(2)
    got = {}

    def receive():
        got["data"], _ = srv.recvfrom(512)

    thread = threading.Thread(target=receive)
    thread.start()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(ping._dns_query(), ("127.0.0.1", port))
    sock.close()
    thread.join(3)
    srv.close()
    assert got["data"] == ping._dns_query()


def test_default_popen_merges_stderr():
    proc = ping.default_popen([sys.executable, "-c", "import sys; print('x', file=sys.stderr)"])
    out, _ = proc.communicate(timeout=10)
    assert out.strip() == "x"
    assert isinstance(proc, subprocess.Popen)


@pytest.mark.parametrize("bad", [None, ""])
def test_process_requires_ip(bad):
    with pytest.raises(ValueError):
        ping.PingProcess(target(1, ip=bad), popen=FakePopen())
