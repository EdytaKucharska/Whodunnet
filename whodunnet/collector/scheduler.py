"""Interval scheduler with an injectable monotonic clock (plan M1.7).

Jobs run on the collector's main thread (`background=False`) or on one worker thread
(`background=True`). Slow probes go to the worker: traceroute rounds, discovery, networkQuality
and the ~11 s WiFi readout must never delay the 10 s heartbeat. Background jobs run one at a time,
in order, so probes never overlap each other (an overlap would disturb the measurements). A job
that is still queued or running is not queued again. A job that raises is logged and rescheduled.
The collector loop never dies because a probe failed.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

log = logging.getLogger(__name__)


@dataclass
class Job:
    name: str
    interval_s: float
    fn: Callable[[], object]
    background: bool = False
    next_due: float = 0.0
    pending: bool = False  # queued or running on the worker
    runs: int = 0
    failures: int = 0
    last_error: str | None = field(default=None, repr=False)


class Scheduler:
    def __init__(self, monotonic: Callable[[], float] = time.monotonic, threaded: bool = True):
        self.monotonic = monotonic
        self.jobs: dict[str, Job] = {}
        self._threaded = threaded
        self._queue: queue.Queue[Job | None] = queue.Queue()
        self._lock = threading.Lock()
        self._worker: threading.Thread | None = None

    def every(
        self,
        name: str,
        interval_s: float,
        fn: Callable[[], object],
        background: bool = False,
        first_in_s: float = 0.0,
    ) -> Job:
        job = Job(name, interval_s, fn, background, next_due=self.monotonic() + first_in_s)
        self.jobs[name] = job
        return job

    def run_soon(self, name: str) -> None:
        """Make a job due now (e.g. rediscovery after wake or a route change)."""
        self.jobs[name].next_due = self.monotonic()

    def _execute(self, job: Job) -> None:
        try:
            job.fn()
            job.runs += 1
        except Exception as exc:  # one failing probe must not stop the collector
            job.failures += 1
            job.last_error = f"{type(exc).__name__}: {exc}"
            log.exception("job %s failed", job.name)
        finally:
            with self._lock:
                job.pending = False

    def _work(self) -> None:
        while True:
            job = self._queue.get()
            if job is None:
                return
            self._execute(job)

    def _ensure_worker(self) -> None:
        if self._worker is None or not self._worker.is_alive():
            self._worker = threading.Thread(target=self._work, name="probes", daemon=True)
            self._worker.start()

    def run_pending(self) -> list[str]:
        """Run (or queue) every due job. Returns the names started, for tests and logs."""
        now = self.monotonic()
        started = []
        for job in list(self.jobs.values()):
            if now < job.next_due:
                continue
            with self._lock:
                if job.pending:
                    continue
                job.pending = True
            # No burst of catch-up runs after a long pause: the next run is one interval from now.
            job.next_due = now + job.interval_s
            started.append(job.name)
            if job.background and self._threaded:
                self._ensure_worker()
                self._queue.put(job)
            else:
                self._execute(job)
        return started

    def run_forever(self, stop: threading.Event, tick_s: float = 1.0) -> None:
        while not stop.is_set():
            self.run_pending()
            stop.wait(tick_s)

    def shutdown(self, timeout_s: float = 15.0) -> None:
        """Let the worker finish its current job, then stop it (queued jobs are dropped)."""
        if self._worker is None:
            return
        while True:
            try:
                job = self._queue.get_nowait()
            except queue.Empty:
                break
            if job is not None:
                with self._lock:
                    job.pending = False
        self._queue.put(None)
        self._worker.join(timeout_s)

    def idle(self) -> bool:
        """True when no background job is queued or running (tests)."""
        with self._lock:
            return not any(j.pending for j in self.jobs.values())
