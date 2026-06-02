"""Auth-failure collector.

Two ways to feed it, matching real deployments:

  1. **Log parsing.** Point it at an sshd/PAM-style auth log; it counts failed
     vs accepted lines and computes a failure RATE over a rolling window.
  2. **Pushed counter.** The ingest API (/ingest/auth) bumps the same counters
     directly, for systems that already aggregate auth events.

The line classifier (``classify_auth_line``) is a pure function, unit-testable
against fixture log lines with no filesystem.

Metrics:
  bastion_auth_failures_total{source}    monotonic failed-login counter
  bastion_auth_attempts_total{source}    monotonic total-attempt counter
  bastion_auth_failure_rate{source}      failures/sec over the rolling window
  bastion_auth_check_success             1 if the collector ran, else 0

The failure RATIO (failures/attempts) that the auth SLO targets is computed in
Prometheus from the two counters (rate(...failures) / rate(...attempts)); this
collector also exposes an instantaneous failures-per-second gauge for context.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from pathlib import Path

from bastion.collectors.base import Collector
from bastion.config import AuthConfig
from bastion.metrics import BastionMetrics

logger = logging.getLogger("bastion.collector.auth")

# Substrings that classify an auth log line. Kept simple and explicit; covers
# the common sshd/PAM phrasings used by the sample log and most real logs.
_FAILURE_MARKERS = (
    "failed password",
    "authentication failure",
    "failed login",
    "invalid user",
    "auth fail",
)
_SUCCESS_MARKERS = (
    "accepted password",
    "accepted publickey",
    "session opened",
    "login successful",
)


def classify_auth_line(line: str) -> str | None:
    """Classify one auth-log line as ``"failure"``, ``"success"``, or None.

    Case-insensitive substring match against known sshd/PAM phrasings. Lines
    that match neither (e.g. unrelated daemon noise) return None so they don't
    inflate the attempt total.
    """
    lowered = line.lower()
    for marker in _FAILURE_MARKERS:
        if marker in lowered:
            return "failure"
    for marker in _SUCCESS_MARKERS:
        if marker in lowered:
            return "success"
    return None


def count_auth_lines(text: str) -> tuple[int, int]:
    """Count (failures, successes) in a block of auth-log text."""
    failures = 0
    successes = 0
    for line in text.splitlines():
        kind = classify_auth_line(line)
        if kind == "failure":
            failures += 1
        elif kind == "success":
            successes += 1
    return failures, successes


class _RollingRate:
    """A sliding-window event-rate estimator.

    Records event timestamps and reports events/sec over the last
    ``window_seconds``. Used to turn a stream of failures into a rate gauge
    without depending on Prometheus' own rate() (handy for the /status view and
    for the ingest path).
    """

    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self._events: deque[float] = deque()

    def add(self, count: int = 1, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        for _ in range(count):
            self._events.append(now)
        self._evict(now)

    def rate(self, now: float | None = None) -> float:
        now = now if now is not None else time.time()
        self._evict(now)
        if not self._events:
            return 0.0
        return len(self._events) / float(self.window_seconds)

    def _evict(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._events and self._events[0] < cutoff:
            self._events.popleft()


class AuthFailureCollector(Collector):
    """Parse an auth log (and/or accept pushes) into auth-failure metrics."""

    def __init__(self, metrics: BastionMetrics, config: AuthConfig):
        super().__init__(metrics)
        self.config = config
        self._rate = _RollingRate(config.window_seconds)
        # Track byte offset so re-scraping a growing log only counts new lines
        # (a real exporter must be idempotent across scrapes).
        self._offset = 0
        self._log_failures = 0
        self._log_attempts = 0

    @property
    def name(self) -> str:
        return "auth_failures"

    def ingest_pushed(self, failures: int, attempts: int, source: str = "pushed") -> None:
        """Apply a pushed batch of auth events (used by the ingest API)."""
        if failures < 0 or attempts < 0 or failures > attempts:
            raise ValueError("auth push: require 0 <= failures <= attempts")
        if failures:
            self.metrics.auth_failures_total.labels(source=source).inc(failures)
            self._rate.add(failures)
        if attempts:
            self.metrics.auth_attempts_total.labels(source=source).inc(attempts)
        self.metrics.auth_failure_rate.labels(source=source).set(self._rate.rate())

    def _collect(self) -> None:
        if not self.config.enabled:
            return
        if not self.config.log_file:
            # No log configured — pushed-counter mode. Just refresh the rate.
            self.metrics.auth_failure_rate.labels(source="pushed").set(self._rate.rate())
            self.metrics.auth_check_success.set(1)
            return

        path = Path(self.config.log_file)
        if not path.exists():
            self.metrics.auth_check_success.set(0)
            return

        # Read only newly-appended bytes since the last scrape.
        data = path.read_text(encoding="utf-8", errors="replace")
        new_text = data[self._offset:]
        self._offset = len(data)

        failures, successes = count_auth_lines(new_text)
        attempts = failures + successes
        if failures:
            self.metrics.auth_failures_total.labels(source="log").inc(failures)
            self._rate.add(failures)
        if attempts:
            self.metrics.auth_attempts_total.labels(source="log").inc(attempts)
        self.metrics.auth_failure_rate.labels(source="log").set(self._rate.rate())
        self.metrics.auth_check_success.set(1)
