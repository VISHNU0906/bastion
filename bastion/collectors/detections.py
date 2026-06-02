"""Runtime-security detection collector + MTTD engine.

This is the heart of Bastion's security-MTTD story. A runtime-security tool
(Falco, Wazuh, an EDR webhook) posts a detection to ``/ingest/detection``. Each
detection carries TWO timestamps that must stay distinct:

  * ``event_time``     — when the suspicious activity actually OCCURRED.
  * ``detection_time`` — when Bastion received/recorded it (defaults to now).

**Detection latency = detection_time - event_time.** This is the real measured
delta. MTTD (mean time to detect) is the rolling mean of that latency over
recent detections, per priority. If a payload only carried receipt time and we
stamped ``now`` for both, latency would be ~0 and MTTD meaningless — so the
ingest model REQUIRES an event time (the sample generator backdates it).

Metrics:
  bastion_security_detections_total{rule,priority}   monotonic detection count
  bastion_detection_latency_seconds{priority}        per-event latency histogram
  bastion_detection_mttd_seconds{priority}           rolling mean latency (MTTD)
  bastion_detection_last_timestamp_seconds{priority} unix ts of last detection

``DetectionEngine`` is plain in-memory state; it has no network and is fully
unit-testable. The collector half just refreshes the rolling MTTD gauges on
each scrape (the counters/histograms are updated at ingest time).
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from bastion.collectors.base import Collector
from bastion.config import DetectionsConfig
from bastion.metrics import BastionMetrics

logger = logging.getLogger("bastion.collector.detections")

# How many recent latencies per priority feed the rolling MTTD mean.
_MTTD_WINDOW = 200


@dataclass(frozen=True)
class Detection:
    """A normalized runtime-security detection."""

    rule: str
    priority: str
    event_time: float       # unix seconds — when it happened
    detection_time: float   # unix seconds — when we recorded it
    output: str = ""

    @property
    def latency_seconds(self) -> float:
        """Detection latency: how long after the event we detected it."""
        return max(0.0, self.detection_time - self.event_time)


def normalize_priority(priority: str) -> str:
    """Canonicalize a Falco-style priority string (Title-case word).

    Falco emits Emergency/Alert/Critical/Error/Warning/Notice/Informational/
    Debug. We Title-case so labels are stable regardless of input casing.
    """
    p = (priority or "").strip()
    return p[:1].upper() + p[1:].lower() if p else "Unknown"


def parse_detection(payload: dict, now: float | None = None) -> Detection:
    """Build a :class:`Detection` from a Falco-style webhook payload.

    Accepted shapes (Falco's native JSON and a couple of common aliases):
      {
        "rule": "Terminal shell in container",
        "priority": "Critical",
        "time": "2026-06-02T12:00:00Z" | <unix_seconds>,   # event_time
        "output": "...",
      }

    ``time``/``event_time``/``timestamp`` give the EVENT time. If none is
    present we fall back to ``now`` (latency 0) — but the documented contract is
    to always send the event time so MTTD is real.

    Raises:
        ValueError: if ``rule`` is missing/empty.
    """
    now = now if now is not None else time.time()
    rule = str(payload.get("rule", "")).strip()
    if not rule:
        raise ValueError("detection payload requires a non-empty 'rule'")
    priority = normalize_priority(str(payload.get("priority", "")))

    raw_time = (
        payload.get("event_time")
        if payload.get("event_time") is not None
        else payload.get("time", payload.get("timestamp"))
    )
    event_time = _coerce_time(raw_time, default=now)
    detection_time = _coerce_time(payload.get("detection_time"), default=now)
    return Detection(
        rule=rule,
        priority=priority,
        event_time=event_time,
        detection_time=detection_time,
        output=str(payload.get("output", "")),
    )


def _coerce_time(value: object, default: float) -> float:
    """Coerce an ISO-8601 string or unix-seconds number into unix seconds."""
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        import datetime as dt

        try:
            ts = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return default
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=dt.timezone.utc)
        return ts.timestamp()
    return default


class DetectionEngine:
    """In-memory detection store that computes rolling MTTD per priority.

    Network-free and deterministic so the MTTD math is unit-testable. The FastAPI
    ingest route and the scrape-time collector both talk to one instance.
    """

    def __init__(self, metrics: BastionMetrics, config: DetectionsConfig):
        self.metrics = metrics
        self.config = config
        self._latencies: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=_MTTD_WINDOW))
        self._count = 0

    def record(self, detection: Detection) -> Detection:
        """Record a detection: bump counters, observe latency, update MTTD."""
        labels_rp = {"rule": detection.rule, "priority": detection.priority}
        self.metrics.detections_total.labels(**labels_rp).inc()
        latency = detection.latency_seconds
        self.metrics.detection_latency_seconds.labels(priority=detection.priority).observe(latency)
        self.metrics.detection_last_timestamp.labels(priority=detection.priority).set(
            detection.detection_time
        )
        self._latencies[detection.priority].append(latency)
        self._update_mttd(detection.priority)
        self._count += 1
        return detection

    def ingest(self, payload: dict, now: float | None = None) -> Detection:
        """Parse + record a raw webhook payload. Returns the normalized record."""
        detection = parse_detection(payload, now=now)
        return self.record(detection)

    def mttd(self, priority: str) -> float:
        """Current rolling mean detection latency (seconds) for a priority."""
        latencies = self._latencies.get(priority)
        if not latencies:
            return 0.0
        return sum(latencies) / len(latencies)

    def is_critical(self, priority: str) -> bool:
        """Whether a priority counts as critical for incident auto-open."""
        return priority in self.config.critical_priorities

    @property
    def total(self) -> int:
        return self._count

    def _update_mttd(self, priority: str) -> None:
        self.metrics.detection_mttd_seconds.labels(priority=priority).set(self.mttd(priority))

    def refresh_gauges(self) -> None:
        """Re-publish MTTD gauges for every seen priority (called on scrape)."""
        for priority in self._latencies:
            self._update_mttd(priority)


class DetectionsCollector(Collector):
    """Scrape-time half: refresh rolling MTTD gauges from the engine."""

    def __init__(self, metrics: BastionMetrics, engine: DetectionEngine):
        super().__init__(metrics)
        self.engine = engine

    @property
    def name(self) -> str:
        return "detections"

    def _collect(self) -> None:
        if not self.engine.config.enabled:
            return
        self.engine.refresh_gauges()
