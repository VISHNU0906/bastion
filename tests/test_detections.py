"""Detection ingest + MTTD tests. The MTTD here is a REAL measured delta
(detection_time - event_time), so these tests pin the headline metric.
"""

from __future__ import annotations

import pytest

from bastion.collectors.detections import (
    Detection,
    DetectionEngine,
    normalize_priority,
    parse_detection,
)
from bastion.config import DetectionsConfig


def test_parse_detection_backdated_event_gives_real_latency():
    now = 1000.0
    payload = {"rule": "Terminal shell in container", "priority": "Critical", "time": now - 120}
    det = parse_detection(payload, now=now)
    assert det.rule == "Terminal shell in container"
    assert det.priority == "Critical"
    assert det.latency_seconds == pytest.approx(120.0)


def test_parse_detection_iso_timestamp():
    # ISO-8601 event time is parsed into a real latency.
    now = 1748865600.0  # 2025-06-02T12:00:00Z
    payload = {"rule": "Outbound C2", "priority": "Critical", "time": "2025-06-02T11:58:00Z"}
    det = parse_detection(payload, now=now)
    assert det.latency_seconds == pytest.approx(120.0, abs=1)


def test_parse_detection_missing_event_time_defaults_to_now():
    det = parse_detection({"rule": "x", "priority": "Warning"}, now=500.0)
    assert det.latency_seconds == pytest.approx(0.0)


def test_parse_detection_requires_rule():
    with pytest.raises(ValueError):
        parse_detection({"priority": "Critical"}, now=0.0)


def test_normalize_priority():
    assert normalize_priority("critical") == "Critical"
    assert normalize_priority("CRITICAL") == "Critical"
    assert normalize_priority("") == "Unknown"


def test_latency_never_negative():
    # A future event_time (clock skew) must not produce negative latency.
    det = Detection(rule="r", priority="Critical", event_time=100.0, detection_time=90.0)
    assert det.latency_seconds == 0.0


def _engine(metrics):
    return DetectionEngine(metrics, DetectionsConfig(enabled=True))


def test_engine_records_metric_and_mttd(metrics):
    engine = _engine(metrics)
    now = 1000.0
    engine.ingest({"rule": "Shell", "priority": "Critical", "time": now - 100}, now=now)
    engine.ingest({"rule": "Shell", "priority": "Critical", "time": now - 200}, now=now)

    # Counter incremented per rule/priority.
    assert metrics.detections_total.labels(rule="Shell", priority="Critical")._value.get() == 2
    # MTTD is the mean of the two latencies: (100 + 200) / 2 = 150.
    assert engine.mttd("Critical") == pytest.approx(150.0)
    assert metrics.detection_mttd_seconds.labels(priority="Critical")._value.get() == pytest.approx(150.0)


def test_mttd_is_per_priority(metrics):
    engine = _engine(metrics)
    now = 1000.0
    engine.ingest({"rule": "a", "priority": "Critical", "time": now - 60}, now=now)
    engine.ingest({"rule": "b", "priority": "Warning", "time": now - 600}, now=now)

    assert engine.mttd("Critical") == pytest.approx(60.0)
    assert engine.mttd("Warning") == pytest.approx(600.0)


def test_last_timestamp_recorded(metrics):
    engine = _engine(metrics)
    engine.ingest({"rule": "a", "priority": "Critical", "time": 900.0}, now=1000.0)
    assert metrics.detection_last_timestamp.labels(priority="Critical")._value.get() == pytest.approx(1000.0)


def test_is_critical_uses_config(metrics):
    engine = DetectionEngine(metrics, DetectionsConfig(enabled=True, critical_priorities=("Critical", "Emergency")))
    assert engine.is_critical("Critical") is True
    assert engine.is_critical("Emergency") is True
    assert engine.is_critical("Warning") is False


def test_latency_histogram_observed(metrics):
    engine = _engine(metrics)
    engine.ingest({"rule": "a", "priority": "Critical", "time": 940.0}, now=1000.0)  # 60s
    # The histogram _count for Critical should be 1 and _sum ~60.
    count = metrics.detection_latency_seconds.labels(priority="Critical")._sum.get()
    assert count == pytest.approx(60.0)
