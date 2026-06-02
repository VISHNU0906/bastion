"""Incident engine tests: breach -> incident, critical detection -> incident,
MTTD captured at open, MTTR on resolve, runbook mapping.
"""

from __future__ import annotations

import pytest

from bastion.incident import IncidentEngine, load_runbooks


def _engine(metrics, runbooks=None):
    return IncidentEngine(metrics, runbooks=runbooks or {})


def test_open_from_breach_records_metrics(metrics):
    engine = _engine(metrics)
    inc = engine.open_from_breach("Auth Failure Ratio", burn_rate=14.4, severity="high", now=1000.0)

    assert inc.kind == "slo_breach"
    assert inc.severity == "high"
    assert "Auth Failure Ratio" in inc.title
    assert metrics.incidents_total.labels(severity="high", kind="slo_breach")._value.get() == 1
    assert metrics.incidents_open.labels(severity="high")._value.get() == 1


def test_open_from_critical_detection_captures_mttd(metrics):
    engine = _engine(metrics)
    inc = engine.open_from_detection(rule="Shell", priority="Critical", latency_seconds=240.0, now=1000.0)

    assert inc.severity == "critical"
    assert inc.kind == "runtime_detection"
    assert inc.mttd_seconds == pytest.approx(240.0)
    # The MTTD histogram observed the detection latency.
    assert metrics.incident_mttd_seconds._sum.get() == pytest.approx(240.0)


def test_resolve_records_mttr(metrics):
    engine = _engine(metrics)
    inc = engine.open(severity="high", kind="slo_breach", title="x", now=1000.0)
    resolved = engine.resolve(inc.id, now=1000.0 + 1800)

    assert resolved.mttr_seconds == pytest.approx(1800.0)
    assert metrics.incident_mttr_seconds._sum.get() == pytest.approx(1800.0)
    # open gauge decremented back to 0.
    assert metrics.incidents_open.labels(severity="high")._value.get() == 0


def test_resolve_unknown_raises(metrics):
    engine = _engine(metrics)
    with pytest.raises(KeyError):
        engine.resolve("INC-nope")


def test_resolve_is_idempotent(metrics):
    engine = _engine(metrics)
    inc = engine.open(severity="high", kind="k", title="t", now=0.0)
    engine.resolve(inc.id, now=100.0)
    # Resolving again is a no-op (doesn't double-decrement the open gauge).
    engine.resolve(inc.id, now=200.0)
    assert metrics.incidents_open.labels(severity="high")._value.get() == 0


def test_runbook_lookup_falls_back_to_default(metrics):
    engine = _engine(metrics, runbooks={"slo_breach": "http://rb/slo", "default": "http://rb/default"})
    assert engine.runbook_for("slo_breach") == "http://rb/slo"
    assert engine.runbook_for("unknown_kind") == "http://rb/default"


def test_open_incidents_query(metrics):
    engine = _engine(metrics)
    a = engine.open(severity="high", kind="k", title="a", now=0.0)
    engine.open(severity="critical", kind="k", title="b", now=0.0)
    engine.resolve(a.id, now=10.0)

    open_ids = {i.id for i in engine.open_incidents()}
    assert a.id not in open_ids
    assert len(open_ids) == 1


def test_load_runbooks_from_file(tmp_path):
    f = tmp_path / "runbooks.yaml"
    f.write_text("runbooks:\n  slo_breach: http://x/slo\n  default: http://x/default\n", encoding="utf-8")
    rb = load_runbooks(str(f))
    assert rb["slo_breach"] == "http://x/slo"


def test_load_runbooks_missing_file_is_empty():
    assert load_runbooks("does-not-exist.yaml") == {}
    assert load_runbooks(None) == {}
