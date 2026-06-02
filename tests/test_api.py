"""End-to-end-ish API tests via FastAPI's TestClient (in-process, no network,
no server). Proves the full loop: ingest a detection -> metric increments +
MTTD recorded -> critical detection auto-opens an incident -> /metrics serves
the exposition -> /status reflects state.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient
from prometheus_client import CollectorRegistry

from bastion.api import create_app
from bastion.config import default_config
from bastion.runtime import Bastion


@pytest.fixture
def client():
    # Disable network collectors so /metrics never touches the network in tests;
    # detections + auth (push) + incidents are all in-memory.
    cfg = default_config()
    cfg = cfg.__class__(
        tls=cfg.tls.__class__(enabled=False),
        headers=cfg.headers.__class__(enabled=False),
        cves=cfg.cves.__class__(enabled=False),
        auth=cfg.auth,
        detections=cfg.detections,
    )
    runtime = Bastion(cfg, registry=CollectorRegistry())
    return TestClient(create_app(runtime)), runtime


def test_healthz(client):
    c, _ = client
    resp = c.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_ingest_detection_increments_metric_and_records_mttd(client):
    c, runtime = client
    now = time.time()
    resp = c.post("/ingest/detection", json={
        "rule": "Terminal shell in container",
        "priority": "Critical",
        "time": now - 120,  # backdated -> real 120s latency
    })
    assert resp.status_code == 202
    body = resp.json()
    assert body["ingested"] == 1
    result = body["results"][0]
    assert result["latency_seconds"] == pytest.approx(120, abs=2)
    # A critical detection auto-opened an incident.
    assert result["incident_id"] is not None

    # MTTD recorded in the engine.
    assert runtime.detection_engine.mttd("Critical") == pytest.approx(120, abs=2)


def test_metrics_endpoint_serves_exposition(client):
    c, _ = client
    c.post("/ingest/detection", json={"rule": "Shell", "priority": "Critical", "time": time.time() - 60})
    resp = c.get("/metrics")
    assert resp.status_code == 200
    body = resp.text
    assert "bastion_security_detections_total" in body
    assert "bastion_detection_mttd_seconds" in body
    assert 'rule="Shell"' in body


def test_status_reflects_incident(client):
    c, _ = client
    c.post("/ingest/detection", json={"rule": "C2", "priority": "Critical", "time": time.time() - 30})
    status = c.get("/status").json()
    assert status["detections_total"] >= 1
    assert status["incidents_open"] >= 1
    assert status["open_incidents"][0]["mttd_seconds"] is not None


def test_non_critical_detection_does_not_open_incident(client):
    c, _ = client
    resp = c.post("/ingest/detection", json={"rule": "Noisy", "priority": "Warning", "time": time.time() - 5})
    assert resp.json()["results"][0]["incident_id"] is None


def test_ingest_detection_rejects_missing_rule(client):
    c, _ = client
    resp = c.post("/ingest/detection", json={"priority": "Critical"})
    assert resp.status_code == 422


def test_ingest_auth_push(client):
    c, _ = client
    resp = c.post("/ingest/auth", json={"failures": 3, "attempts": 40})
    assert resp.status_code == 202


def test_breach_webhook_opens_incident_bastion_shape(client):
    c, _ = client
    resp = c.post("/webhook/breach", json={"slo": "Auth Failure Ratio", "burn_rate": 14.4, "severity": "high"})
    assert resp.status_code == 202
    assert len(resp.json()["incidents_opened"]) == 1


def test_breach_webhook_alertmanager_shape(client):
    c, _ = client
    payload = {
        "alerts": [
            {"status": "firing", "labels": {"slo": "certificate_freshness", "severity": "page", "burn_rate": "6"}},
            {"status": "resolved", "labels": {"slo": "x", "severity": "ticket"}},  # ignored
        ]
    }
    resp = c.post("/webhook/breach", json=payload)
    assert resp.status_code == 202
    assert len(resp.json()["incidents_opened"]) == 1  # only the firing one
