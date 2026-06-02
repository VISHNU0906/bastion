"""Bastion runtime: wires config -> metrics -> collectors -> engines together.

A single :class:`Bastion` object owns the Prometheus registry, the metric set,
every enabled collector, the detection engine, and the incident engine. Both the
metrics scrape path (``render_metrics``) and the FastAPI app share this one
object, so a detection pushed to the API and a metric scraped from /metrics see
the same state.

Keeping assembly here (not in the FastAPI module or the exporter script) means
tests can build a fully-wired Bastion in two lines with a fresh registry and no
network.
"""

from __future__ import annotations

import logging

from prometheus_client import CollectorRegistry, generate_latest

from bastion.collectors.auth_failures import AuthFailureCollector
from bastion.collectors.base import Collector
from bastion.collectors.dependency_cves import DependencyCVECollector
from bastion.collectors.detections import DetectionEngine, DetectionsCollector
from bastion.collectors.http_headers import HeadersCollector
from bastion.collectors.tls_cert import TLSCertCollector
from bastion.config import BastionConfig, default_config
from bastion.incident import IncidentEngine, load_runbooks
from bastion.metrics import BastionMetrics, build_metrics

logger = logging.getLogger("bastion.runtime")


class Bastion:
    """The fully-wired Bastion runtime."""

    def __init__(self, config: BastionConfig | None = None, registry: CollectorRegistry | None = None):
        self.config = config or default_config()
        self.registry = registry or CollectorRegistry()
        self.metrics: BastionMetrics = build_metrics(self.registry)

        # Detection engine is shared between the ingest API and the scrape-time
        # collector so MTTD state is single-sourced.
        self.detection_engine = DetectionEngine(self.metrics, self.config.detections)

        # Incident engine, seeded with runbook links.
        self.incident_engine = IncidentEngine(
            self.metrics, runbooks=load_runbooks(self.config.runbooks_file)
        )

        # Build the enabled collectors. Detections always present (its collector
        # just refreshes MTTD gauges; ingest happens via the API).
        self.collectors: list[Collector] = []
        if self.config.tls.enabled:
            self.collectors.append(TLSCertCollector(self.metrics, self.config.tls))
        if self.config.headers.enabled:
            self.collectors.append(HeadersCollector(self.metrics, self.config.headers))
        if self.config.cves.enabled:
            self.collectors.append(DependencyCVECollector(self.metrics, self.config.cves))
        if self.config.auth.enabled:
            self.auth_collector = AuthFailureCollector(self.metrics, self.config.auth)
            self.collectors.append(self.auth_collector)
        else:
            self.auth_collector = None
        self.collectors.append(DetectionsCollector(self.metrics, self.detection_engine))

    # -- scrape --------------------------------------------------------------
    def run_collectors(self) -> dict[str, bool]:
        """Run every collector once. Returns {collector_name: ok}.

        Never raises — each collector isolates its own failures and reports
        health via ``bastion_collector_up``.
        """
        results: dict[str, bool] = {}
        for collector in self.collectors:
            results[collector.name] = collector.collect()
        return results

    def render_metrics(self) -> bytes:
        """Run collectors and render the Prometheus exposition text."""
        self.run_collectors()
        return generate_latest(self.registry)

    # -- ingest helpers ------------------------------------------------------
    def ingest_detection(self, payload: dict, now: float | None = None):
        """Ingest a Falco-style detection; auto-open an incident if critical.

        Returns (detection, incident_or_None).
        """
        detection = self.detection_engine.ingest(payload, now=now)
        incident = None
        if self.detection_engine.is_critical(detection.priority):
            incident = self.incident_engine.open_from_detection(
                rule=detection.rule,
                priority=detection.priority,
                latency_seconds=detection.latency_seconds,
                now=now,
            )
        return detection, incident

    def ingest_auth(self, failures: int, attempts: int, source: str = "pushed") -> None:
        """Apply a pushed batch of auth events (no-op if auth disabled)."""
        if self.auth_collector is None:
            raise RuntimeError("auth collector is disabled")
        self.auth_collector.ingest_pushed(failures, attempts, source=source)

    def report_breach(self, slo_name: str, burn_rate: float, severity: str = "high"):
        """Open an incident from a security-SLO breach (called by Alertmanager
        webhook or the demo generator)."""
        return self.incident_engine.open_from_breach(slo_name, burn_rate, severity=severity)

    # -- status --------------------------------------------------------------
    def status(self) -> dict:
        """A compact JSON-able status snapshot for the /status endpoint."""
        open_incidents = self.incident_engine.open_incidents()
        return {
            "version": _version(),
            "collectors": [c.name for c in self.collectors],
            "detections_total": self.detection_engine.total,
            "incidents_open": len(open_incidents),
            "incidents_total": len(self.incident_engine.all_incidents()),
            "open_incidents": [
                {
                    "id": i.id,
                    "severity": i.severity,
                    "kind": i.kind,
                    "title": i.title,
                    "runbook": i.runbook,
                    "mttd_seconds": i.mttd_seconds,
                }
                for i in open_incidents
            ],
        }


def _version() -> str:
    from bastion import __version__

    return __version__
