"""Incident engine: turn security-SLO breaches and critical detections into
tracked incidents with severity, a runbook link, and MTTD/MTTR metrics.

An incident is opened when either:
  * a critical runtime-security detection arrives (e.g. Falco priority
    Critical), or
  * a security-SLO breach is reported (a burn-rate / threshold alert fires and
    Alertmanager — or the secgen demo — calls ``open_from_breach``).

For each incident we capture:
  * severity + kind, a stable id, the runbook link for its kind, and
  * the **detection latency at open time** (MTTD) when known, and on resolve,
  * **MTTR** = resolve_time - open_time.

Metrics:
  bastion_incidents_total{severity,kind}    incidents opened
  bastion_incidents_open{severity}          currently-open incidents
  bastion_incident_mttd_seconds             detection latency at open (hist)
  bastion_incident_mttr_seconds             time-to-resolve (hist)

The engine is in-memory and network-free, so the breach->incident path is fully
unit-testable offline.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from bastion.metrics import BastionMetrics

logger = logging.getLogger("bastion.incident")

# Default runbook used when a kind has no explicit mapping.
_DEFAULT_RUNBOOK = "https://runbooks.internal/security/general"


@dataclass
class Incident:
    """A single security incident."""

    id: str
    severity: str
    kind: str
    title: str
    runbook: str
    opened_at: float
    mttd_seconds: float | None = None
    resolved_at: float | None = None
    metadata: dict = field(default_factory=dict)

    @property
    def is_open(self) -> bool:
        return self.resolved_at is None

    @property
    def mttr_seconds(self) -> float | None:
        if self.resolved_at is None:
            return None
        return max(0.0, self.resolved_at - self.opened_at)


def load_runbooks(path: str | Path | None) -> dict[str, str]:
    """Load the kind -> runbook-URL mapping from a YAML file.

    Returns an empty mapping if no path is given or the file is missing, so the
    engine still runs (falling back to the default runbook).
    """
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        logger.warning("runbooks file not found: %s", path)
        return {}
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    runbooks = data.get("runbooks", data) if isinstance(data, dict) else {}
    return {str(k): str(v) for k, v in (runbooks or {}).items()}


class IncidentEngine:
    """Open/resolve security incidents and emit incident + MTTD/MTTR metrics."""

    def __init__(
        self,
        metrics: BastionMetrics,
        runbooks: dict[str, str] | None = None,
    ):
        self.metrics = metrics
        self.runbooks = runbooks or {}
        self._incidents: dict[str, Incident] = {}
        self._seq = 0

    # -- runbook lookup ------------------------------------------------------
    def runbook_for(self, kind: str) -> str:
        return self.runbooks.get(kind, self.runbooks.get("default", _DEFAULT_RUNBOOK))

    # -- opening -------------------------------------------------------------
    def _next_id(self, now: float) -> str:
        self._seq += 1
        return f"INC-{int(now)}-{self._seq:04d}"

    def open(
        self,
        severity: str,
        kind: str,
        title: str,
        mttd_seconds: float | None = None,
        now: float | None = None,
        metadata: dict | None = None,
    ) -> Incident:
        """Open an incident, record metrics, and return it."""
        now = now if now is not None else time.time()
        incident = Incident(
            id=self._next_id(now),
            severity=severity,
            kind=kind,
            title=title,
            runbook=self.runbook_for(kind),
            opened_at=now,
            mttd_seconds=mttd_seconds,
            metadata=metadata or {},
        )
        self._incidents[incident.id] = incident
        self.metrics.incidents_total.labels(severity=severity, kind=kind).inc()
        self.metrics.incidents_open.labels(severity=severity).inc()
        if mttd_seconds is not None:
            self.metrics.incident_mttd_seconds.observe(max(0.0, mttd_seconds))
        logger.info("opened incident %s [%s/%s] %s", incident.id, severity, kind, title)
        return incident

    def open_from_detection(
        self,
        rule: str,
        priority: str,
        latency_seconds: float,
        now: float | None = None,
    ) -> Incident:
        """Open an incident from a critical runtime-security detection.

        The detection's measured latency becomes the incident's MTTD.
        """
        severity = "critical" if priority in ("Critical", "Emergency") else "high"
        return self.open(
            severity=severity,
            kind="runtime_detection",
            title=f"Critical detection: {rule}",
            mttd_seconds=latency_seconds,
            now=now,
            metadata={"rule": rule, "priority": priority},
        )

    def open_from_breach(
        self,
        slo_name: str,
        burn_rate: float,
        severity: str = "high",
        now: float | None = None,
    ) -> Incident:
        """Open an incident from a security-SLO breach (burn-rate/threshold alert)."""
        return self.open(
            severity=severity,
            kind="slo_breach",
            title=f"Security SLO breach: {slo_name} (burn {burn_rate:g}x)",
            now=now,
            metadata={"slo": slo_name, "burn_rate": burn_rate},
        )

    # -- resolving -----------------------------------------------------------
    def resolve(self, incident_id: str, now: float | None = None) -> Incident:
        """Resolve an open incident and record its MTTR."""
        now = now if now is not None else time.time()
        incident = self._incidents.get(incident_id)
        if incident is None:
            raise KeyError(f"unknown incident: {incident_id}")
        if not incident.is_open:
            return incident
        incident.resolved_at = now
        self.metrics.incidents_open.labels(severity=incident.severity).dec()
        mttr = incident.mttr_seconds or 0.0
        self.metrics.incident_mttr_seconds.observe(mttr)
        logger.info("resolved incident %s after %.1fs", incident.id, mttr)
        return incident

    # -- queries -------------------------------------------------------------
    def open_incidents(self) -> list[Incident]:
        return [i for i in self._incidents.values() if i.is_open]

    def all_incidents(self) -> list[Incident]:
        return list(self._incidents.values())

    def get(self, incident_id: str) -> Incident | None:
        return self._incidents.get(incident_id)
