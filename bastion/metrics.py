"""Central Prometheus metric definitions for Bastion.

All metrics live in one registry so the exporter, the collectors, the ingest
webhook, and the incident engine share state. We create our OWN
``CollectorRegistry`` rather than using the global default so that:

  * tests can build a fresh registry per test (no cross-test bleed), and
  * the process exposes exactly Bastion's metrics, nothing implicit.

The module exposes a ``BastionMetrics`` dataclass holding every metric, built by
``build_metrics(registry)``. Pass it around explicitly instead of reaching for
module-level globals — that keeps the whole system unit-testable offline.

Metric naming follows Prometheus conventions: ``bastion_<subsystem>_<unit>``,
counters end in ``_total``, gauges name the thing they measure.
"""

from __future__ import annotations

from dataclasses import dataclass

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram


@dataclass
class BastionMetrics:
    """Every Prometheus metric Bastion exposes, bound to one registry."""

    # --- TLS certificates ---------------------------------------------------
    tls_cert_expiry_days: Gauge
    tls_cert_valid: Gauge
    tls_check_success: Gauge

    # --- HTTP security headers ----------------------------------------------
    header_present: Gauge
    header_coverage_ratio: Gauge
    header_check_success: Gauge

    # --- Dependency CVEs ----------------------------------------------------
    cve_vulns: Gauge
    cve_oldest_critical_age_days: Gauge
    cve_critical_over_age: Gauge
    cve_check_success: Gauge

    # --- Auth failures ------------------------------------------------------
    auth_failures_total: Counter
    auth_attempts_total: Counter
    auth_failure_rate: Gauge
    auth_check_success: Gauge

    # --- Runtime-security detections ----------------------------------------
    detections_total: Counter
    detection_latency_seconds: Histogram
    detection_mttd_seconds: Gauge
    detection_last_timestamp: Gauge

    # --- Incidents ----------------------------------------------------------
    incidents_total: Counter
    incidents_open: Gauge
    incident_mttr_seconds: Histogram
    incident_mttd_seconds: Histogram

    # --- Collector health ---------------------------------------------------
    collector_up: Gauge
    collector_scrape_seconds: Histogram


def build_metrics(registry: CollectorRegistry) -> BastionMetrics:
    """Construct and register every Bastion metric against ``registry``."""
    return BastionMetrics(
        # TLS ----------------------------------------------------------------
        tls_cert_expiry_days=Gauge(
            "bastion_tls_cert_expiry_days",
            "Days until the TLS certificate for an endpoint expires "
            "(negative if already expired).",
            ["endpoint", "host"],
            registry=registry,
        ),
        tls_cert_valid=Gauge(
            "bastion_tls_cert_valid",
            "1 if the certificate has more than warning_days left, else 0. "
            "Point-in-time SLI for the cert-freshness SLO.",
            ["endpoint", "host"],
            registry=registry,
        ),
        tls_check_success=Gauge(
            "bastion_tls_check_success",
            "1 if the TLS check for an endpoint completed, 0 if it errored.",
            ["endpoint", "host"],
            registry=registry,
        ),
        # Headers ------------------------------------------------------------
        header_present=Gauge(
            "bastion_security_header_present",
            "1 if a given security header is present on a target, else 0.",
            ["target", "header"],
            registry=registry,
        ),
        header_coverage_ratio=Gauge(
            "bastion_security_header_coverage_ratio",
            "Fraction of required security headers present on a target (0..1).",
            ["target"],
            registry=registry,
        ),
        header_check_success=Gauge(
            "bastion_security_header_check_success",
            "1 if the header check for a target completed, 0 if it errored.",
            ["target"],
            registry=registry,
        ),
        # CVEs ---------------------------------------------------------------
        cve_vulns=Gauge(
            "bastion_dependency_vulns",
            "Number of known vulnerabilities in scanned dependencies, by severity.",
            ["severity"],
            registry=registry,
        ),
        cve_oldest_critical_age_days=Gauge(
            "bastion_dependency_oldest_critical_age_days",
            "Age in days of the oldest unpatched critical/high CVE "
            "(0 when none). Drives the 'no critical CVE older than N days' SLO.",
            registry=registry,
        ),
        cve_critical_over_age=Gauge(
            "bastion_dependency_critical_over_age",
            "Count of critical/high CVEs older than the configured max age "
            "(the hard-threshold SLI; target is 0).",
            registry=registry,
        ),
        cve_check_success=Gauge(
            "bastion_dependency_check_success",
            "1 if the CVE scan reached OSV.dev and parsed a result, 0 otherwise.",
            registry=registry,
        ),
        # Auth ---------------------------------------------------------------
        auth_failures_total=Counter(
            "bastion_auth_failures_total",
            "Total observed authentication failures.",
            ["source"],
            registry=registry,
        ),
        auth_attempts_total=Counter(
            "bastion_auth_attempts_total",
            "Total observed authentication attempts (success + failure).",
            ["source"],
            registry=registry,
        ),
        auth_failure_rate=Gauge(
            "bastion_auth_failure_rate",
            "Auth failures per second over the configured rolling window.",
            ["source"],
            registry=registry,
        ),
        auth_check_success=Gauge(
            "bastion_auth_check_success",
            "1 if the auth-failure collector ran successfully, 0 otherwise.",
            registry=registry,
        ),
        # Detections ---------------------------------------------------------
        detections_total=Counter(
            "bastion_security_detections_total",
            "Runtime-security detections ingested, by rule and priority.",
            ["rule", "priority"],
            registry=registry,
        ),
        detection_latency_seconds=Histogram(
            "bastion_detection_latency_seconds",
            "Detection latency: time from when an event occurred to when it was "
            "detected/ingested. This is the per-event basis for MTTD.",
            ["priority"],
            buckets=(1, 5, 15, 30, 60, 120, 300, 600, 1800, 3600),
            registry=registry,
        ),
        detection_mttd_seconds=Gauge(
            "bastion_detection_mttd_seconds",
            "Mean time to detect (rolling) over recently ingested detections, "
            "by priority. Headline security MTTD metric.",
            ["priority"],
            registry=registry,
        ),
        detection_last_timestamp=Gauge(
            "bastion_detection_last_timestamp_seconds",
            "Unix timestamp of the most recent detection, by priority.",
            ["priority"],
            registry=registry,
        ),
        # Incidents ----------------------------------------------------------
        incidents_total=Counter(
            "bastion_incidents_total",
            "Security incidents opened, by severity and kind.",
            ["severity", "kind"],
            registry=registry,
        ),
        incidents_open=Gauge(
            "bastion_incidents_open",
            "Currently-open security incidents, by severity.",
            ["severity"],
            registry=registry,
        ),
        incident_mttr_seconds=Histogram(
            "bastion_incident_mttr_seconds",
            "Mean time to resolve: seconds from incident open to resolve.",
            buckets=(60, 300, 900, 1800, 3600, 7200, 14400, 43200, 86400),
            registry=registry,
        ),
        incident_mttd_seconds=Histogram(
            "bastion_incident_mttd_seconds",
            "Detection latency captured at incident-open time (seconds).",
            buckets=(1, 5, 15, 30, 60, 120, 300, 600, 1800, 3600),
            registry=registry,
        ),
        # Collector health ---------------------------------------------------
        collector_up=Gauge(
            "bastion_collector_up",
            "1 if the named collector ran without error on the last scrape, "
            "0 if it raised. The scrape never fails; this surfaces the failure.",
            ["collector"],
            registry=registry,
        ),
        collector_scrape_seconds=Histogram(
            "bastion_collector_scrape_seconds",
            "Wall-clock seconds a collector took on the last scrape.",
            ["collector"],
            buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
            registry=registry,
        ),
    )
