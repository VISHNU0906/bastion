"""Dependency-CVE collector (OSV.dev).

Parses a pip requirements file, batch-queries the OSV.dev API for known
vulnerabilities affecting each pinned package@version, and records counts by
severity plus the age of the oldest unpatched critical/high vuln. That age
drives the hard-threshold SLO "no critical CVE older than N days".

Pure, offline-testable pieces (no network):
  * ``parse_requirements``   text -> [(package, version), ...]
  * ``build_osv_queries``    pins -> OSV batch request body
  * ``summarize_osv``        OSV response -> CveSummary (counts + oldest age)

The network call (``_query_osv``) is the only impure part and is wrapped so an
offline / rate-limited / failing OSV degrades to ``check_success = 0`` with
zeroed counts — the scrape still succeeds.

Metrics:
  bastion_dependency_vulns{severity}                 count by severity bucket
  bastion_dependency_oldest_critical_age_days        age of oldest crit/high
  bastion_dependency_critical_over_age               # crit/high older than max
  bastion_dependency_check_success                   1 if OSV reached, else 0
"""

from __future__ import annotations

import datetime as dt
import logging
import re
from dataclasses import dataclass, field

import requests

from bastion.collectors.base import Collector
from bastion.config import CVEConfig
from bastion.metrics import BastionMetrics

logger = logging.getLogger("bastion.collector.cves")

# A strict pinned requirement: ``package==version`` with optional extras/markers
# stripped. We only audit exact pins (== / ===) because OSV needs a concrete
# version to answer "is THIS version vulnerable".
_PIN_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s;#]+)"
)

# OSV severity buckets we roll vulnerabilities into. CRITICAL/HIGH are what the
# "no critical CVE older than N days" SLO cares about.
_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN")
_CRITICAL_SEVERITIES = ("CRITICAL", "HIGH")


@dataclass
class CveSummary:
    """Aggregated CVE findings from an OSV batch response."""

    counts: dict[str, int] = field(default_factory=lambda: {s: 0 for s in _SEVERITY_ORDER})
    oldest_critical_age_days: float = 0.0
    critical_over_age: int = 0
    total: int = 0


def parse_requirements(text: str) -> list[tuple[str, str]]:
    """Extract ``(package, version)`` pairs from a requirements file body.

    Only exact pins (``==`` / ``===``) are returned; ranges, unpinned packages,
    comments, ``-r`` includes, and editable installs are ignored.
    """
    pins: list[tuple[str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue
        match = _PIN_RE.match(stripped)
        if match:
            pins.append((match.group(1), match.group(2)))
    return pins


def build_osv_queries(pins: list[tuple[str, str]]) -> dict:
    """Build the OSV ``querybatch`` request body for a list of pins."""
    return {
        "queries": [
            {
                "package": {"name": name, "ecosystem": "PyPI"},
                "version": version,
            }
            for name, version in pins
        ]
    }


def _published_age_days(vuln: dict, now: dt.datetime) -> float:
    """Age in days since a vuln's ``published`` date (0 if missing/unparseable)."""
    published = vuln.get("published") or vuln.get("modified")
    if not published:
        return 0.0
    try:
        # OSV timestamps are RFC3339 / ISO-8601 with a trailing Z.
        ts = dt.datetime.fromisoformat(published.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return 0.0
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.timezone.utc)
    return max(0.0, (now - ts).total_seconds() / 86400.0)


def _severity_of(vuln: dict) -> str:
    """Best-effort severity bucket for an OSV vuln record.

    OSV ``severity`` is a CVSS vector list, not a word. We map the database_specific
    severity if present, else infer from the CVSS score, else UNKNOWN. This keeps
    the collector useful across the heterogeneous OSV ecosystem.
    """
    db = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(db, str) and db.upper() in _SEVERITY_ORDER:
        return db.upper()
    # Try a numeric CVSS score from the severity vectors.
    for sev in vuln.get("severity", []) or []:
        score = sev.get("score")
        # Some feeds give a bare number; CVSS vectors we can't cheaply parse, so
        # only use plainly-numeric scores.
        try:
            value = float(score)
        except (TypeError, ValueError):
            continue
        if value >= 9.0:
            return "CRITICAL"
        if value >= 7.0:
            return "HIGH"
        if value >= 4.0:
            return "MODERATE"
        return "LOW"
    return "UNKNOWN"


def collect_vuln_ids(response: dict, limit: int | None = None) -> list[str]:
    """Unique vuln IDs from an OSV batch response, in stable order (capped)."""
    ids: list[str] = []
    seen: set[str] = set()
    for result in response.get("results", []) or []:
        for vuln in result.get("vulns", []) or []:
            vid = vuln.get("id")
            if vid and vid not in seen:
                seen.add(vid)
                ids.append(vid)
                if limit is not None and len(ids) >= limit:
                    return ids
    return ids


def summarize_osv(
    response: dict,
    vuln_details: dict[str, dict] | None = None,
    max_critical_age_days: int = 7,
    now: dt.datetime | None = None,
) -> CveSummary:
    """Roll an OSV batch response into a :class:`CveSummary`.

    Args:
        response: The OSV ``querybatch`` response (``results: [{vulns: [...]}]``).
        vuln_details: Optional map of vuln id -> full vuln record (with
            ``published`` + ``severity``). The batch endpoint returns only ids
            and modified times; details enrich severity/age. When absent we use
            whatever the batch result carries.
        max_critical_age_days: Threshold for the ``critical_over_age`` count.
        now: Reference time (defaults to UTC now) — injectable for tests.

    Returns:
        A populated CveSummary.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    vuln_details = vuln_details or {}
    summary = CveSummary()
    seen: set[str] = set()

    for result in response.get("results", []) or []:
        for vuln in result.get("vulns", []) or []:
            vid = vuln.get("id", "")
            if vid in seen:
                continue
            seen.add(vid)
            detail = vuln_details.get(vid, vuln)
            severity = _severity_of(detail)
            summary.counts[severity] = summary.counts.get(severity, 0) + 1
            summary.total += 1
            if severity in _CRITICAL_SEVERITIES:
                age = _published_age_days(detail, now)
                summary.oldest_critical_age_days = max(summary.oldest_critical_age_days, age)
                if age > max_critical_age_days:
                    summary.critical_over_age += 1
    return summary


class DependencyCVECollector(Collector):
    """Audit a requirements file against OSV.dev and emit vuln metrics."""

    def __init__(self, metrics: BastionMetrics, config: CVEConfig):
        super().__init__(metrics)
        self.config = config

    @property
    def name(self) -> str:
        return "dependency_cves"

    def _query_osv(self, pins: list[tuple[str, str]]) -> dict:
        """POST the batch query to OSV.dev. Raises on any network/HTTP error."""
        body = build_osv_queries(pins)
        resp = requests.post(self.config.osv_url, json=body, timeout=self.config.timeout_seconds)
        resp.raise_for_status()
        return resp.json()

    def _fetch_details(self, response: dict) -> dict[str, dict]:
        """Fetch per-vuln details so severity + published date are populated.

        The OSV batch endpoint returns only vuln IDs and modified times; the
        single-vuln endpoint carries ``severity`` and ``published``. We fetch up
        to ``max_detail_lookups`` of them. Any individual failure is skipped (the
        summary falls back to whatever the batch result carried), so enrichment
        never breaks the collector.
        """
        ids = collect_vuln_ids(response, limit=self.config.max_detail_lookups)
        details: dict[str, dict] = {}
        for vid in ids:
            try:
                url = self.config.osv_detail_url.format(id=vid)
                resp = requests.get(url, timeout=self.config.timeout_seconds)
                resp.raise_for_status()
                details[vid] = resp.json()
            except Exception:  # noqa: BLE001 — skip one bad detail, keep going
                logger.debug("CVE collector: detail fetch failed for %s", vid)
        return details

    def _zero_metrics(self) -> None:
        for severity in _SEVERITY_ORDER:
            self.metrics.cve_vulns.labels(severity=severity).set(0)
        self.metrics.cve_oldest_critical_age_days.set(0)
        self.metrics.cve_critical_over_age.set(0)

    def _collect(self) -> None:
        if not self.config.enabled:
            return
        if not self.config.requirements_file:
            # Nothing to scan — report healthy with zeroed counts.
            self._zero_metrics()
            self.metrics.cve_check_success.set(1)
            return

        from pathlib import Path

        try:
            text = Path(self.config.requirements_file).read_text(encoding="utf-8")
        except OSError:
            logger.warning("CVE collector: requirements file not readable: %s",
                           self.config.requirements_file)
            self._zero_metrics()
            self.metrics.cve_check_success.set(0)
            return

        pins = parse_requirements(text)
        if not pins:
            self._zero_metrics()
            self.metrics.cve_check_success.set(1)
            return

        try:
            response = self._query_osv(pins)
        except Exception:  # noqa: BLE001 — offline / rate-limited: degrade, don't crash
            logger.warning("CVE collector: OSV.dev query failed; reporting unhealthy")
            self._zero_metrics()
            self.metrics.cve_check_success.set(0)
            return

        # Enrich with per-vuln details (severity + published date). Best-effort:
        # if detail fetching fails we still summarize from the batch result.
        details = self._fetch_details(response)
        summary = summarize_osv(
            response,
            vuln_details=details,
            max_critical_age_days=self.config.max_critical_age_days,
        )
        for severity in _SEVERITY_ORDER:
            self.metrics.cve_vulns.labels(severity=severity).set(summary.counts.get(severity, 0))
        self.metrics.cve_oldest_critical_age_days.set(summary.oldest_critical_age_days)
        self.metrics.cve_critical_over_age.set(summary.critical_over_age)
        self.metrics.cve_check_success.set(1)
