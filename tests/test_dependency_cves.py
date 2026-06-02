"""Dependency-CVE collector tests. Requirements parsing, OSV summarization, and
graceful offline degradation — all with mocked network.
"""

from __future__ import annotations

import datetime as dt
from unittest import mock

import pytest

from bastion.collectors.dependency_cves import (
    DependencyCVECollector,
    build_osv_queries,
    collect_vuln_ids,
    parse_requirements,
    summarize_osv,
)
from bastion.config import CVEConfig

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 6, 2, tzinfo=UTC)


def test_parse_requirements_only_exact_pins():
    text = """
    # a comment
    requests==2.19.1
    urllib3 == 1.24.1
    flask>=2.0          # range -> ignored
    django              # unpinned -> ignored
    -r other.txt        # include -> ignored
    cryptography===2.3  # triple-equals exact pin
    pkg[extra]==1.0     # extras stripped
    """
    pins = parse_requirements(text)
    assert ("requests", "2.19.1") in pins
    assert ("urllib3", "1.24.1") in pins
    assert ("cryptography", "2.3") in pins
    assert ("pkg", "1.0") in pins
    names = [p[0] for p in pins]
    assert "flask" not in names
    assert "django" not in names


def test_build_osv_queries_shape():
    body = build_osv_queries([("requests", "2.19.1")])
    assert body == {
        "queries": [
            {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.19.1"}
        ]
    }


def _vuln(vid, severity, published):
    return {
        "id": vid,
        "published": published,
        "database_specific": {"severity": severity},
    }


def test_summarize_counts_by_severity():
    response = {
        "results": [
            {"vulns": [
                _vuln("CVE-1", "CRITICAL", "2026-01-01T00:00:00Z"),
                _vuln("CVE-2", "HIGH", "2026-05-30T00:00:00Z"),
                _vuln("CVE-3", "MODERATE", "2026-05-30T00:00:00Z"),
            ]},
            {"vulns": []},
        ]
    }
    summary = summarize_osv(response, max_critical_age_days=7, now=NOW)
    assert summary.total == 3
    assert summary.counts["CRITICAL"] == 1
    assert summary.counts["HIGH"] == 1
    assert summary.counts["MODERATE"] == 1


def test_summarize_oldest_critical_age_and_over_age():
    response = {
        "results": [
            {"vulns": [
                # 152 days old critical -> over the 7-day limit.
                _vuln("CVE-OLD", "CRITICAL", "2026-01-01T00:00:00Z"),
                # 3 days old high -> under the limit.
                _vuln("CVE-NEW", "HIGH", "2026-05-30T00:00:00Z"),
            ]}
        ]
    }
    summary = summarize_osv(response, max_critical_age_days=7, now=NOW)
    assert summary.oldest_critical_age_days == pytest.approx(152, abs=1)
    assert summary.critical_over_age == 1  # only the old one breaches


def test_summarize_dedupes_same_vuln_id():
    response = {
        "results": [
            {"vulns": [_vuln("CVE-DUP", "CRITICAL", "2026-05-30T00:00:00Z")]},
            {"vulns": [_vuln("CVE-DUP", "CRITICAL", "2026-05-30T00:00:00Z")]},
        ]
    }
    summary = summarize_osv(response, now=NOW)
    assert summary.total == 1


def test_severity_inferred_from_cvss_score():
    response = {"results": [{"vulns": [
        {"id": "X", "published": "2026-05-30T00:00:00Z",
         "severity": [{"type": "CVSS_V3", "score": "9.8"}]},
    ]}]}
    summary = summarize_osv(response, now=NOW)
    assert summary.counts["CRITICAL"] == 1


def test_collector_degrades_offline(metrics, tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.19.1\n", encoding="utf-8")
    cfg = CVEConfig(enabled=True, requirements_file=str(req), max_critical_age_days=7)
    collector = DependencyCVECollector(metrics, cfg)

    # _query_osv fails (offline); _fetch_details must never be reached.
    with mock.patch.object(collector, "_query_osv", side_effect=OSError("offline")), \
         mock.patch.object(collector, "_fetch_details", return_value={}):
        ok = collector.collect()

    assert ok is True  # collector ran; it degraded rather than crashing
    assert metrics.cve_check_success._value.get() == 0
    assert metrics.cve_vulns.labels(severity="CRITICAL")._value.get() == 0


def test_collector_reports_findings(metrics, tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.19.1\n", encoding="utf-8")
    cfg = CVEConfig(enabled=True, requirements_file=str(req), max_critical_age_days=7)
    collector = DependencyCVECollector(metrics, cfg)

    response = {"results": [{"vulns": [{"id": "CVE-OLD"}]}]}
    # The batch result carries only the ID; details supply severity + published.
    details = {"CVE-OLD": _vuln("CVE-OLD", "CRITICAL", "2026-01-01T00:00:00Z")}
    with mock.patch.object(collector, "_query_osv", return_value=response), \
         mock.patch.object(collector, "_fetch_details", return_value=details):
        ok = collector.collect()

    assert ok is True
    assert metrics.cve_check_success._value.get() == 1
    assert metrics.cve_vulns.labels(severity="CRITICAL")._value.get() == 1
    # The oldest critical is well over the 7-day limit.
    assert metrics.cve_critical_over_age._value.get() == 1


def test_collect_vuln_ids_unique_and_capped():
    response = {"results": [
        {"vulns": [{"id": "A"}, {"id": "B"}, {"id": "A"}]},
        {"vulns": [{"id": "C"}]},
    ]}
    assert collect_vuln_ids(response) == ["A", "B", "C"]
    assert collect_vuln_ids(response, limit=2) == ["A", "B"]


def test_summarize_uses_details_over_batch_severity():
    # Batch result has no severity; details say CRITICAL + old.
    response = {"results": [{"vulns": [{"id": "CVE-1"}]}]}
    details = {"CVE-1": _vuln("CVE-1", "CRITICAL", "2026-01-01T00:00:00Z")}
    summary = summarize_osv(response, vuln_details=details, max_critical_age_days=7, now=NOW)
    assert summary.counts["CRITICAL"] == 1
    assert summary.critical_over_age == 1


def test_collector_handles_missing_file(metrics):
    cfg = CVEConfig(enabled=True, requirements_file="does-not-exist.txt")
    collector = DependencyCVECollector(metrics, cfg)
    ok = collector.collect()
    assert ok is True
    assert metrics.cve_check_success._value.get() == 0
