"""Security-header scoring tests — pure dict-in, score-out. No network."""

from __future__ import annotations

from unittest import mock

import pytest

from bastion.collectors.http_headers import (
    HeadersCollector,
    coverage_ratio,
    score_headers,
)
from bastion.config import HeadersConfig, HeaderTarget

REQUIRED = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
)


def test_score_all_present():
    headers = {h: "x" for h in REQUIRED}
    scored = score_headers(headers, REQUIRED)
    assert all(scored.values())
    assert coverage_ratio(scored) == pytest.approx(1.0)


def test_score_none_present():
    scored = score_headers({"Server": "nginx"}, REQUIRED)
    assert not any(scored.values())
    assert coverage_ratio(scored) == pytest.approx(0.0)


def test_score_is_case_insensitive():
    # HTTP header names are case-insensitive; lower-cased input must still match.
    headers = {
        "strict-transport-security": "max-age=63072000",
        "content-security-policy": "default-src 'self'",
    }
    scored = score_headers(headers, REQUIRED)
    assert scored["Strict-Transport-Security"] is True
    assert scored["Content-Security-Policy"] is True
    assert scored["X-Frame-Options"] is False
    assert coverage_ratio(scored) == pytest.approx(0.5)


def test_coverage_ratio_partial():
    scored = {"A": True, "B": False, "C": True, "D": False}
    assert coverage_ratio(scored) == pytest.approx(0.5)


def test_coverage_ratio_empty():
    assert coverage_ratio({}) == 0.0


def test_collector_sets_present_and_coverage(metrics):
    cfg = HeadersConfig(
        enabled=True,
        required_headers=REQUIRED,
        targets=(HeaderTarget("site", "https://site.example"),),
    )
    collector = HeadersCollector(metrics, cfg)

    fake_resp = mock.Mock()
    fake_resp.headers = {
        "Strict-Transport-Security": "max-age=1",
        "X-Content-Type-Options": "nosniff",
    }
    with mock.patch("bastion.collectors.http_headers.requests.get", return_value=fake_resp):
        ok = collector.collect()

    assert ok is True
    assert metrics.header_present.labels(target="site", header="Strict-Transport-Security")._value.get() == 1
    assert metrics.header_present.labels(target="site", header="Content-Security-Policy")._value.get() == 0
    assert metrics.header_coverage_ratio.labels(target="site")._value.get() == pytest.approx(0.5)
    assert metrics.header_check_success.labels(target="site")._value.get() == 1


def test_collector_degrades_on_request_error(metrics):
    cfg = HeadersConfig(enabled=True, required_headers=REQUIRED,
                        targets=(HeaderTarget("down", "https://down.example"),))
    collector = HeadersCollector(metrics, cfg)

    with mock.patch("bastion.collectors.http_headers.requests.get", side_effect=OSError("boom")):
        ok = collector.collect()

    assert ok is True  # per-target failure isolated
    assert metrics.header_check_success.labels(target="down")._value.get() == 0
