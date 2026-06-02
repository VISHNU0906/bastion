"""TLS expiry logic tests. Pure math on synthetic notAfter datetimes — no
sockets. The collector's network fetch is exercised separately via a mock.
"""

from __future__ import annotations

import datetime as dt
from unittest import mock

import pytest

from bastion.collectors.tls_cert import (
    TLSCertCollector,
    days_until_expiry,
    is_valid,
)
from bastion.config import TLSConfig, TLSTarget

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 6, 2, 12, 0, 0, tzinfo=UTC)


def test_days_until_expiry_future():
    not_after = NOW + dt.timedelta(days=30)
    assert days_until_expiry(not_after, NOW) == pytest.approx(30.0)


def test_days_until_expiry_expired_is_negative():
    not_after = NOW - dt.timedelta(days=3)
    assert days_until_expiry(not_after, NOW) == pytest.approx(-3.0)


def test_days_until_expiry_handles_naive_datetime():
    # A naive notAfter is treated as UTC, not crashed on.
    naive = (NOW + dt.timedelta(days=10)).replace(tzinfo=None)
    assert days_until_expiry(naive, NOW) == pytest.approx(10.0)


def test_is_valid_boundary():
    # Strictly MORE than warning_days counts as valid.
    just_over = NOW + dt.timedelta(days=14, seconds=1)
    just_under = NOW + dt.timedelta(days=14) - dt.timedelta(seconds=1)
    assert is_valid(just_over, 14, NOW) is True
    assert is_valid(just_under, 14, NOW) is False


def test_collector_sets_metrics_on_success(metrics):
    cfg = TLSConfig(enabled=True, warning_days=14, targets=(TLSTarget("api", "api.example.com", 443),))
    collector = TLSCertCollector(metrics, cfg)
    future = dt.datetime.now(UTC) + dt.timedelta(days=40)

    with mock.patch("bastion.collectors.tls_cert.fetch_not_after", return_value=future):
        ok = collector.collect()

    assert ok is True
    labels = {"endpoint": "api", "host": "api.example.com"}
    days = metrics.tls_cert_expiry_days.labels(**labels)._value.get()
    assert days == pytest.approx(40, abs=1)
    assert metrics.tls_cert_valid.labels(**labels)._value.get() == 1
    assert metrics.tls_check_success.labels(**labels)._value.get() == 1


def test_collector_marks_invalid_when_close_to_expiry(metrics):
    cfg = TLSConfig(enabled=True, warning_days=14, targets=(TLSTarget("soon", "soon.example.com", 443),))
    collector = TLSCertCollector(metrics, cfg)
    soon = dt.datetime.now(UTC) + dt.timedelta(days=5)

    with mock.patch("bastion.collectors.tls_cert.fetch_not_after", return_value=soon):
        collector.collect()

    labels = {"endpoint": "soon", "host": "soon.example.com"}
    assert metrics.tls_cert_valid.labels(**labels)._value.get() == 0


def test_collector_degrades_on_network_error(metrics):
    # A failing endpoint sets check_success=0 but does NOT raise into the scrape.
    cfg = TLSConfig(enabled=True, targets=(TLSTarget("down", "down.example.com", 443),))
    collector = TLSCertCollector(metrics, cfg)

    with mock.patch("bastion.collectors.tls_cert.fetch_not_after", side_effect=OSError("refused")):
        ok = collector.collect()

    # The collector itself ran cleanly (it isolated the per-target failure).
    assert ok is True
    labels = {"endpoint": "down", "host": "down.example.com"}
    assert metrics.tls_check_success.labels(**labels)._value.get() == 0


def test_one_bad_target_does_not_blank_the_others(metrics):
    cfg = TLSConfig(
        enabled=True,
        warning_days=14,
        targets=(
            TLSTarget("good", "good.example.com", 443),
            TLSTarget("bad", "bad.example.com", 443),
        ),
    )
    collector = TLSCertCollector(metrics, cfg)
    future = dt.datetime.now(UTC) + dt.timedelta(days=60)

    def fake_fetch(host, port, timeout):
        if host == "bad.example.com":
            raise OSError("refused")
        return future

    with mock.patch("bastion.collectors.tls_cert.fetch_not_after", side_effect=fake_fetch):
        collector.collect()

    assert metrics.tls_check_success.labels(endpoint="good", host="good.example.com")._value.get() == 1
    assert metrics.tls_check_success.labels(endpoint="bad", host="bad.example.com")._value.get() == 0
