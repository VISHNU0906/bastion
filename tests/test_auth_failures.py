"""Auth-failure collector tests: log-line classification, rolling rate, pushed
counters. No filesystem dependency beyond tmp_path.
"""

from __future__ import annotations

import pytest

from bastion.collectors.auth_failures import (
    AuthFailureCollector,
    _RollingRate,
    classify_auth_line,
    count_auth_lines,
)
from bastion.config import AuthConfig


def test_classify_failure_lines():
    assert classify_auth_line("Failed password for invalid user admin from 1.2.3.4") == "failure"
    assert classify_auth_line("pam_unix(sshd:auth): authentication failure; rhost=x") == "failure"
    assert classify_auth_line("Invalid user oracle from 5.6.7.8") == "failure"


def test_classify_success_lines():
    assert classify_auth_line("Accepted publickey for deploy from 10.0.0.5") == "success"
    assert classify_auth_line("Accepted password for vishnu from 10.0.0.9") == "success"


def test_classify_unrelated_line_is_none():
    assert classify_auth_line("systemd: Started Daily apt upgrade") is None


def test_count_auth_lines():
    text = "\n".join([
        "Accepted password for vishnu from 10.0.0.9",
        "Failed password for invalid user admin from 1.2.3.4",
        "Failed password for invalid user root from 1.2.3.4",
        "unrelated daemon noise",
    ])
    failures, successes = count_auth_lines(text)
    assert failures == 2
    assert successes == 1


def test_rolling_rate_evicts_old_events():
    rate = _RollingRate(window_seconds=10)
    rate.add(5, now=100.0)
    assert rate.rate(now=100.0) == pytest.approx(0.5)  # 5 events / 10s
    # 20s later, all evicted.
    assert rate.rate(now=120.0) == pytest.approx(0.0)


def test_collector_parses_log_file(metrics, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Failed password for invalid user admin from 1.2.3.4\n"
        "Accepted password for vishnu from 10.0.0.9\n"
        "Failed password for invalid user root from 1.2.3.4\n",
        encoding="utf-8",
    )
    cfg = AuthConfig(enabled=True, log_file=str(log), window_seconds=300)
    collector = AuthFailureCollector(metrics, cfg)
    ok = collector.collect()

    assert ok is True
    assert metrics.auth_failures_total.labels(source="log")._value.get() == 2
    assert metrics.auth_attempts_total.labels(source="log")._value.get() == 3
    assert metrics.auth_check_success._value.get() == 1


def test_collector_is_idempotent_across_scrapes(metrics, tmp_path):
    # Re-scraping a non-growing log must NOT double-count.
    log = tmp_path / "auth.log"
    log.write_text("Failed password for invalid user admin from 1.2.3.4\n", encoding="utf-8")
    cfg = AuthConfig(enabled=True, log_file=str(log), window_seconds=300)
    collector = AuthFailureCollector(metrics, cfg)

    collector.collect()
    collector.collect()
    collector.collect()

    assert metrics.auth_failures_total.labels(source="log")._value.get() == 1


def test_collector_counts_only_appended_lines(metrics, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("Failed password for invalid user a from 1.2.3.4\n", encoding="utf-8")
    cfg = AuthConfig(enabled=True, log_file=str(log), window_seconds=300)
    collector = AuthFailureCollector(metrics, cfg)
    collector.collect()

    # Append a new failure line; only the new one should be counted.
    with log.open("a", encoding="utf-8") as fh:
        fh.write("Failed password for invalid user b from 1.2.3.4\n")
    collector.collect()

    assert metrics.auth_failures_total.labels(source="log")._value.get() == 2


def test_pushed_counter(metrics):
    cfg = AuthConfig(enabled=True, log_file=None, window_seconds=300)
    collector = AuthFailureCollector(metrics, cfg)
    collector.ingest_pushed(failures=3, attempts=50, source="pushed")

    assert metrics.auth_failures_total.labels(source="pushed")._value.get() == 3
    assert metrics.auth_attempts_total.labels(source="pushed")._value.get() == 50


def test_pushed_counter_rejects_bad_input(metrics):
    cfg = AuthConfig(enabled=True, log_file=None)
    collector = AuthFailureCollector(metrics, cfg)
    with pytest.raises(ValueError):
        collector.ingest_pushed(failures=10, attempts=5)  # more failures than attempts


def test_missing_log_marks_unhealthy(metrics):
    cfg = AuthConfig(enabled=True, log_file="nope.log")
    collector = AuthFailureCollector(metrics, cfg)
    ok = collector.collect()
    assert ok is True
    assert metrics.auth_check_success._value.get() == 0
