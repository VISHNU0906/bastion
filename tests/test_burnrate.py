"""Burn-rate math tests, asserted against the Google SRE Workbook's known
values. These are the numbers a reviewer can check by hand, so they are the
strongest evidence the math is genuine, not approximated.
"""

from __future__ import annotations

import math

import pytest

from bastion.slo.burnrate import (
    HOURS_30D,
    budget_consumed,
    burn_rate_alerts,
    burn_threshold,
    error_budget,
    format_duration_minutes,
    parse_duration_minutes,
    short_window_for,
)


def test_error_budget_known_values():
    assert error_budget(99.9) == pytest.approx(0.001)
    assert error_budget(99) == pytest.approx(0.01)
    assert error_budget(95) == pytest.approx(0.05)


@pytest.mark.parametrize("objective", [0, 100, -1, 100.1, 1000])
def test_error_budget_rejects_out_of_range(objective):
    with pytest.raises(ValueError):
        error_budget(objective)


def test_burn_threshold_canonical_999():
    # The textbook thresholds for a 99.9% objective (budget 0.001).
    assert burn_threshold(99.9, 14.4) == pytest.approx(0.0144)
    assert burn_threshold(99.9, 6) == pytest.approx(0.006)
    assert burn_threshold(99.9, 3) == pytest.approx(0.003)
    assert burn_threshold(99.9, 1) == pytest.approx(0.001)


def test_burn_threshold_is_window_independent():
    # Threshold depends only on objective + burn rate, never on a window.
    assert burn_threshold(99, 14.4) == pytest.approx(0.144)
    assert burn_threshold(99, 1) == pytest.approx(0.01)


def test_budget_consumed_canonical_2_5_10_10():
    # Over a 30d window the four canonical alerts consume 2%, 5%, 10%, 10%.
    assert budget_consumed(14.4, "1h") == pytest.approx(0.02, abs=1e-9)
    assert budget_consumed(6, "6h") == pytest.approx(0.05, abs=1e-9)
    assert budget_consumed(3, "24h") == pytest.approx(0.10, abs=1e-9)
    assert budget_consumed(1, "3d") == pytest.approx(0.10, abs=1e-9)


def test_parse_duration_minutes():
    assert parse_duration_minutes("5m") == 5
    assert parse_duration_minutes("1h") == 60
    assert parse_duration_minutes("3d") == 4320


@pytest.mark.parametrize("bad", ["", "h", "10x", "-5m", "0h", "1.5h"])
def test_parse_duration_rejects_bad(bad):
    with pytest.raises(ValueError):
        parse_duration_minutes(bad)


def test_format_duration_picks_largest_clean_unit():
    assert format_duration_minutes(360) == "6h"
    assert format_duration_minutes(30) == "30m"
    assert format_duration_minutes(4320) == "3d"
    assert format_duration_minutes(90) == "90m"  # not a clean hour


def test_short_window_is_one_twelfth():
    assert short_window_for("1h") == "5m"
    assert short_window_for("6h") == "30m"
    assert short_window_for("24h") == "2h"
    assert short_window_for("3d") == "6h"


def test_burn_rate_alerts_full_canonical_set():
    alerts = burn_rate_alerts(99.9)
    assert len(alerts) == 4

    by_burn = {a.burn_rate: a for a in alerts}
    assert set(by_burn) == {14.4, 6.0, 3.0, 1.0}

    fast = by_burn[14.4]
    assert fast.severity == "page"
    assert fast.long_window == "1h"
    assert fast.short_window == "5m"
    assert fast.threshold == pytest.approx(0.0144)
    assert fast.budget_consumed == pytest.approx(0.02, abs=1e-9)

    slow = by_burn[1.0]
    assert slow.severity == "ticket"
    assert slow.long_window == "3d"
    assert slow.short_window == "6h"
    assert slow.threshold == pytest.approx(0.001)


def test_two_pages_two_tickets():
    alerts = burn_rate_alerts(99)
    severities = [a.severity for a in alerts]
    assert severities.count("page") == 2
    assert severities.count("ticket") == 2


def test_hours_30d_constant():
    assert HOURS_30D == 720
    # budget_consumed at objective-independent burn 1 over the whole window = 1.
    assert budget_consumed(1, "30d") == pytest.approx(1.0)


def test_threshold_scales_linearly_with_objective():
    # A 99% objective has 10x the budget of 99.9%, so 10x the thresholds.
    for burn in (14.4, 6, 3, 1):
        assert burn_threshold(99, burn) == pytest.approx(10 * burn_threshold(99.9, burn))


def test_no_nan_or_inf_anywhere():
    for objective in (99.9, 99, 95, 90):
        for a in burn_rate_alerts(objective):
            assert math.isfinite(a.threshold)
            assert math.isfinite(a.budget_consumed)
