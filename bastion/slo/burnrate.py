"""Multi-window, multi-burn-rate math from the Google SRE Workbook.

Reference: "Site Reliability Workbook", Chapter 5, "Alerting on SLOs",
the section "Multiwindow, Multi-Burn-Rate Alerts".

This module is intentionally self-contained (no Bastion imports) and is the
same proven, unit-tested burn-rate math used by the Vigil SLO tool. It is
vendored here verbatim so Bastion ships as one repo; the canonical test values
(14.4/6/3/1 -> 0.0144/0.006/0.003/0.001 at 99.9%) are asserted in the tests.

Two distinct quantities that are easy to conflate -- keep them separate:

1. Alert THRESHOLD (the number that goes into the PromQL expression):

       threshold = burn_rate * (1 - objective)

   This is WINDOW-INDEPENDENT. A burn rate of 1.0 means the observed
   error rate exactly equals the error budget. The window only decides
   which ``rate(...)`` ranges the recording rules measure over; it never
   appears in the threshold.

2. Budget CONSUMED (the design rationale, used to pick the burn factors):

       budget_consumed = burn_rate * long_window_hours / slo_window_hours

   For a 30d (720h) SLO window the four canonical alerts consume
   2%, 5%, 10%, 10% of the budget over their long windows.

Each alert is a PAIR of windows ANDed together at the same threshold:

       ratio_over_long_window  > threshold
   AND ratio_over_short_window > threshold

The long window provides confidence the budget is really burning; the
short window makes the alert reset quickly once the burn stops.
"""

from __future__ import annotations

from dataclasses import dataclass

# Hours in a standard 30-day SLO window. Used only for the budget-consumed
# sanity figure (the rationale), never for the threshold.
HOURS_30D = 30 * 24  # 720

# In the SRE Workbook the short window of each pair is always 1/12th of the
# long window. We derive it rather than hardcoding four magic numbers.
SHORT_WINDOW_DIVISOR = 12


@dataclass(frozen=True)
class BurnRateAlert:
    """One multi-window, multi-burn-rate alert.

    Attributes:
        severity: "page" (fast, urgent) or "ticket" (slow, deferrable).
        burn_rate: The burn-rate multiplier (14.4, 6, 3, 1).
        long_window: Prometheus duration string for the long window, e.g. "1h".
        short_window: Prometheus duration string for the short window, e.g. "5m".
        threshold: Error-rate threshold for this alert = burn_rate * (1 - objective).
        budget_consumed: Fraction of the total error budget burned over the long
            window at exactly this burn rate (design rationale, not the threshold).
    """

    severity: str
    burn_rate: float
    long_window: str
    short_window: str
    threshold: float
    budget_consumed: float


# The canonical four-alert / two-window configuration from the SRE Workbook.
# Each entry: (severity, burn_rate, long_window). The short window is derived.
_CANONICAL = (
    ("page", 14.4, "1h"),
    ("page", 6.0, "6h"),
    ("ticket", 3.0, "24h"),
    ("ticket", 1.0, "3d"),
)

# Mapping of supported Prometheus duration units to minutes, for deriving the
# short window (long_window / 12) and the budget-consumed figure.
_UNIT_MINUTES = {
    "m": 1,
    "h": 60,
    "d": 60 * 24,
}


def parse_duration_minutes(duration: str) -> int:
    """Parse a simple Prometheus duration like '1h', '5m', '3d' into minutes.

    Only single-unit durations using m/h/d are supported, which is all the
    SRE Workbook windows require.

    Raises:
        ValueError: if the duration is malformed or uses an unsupported unit.
    """
    duration = duration.strip()
    if len(duration) < 2:
        raise ValueError(f"invalid duration: {duration!r}")
    unit = duration[-1]
    if unit not in _UNIT_MINUTES:
        raise ValueError(
            f"unsupported duration unit {unit!r} in {duration!r}; use m, h, or d"
        )
    try:
        value = int(duration[:-1])
    except ValueError as exc:
        raise ValueError(f"invalid duration value in {duration!r}") from exc
    if value <= 0:
        raise ValueError(f"duration must be positive: {duration!r}")
    return value * _UNIT_MINUTES[unit]


def format_duration_minutes(minutes: int) -> str:
    """Render a whole number of minutes back into a compact Prometheus duration.

    Picks the largest clean unit: 360 -> '6h', 30 -> '30m', 4320 -> '3d'.
    """
    if minutes <= 0:
        raise ValueError(f"minutes must be positive: {minutes}")
    if minutes % _UNIT_MINUTES["d"] == 0:
        return f"{minutes // _UNIT_MINUTES['d']}d"
    if minutes % _UNIT_MINUTES["h"] == 0:
        return f"{minutes // _UNIT_MINUTES['h']}h"
    return f"{minutes}m"


def error_budget(objective: float) -> float:
    """Return the error budget (allowed failure fraction) for an objective.

    The objective is a percentage like 99.9. The budget is 1 - objective/100,
    so 99.9 -> 0.001 and 99 -> 0.01.

    Raises:
        ValueError: if the objective is not in the open interval (0, 100).
    """
    if not 0 < objective < 100:
        raise ValueError(f"objective must be between 0 and 100 (exclusive), got {objective}")
    return 1.0 - objective / 100.0


def burn_threshold(objective: float, burn_rate: float) -> float:
    """Error-rate threshold for a given objective and burn rate.

        threshold = burn_rate * (1 - objective)

    Window-independent. For objective=99.9 (budget 0.001):
        burn 14.4 -> 0.0144,  6 -> 0.006,  3 -> 0.003,  1 -> 0.001.
    """
    if burn_rate <= 0:
        raise ValueError(f"burn_rate must be positive, got {burn_rate}")
    return burn_rate * error_budget(objective)


def budget_consumed(
    burn_rate: float, long_window: str, slo_window_hours: float = HOURS_30D
) -> float:
    """Fraction of the total error budget consumed over the long window.

        budget_consumed = burn_rate * long_window_hours / slo_window_hours

    Design rationale only -- this is NOT the alert threshold. For the canonical
    four alerts on a 30d window this yields 0.02, 0.05, 0.10, 0.10.
    """
    long_window_hours = parse_duration_minutes(long_window) / 60.0
    return burn_rate * long_window_hours / slo_window_hours


def short_window_for(long_window: str) -> str:
    """Derive the short window of a pair as long_window / 12.

    1h -> 5m, 6h -> 30m, 24h -> 2h, 3d -> 6h.
    """
    long_minutes = parse_duration_minutes(long_window)
    if long_minutes % SHORT_WINDOW_DIVISOR != 0:
        raise ValueError(
            f"long window {long_window!r} ({long_minutes}m) is not divisible "
            f"by {SHORT_WINDOW_DIVISOR}"
        )
    return format_duration_minutes(long_minutes // SHORT_WINDOW_DIVISOR)


def burn_rate_alerts(
    objective: float, slo_window_hours: float = HOURS_30D
) -> list[BurnRateAlert]:
    """Build the canonical four multi-window multi-burn-rate alerts.

    Args:
        objective: SLO objective as a percentage, e.g. 99.9.
        slo_window_hours: SLO compliance window in hours (default 720 = 30d),
            used only for the budget-consumed rationale figure.

    Returns:
        Four BurnRateAlert objects: two page-level (1h/5m, 6h/30m) and two
        ticket-level (24h/2h, 3d/6h), each with the correct threshold.
    """
    alerts: list[BurnRateAlert] = []
    for severity, rate, long_window in _CANONICAL:
        alerts.append(
            BurnRateAlert(
                severity=severity,
                burn_rate=rate,
                long_window=long_window,
                short_window=short_window_for(long_window),
                threshold=burn_threshold(objective, rate),
                budget_consumed=budget_consumed(rate, long_window, slo_window_hours),
            )
        )
    return alerts


def all_windows(alerts: list[BurnRateAlert]) -> list[str]:
    """Return the sorted unique set of every window referenced by the alerts.

    Used by the generator to emit exactly one recording rule per window
    (so e.g. the 5m window shared by no other alert still gets its rule,
    and windows are not duplicated).
    """
    windows: set[str] = set()
    for alert in alerts:
        windows.add(alert.long_window)
        windows.add(alert.short_window)
    return sorted(windows, key=parse_duration_minutes)
