"""HTTP security-header collector.

For each target URL, fetches the response headers and records which of the
required security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
are present, plus a coverage ratio. The header-scoring logic is a pure function
(``score_headers``) so it is unit-testable from a plain dict with no network.

Metrics:
  bastion_security_header_present{target,header}     1 present / 0 absent
  bastion_security_header_coverage_ratio{target}     present / required (0..1)
  bastion_security_header_check_success{target}      1 if fetched, 0 on error

Header matching is case-insensitive (HTTP header names are case-insensitive).
"""

from __future__ import annotations

import logging

import requests

from bastion.collectors.base import Collector
from bastion.config import HeaderTarget, HeadersConfig
from bastion.metrics import BastionMetrics

logger = logging.getLogger("bastion.collector.headers")


def score_headers(
    response_headers: dict, required_headers: tuple[str, ...]
) -> dict[str, bool]:
    """Map each required header -> present (case-insensitive).

    Args:
        response_headers: Headers from the HTTP response (any mapping).
        required_headers: The security headers we care about, in canonical case.

    Returns:
        Ordered dict {canonical_header_name: present_bool}.
    """
    # Lower-case the response header names once for O(1) case-insensitive lookup.
    present_lower = {str(k).lower() for k in response_headers.keys()}
    return {header: header.lower() in present_lower for header in required_headers}


def coverage_ratio(scored: dict[str, bool]) -> float:
    """Fraction of required headers present (0.0 if the set is empty)."""
    if not scored:
        return 0.0
    return sum(1 for present in scored.values() if present) / len(scored)


class HeadersCollector(Collector):
    """Emit security-header presence + coverage for every configured URL."""

    def __init__(self, metrics: BastionMetrics, config: HeadersConfig):
        super().__init__(metrics)
        self.config = config

    @property
    def name(self) -> str:
        return "http_headers"

    def _collect_target(self, target: HeaderTarget) -> None:
        try:
            resp = requests.get(
                target.url,
                timeout=self.config.timeout_seconds,
                allow_redirects=True,
            )
            scored = score_headers(dict(resp.headers), self.config.required_headers)
        except Exception:  # noqa: BLE001 — isolate one bad target
            logger.warning("header check failed for %s (%s)", target.name, target.url)
            self.metrics.header_check_success.labels(target=target.name).set(0)
            return
        for header, present in scored.items():
            self.metrics.header_present.labels(target=target.name, header=header).set(
                1 if present else 0
            )
        self.metrics.header_coverage_ratio.labels(target=target.name).set(coverage_ratio(scored))
        self.metrics.header_check_success.labels(target=target.name).set(1)

    def _collect(self) -> None:
        if not self.config.enabled:
            return
        for target in self.config.targets:
            self._collect_target(target)
