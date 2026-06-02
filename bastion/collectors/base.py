"""Base class for Bastion collectors.

A collector's ``collect()`` is called once per Prometheus scrape. The base class
guarantees three things every real-world exporter needs but is easy to forget:

  1. **It never raises into the scrape.** A collector that throws (DNS failure,
     timeout, malformed log) sets ``bastion_collector_up{collector=...} = 0``
     and is otherwise a no-op. The /metrics endpoint always returns 200.
  2. **It is timed.** Each run records ``bastion_collector_scrape_seconds``.
  3. **It self-reports health.** ``bastion_collector_up = 1`` on a clean run.

Subclasses implement ``_collect()`` (the real work) and ``name`` (a stable
identifier). They should still use try/except internally for *per-target*
failures so one bad endpoint doesn't blank out the others — the base guard is
the last line of defence, not the only one.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod

from bastion.metrics import BastionMetrics

logger = logging.getLogger("bastion.collector")


class Collector(ABC):
    """Abstract base for a scrape-time security-signal collector."""

    def __init__(self, metrics: BastionMetrics):
        self.metrics = metrics

    @property
    @abstractmethod
    def name(self) -> str:
        """Stable collector identifier used in the ``collector`` metric label."""

    @abstractmethod
    def _collect(self) -> None:
        """Do the real work: read the signal, set the metrics. May raise."""

    def collect(self) -> bool:
        """Run the collector with timing + health + crash isolation.

        Returns True on a clean run, False if ``_collect`` raised.
        """
        start = time.perf_counter()
        try:
            self._collect()
            self.metrics.collector_up.labels(collector=self.name).set(1)
            ok = True
        except Exception:  # noqa: BLE001 — last-line guard: never break the scrape
            logger.exception("collector %s failed", self.name)
            self.metrics.collector_up.labels(collector=self.name).set(0)
            ok = False
        finally:
            elapsed = time.perf_counter() - start
            self.metrics.collector_scrape_seconds.labels(collector=self.name).observe(elapsed)
        return ok
