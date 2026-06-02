"""Shared pytest fixtures. Everything here is offline — no network, no Docker."""

from __future__ import annotations

import pytest
from prometheus_client import CollectorRegistry

from bastion.config import default_config
from bastion.metrics import BastionMetrics, build_metrics
from bastion.runtime import Bastion


@pytest.fixture
def registry() -> CollectorRegistry:
    """A fresh registry per test so metrics never bleed across tests."""
    return CollectorRegistry()


@pytest.fixture
def metrics(registry: CollectorRegistry) -> BastionMetrics:
    return build_metrics(registry)


@pytest.fixture
def bastion(registry: CollectorRegistry) -> Bastion:
    """A fully-wired Bastion runtime on a fresh registry (no collectors run)."""
    return Bastion(default_config(), registry=registry)


def metric_value(registry: CollectorRegistry, name: str, labels: dict | None = None) -> float:
    """Read a single sample value from a registry by metric name + labels.

    Handy for asserting "the gauge/counter has the expected value" without
    scraping the whole exposition text.
    """
    value = registry.get_sample_value(name, labels or {})
    return value if value is not None else float("nan")
