"""Security-SLO engine.

Turns ``slos.example.yaml`` into Prometheus recording + alerting rules and a
Grafana dashboard, applying the Google SRE Workbook multi-window multi-burn-rate
method to SECURITY SLIs.

The key insight (and the reason this is not just a copy of a generic SLO tool):
security SLIs are not all the same SHAPE, so the generator branches on an SLI
``type``:

  * ``ratio``         — counter-rate ratio (auth failures / attempts). Classic
                        burn-rate over ``rate(...)`` recording rules.
  * ``freshness``     — point-in-time gauge ratio (fraction of certs valid). Uses
                        ``avg_over_time`` of a boolean gauge, not ``rate()``.
  * ``latency_ratio`` — fraction of events meeting a latency target (detections
                        with MTTD < 5m). Burn-rate over a good/total ratio.
  * ``threshold``     — a hard invariant (0 critical CVEs older than 7 days).
                        No error budget; a single comparison alert.

Burn-rate math lives in :mod:`bastion.slo.burnrate` (the same proven, unit-tested
math from the Vigil SLO tool, vendored here so Bastion is self-contained).
"""

from bastion.slo.burnrate import BurnRateAlert, burn_rate_alerts
from bastion.slo.model import SLO, SLOConfig, load_config, parse_config

__all__ = [
    "BurnRateAlert",
    "burn_rate_alerts",
    "SLO",
    "SLOConfig",
    "load_config",
    "parse_config",
]
