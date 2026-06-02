"""Security-signal collectors.

Each collector turns a class of security signal into Prometheus metrics:

  * ``tls_cert``        — TLS certificate days-to-expiry per endpoint.
  * ``http_headers``    — presence of HSTS/CSP/X-Frame/X-Content-Type headers.
  * ``dependency_cves`` — known vulnerabilities for a requirements file (OSV.dev).
  * ``auth_failures``   — auth-failure rate from a log file or pushed counter.
  * ``detections``      — runtime-security detections (Falco-style) + MTTD.

All collectors share the ``Collector`` base, which wraps every run in
try/except + timing and emits ``bastion_collector_up`` so a single failing
collector degrades gracefully without ever breaking the /metrics scrape.
"""

from bastion.collectors.base import Collector

__all__ = ["Collector"]
