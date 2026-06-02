"""Bastion — SRE for security infrastructure.

Bastion collects security signals (TLS cert expiry, security headers, dependency
CVEs, auth-failure rates, runtime-security detections), exposes them as
Prometheus metrics, defines *security SLOs* with multi-window multi-burn-rate
alerting, and routes security-SLO breaches to incidents with MTTD/MTTR tracking.

It applies SRE rigor — SLOs, error budgets, burn-rate alerts, MTTD/MTTR — to
SECURITY signals: "monitoring and alerting on security infrastructure, done the
SRE way."
"""

__version__ = "0.1.0"
