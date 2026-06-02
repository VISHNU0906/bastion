"""TLS certificate expiry collector.

Connects to each configured endpoint over TLS, reads the leaf certificate, and
emits days-to-expiry plus a point-in-time "valid" SLI (1 if more than
``warning_days`` remain). The fetch and the math are split so the math is unit-
testable offline with a synthetic ``notAfter`` and no sockets.

Metrics:
  bastion_tls_cert_expiry_days{endpoint,host}   days until expiry (may be < 0)
  bastion_tls_cert_valid{endpoint,host}         1 if > warning_days left, else 0
  bastion_tls_check_success{endpoint,host}      1 if the check ran, 0 on error

A single unreachable endpoint sets its own check_success to 0 but does NOT stop
the others from being scraped.
"""

from __future__ import annotations

import datetime as dt
import logging
import socket
import ssl

from cryptography import x509

from bastion.collectors.base import Collector
from bastion.config import TLSConfig, TLSTarget
from bastion.metrics import BastionMetrics

logger = logging.getLogger("bastion.collector.tls")


def days_until_expiry(not_after: dt.datetime, now: dt.datetime | None = None) -> float:
    """Days from ``now`` until ``not_after`` (negative if already expired).

    Both datetimes are normalised to timezone-aware UTC so naive certs (as
    returned by some libraries) and aware ones compare correctly.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=dt.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)
    return (not_after - now).total_seconds() / 86400.0


def is_valid(not_after: dt.datetime, warning_days: int, now: dt.datetime | None = None) -> bool:
    """True if the cert has strictly more than ``warning_days`` left."""
    return days_until_expiry(not_after, now) > warning_days


def fetch_not_after(host: str, port: int, timeout: float) -> dt.datetime:
    """Connect over TLS and return the leaf certificate's notAfter (UTC).

    Raises on any connection/handshake/parse failure; the caller isolates it.
    """
    ctx = ssl.create_default_context()
    # We want the certificate even if the chain/hostname is imperfect — expiry
    # monitoring must still work for a misconfigured endpoint. We are reading,
    # not establishing a trusted session.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
    if not der:
        raise ValueError(f"no certificate returned by {host}:{port}")
    cert = x509.load_der_x509_certificate(der)
    # cryptography >= 42 exposes a timezone-aware accessor; fall back for older.
    try:
        return cert.not_valid_after_utc
    except AttributeError:  # pragma: no cover - older cryptography
        return cert.not_valid_after.replace(tzinfo=dt.timezone.utc)


class TLSCertCollector(Collector):
    """Emit cert expiry + validity for every configured TLS endpoint."""

    def __init__(self, metrics: BastionMetrics, config: TLSConfig):
        super().__init__(metrics)
        self.config = config

    @property
    def name(self) -> str:
        return "tls_cert"

    def _collect_target(self, target: TLSTarget) -> None:
        labels = {"endpoint": target.name, "host": target.host}
        try:
            not_after = fetch_not_after(target.host, target.port, self.config.timeout_seconds)
        except Exception:  # noqa: BLE001 — isolate one bad endpoint
            logger.warning("tls check failed for %s (%s:%s)", target.name, target.host, target.port)
            self.metrics.tls_check_success.labels(**labels).set(0)
            return
        days = days_until_expiry(not_after)
        self.metrics.tls_cert_expiry_days.labels(**labels).set(days)
        self.metrics.tls_cert_valid.labels(**labels).set(
            1 if days > self.config.warning_days else 0
        )
        self.metrics.tls_check_success.labels(**labels).set(1)

    def _collect(self) -> None:
        if not self.config.enabled:
            return
        for target in self.config.targets:
            self._collect_target(target)
