"""Runtime configuration for Bastion: targets, thresholds, enabled collectors.

The config is a single YAML file (see ``config.example.yaml``). It decides which
collectors run on each Prometheus scrape and gives each one its targets and
thresholds. Everything has a sane default so a half-filled config still works,
and unknown keys are ignored (forward-compatible).

Design notes:
  * Collectors are opt-in per ``enabled`` flag. A disabled collector emits no
    metrics and does no I/O.
  * Thresholds (cert warning days, auth-failure window, CVE max age) live here,
    not hardcoded in collectors, so an operator tunes posture without code.
  * Loading never raises on a *missing* optional section — it raises only on a
    structurally invalid file (so misconfiguration is loud, absence is quiet).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True)
class TLSTarget:
    """One TLS endpoint to inspect for certificate expiry.

    Attributes:
        name: Friendly label attached to the metric (e.g. "api-gateway").
        host: Hostname to connect to / send in SNI.
        port: TLS port (default 443).
    """

    name: str
    host: str
    port: int = 443


@dataclass(frozen=True)
class HeaderTarget:
    """One HTTP(S) URL to inspect for security headers."""

    name: str
    url: str


@dataclass(frozen=True)
class TLSConfig:
    enabled: bool = True
    # Cert is "compliant" while it has more than this many days to expiry.
    # Mirrors the "certs valid > 14 days" security SLO.
    warning_days: int = 14
    timeout_seconds: float = 5.0
    targets: tuple[TLSTarget, ...] = ()


@dataclass(frozen=True)
class HeadersConfig:
    enabled: bool = True
    timeout_seconds: float = 5.0
    # The security headers we score presence of. Order is stable for metrics.
    required_headers: tuple[str, ...] = (
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
    )
    targets: tuple[HeaderTarget, ...] = ()


@dataclass(frozen=True)
class CVEConfig:
    enabled: bool = True
    # Path to a pip requirements file to audit against OSV.dev.
    requirements_file: str | None = None
    # A CVE older than this many days that is still unpatched breaches the
    # "0 critical CVEs older than 7 days" SLO. The collector records ages so the
    # threshold rule can be evaluated in Prometheus.
    max_critical_age_days: int = 7
    timeout_seconds: float = 8.0
    # OSV.dev batch query endpoint. Overridable for testing / air-gapped mirrors.
    osv_url: str = "https://api.osv.dev/v1/querybatch"
    # Per-vuln detail endpoint (the batch endpoint returns only IDs, so we fetch
    # details to learn each vuln's severity + published date). {id} is filled in.
    osv_detail_url: str = "https://api.osv.dev/v1/vulns/{id}"
    # Cap on per-vuln detail lookups per scrape (keeps the scrape bounded even
    # if a requirements file pulls in hundreds of advisories).
    max_detail_lookups: int = 50


@dataclass(frozen=True)
class AuthConfig:
    enabled: bool = True
    # Path to an auth log to parse for failed-login lines. Optional: auth
    # failures can also be pushed via the /ingest webhook.
    log_file: str | None = None
    # Rolling window (seconds) over which the failure RATE is computed.
    window_seconds: int = 300


@dataclass(frozen=True)
class DetectionsConfig:
    enabled: bool = True
    # Priorities (Falco-style) considered "critical" for incident auto-open.
    critical_priorities: tuple[str, ...] = ("Critical", "Emergency")
    # MTTD target (seconds) for critical detections — the "MTTD < 5m" SLO.
    mttd_target_seconds: float = 300.0


@dataclass(frozen=True)
class BastionConfig:
    """Top-level Bastion configuration."""

    exporter_host: str = "0.0.0.0"
    exporter_port: int = 9300
    tls: TLSConfig = field(default_factory=TLSConfig)
    headers: HeadersConfig = field(default_factory=HeadersConfig)
    cves: CVEConfig = field(default_factory=CVEConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    detections: DetectionsConfig = field(default_factory=DetectionsConfig)
    runbooks_file: str | None = None


def _as_bool(value: object, default: bool) -> bool:
    if value is None:
        return default
    return bool(value)


def _build_tls(raw: dict) -> TLSConfig:
    targets = tuple(
        TLSTarget(
            name=str(t["name"]),
            host=str(t["host"]),
            port=int(t.get("port", 443)),
        )
        for t in raw.get("targets", []) or []
    )
    return TLSConfig(
        enabled=_as_bool(raw.get("enabled"), True),
        warning_days=int(raw.get("warning_days", 14)),
        timeout_seconds=float(raw.get("timeout_seconds", 5.0)),
        targets=targets,
    )


def _build_headers(raw: dict) -> HeadersConfig:
    targets = tuple(
        HeaderTarget(name=str(t["name"]), url=str(t["url"]))
        for t in raw.get("targets", []) or []
    )
    required = raw.get("required_headers")
    defaults = HeadersConfig()
    return HeadersConfig(
        enabled=_as_bool(raw.get("enabled"), True),
        timeout_seconds=float(raw.get("timeout_seconds", 5.0)),
        required_headers=tuple(str(h) for h in required) if required else defaults.required_headers,
        targets=targets,
    )


def _build_cves(raw: dict) -> CVEConfig:
    defaults = CVEConfig()
    return CVEConfig(
        enabled=_as_bool(raw.get("enabled"), True),
        requirements_file=(str(raw["requirements_file"]) if raw.get("requirements_file") else None),
        max_critical_age_days=int(raw.get("max_critical_age_days", 7)),
        timeout_seconds=float(raw.get("timeout_seconds", 8.0)),
        osv_url=str(raw.get("osv_url", defaults.osv_url)),
        osv_detail_url=str(raw.get("osv_detail_url", defaults.osv_detail_url)),
        max_detail_lookups=int(raw.get("max_detail_lookups", defaults.max_detail_lookups)),
    )


def _build_auth(raw: dict) -> AuthConfig:
    return AuthConfig(
        enabled=_as_bool(raw.get("enabled"), True),
        log_file=(str(raw["log_file"]) if raw.get("log_file") else None),
        window_seconds=int(raw.get("window_seconds", 300)),
    )


def _build_detections(raw: dict) -> DetectionsConfig:
    defaults = DetectionsConfig()
    crit = raw.get("critical_priorities")
    return DetectionsConfig(
        enabled=_as_bool(raw.get("enabled"), True),
        critical_priorities=(tuple(str(p) for p in crit) if crit else defaults.critical_priorities),
        mttd_target_seconds=float(raw.get("mttd_target_seconds", 300.0)),
    )


def parse_config(data: object) -> BastionConfig:
    """Validate an already-loaded config mapping into a BastionConfig.

    Missing sections fall back to defaults; only a non-mapping root or a
    malformed target raises.
    """
    if data is None:
        return BastionConfig()
    if not isinstance(data, dict):
        raise ValueError("Bastion config root must be a mapping")

    exporter = data.get("exporter", {}) or {}
    return BastionConfig(
        exporter_host=str(exporter.get("host", "0.0.0.0")),
        exporter_port=int(exporter.get("port", 9300)),
        tls=_build_tls(data.get("tls", {}) or {}),
        headers=_build_headers(data.get("headers", {}) or {}),
        cves=_build_cves(data.get("cves", {}) or {}),
        auth=_build_auth(data.get("auth", {}) or {}),
        detections=_build_detections(data.get("detections", {}) or {}),
        runbooks_file=(str(data["runbooks_file"]) if data.get("runbooks_file") else None),
    )


def load_config(path: str | Path) -> BastionConfig:
    """Load and validate a Bastion config from a YAML file.

    Raises:
        FileNotFoundError: if the file does not exist.
        ValueError: on a structurally invalid config.
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    return parse_config(yaml.safe_load(text))


def default_config() -> BastionConfig:
    """Return an all-defaults config (used when no file is provided)."""
    return BastionConfig()
