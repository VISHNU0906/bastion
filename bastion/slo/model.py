"""The security-SLO data model and YAML loader.

A security SLO pairs an objective with a Service Level Indicator (SLI). Unlike a
generic availability SLO tool, Bastion supports FOUR SLI shapes because security
signals are not all the same shape. The shape decides how the Prometheus rules
are generated (this is the architectural spine):

  ratio          counter-rate ratio. error_ratio = error/total or 1-good/total
                 over ``rate(...)`` windows. Burn-rate applies directly.
                 e.g. auth failures: rate(failures) / rate(attempts) < 1%.

  freshness      point-in-time GAUGE ratio. A boolean gauge per resource (1 =
                 compliant) is averaged with ``avg_over_time(...[w])``; the
                 error ratio is ``1 - avg_over_time(good[w])``. rate() is
                 nonsense on a gauge, so we never use it here.
                 e.g. certs: fraction valid > 14 days >= 99.9%.

  latency_ratio  fraction of events meeting a latency target. good = events
                 within target (a histogram bucket / a "fast" counter), error
                 ratio = 1 - good/total over ``rate(...)``. Burn-rate applies.
                 e.g. MTTD: fraction of critical detections detected < 5m >= 99%.

  threshold      a hard INVARIANT with no error budget. A single gauge compared
                 to a limit; there is no "burn rate" when the target is exactly
                 zero. Generates one simple alert, not the four burn-rate pairs.
                 e.g. 0 critical CVEs older than 7 days.

For ratio / freshness / latency_ratio the burn-rate math is identical (it only
needs an error-ratio time series); only the recording-rule EXPRESSION differs.
``threshold`` takes a separate, simpler generation path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# SLI types that produce an error-ratio time series and therefore support the
# multi-window multi-burn-rate alerting.
BURN_RATE_TYPES = ("ratio", "freshness", "latency_ratio")
# All supported SLI types.
SLI_TYPES = (*BURN_RATE_TYPES, "threshold")

# Comparison operators allowed for threshold SLOs.
_THRESHOLD_OPS = (">", ">=", "<", "<=", "==")

# Metric-name-safe slug. Prometheus recording rule names must match
# [a-zA-Z_:][a-zA-Z0-9_:]*; we build names like
# securityslo:<slug>:error_ratio_rate1h, so the slug must be conservative.
_SLUG_RE = re.compile(r"[^a-zA-Z0-9_]")


def slugify(name: str) -> str:
    """Turn an SLO name into a Prometheus-metric-safe slug.

    "Certificate Freshness" -> "certificate_freshness".
    """
    slug = _SLUG_RE.sub("_", name.strip().lower())
    slug = re.sub(r"_+", "_", slug).strip("_")
    if not slug:
        raise ValueError(f"SLO name {name!r} produces an empty slug")
    if slug[0].isdigit():
        slug = f"slo_{slug}"
    return slug


@dataclass(frozen=True)
class SLO:
    """A single security Service Level Objective.

    The fields used depend on ``sli_type``:

      ratio:          total_query + (good_query OR error_query)
      freshness:      good_query (a boolean gauge, 1=compliant) [+ optional total]
      latency_ratio:  total_query + good_query (events meeting the target)
      threshold:      metric_query + comparison + limit (no objective budget)
    """

    name: str
    sli_type: str
    window: str
    description: str = ""
    # Burn-rate SLO fields (ratio / freshness / latency_ratio).
    objective: float | None = None
    total_query: str | None = None
    good_query: str | None = None
    error_query: str | None = None
    # Threshold SLO fields.
    metric_query: str | None = None
    comparison: str | None = None
    limit: float | None = None
    threshold_severity: str = "page"

    def __post_init__(self) -> None:
        if self.sli_type not in SLI_TYPES:
            raise ValueError(
                f"SLO {self.name!r}: sli_type must be one of {SLI_TYPES}, got {self.sli_type!r}"
            )
        if self.sli_type == "threshold":
            self._validate_threshold()
        else:
            self._validate_burn_rate()

    def _validate_burn_rate(self) -> None:
        if self.objective is None or not 0 < self.objective < 100:
            raise ValueError(
                f"SLO {self.name!r}: '{self.sli_type}' requires objective in (0, 100), "
                f"got {self.objective}"
            )
        if self.sli_type == "ratio":
            if not self.total_query:
                raise ValueError(f"SLO {self.name!r}: 'ratio' requires total")
            if not (self.good_query or self.error_query):
                raise ValueError(f"SLO {self.name!r}: 'ratio' requires good or error")
            if self.good_query and self.error_query:
                raise ValueError(f"SLO {self.name!r}: 'ratio' set both good and error")
        elif self.sli_type == "freshness":
            if not self.good_query:
                raise ValueError(
                    f"SLO {self.name!r}: 'freshness' requires good (a boolean gauge, 1=compliant)"
                )
        elif self.sli_type == "latency_ratio":
            if not (self.total_query and self.good_query):
                raise ValueError(
                    f"SLO {self.name!r}: 'latency_ratio' requires total and good "
                    "(events meeting the latency target)"
                )

    def _validate_threshold(self) -> None:
        if not self.metric_query:
            raise ValueError(f"SLO {self.name!r}: 'threshold' requires metric")
        if self.comparison not in _THRESHOLD_OPS:
            raise ValueError(
                f"SLO {self.name!r}: 'threshold' comparison must be one of {_THRESHOLD_OPS}, "
                f"got {self.comparison!r}"
            )
        if self.limit is None:
            raise ValueError(f"SLO {self.name!r}: 'threshold' requires a numeric limit")

    # -- derived -------------------------------------------------------------
    @property
    def slug(self) -> str:
        return slugify(self.name)

    @property
    def is_burn_rate(self) -> bool:
        return self.sli_type in BURN_RATE_TYPES

    @property
    def error_budget(self) -> float:
        """Allowed failure fraction for a burn-rate SLO."""
        if self.objective is None:
            raise ValueError(f"SLO {self.name!r}: no objective (threshold SLO has no budget)")
        return 1.0 - self.objective / 100.0

    def error_ratio_expr(self, window: str) -> str:
        """PromQL for the error ratio over ``window`` (burn-rate SLOs only).

        ratio:          error/total            or  1 - good/total   over rate()
        freshness:      1 - avg_over_time(good[w])   (boolean gauge, NOT rate())
        latency_ratio:  1 - rate(good[w]) / rate(total[w])
        """
        if self.sli_type == "ratio":
            total = f"sum(rate({self.total_query}[{window}]))"
            if self.error_query:
                return f"sum(rate({self.error_query}[{window}])) / {total}"
            good = f"sum(rate({self.good_query}[{window}]))"
            return f"1 - ({good} / {total})"

        if self.sli_type == "freshness":
            # Gauge ratio: average a boolean compliance gauge over the window.
            # avg_over_time on a 0/1 gauge yields the fraction of time compliant;
            # averaging across resources with avg(...) gives the fleet fraction.
            good = f"avg(avg_over_time({self.good_query}[{window}]))"
            return f"1 - ({good})"

        if self.sli_type == "latency_ratio":
            total = f"sum(rate({self.total_query}[{window}]))"
            good = f"sum(rate({self.good_query}[{window}]))"
            return f"1 - ({good} / {total})"

        raise ValueError(f"SLO {self.name!r}: error_ratio_expr is not defined for 'threshold'")

    def threshold_expr(self) -> str:
        """PromQL for a threshold SLO's single alert expression."""
        if self.sli_type != "threshold":
            raise ValueError(f"SLO {self.name!r}: threshold_expr only valid for 'threshold'")
        # Render the limit without trailing-zero noise.
        limit = f"{self.limit:.12g}"
        return f"{self.metric_query} {self.comparison} {limit}"


@dataclass
class SLOConfig:
    """A parsed security-SLO config: a list of SLOs plus optional metadata."""

    slos: list[SLO] = field(default_factory=list)
    group_name: str = "bastion_security_slo_rules"


def _build_slo(raw: dict, index: int) -> SLO:
    if not isinstance(raw, dict):
        raise ValueError(f"slo #{index} must be a mapping, got {type(raw).__name__}")
    missing = [k for k in ("name", "window", "sli") if k not in raw]
    if missing:
        raise ValueError(f"slo #{index} is missing required keys: {missing}")

    sli = raw["sli"]
    if not isinstance(sli, dict):
        raise ValueError(f"slo {raw['name']!r}: 'sli' must be a mapping")
    sli_type = sli.get("type")
    if sli_type not in SLI_TYPES:
        raise ValueError(
            f"slo {raw['name']!r}: sli.type must be one of {SLI_TYPES}, got {sli_type!r}"
        )

    def q(key: str) -> str | None:
        v = sli.get(key)
        return str(v).strip() if v is not None and str(v).strip() else None

    objective = float(raw["objective"]) if raw.get("objective") is not None else None

    return SLO(
        name=str(raw["name"]),
        sli_type=sli_type,
        window=str(raw["window"]),
        description=str(raw.get("description", "")),
        objective=objective,
        total_query=q("total"),
        good_query=q("good"),
        error_query=q("error"),
        metric_query=q("metric"),
        comparison=(str(sli["comparison"]).strip() if sli.get("comparison") else None),
        limit=(float(sli["limit"]) if sli.get("limit") is not None else None),
        threshold_severity=str(sli.get("severity", "page")),
    )


def parse_config(data: object) -> SLOConfig:
    """Validate an already-loaded config mapping into an SLOConfig."""
    if not isinstance(data, dict):
        raise ValueError("SLO config root must be a mapping")
    if "slos" not in data or not isinstance(data["slos"], list) or not data["slos"]:
        raise ValueError("SLO config must contain a non-empty 'slos' list")

    slos = [_build_slo(raw, i) for i, raw in enumerate(data["slos"])]

    seen: set[str] = set()
    for slo in slos:
        if slo.slug in seen:
            raise ValueError(f"duplicate SLO slug {slo.slug!r} (names must be distinct)")
        seen.add(slo.slug)

    group_name = str(data.get("group_name", "bastion_security_slo_rules"))
    return SLOConfig(slos=slos, group_name=group_name)


def load_config(path: str | Path) -> SLOConfig:
    """Load and validate a security-SLO config from a YAML file.

    Raises:
        FileNotFoundError: if the file does not exist.
        ValueError: on any structural or semantic problem.
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    return parse_config(yaml.safe_load(text))
