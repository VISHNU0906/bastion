"""Render Prometheus rules and a Grafana dashboard from a security-SLO config.

Bridges the validated SLO model (model.py), the burn-rate math (burnrate.py),
and the Jinja2 rules template. Branches on ``sli_type``:

  * burn-rate SLOs (ratio / freshness / latency_ratio) -> recording rules per
    window + the four burn-rate alerts + budget/burn/SLI dashboard panels.
  * threshold SLOs -> one comparison alert + a stat panel.

``render_security_rules`` and ``render_grafana_dashboard`` are pure functions
returning strings (and they self-check that the output parses as YAML / JSON),
so tests can assert validity trivially. ``generate`` writes both to disk.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from bastion.slo.burnrate import BurnRateAlert, all_windows, burn_rate_alerts
from bastion.slo.model import SLO, SLOConfig

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_DS_VAR = "${datasource}"


def _clean_float(value: float) -> str:
    """Render a float as a short, noise-free decimal (0.0144 not 0.01439999...)."""
    return f"{value:.12g}"


def _yaml_quote(value: str) -> str:
    """Render a string as a safe double-quoted YAML scalar (PromQL-safe)."""
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _make_environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    env.filters["yaml_quote"] = _yaml_quote
    return env


class _SLOView:
    """Template adapter wrapping an SLO with its computed alerts + windows."""

    def __init__(self, slo: SLO):
        self._slo = slo
        self.is_burn_rate = slo.is_burn_rate
        if slo.is_burn_rate:
            self.alerts: list[BurnRateAlert] = burn_rate_alerts(slo.objective)
            self.alert_windows: list[str] = all_windows(self.alerts)
            self.slo_window: str = slo.window
            rule_windows = list(self.alert_windows)
            if self.slo_window not in rule_windows:
                rule_windows.append(self.slo_window)
            self.windows: list[str] = rule_windows
        else:
            self.alerts = []
            self.alert_windows = []
            self.windows = []

    # Pass-throughs the template needs.
    @property
    def name(self) -> str:
        return self._slo.name

    @property
    def slug(self) -> str:
        return self._slo.slug

    @property
    def objective(self) -> float | None:
        return self._slo.objective

    @property
    def window(self) -> str:
        return self._slo.window

    @property
    def description(self) -> str:
        return self._slo.description

    @property
    def sli_type(self) -> str:
        return self._slo.sli_type

    @property
    def error_budget(self) -> float:
        return self._slo.error_budget

    @property
    def threshold_severity(self) -> str:
        return self._slo.threshold_severity

    def error_ratio_expr(self, window: str) -> str:
        return self._slo.error_ratio_expr(window)

    def threshold_expr(self) -> str:
        return self._slo.threshold_expr()

    def recording_metric(self, window: str) -> str:
        return f"securityslo:{self._slo.slug}:error_ratio_rate{window}"

    def alert_name(self, alert: BurnRateAlert) -> str:
        suffix = "Fast" if alert.severity == "page" else "Slow"
        return f"SecuritySLOBurn_{self._slo.slug}_{alert.long_window}_{suffix}"

    def threshold_alert_name(self) -> str:
        return f"SecurityInvariant_{self._slo.slug}"

    def alert_expr(self, alert: BurnRateAlert) -> str:
        t = _clean_float(alert.threshold)
        long_m = self.recording_metric(alert.long_window)
        short_m = self.recording_metric(alert.short_window)
        return f"{long_m} > {t} and {short_m} > {t}"


# --------------------------------------------------------------------------
# Prometheus rules
# --------------------------------------------------------------------------


def render_security_rules(config: SLOConfig) -> str:
    """Render the Prometheus recording + alerting rules YAML as a string."""
    env = _make_environment()
    template = env.get_template("security_rules.yaml.j2")
    views = [_SLOView(slo) for slo in config.slos]
    rendered = template.render(group_name=config.group_name, slos=views)
    yaml.safe_load(rendered)  # fail fast on invalid YAML
    return rendered


# --------------------------------------------------------------------------
# Grafana dashboard (built programmatically for clean per-type branching)
# --------------------------------------------------------------------------


def _grid(x: int, y: int, w: int, h: int) -> dict:
    return {"h": h, "w": w, "x": x, "y": y}


def _ds() -> dict:
    return {"type": "prometheus", "uid": _DS_VAR}


def _target(expr: str, legend: str, ref: str = "A") -> dict:
    return {
        "datasource": _ds(),
        "editorMode": "code",
        "expr": expr,
        "legendFormat": legend,
        "range": True,
        "refId": ref,
    }


def _row(title: str, y: int, panel_id: int) -> dict:
    return {
        "id": panel_id,
        "type": "row",
        "title": title,
        "collapsed": False,
        "gridPos": _grid(0, y, 24, 1),
        "panels": [],
    }


def _burn_rate_panels(view: _SLOView, y: int, panel_id: int) -> tuple[list[dict], int, int]:
    """Budget gauge + burn-rate timeseries + SLI error-ratio timeseries."""
    panels: list[dict] = []
    budget = view.error_budget
    slo_metric = view.recording_metric(view.slo_window)
    burn_short = view.alert_windows[0]
    burn_long = view.alert_windows[-1]

    panels.append(
        _row(f"{view.name} - {view.sli_type} SLO {view.objective}% / {view.window}", y, panel_id)
    )
    panel_id += 1
    y += 1

    # Error budget remaining gauge over the full SLO window.
    budget_expr = f"clamp_min(1 - ({slo_metric} / {_clean_float(budget)}), 0)"
    panels.append(
        {
            "id": panel_id,
            "type": "gauge",
            "title": "Error budget remaining",
            "description": f"Fraction of the security error budget left over the {view.slo_window} window.",
            "datasource": _ds(),
            "gridPos": _grid(0, y, 6, 8),
            "fieldConfig": {
                "defaults": {
                    "unit": "percentunit",
                    "min": 0,
                    "max": 1,
                    "thresholds": {
                        "mode": "absolute",
                        "steps": [
                            {"color": "red", "value": None},
                            {"color": "orange", "value": 0.25},
                            {"color": "yellow", "value": 0.5},
                            {"color": "green", "value": 0.75},
                        ],
                    },
                },
                "overrides": [],
            },
            "options": {
                "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                "showThresholdLabels": False,
                "showThresholdMarkers": True,
            },
            "targets": [_target(budget_expr, "budget remaining")],
        }
    )
    panel_id += 1

    burn_targets = [
        _target(
            f"{view.recording_metric(w)} / {_clean_float(budget)}",
            f"burn rate ({w})",
            ref=w,
        )
        for w in (burn_short, burn_long)
    ]
    panels.append(
        {
            "id": panel_id,
            "type": "timeseries",
            "title": "Burn rate (x budget)",
            "description": "Error ratio / error budget. 1 = burning at budget; 14.4 = fast-page.",
            "datasource": _ds(),
            "gridPos": _grid(6, y, 10, 8),
            "fieldConfig": {
                "defaults": {
                    "unit": "none",
                    "custom": {"drawStyle": "line", "fillOpacity": 10, "lineWidth": 2},
                    "thresholds": {
                        "mode": "absolute",
                        "steps": [
                            {"color": "green", "value": None},
                            {"color": "orange", "value": 6},
                            {"color": "red", "value": 14.4},
                        ],
                    },
                },
                "overrides": [],
            },
            "options": {
                "legend": {"calcs": [], "displayMode": "list", "placement": "bottom"},
                "tooltip": {"mode": "multi", "sort": "desc"},
            },
            "targets": burn_targets,
        }
    )
    panel_id += 1

    sli_targets = [
        _target(view.recording_metric(w), f"error ratio ({w})", ref=w)
        for w in view.alert_windows
    ]
    panels.append(
        {
            "id": panel_id,
            "type": "timeseries",
            "title": "SLI error ratio",
            "description": "Observed security error ratio per window.",
            "datasource": _ds(),
            "gridPos": _grid(16, y, 8, 8),
            "fieldConfig": {
                "defaults": {
                    "unit": "percentunit",
                    "custom": {"drawStyle": "line", "fillOpacity": 5, "lineWidth": 1},
                },
                "overrides": [],
            },
            "options": {
                "legend": {"calcs": [], "displayMode": "list", "placement": "bottom"},
                "tooltip": {"mode": "multi", "sort": "desc"},
            },
            "targets": sli_targets,
        }
    )
    panel_id += 1
    y += 8
    return panels, y, panel_id


def _threshold_panels(view: _SLOView, y: int, panel_id: int) -> tuple[list[dict], int, int]:
    """A single stat panel showing the invariant's current value (target: pass)."""
    panels: list[dict] = []
    panels.append(_row(f"{view.name} - threshold invariant ({view.window})", y, panel_id))
    panel_id += 1
    y += 1
    panels.append(
        {
            "id": panel_id,
            "type": "stat",
            "title": view.name,
            "description": f"Hard security invariant: {view.threshold_expr()} should never hold.",
            "datasource": _ds(),
            "gridPos": _grid(0, y, 24, 6),
            "fieldConfig": {
                "defaults": {
                    "unit": "short",
                    "thresholds": {
                        "mode": "absolute",
                        "steps": [
                            {"color": "green", "value": None},
                            {"color": "red", "value": 1},
                        ],
                    },
                },
                "overrides": [],
            },
            "options": {
                "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                "colorMode": "background",
                "graphMode": "area",
            },
            # Show the metric that the invariant guards.
            "targets": [_target(view._slo.metric_query, view.name)],
        }
    )
    panel_id += 1
    y += 6
    return panels, y, panel_id


def _build_panels(views: list[_SLOView]) -> list[dict]:
    panels: list[dict] = []
    panel_id = 1
    y = 0
    for view in views:
        if view.is_burn_rate:
            new, y, panel_id = _burn_rate_panels(view, y, panel_id)
        else:
            new, y, panel_id = _threshold_panels(view, y, panel_id)
        panels.extend(new)
    return panels


def _build_templating(default_uid: str = "bastion-prometheus") -> dict:
    return {
        "list": [
            {
                "current": {"selected": True, "text": "Prometheus", "value": default_uid},
                "hide": 0,
                "includeAll": False,
                "label": "Datasource",
                "multi": False,
                "name": "datasource",
                "options": [],
                "query": "prometheus",
                "refresh": 1,
                "regex": "",
                "skipUrlSync": False,
                "type": "datasource",
            }
        ]
    }


def _build_annotations() -> dict:
    return {
        "list": [
            {
                "builtIn": 1,
                "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                "enable": True,
                "hide": True,
                "iconColor": "rgba(0, 211, 255, 1)",
                "name": "Annotations & Alerts",
                "type": "dashboard",
            }
        ]
    }


def render_grafana_dashboard(
    config: SLOConfig, title: str = "Bastion - Security SLOs"
) -> str:
    """Render the Grafana security-SLO dashboard JSON as a string."""
    views = [_SLOView(slo) for slo in config.slos]
    dashboard = {
        "annotations": _build_annotations(),
        "editable": True,
        "fiscalYearStartMonth": 0,
        "graphTooltip": 0,
        "links": [],
        "panels": _build_panels(views),
        "refresh": "30s",
        "schemaVersion": 39,
        "tags": ["bastion", "security", "slo", "sre"],
        "templating": _build_templating(),
        "time": {"from": "now-6h", "to": "now"},
        "timepicker": {},
        "timezone": "",
        "title": title,
        "uid": "bastion-security-slos",
        "version": 1,
        "weekStart": "",
    }
    rendered = json.dumps(dashboard, indent=2)
    json.loads(rendered)  # fail fast on invalid JSON
    return rendered


# --------------------------------------------------------------------------
# Disk output
# --------------------------------------------------------------------------


def generate(config: SLOConfig, out_dir: str | Path) -> dict[str, Path]:
    """Render both artifacts and write them under ``out_dir``."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rules_path = out_dir / "bastion_security_rules.yaml"
    dashboard_path = out_dir / "bastion_security_slo_dashboard.json"

    rules_path.write_text(render_security_rules(config), encoding="utf-8")
    dashboard_path.write_text(render_grafana_dashboard(config), encoding="utf-8")

    return {"rules": rules_path, "dashboard": dashboard_path}
