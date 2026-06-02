"""Security-SLO model + generation tests.

Asserts the SLI-type branching (the architectural spine): ratio/latency_ratio
use rate(), freshness uses avg_over_time (never rate), threshold emits a single
comparison alert with no burn-rate pairs — and the generated rules YAML +
dashboard JSON always parse.
"""

from __future__ import annotations

import json

import pytest
import yaml

from bastion.slo.generate import render_grafana_dashboard, render_security_rules
from bastion.slo.model import SLO, load_config, parse_config

# --- model validation -------------------------------------------------------


def test_ratio_slo_error_expr_uses_rate():
    slo = SLO(name="Auth", sli_type="ratio", window="30d", objective=99,
              error_query="bastion_auth_failures_total", total_query="bastion_auth_attempts_total")
    expr = slo.error_ratio_expr("1h")
    assert "rate(" in expr
    assert "bastion_auth_failures_total[1h]" in expr


def test_freshness_slo_uses_avg_over_time_not_rate():
    slo = SLO(name="Certs", sli_type="freshness", window="30d", objective=99.9,
              good_query="bastion_tls_cert_valid")
    expr = slo.error_ratio_expr("6h")
    assert "avg_over_time(" in expr
    assert "rate(" not in expr  # rate() on a gauge would be wrong
    assert expr.startswith("1 - (")


def test_latency_ratio_slo_uses_rate():
    slo = SLO(name="MTTD", sli_type="latency_ratio", window="30d", objective=99,
              good_query='bucket{le="300"}', total_query="count")
    expr = slo.error_ratio_expr("1h")
    assert "rate(" in expr
    assert expr.startswith("1 - (")


def test_threshold_slo_has_no_budget_and_emits_comparison():
    slo = SLO(name="CVE Age", sli_type="threshold", window="30d",
              metric_query="bastion_dependency_critical_over_age", comparison=">", limit=0)
    assert slo.is_burn_rate is False
    assert slo.threshold_expr() == "bastion_dependency_critical_over_age > 0"
    with pytest.raises(ValueError):
        _ = slo.error_budget  # threshold SLOs have no error budget


def test_threshold_requires_valid_comparison():
    with pytest.raises(ValueError):
        SLO(name="x", sli_type="threshold", window="30d",
            metric_query="m", comparison="!!", limit=1)


def test_burn_rate_slo_requires_objective():
    with pytest.raises(ValueError):
        SLO(name="x", sli_type="ratio", window="30d",
            error_query="e", total_query="t")  # no objective


def test_ratio_rejects_both_good_and_error():
    with pytest.raises(ValueError):
        SLO(name="x", sli_type="ratio", window="30d", objective=99,
            good_query="g", error_query="e", total_query="t")


# --- config loading ---------------------------------------------------------


def test_load_example_config_has_all_four_types():
    cfg = load_config("slos.example.yaml")
    types = {s.sli_type for s in cfg.slos}
    assert types == {"ratio", "freshness", "latency_ratio", "threshold"}


def test_duplicate_slug_rejected():
    data = {"slos": [
        {"name": "Same", "window": "30d", "objective": 99, "sli": {"type": "ratio", "error": "e", "total": "t"}},
        {"name": "same", "window": "30d", "objective": 99, "sli": {"type": "ratio", "error": "e", "total": "t"}},
    ]}
    with pytest.raises(ValueError):
        parse_config(data)


def test_empty_slos_rejected():
    with pytest.raises(ValueError):
        parse_config({"slos": []})


# --- generation -------------------------------------------------------------


def test_render_rules_is_valid_yaml():
    cfg = load_config("slos.example.yaml")
    rules = render_security_rules(cfg)
    parsed = yaml.safe_load(rules)
    assert "groups" in parsed
    assert parsed["groups"][0]["name"] == "bastion_security_slos"


def test_rules_contain_recording_and_alert_rules():
    cfg = load_config("slos.example.yaml")
    parsed = yaml.safe_load(render_security_rules(cfg))
    rules = parsed["groups"][0]["rules"]
    records = [r for r in rules if "record" in r]
    alerts = [r for r in rules if "alert" in r]
    # 3 burn-rate SLOs * (4 windows recording + 4 alerts) + 1 threshold alert.
    assert len(records) > 0
    assert len(alerts) > 0
    # The threshold SLO emits exactly one alert (a single invariant), not four.
    cve_alerts = [a for a in alerts if a["labels"]["slo"] == "critical_cve_age"]
    assert len(cve_alerts) == 1


def test_freshness_recording_rule_uses_avg_over_time():
    cfg = load_config("slos.example.yaml")
    parsed = yaml.safe_load(render_security_rules(cfg))
    rules = parsed["groups"][0]["rules"]
    freshness_records = [
        r for r in rules
        if "record" in r and r["labels"].get("slo") == "certificate_freshness"
    ]
    assert freshness_records
    for r in freshness_records:
        assert "avg_over_time" in r["expr"]
        assert "rate(" not in r["expr"]


def test_burn_rate_threshold_values_in_rules():
    # Spot-check that a 99% ratio SLO emits the textbook 0.144 fast threshold.
    cfg = load_config("slos.example.yaml")
    parsed = yaml.safe_load(render_security_rules(cfg))
    alerts = [r for r in parsed["groups"][0]["rules"]
              if "alert" in r and r["labels"]["slo"] == "auth_failure_ratio"]
    exprs = " ".join(a["expr"] for a in alerts)
    assert "0.144" in exprs  # 14.4 * 0.01


def test_render_dashboard_is_valid_json():
    cfg = load_config("slos.example.yaml")
    dash = json.loads(render_grafana_dashboard(cfg))
    assert dash["title"]
    assert isinstance(dash["panels"], list)
    assert len(dash["panels"]) > 0


def test_dashboard_panels_reference_recording_metrics():
    cfg = load_config("slos.example.yaml")
    dash = json.loads(render_grafana_dashboard(cfg))
    blob = json.dumps(dash)
    assert "securityslo:" in blob  # burn-rate panels reference recording rules
