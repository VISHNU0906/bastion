"""Config loading tests: defaults, partial files, target parsing."""

from __future__ import annotations

import pytest

from bastion.config import default_config, load_config, parse_config


def test_default_config_is_complete():
    cfg = default_config()
    assert cfg.exporter_port == 9300
    assert cfg.tls.warning_days == 14
    assert cfg.detections.mttd_target_seconds == 300.0
    assert "Strict-Transport-Security" in cfg.headers.required_headers


def test_empty_config_falls_back_to_defaults():
    assert parse_config(None).exporter_port == 9300
    assert parse_config({}).tls.enabled is True


def test_non_mapping_root_raises():
    with pytest.raises(ValueError):
        parse_config(["not", "a", "mapping"])


def test_parse_targets():
    data = {
        "tls": {"warning_days": 7, "targets": [{"name": "api", "host": "api.x", "port": 8443}]},
        "headers": {"targets": [{"name": "web", "url": "https://web.x"}]},
    }
    cfg = parse_config(data)
    assert cfg.tls.warning_days == 7
    assert cfg.tls.targets[0].host == "api.x"
    assert cfg.tls.targets[0].port == 8443
    assert cfg.headers.targets[0].url == "https://web.x"


def test_disabled_collector():
    cfg = parse_config({"cves": {"enabled": False}})
    assert cfg.cves.enabled is False


def test_load_example_config():
    cfg = load_config("config.example.yaml")
    assert cfg.exporter_port == 9300
    assert cfg.cves.requirements_file == "sample/vulnerable-requirements.txt"
    assert cfg.runbooks_file == "runbooks.example.yaml"
