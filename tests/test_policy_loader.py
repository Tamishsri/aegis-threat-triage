"""Tests for policy configuration loading and validation."""

import json
import tempfile
from pathlib import Path

import pytest

from aegis.config.policy_loader import (
    export_default_policy_json,
    load_policy_from_json,
    validate_policy_config,
)
from aegis.config.risk_policy import RiskPolicy, RoutingPolicy


def test_load_policy_from_json_valid(tmp_path: Path) -> None:
    """Test loading a valid policy JSON file."""
    policy_file = tmp_path / "policy.json"
    policy_data = {
        "risk_policy": {
            "signal_weights": {"otp_request": 6, "credential_request": 6},
            "strength_multipliers": {"strong": 3, "moderate": 2, "weak": 1},
            "suspicious_threshold": 4,
            "high_risk_threshold": 12,
        },
        "routing_policy": {
            "minimum_evidence_items_to_resolve": 2,
            "decisive_signals": ["otp_request", "credential_request"],
        },
    }
    policy_file.write_text(json.dumps(policy_data))

    risk_policy, routing_policy = load_policy_from_json(policy_file)

    assert isinstance(risk_policy, RiskPolicy)
    assert isinstance(routing_policy, RoutingPolicy)
    assert risk_policy.signal_weights["otp_request"] == 6
    assert risk_policy.high_risk_threshold == 12
    assert "otp_request" in routing_policy.decisive_signals


def test_load_policy_from_json_missing_file(tmp_path: Path) -> None:
    """Test error handling for missing policy file."""
    with pytest.raises(FileNotFoundError):
        load_policy_from_json(tmp_path / "nonexistent.json")


def test_load_policy_from_json_invalid_json(tmp_path: Path) -> None:
    """Test error handling for invalid JSON."""
    policy_file = tmp_path / "bad.json"
    policy_file.write_text("{invalid json content")

    with pytest.raises(ValueError):
        load_policy_from_json(policy_file)


def test_load_policy_from_json_missing_risk_policy(tmp_path: Path) -> None:
    """Test error handling for missing risk_policy section."""
    policy_file = tmp_path / "policy.json"
    policy_file.write_text('{"routing_policy": {}}')

    with pytest.raises(ValueError, match="risk_policy"):
        load_policy_from_json(policy_file)


def test_load_policy_from_json_missing_signal_weights(tmp_path: Path) -> None:
    """Test error handling for missing signal_weights."""
    policy_file = tmp_path / "policy.json"
    policy_data = {
        "risk_policy": {
            "strength_multipliers": {"strong": 3, "moderate": 2, "weak": 1},
            "suspicious_threshold": 4,
            "high_risk_threshold": 12,
        }
    }
    policy_file.write_text(json.dumps(policy_data))

    with pytest.raises(ValueError, match="signal_weights"):
        load_policy_from_json(policy_file)


def test_validate_policy_config_valid(tmp_path: Path) -> None:
    """Test validation of a valid policy file."""
    policy_file = tmp_path / "policy.json"
    policy_data = {
        "risk_policy": {
            "signal_weights": {"otp_request": 6},
            "strength_multipliers": {"strong": 3, "moderate": 2, "weak": 1},
            "suspicious_threshold": 4,
            "high_risk_threshold": 12,
        },
        "routing_policy": {
            "minimum_evidence_items_to_resolve": 2,
            "decisive_signals": ["otp_request"],
        },
    }
    policy_file.write_text(json.dumps(policy_data))

    assert validate_policy_config(policy_file) is True


def test_validate_policy_config_invalid_thresholds(tmp_path: Path) -> None:
    """Test detection of invalid threshold ordering."""
    policy_file = tmp_path / "policy.json"
    policy_data = {
        "risk_policy": {
            "signal_weights": {"otp_request": 6},
            "strength_multipliers": {"strong": 3, "moderate": 2, "weak": 1},
            "suspicious_threshold": 15,
            "high_risk_threshold": 12,  # Invalid: suspicious >= high_risk
        },
        "routing_policy": {
            "minimum_evidence_items_to_resolve": 2,
            "decisive_signals": [],
        },
    }
    policy_file.write_text(json.dumps(policy_data))

    assert validate_policy_config(policy_file) is False


def test_validate_policy_config_unknown_decisive_signal(tmp_path: Path) -> None:
    """Test detection of decisive signals not in signal_weights."""
    policy_file = tmp_path / "policy.json"
    policy_data = {
        "risk_policy": {
            "signal_weights": {"otp_request": 6},
            "strength_multipliers": {"strong": 3, "moderate": 2, "weak": 1},
            "suspicious_threshold": 4,
            "high_risk_threshold": 12,
        },
        "routing_policy": {
            "minimum_evidence_items_to_resolve": 2,
            "decisive_signals": ["otp_request", "unknown_signal"],
        },
    }
    policy_file.write_text(json.dumps(policy_data))

    assert validate_policy_config(policy_file) is False


def test_export_default_policy_json(tmp_path: Path) -> None:
    """Test exporting default policy to JSON file."""
    output_file = tmp_path / "exported_policy.json"

    export_default_policy_json(output_file)

    assert output_file.exists()
    data = json.loads(output_file.read_text())
    assert "risk_policy" in data
    assert "routing_policy" in data
    assert "signal_weights" in data["risk_policy"]
    assert "strength_multipliers" in data["risk_policy"]
    assert data["risk_policy"]["high_risk_threshold"] >= data["risk_policy"]["suspicious_threshold"]


def test_policy_export_and_reload_consistency(tmp_path: Path) -> None:
    """Test that exported policy can be reloaded and produces same results."""
    from aegis.config.risk_policy import DEFAULT_RISK_POLICY, DEFAULT_ROUTING_POLICY

    export_file = tmp_path / "policy.json"
    export_default_policy_json(export_file)

    reloaded_risk, reloaded_routing = load_policy_from_json(export_file)

    # Compare policies
    assert reloaded_risk.signal_weights == DEFAULT_RISK_POLICY.signal_weights
    assert reloaded_risk.strength_multipliers == DEFAULT_RISK_POLICY.strength_multipliers
    assert reloaded_risk.suspicious_threshold == DEFAULT_RISK_POLICY.suspicious_threshold
    assert reloaded_risk.high_risk_threshold == DEFAULT_RISK_POLICY.high_risk_threshold
    assert reloaded_routing.decisive_signals == DEFAULT_ROUTING_POLICY.decisive_signals
