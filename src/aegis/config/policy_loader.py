"""Load and validate risk policies from JSON configuration files.

Allows users to customize signal weights, thresholds, and routing without
modifying source code. Uses only the Python standard library.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from aegis.config.risk_policy import RiskPolicy, RoutingPolicy


def load_policy_from_json(json_path: Path) -> tuple[RiskPolicy, RoutingPolicy]:
    """Load risk and routing policies from a JSON configuration file.
    
    Expected JSON structure:
    
    {
      "risk_policy": {
        "signal_weights": {
          "otp_request": 6,
          "credential_request": 6,
          "payment_request": 5,
          ...
        },
        "strength_multipliers": {
          "strong": 3,
          "moderate": 2,
          "weak": 1
        },
        "suspicious_threshold": 4,
        "high_risk_threshold": 12
      },
      "routing_policy": {
        "minimum_evidence_items_to_resolve": 2,
        "decisive_signals": [
          "otp_request",
          "credential_request",
          ...
        ]
      }
    }
    """

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Policy file not found: {json_path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in policy file: {e}")

    if not isinstance(config, dict):
        raise ValueError("Policy file must contain a JSON object at root")

    # Parse risk policy
    risk_config = config.get("risk_policy", {})
    if not risk_config:
        raise ValueError("Policy file must contain 'risk_policy' section")

    signal_weights = risk_config.get("signal_weights", {})
    if not signal_weights:
        raise ValueError("risk_policy must contain 'signal_weights'")

    strength_multipliers_input = risk_config.get("strength_multipliers", {})
    strength_multipliers = {
        strength: int(mult) for strength, mult in strength_multipliers_input.items()
    }

    risk_policy = RiskPolicy(
        signal_weights={signal: int(weight) for signal, weight in signal_weights.items()},
        strength_multipliers=strength_multipliers,
        suspicious_threshold=int(risk_config.get("suspicious_threshold", 4)),
        high_risk_threshold=int(risk_config.get("high_risk_threshold", 12)),
    )

    # Parse routing policy
    routing_config = config.get("routing_policy", {})
    routing_policy = RoutingPolicy(
        minimum_evidence_items_to_resolve=int(
            routing_config.get("minimum_evidence_items_to_resolve", 2)
        ),
        decisive_signals=frozenset(routing_config.get("decisive_signals", [])),
    )

    return risk_policy, routing_policy


def validate_policy_config(json_path: Path) -> bool:
    """Validate a policy configuration file without loading it into the system.
    
    Returns True if valid, prints validation results to stdout/stderr.
    """

    try:
        risk_policy, routing_policy = load_policy_from_json(json_path)
    except (FileNotFoundError, ValueError, KeyError) as e:
        print(f"Policy validation failed: {e}", file=sys.stderr)
        return False

    # Check for consistency
    errors = []

    if risk_policy.suspicious_threshold >= risk_policy.high_risk_threshold:
        errors.append(
            f"suspicious_threshold ({risk_policy.suspicious_threshold}) "
            f">= high_risk_threshold ({risk_policy.high_risk_threshold})"
        )

    for signal in routing_policy.decisive_signals:
        if signal not in risk_policy.signal_weights:
            errors.append(f"Decisive signal '{signal}' not in signal_weights")

    if errors:
        print("Policy validation errors:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return False

    print(f"✓ Policy file is valid ({json_path})")
    print(f"  - {len(risk_policy.signal_weights)} signals configured")
    print(
        f"  - Thresholds: SUSPICIOUS >= {risk_policy.suspicious_threshold}, "
        f"HIGH_RISK >= {risk_policy.high_risk_threshold}"
    )
    print(f"  - {len(routing_policy.decisive_signals)} decisive signals")

    return True


def export_default_policy_json(output_path: Path) -> None:
    """Export the current default policy to a JSON file for reference/customization."""

    from aegis.config.risk_policy import DEFAULT_RISK_POLICY, DEFAULT_ROUTING_POLICY

    policy = DEFAULT_RISK_POLICY
    routing = DEFAULT_ROUTING_POLICY

    config = {
        "risk_policy": {
            "signal_weights": dict(policy.signal_weights),
            "strength_multipliers": dict(policy.strength_multipliers),
            "suspicious_threshold": policy.suspicious_threshold,
            "high_risk_threshold": policy.high_risk_threshold,
        },
        "routing_policy": {
            "minimum_evidence_items_to_resolve": routing.minimum_evidence_items_to_resolve,
            "decisive_signals": sorted(routing.decisive_signals),
        },
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    print(f"✓ Default policy exported to {output_path}")
