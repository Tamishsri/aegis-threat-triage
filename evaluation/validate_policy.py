"""Utility to validate and explain the risk policy configuration.

Helps users understand signal weights, thresholds, and routing decisions.
"""

from __future__ import annotations

import sys
from pathlib import Path

from aegis.config.risk_policy import DEFAULT_RISK_POLICY, DEFAULT_ROUTING_POLICY


def print_policy_summary() -> None:
    """Display the current risk policy configuration with explanations."""

    print("=" * 60)
    print("AEGIS RISK POLICY CONFIGURATION")
    print("=" * 60)
    print()

    policy = DEFAULT_RISK_POLICY
    routing = DEFAULT_ROUTING_POLICY

    # Signal weights
    print("SIGNAL WEIGHTS (contribution to policy points)")
    print("-" * 60)
    sorted_signals = sorted(policy.signal_weights.items(), key=lambda x: -x[1])
    for signal, weight in sorted_signals:
        strength_mult = {
            "STRONG": policy.strength_multipliers.get("strong", 1),
            "MODERATE": policy.strength_multipliers.get("moderate", 1),
            "WEAK": policy.strength_multipliers.get("weak", 1),
        }
        points_strong = weight * strength_mult["STRONG"]
        points_moderate = weight * strength_mult["MODERATE"]
        points_weak = weight * strength_mult["WEAK"]
        print(f"  {signal:30s} weight={weight:2d} "
              f"→ {points_strong:3d}pts(S) {points_moderate:2d}pts(M) {points_weak}pt(W)")
    print()

    # Thresholds
    print("THRESHOLDS (policy point accumulation)")
    print("-" * 60)
    print(f"  SUSPICIOUS threshold:   >= {policy.suspicious_threshold} points")
    print(f"  HIGH_RISK threshold:    >= {policy.high_risk_threshold} points")
    print()

    # Strength multipliers
    print("STRENGTH MULTIPLIERS (qualify signal contribution)")
    print("-" * 60)
    for strength, multiplier in sorted(policy.strength_multipliers.items()):
        print(f"  {strength:10s}: {multiplier}x weight")
    print()

    # Routing
    print("ROUTING POLICY (fast resolution rules)")
    print("-" * 60)
    print(f"  Minimum evidence items to resolve: {routing.minimum_evidence_items_to_resolve}")
    print(f"  Decisive signals (immediate HIGH_RISK):")
    for signal in sorted(routing.decisive_signals):
        print(f"    - {signal}")
    print()

    # Example calculations
    print("EXAMPLE CALCULATIONS")
    print("-" * 60)
    examples = [
        ("OTP request (STRONG)", {"otp_request": ("strong", 1)}),
        ("Credential request (STRONG)", {"credential_request": ("strong", 1)}),
        ("Account threat + Urgency", {"account_threat": ("moderate", 1), "urgency": ("moderate", 1)}),
        ("URL shortener + Brand mismatch", {"url_shortener": ("moderate", 1), "brand_domain_mismatch": ("moderate", 1)}),
    ]

    for description, signals in examples:
        total = 0
        for signal, (strength_name, count) in signals.items():
            weight = policy.signal_weights.get(signal, 0)
            strength_mult = policy.strength_multipliers.get(strength_name, 1)
            contribution = weight * strength_mult * count
            total += contribution
            print(f"  {signal} ({strength_name}): {weight} × {strength_mult} × {count} = {contribution}")
        
        risk_state = "HIGH_RISK" if total >= policy.high_risk_threshold else (
            "SUSPICIOUS" if total >= policy.suspicious_threshold else "LOW_RISK"
        )
        print(f"  Total: {total} points → {risk_state}")
        print()


def validate_policy() -> bool:
    """Validate policy for consistency and soundness.
    
    Returns True if policy is valid, False if issues found.
    """

    policy = DEFAULT_RISK_POLICY
    routing = DEFAULT_ROUTING_POLICY
    issues = []

    # Check threshold ordering
    if policy.suspicious_threshold >= policy.high_risk_threshold:
        issues.append(
            f"ERROR: suspicious_threshold ({policy.suspicious_threshold}) "
            f">= high_risk_threshold ({policy.high_risk_threshold})"
        )

    # Check threshold positivity
    if policy.suspicious_threshold <= 0:
        issues.append(f"WARNING: suspicious_threshold is {policy.suspicious_threshold} (should be > 0)")

    # Check signal weights are positive
    for signal, weight in policy.signal_weights.items():
        if weight <= 0:
            issues.append(f"ERROR: signal '{signal}' has non-positive weight {weight}")

    # Check strength multipliers are positive
    for strength, mult in policy.strength_multipliers.items():
        if mult <= 0:
            issues.append(f"ERROR: strength '{strength}' has non-positive multiplier {mult}")

    # Check decisive signals exist in weights
    for signal in routing.decisive_signals:
        if signal not in policy.signal_weights:
            issues.append(f"WARNING: decisive signal '{signal}' not in signal_weights")

    if issues:
        print("POLICY VALIDATION ISSUES")
        print("-" * 60)
        for issue in issues:
            print(f"  {issue}")
        return False

    print("POLICY VALIDATION")
    print("-" * 60)
    print("  ✓ No policy issues detected")
    return True


def main(argv: list[str] | None = None) -> int:
    """Display policy summary and validate configuration."""
    print()
    print_policy_summary()
    validate_policy()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
