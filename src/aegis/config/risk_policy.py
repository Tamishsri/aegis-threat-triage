"""Explicit engineering assumptions used by routing and risk assessment.

These values are deliberately not presented as learned probabilities or
calibrated confidence. They are centralized so they can be reviewed and
evaluated against a disclosed labelled set later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from aegis.evidence.models import EvidenceStrength


@dataclass(frozen=True)
class RiskPolicy:
    """Transparent weights and thresholds for the deterministic risk engine."""

    signal_weights: Mapping[str, int] = field(
        default_factory=lambda: {
            "otp_request": 6,
            "credential_request": 6,
            "payment_request": 5,
            "refund_scam": 5,
            "prize_lottery_scam": 5,
            "manipulation_attempt": 5,
            "suspicious_instruction": 4,
            "url_embedded_credentials": 4,
            "url_ip_host": 3,
            "url_punycode": 3,
            "brand_domain_mismatch": 3,
            "account_verification": 3,
            "url_shortener": 2,
            "account_threat": 2,
            "identity_impersonation": 2,
            "unusual_subdomain": 1,
            "suspicious_url_path": 1,
            "urgency": 1,
        }
    )
    strength_multipliers: Mapping[EvidenceStrength, int] = field(
        default_factory=lambda: {
            EvidenceStrength.STRONG: 3,
            EvidenceStrength.MODERATE: 2,
            EvidenceStrength.WEAK: 1,
        }
    )
    suspicious_threshold: int = 4
    high_risk_threshold: int = 12


@dataclass(frozen=True)
class RoutingPolicy:
    """Rules for deciding whether deterministic screening needs Stage 1.

    Routing is not a verdict. It only decides whether a future semantic backend
    could add useful interpretation.
    """

    decisive_signals: frozenset[str] = frozenset(
        {
            "otp_request",
            "credential_request",
            "payment_request",
            "refund_scam",
            "prize_lottery_scam",
            "manipulation_attempt",
            "suspicious_instruction",
            "url_embedded_credentials",
        }
    )
    minimum_evidence_items_to_resolve: int = 2


DEFAULT_RISK_POLICY = RiskPolicy()
DEFAULT_ROUTING_POLICY = RoutingPolicy()
