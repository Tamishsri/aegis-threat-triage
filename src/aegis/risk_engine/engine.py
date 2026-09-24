"""Transparent risk assessment derived only from retained evidence."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from aegis.config.risk_policy import DEFAULT_RISK_POLICY, RiskPolicy
from aegis.evidence.ledger import EvidenceLedger
from aegis.evidence.models import Evidence


class RiskState(StrEnum):
    LOW_RISK = "LOW_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


@dataclass(frozen=True, slots=True)
class RiskContribution:
    """A reviewable policy contribution, not a model confidence value."""

    evidence_id: str
    signal: str
    policy_points: int


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    state: RiskState
    contributions: tuple[RiskContribution, ...]
    policy_total: int
    rationale: str


class RiskEngine:
    """Apply one explicit policy to a provenance-preserving evidence ledger."""

    def __init__(self, policy: RiskPolicy = DEFAULT_RISK_POLICY) -> None:
        self._policy = policy

    def assess(self, ledger: EvidenceLedger, *, allow_low_risk: bool = False) -> RiskAssessment:
        """Produce a deterministic assessment.

        ``allow_low_risk`` is only set by a caller that has an explicit benign
        Stage 0 disposition. An empty ledger alone always means insufficient
        evidence, never safe.
        """

        contributions = tuple(self._contribution(item) for item in ledger)
        scored = tuple(item for item in contributions if item.policy_points > 0)
        total = sum(item.policy_points for item in scored)

        if total >= self._policy.high_risk_threshold:
            return RiskAssessment(
                RiskState.HIGH_RISK,
                scored,
                total,
                "Strong or combined indicators reached the high-risk policy threshold.",
            )
        if total >= self._policy.suspicious_threshold:
            return RiskAssessment(
                RiskState.SUSPICIOUS,
                scored,
                total,
                "Observed indicators warrant caution under the current policy.",
            )
        if not scored and allow_low_risk:
            return RiskAssessment(
                RiskState.LOW_RISK,
                (),
                0,
                "An explicitly benign deterministic context contained no meaningful known indicators; this is not a guarantee of safety.",
            )
        return RiskAssessment(
            RiskState.INSUFFICIENT_EVIDENCE,
            scored,
            total,
            "The retained evidence does not meet the current policy threshold for a stronger assessment.",
        )

    def _contribution(self, evidence: Evidence) -> RiskContribution:
        base_weight = self._policy.signal_weights.get(evidence.signal, 0)
        multiplier = self._policy.strength_multipliers[evidence.strength]
        return RiskContribution(
            evidence_id=evidence.id,
            signal=evidence.signal,
            policy_points=base_weight * multiplier,
        )
