from __future__ import annotations

from aegis.evidence import Evidence, EvidenceLedger, EvidenceSource, EvidenceStrength
from aegis.risk_engine import RiskEngine, RiskState


def _evidence(signal: str, strength: EvidenceStrength) -> Evidence:
    return Evidence(
        source=EvidenceSource.TEXT,
        signal=signal,
        strength=strength,
        extractor="test",
        details=f"Test evidence for {signal}.",
    )


def test_high_risk_for_strong_otp_request() -> None:
    assessment = RiskEngine().assess(EvidenceLedger([_evidence("otp_request", EvidenceStrength.STRONG)]))

    assert assessment.state is RiskState.HIGH_RISK
    assert assessment.policy_total >= 12


def test_suspicious_for_contextual_indicators_that_reach_policy_threshold() -> None:
    ledger = EvidenceLedger(
        [
            _evidence("account_threat", EvidenceStrength.MODERATE),
            _evidence("urgency", EvidenceStrength.MODERATE),
        ]
    )
    assessment = RiskEngine().assess(ledger)

    assert assessment.state is RiskState.SUSPICIOUS


def test_ambiguous_or_empty_ledger_is_insufficient_by_default() -> None:
    engine = RiskEngine()

    assert engine.assess(EvidenceLedger()).state is RiskState.INSUFFICIENT_EVIDENCE
    assert engine.assess(EvidenceLedger([_evidence("urgency", EvidenceStrength.WEAK)])).state is RiskState.INSUFFICIENT_EVIDENCE


def test_low_risk_requires_explicit_benign_disposition() -> None:
    assessment = RiskEngine().assess(EvidenceLedger(), allow_low_risk=True)

    assert assessment.state is RiskState.LOW_RISK
    assert "not" in assessment.rationale.casefold()
