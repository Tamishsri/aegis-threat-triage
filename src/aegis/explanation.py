"""Template-based explanations and actions derived from structured evidence."""

from __future__ import annotations

from dataclasses import dataclass

from aegis.evidence.ledger import EvidenceLedger
from aegis.risk_engine import RiskAssessment, RiskState

SIGNAL_LABELS = {
    "otp_request": "an OTP request",
    "credential_request": "a credential request",
    "payment_request": "a payment request",
    "manipulation_attempt": "a manipulation attempt",
    "suspicious_instruction": "a suspicious instruction",
    "url_embedded_credentials": "a URL with embedded credentials",
    "url_ip_host": "a URL using an IP-address host",
    "url_punycode": "an IDN/punycode URL",
    "brand_domain_mismatch": "a brand/domain mismatch",
    "url_shortener": "a shortened URL",
    "unusual_subdomain": "an unusual subdomain structure",
    "suspicious_url_path": "a security-themed URL path",
    "account_threat": "account-threat language",
    "identity_impersonation": "an identity/authority claim",
    "urgency": "urgency language",
}


@dataclass(frozen=True, slots=True)
class Explanation:
    summary: str
    recommended_actions: tuple[str, ...]


class ExplanationBuilder:
    """Build fixed templates; no generative model can change the verdict."""

    def build(self, assessment: RiskAssessment, ledger: EvidenceLedger) -> Explanation:
        labels = _labels_for_assessment(assessment, ledger)
        joined = _join_labels(labels)

        if assessment.state is RiskState.HIGH_RISK:
            return Explanation(
                summary=(
                    f"This content is high risk because it includes {joined}."
                    if joined
                    else "This content is high risk under the current evidence policy."
                ),
                recommended_actions=_high_risk_actions(ledger),
            )
        if assessment.state is RiskState.SUSPICIOUS:
            return Explanation(
                summary=(
                    f"This content is suspicious because it includes {joined}."
                    if joined
                    else "This content is suspicious under the current evidence policy."
                ),
                recommended_actions=(
                    "Pause before responding, clicking, paying, or opening an attachment.",
                    "Verify the request through a known official channel you find independently.",
                ),
            )
        if assessment.state is RiskState.LOW_RISK:
            return Explanation(
                summary=(
                    "No meaningful risk indicators were detected within AEGIS's current "
                    "evidence vocabulary. This is not a guarantee that the content is safe."
                ),
                recommended_actions=(
                    "Continue to use normal caution with unexpected requests or links.",
                    "Verify independently before sharing sensitive information.",
                ),
            )
        if labels:
            detail = f"AEGIS observed {joined}, but "
        else:
            detail = "AEGIS did not find enough reliable evidence, and "
        return Explanation(
            summary=(
                detail
                + "does not have enough reliable evidence within its current local "
                "analysis vocabulary for a stronger assessment. This is not a safety guarantee."
            ),
            recommended_actions=(
                "Treat unexpected content cautiously and do not act on sensitive requests yet.",
                "Verify the request through an independently obtained official channel.",
            ),
        )


def _labels_for_assessment(assessment: RiskAssessment, ledger: EvidenceLedger) -> tuple[str, ...]:
    contribution_ids = {contribution.evidence_id for contribution in assessment.contributions}
    labels: list[str] = []
    for evidence in ledger:
        if evidence.id not in contribution_ids:
            continue
        label = SIGNAL_LABELS.get(evidence.signal, evidence.signal.replace("_", " "))
        if label not in labels:
            labels.append(label)
    return tuple(labels[:3])


def _join_labels(labels: tuple[str, ...]) -> str:
    if not labels:
        return ""
    if len(labels) == 1:
        return labels[0]
    if len(labels) == 2:
        return f"{labels[0]} and {labels[1]}"
    return f"{', '.join(labels[:-1])}, and {labels[-1]}"


def _high_risk_actions(ledger: EvidenceLedger) -> tuple[str, ...]:
    signals = {item.signal for item in ledger}
    actions: list[str] = ["Do not respond, click links, open attachments, or continue the requested action."]
    if {"otp_request", "credential_request"} & signals:
        actions.append("Do not share passwords, credentials, or one-time verification codes.")
    if "payment_request" in signals:
        actions.append("Do not send money or payment details in response to this request.")
    actions.append("Verify through an official channel you locate independently.")
    return tuple(actions)
