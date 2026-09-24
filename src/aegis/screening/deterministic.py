"""Stage 0 deterministic text screening for observable threat indicators."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern

from aegis.config.risk_policy import DEFAULT_ROUTING_POLICY, RoutingPolicy
from aegis.evidence.models import Evidence, EvidenceSource, EvidenceStrength
from aegis.screening.models import ScreeningReason, ScreeningResult
from aegis.screening.urls import inspect_urls

REQUEST_VERBS = r"(?:send|share|provide|give|reply(?:\s+with)?|enter|confirm|verify|forward|tell(?:\s+me)?|submit|upload|attach)"
OTP_TERMS = r"(?:otp|one[ -]?time(?:\s+(?:password|passcode|code))?|verification\s+code|security\s+code|authentication\s+code)"
CREDENTIAL_TERMS = r"(?:password|passcode|username|login\s+details|credentials?|ssn|social\s+security)"
PAYMENT_TERMS = r"(?:payment|pay(?:ment)?|transfer|wire(?:\s+transfer)?|upi|gift\s+card|card\s+number|bank\s+account|bitcoin|crypto)"


@dataclass(frozen=True, slots=True)
class _SignalRule:
    signal: str
    pattern: Pattern[str]
    strength: EvidenceStrength
    details: str


def _compile(expression: str) -> Pattern[str]:
    return re.compile(expression, re.IGNORECASE | re.DOTALL)


RULES: tuple[_SignalRule, ...] = (
    _SignalRule(
        "otp_request",
        _compile(rf"\b{REQUEST_VERBS}\b.{{0,80}}?\b{OTP_TERMS}\b"),
        EvidenceStrength.STRONG,
        "A request to provide a one-time verification code was detected.",
    ),
    _SignalRule(
        "credential_request",
        _compile(rf"\b{REQUEST_VERBS}\b.{{0,80}}?\b{CREDENTIAL_TERMS}\b"),
        EvidenceStrength.STRONG,
        "A request to provide login credentials was detected.",
    ),
    _SignalRule(
        "payment_request",
        _compile(rf"\b{REQUEST_VERBS}\b.{{0,80}}?\b{PAYMENT_TERMS}\b|\bpay\s+(?:now|immediately|today)\b"),
        EvidenceStrength.STRONG,
        "A request to make or arrange a payment was detected.",
    ),
    _SignalRule(
        "refund_scam",
        _compile(r"\b(?:refund|rebate|compensation|reimburse|return\s+your\s+money)\b.*?(?:click|confirm|verify|submit|reply)\b"),
        EvidenceStrength.STRONG,
        "Language combining refund/compensation with action requests was detected.",
    ),
    _SignalRule(
        "prize_lottery_scam",
        _compile(r"\b(?:you\s+(?:have|won|been\s+selected|are|eligible)|claim\s+(?:your|a))\s+(?:won|prize|reward|jackpot|lottery|drawing)\b"),
        EvidenceStrength.STRONG,
        "Unsolicited prize or lottery claim language was detected.",
    ),
    _SignalRule(
        "account_verification",
        _compile(r"\b(?:verify\s+(?:your|account)|confirm\s+(?:your|account)|validate\s+(?:your|account)|reactivate\s+(?:your|account))\b"),
        EvidenceStrength.MODERATE,
        "Account verification or reactivation request language was detected.",
    ),
    _SignalRule(
        "urgency",
        _compile(r"\b(?:urgent(?:ly)?|immediately|right\s+away|act\s+now|final\s+warning|today\s+only|expir(?:ing|es)?|within\s+\d+\s+(?:minutes?|hours?|days?)|don't\s+wait|hurry)\b"),
        EvidenceStrength.MODERATE,
        "Urgency language was detected.",
    ),
    _SignalRule(
        "account_threat",
        _compile(r"\b(?:account\s+(?:will\s+be|has\s+been|is)\s+(?:suspended|locked|disabled|closed|limited|compromised|terminated)|(?:suspend|lock|disable|close)\s+.{0,30}?\baccount|access\s+(?:denied|restricted))\b"),
        EvidenceStrength.MODERATE,
        "Language threatening an account consequence was detected.",
    ),
    _SignalRule(
        "identity_impersonation",
        _compile(r"\b(?:this\s+is|i\s+am|we\s+are)\s+(?:from|with)\s+(?:your\s+)?(?:bank|support|security\s+team|microsoft|google|amazon|paypal|government|police|tax\s+department|revenue|customs)\b"),
        EvidenceStrength.MODERATE,
        "A claim of authority or organizational identity was detected.",
    ),
    _SignalRule(
        "suspicious_instruction",
        _compile(r"\b(?:disable\s+(?:security|antivirus|defender|virus\s+protection)|install\s+(?:this|the)\s+(?:app|application)|download\s+(?:and\s+)?(?:run|open|execute)|enable\s+(?:macros?|unknown\s+sources?|remote\s+access))\b"),
        EvidenceStrength.STRONG,
        "An instruction that could reduce security controls or run untrusted content was detected.",
    ),
    _SignalRule(
        "attachment_request",
        _compile(r"\b(?:upload|attach|send)\b.{0,60}?\b(?:attachment|file|document|screenshot|photo|image|receipt|invoice|proof)"),
        EvidenceStrength.MODERATE,
        "A request to upload or send an attachment or file was detected.",
    ),
)

MANIPULATION_RULES: tuple[_SignalRule, ...] = (
    _SignalRule(
        "manipulation_attempt",
        _compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|earlier)\s+instructions\b"),
        EvidenceStrength.STRONG,
        "An attempt to override prior instructions was detected.",
    ),
    _SignalRule(
        "manipulation_attempt",
        _compile(r"\bdisregard\s+(?:the\s+)?(?:above|previous|prior)(?:\s+instructions)?\b"),
        EvidenceStrength.STRONG,
        "An attempt to disregard prior context or instructions was detected.",
    ),
    _SignalRule(
        "manipulation_attempt",
        _compile(r"\b(?:mark|say|declare|classify)\s+(?:this|it)\s+(?:(?:as|is)\s+)?safe\b"),
        EvidenceStrength.STRONG,
        "An attempt to influence the assessment outcome was detected.",
    ),
    _SignalRule(
        "manipulation_attempt",
        _compile(r"\boverride\s+(?:your\s+)?(?:rules|safety|instructions)\b"),
        EvidenceStrength.STRONG,
        "An attempt to override system rules was detected.",
    ),
    _SignalRule(
        "manipulation_attempt",
        _compile(r"\b(?:don't|do\s+not)\s+(?:filter|flag|block|quarantine|block)\b"),
        EvidenceStrength.STRONG,
        "An attempt to suppress content moderation or filtering was detected.",
    ),
    _SignalRule(
        "manipulation_attempt",
        _compile(r"\b(?:this|it)\s+(?:is\s+)?(?:not|isn't)\s+(?:spam|phishing|malicious|scam)\b"),
        EvidenceStrength.MODERATE,
        "Preemptive reassurance about malicious classification was detected.",
    ),
    _SignalRule(
        "manipulation_attempt",
        _compile(r"\b(?:trust\s+(?:me|this|us)|you\s+can\s+trust)\b"),
        EvidenceStrength.MODERATE,
        "A request to override caution or trust judgment was detected.",
    ),
)

CLEAR_BENIGN_CONTEXT = _compile(
    r"\b(?:meeting\s+agenda|project\s+update|class\s+assignment|calendar\s+invitation|lunch\s+plans|team\s+minutes)\b"
)


class DeterministicTextScreener:
    """Cheap Stage 0 rules that emit evidence rather than a safety claim."""

    def __init__(self, routing_policy: RoutingPolicy = DEFAULT_ROUTING_POLICY) -> None:
        self._routing_policy = routing_policy

    def screen(
        self, text: str, *, source: EvidenceSource = EvidenceSource.TEXT
    ) -> ScreeningResult:
        if not isinstance(text, str):
            raise TypeError("Text screening requires a string.")

        evidence = [
            *self._find_evidence(text, RULES, source),
            *self._find_evidence(text, MANIPULATION_RULES, source),
        ]
        evidence.extend(inspect_urls(text, source=source))
        evidence = _deduplicate(evidence)

        if any(
            item.signal in self._routing_policy.decisive_signals
            and item.strength is EvidenceStrength.STRONG
            for item in evidence
        ):
            return ScreeningResult(True, tuple(evidence), ScreeningReason.DECISIVE_EVIDENCE)
        if len(evidence) >= self._routing_policy.minimum_evidence_items_to_resolve:
            return ScreeningResult(True, tuple(evidence), ScreeningReason.MULTIPLE_SIGNALS)
        if not evidence and CLEAR_BENIGN_CONTEXT.search(text):
            return ScreeningResult(True, (), ScreeningReason.EXPLICIT_BENIGN_CONTEXT)
        return ScreeningResult(False, tuple(evidence), ScreeningReason.SEMANTIC_ANALYSIS_REQUIRED)

    @staticmethod
    def _find_evidence(
        text: str, rules: tuple[_SignalRule, ...], source: EvidenceSource
    ) -> list[Evidence]:
        found: list[Evidence] = []
        for rule in rules:
            for match in rule.pattern.finditer(text):
                found.append(
                    Evidence(
                        source=source,
                        signal=rule.signal,
                        strength=rule.strength,
                        extractor="deterministic_screening",
                        details=rule.details,
                        span=(match.start(), match.end()),
                    )
                )
                break  # One occurrence per rule is enough for the initial policy.
        return found


def _deduplicate(evidence: list[Evidence]) -> list[Evidence]:
    seen: set[tuple[str, tuple[int, int] | None]] = set()
    unique: list[Evidence] = []
    for item in evidence:
        key = (item.signal, item.span)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique
