"""End-to-end local text triage: observation to evidence to action."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aegis.backends import CPUBackend, InferenceBackend
from aegis.evidence import EvidenceLedger, EvidenceSource
from aegis.explanation import Explanation, ExplanationBuilder
from aegis.risk_engine import RiskAssessment, RiskEngine
from aegis.screening import DeterministicTextScreener, ScreeningResult
from aegis.screening.models import ScreeningReason
from aegis.semantic import SemanticAnalyzer, UnavailableSemanticAnalyzer


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """A reviewable end-to-end result without retaining input outside the caller."""

    source: EvidenceSource
    screening: ScreeningResult
    ledger: EvidenceLedger
    assessment: RiskAssessment
    explanation: Explanation
    stage_1_requested: bool
    stage_1_invoked: bool
    semantic_status: str
    execution_backend: str
    network_status: str = "Offline"

    @property
    def evidence(self) -> tuple:
        return self.ledger.items

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source.value,
            "routing": {
                "stage_0_resolved": self.screening.resolved,
                "stage_0_reason": self.screening.reason.value,
                "stage_1_requested": self.stage_1_requested,
                "stage_1_invoked": self.stage_1_invoked,
                "semantic_status": self.semantic_status,
            },
            "risk": {
                "state": self.assessment.state.value,
                "rationale": self.assessment.rationale,
                "policy_total": self.assessment.policy_total,
                "contributions": [
                    {
                        "evidence_id": contribution.evidence_id,
                        "signal": contribution.signal,
                        "policy_points": contribution.policy_points,
                    }
                    for contribution in self.assessment.contributions
                ],
            },
            "explanation": {
                "summary": self.explanation.summary,
                "recommended_actions": list(self.explanation.recommended_actions),
            },
            "evidence": [item.to_dict() for item in self.ledger],
            "system": {
                "local_analysis": True,
                "network": self.network_status,
                "ai_acceleration": self.execution_backend,
            },
        }


class TextTriagePipeline:
    """The first working AEGIS pipeline, intentionally CPU-first and offline."""

    def __init__(
        self,
        *,
        screener: DeterministicTextScreener | None = None,
        risk_engine: RiskEngine | None = None,
        explanation_builder: ExplanationBuilder | None = None,
        semantic_analyzer: SemanticAnalyzer | None = None,
        backend: InferenceBackend | None = None,
    ) -> None:
        self._screener = screener or DeterministicTextScreener()
        self._risk_engine = risk_engine or RiskEngine()
        self._explanation_builder = explanation_builder or ExplanationBuilder()
        self._semantic_analyzer = semantic_analyzer or UnavailableSemanticAnalyzer()
        self._backend = backend or CPUBackend()

    def analyze(self, text: str, *, source: EvidenceSource = EvidenceSource.TEXT) -> AnalysisResult:
        """Analyze untrusted text without allowing it to control the verdict."""

        if not isinstance(text, str):
            raise TypeError("Text analysis requires a string.")

        screening = self._screener.screen(text, source=source)
        ledger = EvidenceLedger(screening.evidence)
        stage_1_requested = screening.requires_semantic_analysis
        stage_1_invoked = False

        if stage_1_requested and self._semantic_analyzer.is_available:
            semantic_result = self._semantic_analyzer.analyze(text)
            ledger.extend(semantic_result.evidence)
            stage_1_invoked = True
            semantic_status = f"completed via {semantic_result.backend_name}"
        elif stage_1_requested:
            semantic_status = f"unavailable: {self._semantic_analyzer.unavailable_reason}"
        else:
            semantic_status = "not requested"

        allow_low_risk = (
            screening.reason is ScreeningReason.EXPLICIT_BENIGN_CONTEXT and not ledger.items
        )
        assessment = self._risk_engine.assess(ledger, allow_low_risk=allow_low_risk)
        explanation = self._explanation_builder.build(assessment, ledger)

        return AnalysisResult(
            source=source,
            screening=screening,
            ledger=ledger,
            assessment=assessment,
            explanation=explanation,
            stage_1_requested=stage_1_requested,
            stage_1_invoked=stage_1_invoked,
            semantic_status=semantic_status,
            execution_backend=self._backend.acceleration_label,
        )
