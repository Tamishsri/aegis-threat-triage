"""Results produced by Stage 0 deterministic screening."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from aegis.evidence.models import Evidence


class ScreeningReason(StrEnum):
    DECISIVE_EVIDENCE = "decisive_deterministic_evidence"
    MULTIPLE_SIGNALS = "multiple_deterministic_signals"
    EXPLICIT_BENIGN_CONTEXT = "explicit_benign_context"
    SEMANTIC_ANALYSIS_REQUIRED = "semantic_analysis_required"


@dataclass(frozen=True, slots=True)
class ScreeningResult:
    """Stage 0 output, intentionally separate from a safety verdict."""

    resolved: bool
    evidence: tuple[Evidence, ...]
    reason: ScreeningReason

    @property
    def requires_semantic_analysis(self) -> bool:
        return not self.resolved
