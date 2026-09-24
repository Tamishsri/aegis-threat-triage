"""No-op-safe semantic-analysis interface; no generative model is used."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from aegis.evidence.models import Evidence


class SemanticBackendUnavailable(RuntimeError):
    """Raised when Stage 1 has no installed, verified local implementation."""


@dataclass(frozen=True, slots=True)
class SemanticAnalysisResult:
    evidence: tuple[Evidence, ...]
    backend_name: str


class SemanticAnalyzer(ABC):
    """Future compact local encoder/classifier contract.

    An implementation must return structured evidence only. It must not decide
    the risk state or overwrite evidence already present in the ledger.
    """

    @property
    @abstractmethod
    def is_available(self) -> bool:
        pass

    @property
    @abstractmethod
    def unavailable_reason(self) -> str | None:
        pass

    @abstractmethod
    def analyze(self, text: str) -> SemanticAnalysisResult:
        pass


class UnavailableSemanticAnalyzer(SemanticAnalyzer):
    """Honest default until a compact local model is evaluated and installed."""

    @property
    def is_available(self) -> bool:
        return False

    @property
    def unavailable_reason(self) -> str:
        return "No verified local semantic model is installed in this first-pass build."

    def analyze(self, text: str) -> SemanticAnalysisResult:
        raise SemanticBackendUnavailable(self.unavailable_reason)
