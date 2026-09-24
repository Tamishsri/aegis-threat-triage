"""Static-only file analysis; submitted files are never executed."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


class MalwareClassifierUnavailable(RuntimeError):
    """Raised until a verified ClaMP-compatible classifier is supplied."""


@dataclass(frozen=True, slots=True)
class StaticAnalysisResult:
    path: Path
    file_size: int
    is_pe: bool
    pe_signature_valid: bool
    features: Mapping[str, int | bool]


@dataclass(frozen=True, slots=True)
class MalwarePrediction:
    label: str
    explanation: str


class StaticFileAnalyzer(ABC):
    """A static parser interface. Implementations must not execute input files."""

    @abstractmethod
    def analyze(self, path: str | Path) -> StaticAnalysisResult:
        pass


class MalwareClassifier(ABC):
    """Supporting-evidence model seam for a future ClaMP classifier."""

    @abstractmethod
    def predict(self, features: Mapping[str, int | bool]) -> MalwarePrediction:
        pass

    @abstractmethod
    def explain(self, features: Mapping[str, int | bool]) -> str:
        pass


class HeaderOnlyPEAnalyzer(StaticFileAnalyzer):
    """Safe static preflight that reads PE headers and runs no submitted code.

    This is intentionally not a malware classifier or a full PE feature parser.
    It provides a tested insertion point for later static feature extraction.
    """

    def analyze(self, path: str | Path) -> StaticAnalysisResult:
        target = Path(path)
        size = target.stat().st_size
        with target.open("rb") as submitted_file:
            header = submitted_file.read(64)
            has_mz_header = header.startswith(b"MZ")
            pe_offset = 0
            has_pe_signature = False
            if has_mz_header and len(header) >= 64:
                pe_offset = int.from_bytes(header[60:64], byteorder="little", signed=False)
                submitted_file.seek(pe_offset)
                has_pe_signature = submitted_file.read(4) == b"PE\x00\x00"

        return StaticAnalysisResult(
            path=target,
            file_size=size,
            is_pe=has_mz_header,
            pe_signature_valid=has_pe_signature,
            features={
                "has_mz_header": has_mz_header,
                "has_valid_pe_signature": has_pe_signature,
                "pe_header_offset": pe_offset,
            },
        )


class UnavailableMalwareClassifier(MalwareClassifier):
    """Honest default until a validated model artifact is provided."""

    _reason = "No validated ClaMP-compatible malware classifier is installed in this first-pass build."

    def predict(self, features: Mapping[str, int | bool]) -> MalwarePrediction:
        raise MalwareClassifierUnavailable(self._reason)

    def explain(self, features: Mapping[str, int | bool]) -> str:
        raise MalwareClassifierUnavailable(self._reason)
