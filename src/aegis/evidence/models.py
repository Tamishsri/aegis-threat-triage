"""Immutable evidence records shared by every AEGIS analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4


class EvidenceStrength(StrEnum):
    """Qualitative evidence strength, intentionally not a confidence score."""

    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"


class EvidenceSource(StrEnum):
    TEXT = "text"
    VOICE = "voice"
    FILE = "file"


@dataclass(frozen=True, slots=True)
class Evidence:
    """An immutable observation with enough provenance for later review."""

    source: EvidenceSource
    signal: str
    strength: EvidenceStrength
    extractor: str
    details: str
    span: tuple[int, int] | None = None
    id: str = field(default_factory=lambda: str(uuid4()))
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.signal.strip():
            raise ValueError("Evidence signal must not be empty.")
        if not self.extractor.strip():
            raise ValueError("Evidence extractor must not be empty.")
        if not self.details.strip():
            raise ValueError("Evidence details must not be empty.")
        if self.span is not None:
            start, end = self.span
            if start < 0 or end < start:
                raise ValueError("Evidence span must be a non-negative (start, end) pair.")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation without invented confidence."""

        return {
            "id": self.id,
            "source": self.source.value,
            "signal": self.signal,
            "strength": self.strength.value,
            "extractor": self.extractor,
            "details": self.details,
            "span": list(self.span) if self.span is not None else None,
            "observed_at": self.observed_at.isoformat(),
        }
