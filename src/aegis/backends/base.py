"""Backend interfaces; no Qualcomm runtime is invented here."""

from __future__ import annotations

from abc import ABC, abstractmethod


class BackendUnavailable(RuntimeError):
    """Raised when a requested backend has no verified implementation."""


class InferenceBackend(ABC):
    """A backend capability used by future speech/semantic adapters."""

    name: str
    acceleration_label: str

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Whether a verified implementation is actually available."""

    @property
    @abstractmethod
    def unavailable_reason(self) -> str | None:
        """Explain unavailability without implying an integration exists."""

    def require_available(self) -> None:
        if not self.is_available:
            raise BackendUnavailable(self.unavailable_reason or f"{self.name} is unavailable.")


class CPUBackend(InferenceBackend):
    """The working local execution path for orchestration and rules."""

    name = "CPU"
    acceleration_label = "CPU"

    @property
    def is_available(self) -> bool:
        return True

    @property
    def unavailable_reason(self) -> str | None:
        return None


class QualcommBackend(InferenceBackend):
    """Explicit future seam, unavailable until target/model integration is verified."""

    name = "Qualcomm Snapdragon NPU"
    acceleration_label = "NPU"

    @property
    def is_available(self) -> bool:
        return False

    @property
    def unavailable_reason(self) -> str:
        return "Snapdragon backend pending verified target-device/model integration."
