"""Speech seam. AEGIS does not claim a Whisper or Snapdragon implementation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from aegis.pipeline import AnalysisResult, TextTriagePipeline
from aegis.evidence.models import EvidenceSource


class SpeechRecognizerUnavailable(RuntimeError):
    """Raised when no verified local speech recognizer has been configured."""


@dataclass(frozen=True, slots=True)
class Transcription:
    text: str
    backend_name: str
    language: str | None = None
    duration_seconds: float | None = None


class SpeechRecognizer(ABC):
    """Contract for local CPU or verified future Snapdragon transcription."""

    @property
    @abstractmethod
    def is_available(self) -> bool:
        pass

    @property
    @abstractmethod
    def unavailable_reason(self) -> str | None:
        pass

    @abstractmethod
    def transcribe(self, audio_path: Path) -> Transcription:
        pass


class UnavailableSpeechRecognizer(SpeechRecognizer):
    """Honest default: no audio model or model download is bundled."""

    @property
    def is_available(self) -> bool:
        return False

    @property
    def unavailable_reason(self) -> str:
        return "No verified local speech model is configured in this first-pass build."

    def transcribe(self, audio_path: Path) -> Transcription:
        raise SpeechRecognizerUnavailable(self.unavailable_reason)


class CallableSpeechRecognizer(SpeechRecognizer):
    """Adapter for a caller-provided local CPU transcription function.

    This is an integration seam, not a bundled Whisper implementation. It lets
    a verified local recognizer be supplied without coupling the core pipeline
    to a particular package or inventing a Qualcomm API.
    """

    def __init__(self, transcriber: Callable[[Path], Transcription], *, backend_name: str = "CPU") -> None:
        self._transcriber = transcriber
        self._backend_name = backend_name

    @property
    def is_available(self) -> bool:
        return True

    @property
    def unavailable_reason(self) -> None:
        return None

    def transcribe(self, audio_path: Path) -> Transcription:
        result = self._transcriber(audio_path)
        if not isinstance(result, Transcription):
            raise TypeError("Speech recognizer callable must return a Transcription.")
        return result


@dataclass(frozen=True, slots=True)
class VoiceTriageResult:
    transcription: Transcription
    analysis: AnalysisResult


class VoiceTriagePipeline:
    """Audio -> transcript -> the same evidence-first text pipeline.

    The transcript cost is always paid before Stage 0 routing; routing only
    controls a future semantic-analysis stage after transcription.
    """

    def __init__(
        self,
        recognizer: SpeechRecognizer | None = None,
        text_pipeline: TextTriagePipeline | None = None,
    ) -> None:
        self._recognizer = recognizer or UnavailableSpeechRecognizer()
        self._text_pipeline = text_pipeline or TextTriagePipeline()

    def analyze(self, audio_path: str | Path) -> VoiceTriageResult:
        if not self._recognizer.is_available:
            raise SpeechRecognizerUnavailable(self._recognizer.unavailable_reason or "Speech unavailable.")
        transcription = self._recognizer.transcribe(Path(audio_path))
        analysis = self._text_pipeline.analyze(transcription.text, source=EvidenceSource.VOICE)
        return VoiceTriageResult(transcription=transcription, analysis=analysis)
