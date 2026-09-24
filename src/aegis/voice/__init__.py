"""Voice-transcription contracts and safe text-pipeline delegation."""

from aegis.voice.base import (
    CallableSpeechRecognizer,
    SpeechRecognizer,
    SpeechRecognizerUnavailable,
    Transcription,
    UnavailableSpeechRecognizer,
    VoiceTriagePipeline,
    VoiceTriageResult,
)

__all__ = [
    "CallableSpeechRecognizer",
    "SpeechRecognizer",
    "SpeechRecognizerUnavailable",
    "Transcription",
    "UnavailableSpeechRecognizer",
    "VoiceTriagePipeline",
    "VoiceTriageResult",
]
