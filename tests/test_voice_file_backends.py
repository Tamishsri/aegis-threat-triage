from __future__ import annotations

from pathlib import Path

import pytest

from aegis.backends import BackendUnavailable, CPUBackend, QualcommBackend
from aegis.evidence import EvidenceSource
from aegis.file_analysis import HeaderOnlyPEAnalyzer, UnavailableMalwareClassifier
from aegis.risk_engine import RiskState
from aegis.voice import CallableSpeechRecognizer, Transcription, VoiceTriagePipeline


def test_voice_pipeline_routes_a_transcript_through_text_analysis() -> None:
    recognizer = CallableSpeechRecognizer(
        lambda path: Transcription(
            text="Please send your OTP immediately.", backend_name="test CPU recognizer"
        )
    )
    result = VoiceTriagePipeline(recognizer=recognizer).analyze("recording.wav")

    assert result.transcription.backend_name == "test CPU recognizer"
    assert result.analysis.source is EvidenceSource.VOICE
    assert result.analysis.assessment.state is RiskState.HIGH_RISK
    assert all(item.source is EvidenceSource.VOICE for item in result.analysis.evidence)


def test_header_only_file_analysis_never_executes_submitted_content() -> None:
    submitted = Path(__file__).parent / "fixtures" / "untrusted_static_sample.txt"

    result = HeaderOnlyPEAnalyzer().analyze(submitted)

    assert result.is_pe is True
    assert result.pe_signature_valid is False
    assert result.features["has_mz_header"] is True


def test_malware_classifier_is_explicitly_unavailable_without_a_model() -> None:
    with pytest.raises(Exception, match="No validated ClaMP-compatible"):
        UnavailableMalwareClassifier().predict({"has_mz_header": True})


def test_backend_status_never_claims_unavailable_snapdragon_execution() -> None:
    assert CPUBackend().is_available is True
    snapdragon = QualcommBackend()
    assert snapdragon.is_available is False
    assert snapdragon.acceleration_label == "NPU"
    with pytest.raises(BackendUnavailable, match="pending verified"):
        snapdragon.require_available()
