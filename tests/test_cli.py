"""Tests for CLI functionality including batch processing."""

import json
import tempfile
from pathlib import Path

import pytest

from aegis.cli import _batch_analyze_file


def test_batch_analyze_file_basic(tmp_path: Path) -> None:
    """Test basic batch file processing with JSONL output."""
    input_file = tmp_path / "messages.txt"
    output_file = tmp_path / "predictions.jsonl"

    messages = [
        "Send me your OTP immediately.",
        "The weather is nice today.",
        "Claim your prize now!",
    ]
    input_file.write_text("\n".join(messages))

    result = _batch_analyze_file(str(input_file), str(output_file), None)
    assert result == 0
    assert output_file.exists()

    lines = output_file.read_text().strip().split("\n")
    assert len(lines) == 3

    predictions = [json.loads(line) for line in lines]
    assert predictions[0]["predicted"] == "HIGH_RISK"  # OTP request
    assert predictions[1]["predicted"] in ("LOW_RISK", "INSUFFICIENT_EVIDENCE")  # Benign
    assert predictions[2]["predicted"] in ("SUSPICIOUS", "HIGH_RISK")  # Prize language


def test_batch_analyze_file_with_label(tmp_path: Path) -> None:
    """Test batch processing with expected label for evaluation."""
    input_file = tmp_path / "messages.txt"
    output_file = tmp_path / "predictions.jsonl"

    messages = ["Verify your account.", "Meeting at 3pm."]
    input_file.write_text("\n".join(messages))

    result = _batch_analyze_file(str(input_file), str(output_file), "SCAM")
    assert result == 0

    lines = output_file.read_text().strip().split("\n")
    predictions = [json.loads(line) for line in lines]

    for pred in predictions:
        assert pred["expected"] == "SCAM"
        assert "predicted" in pred
        assert "stage_0_resolved" in pred


def test_batch_analyze_file_no_output(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """Test batch processing without output file (prints to stdout)."""
    input_file = tmp_path / "messages.txt"
    input_file.write_text("Send money now.\nHave a good day.")

    result = _batch_analyze_file(str(input_file), None, None)
    assert result == 0

    captured = capsys.readouterr()
    lines = captured.out.strip().split("\n")
    assert len(lines) == 2

    for line in lines:
        pred = json.loads(line)
        assert "predicted" in pred


def test_batch_analyze_file_missing_input(tmp_path: Path) -> None:
    """Test batch processing with missing input file."""
    result = _batch_analyze_file(str(tmp_path / "missing.txt"), None, None)
    assert result == 1


def test_batch_analyze_file_empty_lines(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """Test batch processing skips empty lines."""
    input_file = tmp_path / "messages.txt"
    input_file.write_text("OTP request\n\n\nVerify account\n\n")

    result = _batch_analyze_file(str(input_file), None, None)
    assert result == 0

    captured = capsys.readouterr()
    lines = [line for line in captured.out.strip().split("\n") if line]
    assert len(lines) == 2


def test_batch_analyze_file_produces_valid_jsonl(tmp_path: Path) -> None:
    """Test that batch output is valid JSONL (one JSON per line)."""
    input_file = tmp_path / "messages.txt"
    output_file = tmp_path / "predictions.jsonl"

    messages = ["Test one", "Test two", "Test three"]
    input_file.write_text("\n".join(messages))

    result = _batch_analyze_file(str(input_file), str(output_file), "LABEL")
    assert result == 0

    # Verify each line is valid JSON
    with open(output_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            assert "predicted" in data
            assert "stage_0_resolved" in data
            assert "backend" in data
            assert "expected" in data
