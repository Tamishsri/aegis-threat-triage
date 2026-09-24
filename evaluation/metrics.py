"""Compute reproducible binary and routing metrics from JSON Lines predictions.

This module intentionally depends only on the Python standard library. It does
not ship evaluation records or make performance claims.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from numbers import Real
from pathlib import Path
from typing import Any, TextIO


class InputFormatError(ValueError):
    """Raised when an evaluation record cannot be measured safely."""


@dataclass(frozen=True)
class Record:
    expected: str
    predicted: str
    stage_0_resolved: bool | None
    stage_1_invoked: bool | None
    latency_ms: float | None
    backend: str | None


def _require_label(item: dict[str, Any], key: str, line_number: int) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise InputFormatError(
            f"line {line_number}: {key!r} must be a non-empty string"
        )
    return value


def _optional_bool(
    item: dict[str, Any], key: str, line_number: int
) -> bool | None:
    if key not in item:
        return None
    value = item[key]
    if type(value) is not bool:
        raise InputFormatError(
            f"line {line_number}: {key!r} must be a JSON boolean when present"
        )
    return value


def _optional_finite_number(
    item: dict[str, Any], key: str, line_number: int
) -> float | None:
    if key not in item:
        return None
    value = item[key]
    if isinstance(value, bool) or not isinstance(value, Real):
        raise InputFormatError(
            f"line {line_number}: {key!r} must be a finite number when present"
        )
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise InputFormatError(
            f"line {line_number}: {key!r} must be a non-negative finite number when present"
        )
    return result


def _optional_backend(
    item: dict[str, Any], key: str, line_number: int
) -> str | None:
    if key not in item:
        return None
    value = item[key]
    if not isinstance(value, str) or not value.strip():
        raise InputFormatError(
            f"line {line_number}: {key!r} must be a non-empty string when present"
        )
    return value


def load_records(
    input_path: Path,
    expected_key: str,
    predicted_key: str,
    stage_0_key: str,
    stage_1_key: str,
    latency_key: str,
    backend_key: str,
) -> list[Record]:
    """Load and validate JSON Lines records without silently skipping bad rows."""

    stream: TextIO
    close_stream = False
    if str(input_path) == "-":
        stream = sys.stdin
    else:
        stream = input_path.open("r", encoding="utf-8")
        close_stream = True

    records: list[Record] = []
    try:
        for line_number, raw_line in enumerate(stream, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as error:
                raise InputFormatError(
                    f"line {line_number}: invalid JSON ({error.msg})"
                ) from error
            if not isinstance(item, dict):
                raise InputFormatError(
                    f"line {line_number}: each JSON Lines value must be an object"
                )

            records.append(
                Record(
                    expected=_require_label(item, expected_key, line_number),
                    predicted=_require_label(item, predicted_key, line_number),
                    stage_0_resolved=_optional_bool(
                        item, stage_0_key, line_number
                    ),
                    stage_1_invoked=_optional_bool(item, stage_1_key, line_number),
                    latency_ms=_optional_finite_number(
                        item, latency_key, line_number
                    ),
                    backend=_optional_backend(item, backend_key, line_number),
                )
            )
    finally:
        if close_stream:
            stream.close()

    if not records:
        raise InputFormatError("input contains no JSON Lines records")
    return records


def _rate_summary(values: Iterable[bool | None]) -> dict[str, int | float] | None:
    observed = [value for value in values if value is not None]
    if not observed:
        return None
    true_count = sum(observed)
    count = len(observed)
    return {
        "available_records": count,
        "true": true_count,
        "false": count - true_count,
        "rate": true_count / count,
    }


def _latency_summary(values: Iterable[float | None]) -> dict[str, float | int] | None:
    observed = [value for value in values if value is not None]
    if not observed:
        return None
    return {
        "available_records": len(observed),
        "mean": statistics.fmean(observed),
        "median": statistics.median(observed),
        "minimum": min(observed),
        "maximum": max(observed),
    }


def build_report(records: Sequence[Record], positive_label: str) -> dict[str, Any]:
    """Build a deterministic report for a declared one-vs-rest positive label."""

    true_positive = true_negative = false_positive = false_negative = 0
    for record in records:
        expected_positive = record.expected == positive_label
        predicted_positive = record.predicted == positive_label
        if expected_positive and predicted_positive:
            true_positive += 1
        elif not expected_positive and not predicted_positive:
            true_negative += 1
        elif predicted_positive:
            false_positive += 1
        else:
            false_negative += 1

    total = len(records)
    precision_denominator = true_positive + false_positive
    recall_denominator = true_positive + false_negative
    precision = (
        true_positive / precision_denominator if precision_denominator else 0.0
    )
    recall = true_positive / recall_denominator if recall_denominator else 0.0
    f1_denominator = precision + recall
    f1 = 2 * precision * recall / f1_denominator if f1_denominator else 0.0

    expected_labels = Counter(record.expected for record in records)
    predicted_labels = Counter(record.predicted for record in records)
    backends = Counter(record.backend for record in records if record.backend)

    return {
        "schema_version": 1,
        "records": total,
        "positive_label": positive_label,
        "confusion_matrix": {
            "tp": true_positive,
            "tn": true_negative,
            "fp": false_positive,
            "fn": false_negative,
        },
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "accuracy": (true_positive + true_negative) / total,
        },
        "labels": {
            "expected": dict(sorted(expected_labels.items())),
            "predicted": dict(sorted(predicted_labels.items())),
        },
        "routing": {
            "stage_0_resolved": _rate_summary(
                record.stage_0_resolved for record in records
            ),
            "stage_1_invoked": _rate_summary(
                record.stage_1_invoked for record in records
            ),
        },
        "performance": {
            "latency_ms": _latency_summary(record.latency_ms for record in records),
            "backends": dict(sorted(backends.items())),
        },
    }


def _write_json(report: dict[str, Any], stream: TextIO) -> None:
    json.dump(report, stream, indent=2, sort_keys=True)
    stream.write("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compute binary classification, routing, and optional latency "
            "summaries from JSON Lines predictions."
        )
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="JSON Lines predictions path, or - to read from standard input.",
    )
    parser.add_argument(
        "--positive-label",
        required=True,
        help="Exact label treated as positive for one-vs-rest metrics.",
    )
    parser.add_argument(
        "--expected-key",
        default="expected",
        help="Expected-label field name (default: expected).",
    )
    parser.add_argument(
        "--predicted-key",
        default="predicted",
        help="Predicted-label field name (default: predicted).",
    )
    parser.add_argument(
        "--stage-0-key",
        default="stage_0_resolved",
        help="Optional Stage 0 boolean field name.",
    )
    parser.add_argument(
        "--stage-1-key",
        default="stage_1_invoked",
        help="Optional Stage 1 boolean field name.",
    )
    parser.add_argument(
        "--latency-key",
        default="end_to_end_ms",
        help="Optional finite latency field name.",
    )
    parser.add_argument(
        "--backend-key",
        default="backend",
        help="Optional execution-backend field name.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional file to receive the same JSON report printed to stdout.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.positive_label.strip():
        parser.error("--positive-label must be a non-empty string")
    try:
        records = load_records(
            args.input,
            args.expected_key,
            args.predicted_key,
            args.stage_0_key,
            args.stage_1_key,
            args.latency_key,
            args.backend_key,
        )
        report = build_report(records, args.positive_label)
        if args.output:
            with args.output.open("w", encoding="utf-8", newline="\n") as output:
                _write_json(report, output)
        _write_json(report, sys.stdout)
    except (InputFormatError, OSError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
