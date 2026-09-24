"""Analyze misclassifications from evaluation predictions to identify patterns."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, TextIO


def analyze_misclassifications(input_path: Path) -> dict[str, Any]:
    """Analyze false positives and false negatives from prediction records.
    
    Builds confusion patterns to help identify systematic failures.
    """

    false_positives: list[dict[str, Any]] = []
    false_negatives: list[dict[str, Any]] = []
    confusions: dict[str, int] = defaultdict(int)

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            for line_num, raw_line in enumerate(f, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as e:
                    print(f"Warning: line {line_num} invalid JSON: {e}", file=sys.stderr)
                    continue

                expected = record.get("expected", "")
                predicted = record.get("predicted", "")

                # Track confusion pairs
                if expected != predicted:
                    confusions[f"{expected} → {predicted}"] += 1

                # Categorize errors
                if expected and predicted:
                    if predicted != expected:
                        # Categorize error type
                        error_record = {
                            "line": line_num,
                            "expected": expected,
                            "predicted": predicted,
                            "stage_0_resolved": record.get("stage_0_resolved"),
                            "stage_1_invoked": record.get("stage_1_invoked"),
                            "backend": record.get("backend"),
                        }
                        
                        # False positive: predicted positive when actually negative
                        # False negative: predicted negative when actually positive
                        if predicted == "HIGH_RISK" and expected != "HIGH_RISK":
                            false_positives.append(error_record)
                        elif predicted != "HIGH_RISK" and expected == "HIGH_RISK":
                            false_negatives.append(error_record)

    except IOError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return {}

    # Compute error statistics
    total_errors = len(false_positives) + len(false_negatives)

    return {
        "total_misclassifications": total_errors,
        "false_positives": {
            "count": len(false_positives),
            "examples": false_positives[:5],  # Show first 5
        },
        "false_negatives": {
            "count": len(false_negatives),
            "examples": false_negatives[:5],  # Show first 5
        },
        "confusion_patterns": dict(sorted(confusions.items(), key=lambda x: -x[1])),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze misclassifications and confusion patterns from predictions."
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="JSON Lines predictions file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional file to save the analysis as JSON.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    analysis = analyze_misclassifications(args.input)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(analysis, f, indent=2)
        print(f"Analysis saved to {args.output}")

    json.dump(analysis, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
