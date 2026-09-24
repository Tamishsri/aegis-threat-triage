"""Analyze signal correlations to identify common threat patterns.

Shows which threat signals commonly appear together, helping to understand
threat composition and refine policy.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def extract_signals_from_json(evidence_json: dict) -> list[str]:
    """Extract signal names from evidence JSON array."""
    signals = []
    for evidence_item in evidence_json:
        if isinstance(evidence_item, dict) and "signal" in evidence_item:
            signals.append(evidence_item["signal"])
    return signals


def analyze_signal_correlations(
    predictions_with_evidence_path: Path,
) -> dict[str, Any]:
    """Analyze signal correlations from detailed prediction records.
    
    Expects JSONL with 'evidence' field containing full evidence array.
    Returns correlation matrix and common threat patterns.
    """

    signal_combinations: dict[frozenset, int] = defaultdict(int)
    signal_frequency: Counter = Counter()
    risk_state_signals: dict[str, list[frozenset]] = defaultdict(list)

    try:
        with open(predictions_with_evidence_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if "evidence" not in record:
                    continue

                signals = extract_signals_from_json(record["evidence"])
                if not signals:
                    continue

                # Track signal frequency
                for signal in signals:
                    signal_frequency[signal] += 1

                # Track signal combinations
                signal_set = frozenset(signals)
                signal_combinations[signal_set] += 1

                # Group by risk state
                risk_state = record.get("predicted", "UNKNOWN")
                risk_state_signals[risk_state].append(signal_set)

    except IOError:
        return {}

    if not signal_frequency:
        return {}

    # Identify most common threat patterns
    most_common_combinations = sorted(
        signal_combinations.items(), key=lambda x: -x[1]
    )[:10]

    # Compute correlation matrix for top signals
    top_signals = [signal for signal, _ in signal_frequency.most_common(10)]
    correlation_matrix: dict[str, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )

    for signal_set, count in signal_combinations.items():
        signals_in_set = list(signal_set)
        for i, signal_a in enumerate(signals_in_set):
            for signal_b in signals_in_set[i + 1 :]:
                if signal_a in top_signals and signal_b in top_signals:
                    correlation_matrix[signal_a][signal_b] += count
                    correlation_matrix[signal_b][signal_a] += count

    # Analyze patterns by risk state
    risk_patterns: dict[str, list] = {}
    for risk_state, signal_sets in risk_state_signals.items():
        if not signal_sets:
            continue
        # Find most common signal combinations for this risk state
        risk_combination_counts = Counter(signal_sets)
        most_common = [
            {"signals": sorted(list(s)), "count": c}
            for s, c in risk_combination_counts.most_common(5)
        ]
        risk_patterns[risk_state] = most_common

    return {
        "signal_frequency": dict(sorted(signal_frequency.items(), key=lambda x: -x[1])),
        "total_records": sum(signal_combinations.values()),
        "unique_combinations": len(signal_combinations),
        "most_common_patterns": [
            {"signals": sorted(list(s)), "count": c}
            for s, c in most_common_combinations
        ],
        "risk_state_patterns": risk_patterns,
        "correlation_matrix": {
            k: dict(sorted(v.items(), key=lambda x: -x[1]))
            for k, v in correlation_matrix.items()
        },
    }


def print_signal_analysis(analysis: dict[str, Any]) -> None:
    """Pretty-print signal correlation analysis."""

    if not analysis:
        print("No valid evidence data to analyze.")
        return

    print()
    print("=" * 70)
    print("SIGNAL CORRELATION ANALYSIS")
    print("=" * 70)
    print()

    # Overall statistics
    print("OVERVIEW")
    print("-" * 70)
    print(f"  Total combinations analyzed: {analysis.get('unique_combinations', 0)}")
    print(f"  Total records: {analysis.get('total_records', 0)}")
    print()

    # Signal frequency
    signal_freq = analysis.get("signal_frequency", {})
    if signal_freq:
        print("SIGNAL FREQUENCY (Top 10)")
        print("-" * 70)
        for i, (signal, count) in enumerate(
            sorted(signal_freq.items(), key=lambda x: -x[1])[:10], 1
        ):
            percent = 100 * count / analysis.get("total_records", 1)
            print(f"  {i:2d}. {signal:30s} {count:4d} ({percent:5.1f}%)")
        print()

    # Most common patterns
    patterns = analysis.get("most_common_patterns", [])
    if patterns:
        print("MOST COMMON THREAT COMBINATIONS (Top 5)")
        print("-" * 70)
        for i, pattern in enumerate(patterns[:5], 1):
            signals = pattern.get("signals", [])
            count = pattern.get("count", 0)
            signal_str = " + ".join(signals)
            print(f"  {i}. {signal_str}")
            print(f"     Observed {count} times")
        print()

    # Risk state patterns
    risk_patterns = analysis.get("risk_state_patterns", {})
    if risk_patterns:
        print("THREAT PATTERNS BY RISK STATE")
        print("-" * 70)
        for risk_state in sorted(risk_patterns.keys()):
            patterns_list = risk_patterns[risk_state]
            print(f"  {risk_state}:")
            for pattern in patterns_list[:3]:
                signals = pattern.get("signals", [])
                count = pattern.get("count", 0)
                signal_str = " + ".join(signals)
                print(f"    - {signal_str} ({count}x)")
            print()

    # Correlation matrix (top signals)
    correlations = analysis.get("correlation_matrix", {})
    if correlations:
        print("STRONGEST SIGNAL CORRELATIONS")
        print("-" * 70)
        # Find top correlated pairs
        corr_pairs = []
        for signal_a, correlations_b in correlations.items():
            for signal_b, count in correlations_b.items():
                if signal_a < signal_b:  # Avoid duplicates
                    corr_pairs.append((signal_a, signal_b, count))
        corr_pairs.sort(key=lambda x: -x[2])
        for signal_a, signal_b, count in corr_pairs[:10]:
            print(f"  {signal_a:25s} ↔ {signal_b:25s} ({count}x together)")
        print()

    print("=" * 70)
    print()
