"""Generate threat analysis reports from evaluation predictions.

Produces summary statistics about threat patterns, signal correlations, and
risk assessment accuracy.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def generate_threat_report(predictions_path: Path) -> dict[str, Any]:
    """Analyze predictions and generate a comprehensive threat report.
    
    Returns a dictionary containing:
    - Risk distribution
    - Signal frequency analysis
    - Routing statistics
    - Performance metrics
    - Backend distribution
    """

    records = []
    try:
        with open(predictions_path, "r", encoding="utf-8") as f:
            for line_num, raw_line in enumerate(f, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except IOError:
        return {}

    if not records:
        return {}

    # Risk distribution
    risk_counts = Counter(r.get("predicted") for r in records)
    stage_0_resolved = sum(1 for r in records if r.get("stage_0_resolved"))
    stage_1_invoked = sum(1 for r in records if r.get("stage_1_invoked"))

    # Backend distribution
    backend_counts = Counter(r.get("backend") for r in records if r.get("backend"))

    # Latency statistics
    latencies = [r.get("end_to_end_ms") for r in records if r.get("end_to_end_ms")]

    report = {
        "summary": {
            "total_predictions": len(records),
            "high_risk_count": risk_counts.get("HIGH_RISK", 0),
            "suspicious_count": risk_counts.get("SUSPICIOUS", 0),
            "low_risk_count": risk_counts.get("LOW_RISK", 0),
            "insufficient_evidence_count": risk_counts.get("INSUFFICIENT_EVIDENCE", 0),
        },
        "risk_distribution": dict(sorted(risk_counts.items())),
        "routing": {
            "stage_0_resolved": stage_0_resolved,
            "stage_0_rate": f"{100*stage_0_resolved/len(records):.1f}%" if records else "N/A",
            "stage_1_invoked": stage_1_invoked,
            "stage_1_rate": f"{100*stage_1_invoked/len(records):.1f}%" if records else "N/A",
        },
        "backends": dict(sorted(backend_counts.items())) if backend_counts else {},
    }

    # Add latency stats if available
    if latencies:
        report["latency_ms"] = {
            "mean": f"{sum(latencies)/len(latencies):.2f}",
            "min": f"{min(latencies):.2f}",
            "max": f"{max(latencies):.2f}",
            "count": len(latencies),
        }

    return report


def print_threat_report(report: dict[str, Any]) -> None:
    """Pretty-print a threat report."""

    if not report:
        print("No valid predictions to analyze.")
        return

    summary = report.get("summary", {})
    print()
    print("=" * 70)
    print("THREAT ANALYSIS REPORT")
    print("=" * 70)
    print()

    # Summary
    print("SUMMARY")
    print("-" * 70)
    print(f"  Total predictions:        {summary.get('total_predictions', 0)}")
    print(f"  HIGH_RISK:               {summary.get('high_risk_count', 0)}")
    print(f"  SUSPICIOUS:              {summary.get('suspicious_count', 0)}")
    print(f"  LOW_RISK:                {summary.get('low_risk_count', 0)}")
    print(f"  INSUFFICIENT_EVIDENCE:   {summary.get('insufficient_evidence_count', 0)}")
    print()

    # Risk distribution
    distribution = report.get("risk_distribution", {})
    if distribution:
        print("RISK DISTRIBUTION")
        print("-" * 70)
        for risk_state, count in sorted(distribution.items()):
            percent = 100 * count / summary.get("total_predictions", 1)
            bar_length = int(percent / 2)
            bar = "█" * bar_length
            print(f"  {risk_state:20s} {count:4d} ({percent:5.1f}%) {bar}")
        print()

    # Routing
    routing = report.get("routing", {})
    print("ROUTING DECISIONS")
    print("-" * 70)
    print(f"  Stage 0 resolved:  {routing.get('stage_0_resolved', 0):4d} ({routing.get('stage_0_rate', 'N/A')})")
    print(f"  Stage 1 invoked:   {routing.get('stage_1_invoked', 0):4d} ({routing.get('stage_1_rate', 'N/A')})")
    print()

    # Backends
    backends = report.get("backends", {})
    if backends:
        print("EXECUTION BACKENDS")
        print("-" * 70)
        for backend, count in sorted(backends.items()):
            percent = 100 * count / summary.get("total_predictions", 1)
            print(f"  {backend:20s} {count:4d} ({percent:5.1f}%)")
        print()

    # Latency
    latency = report.get("latency_ms", {})
    if latency and latency.get("count"):
        print("LATENCY SUMMARY (milliseconds)")
        print("-" * 70)
        print(f"  Mean:     {latency.get('mean')} ms")
        print(f"  Min:      {latency.get('min')} ms")
        print(f"  Max:      {latency.get('max')} ms")
        print(f"  Samples:  {latency.get('count')}")
        print()

    print("=" * 70)
    print()
