"""Collect detailed predictions including full evidence for analysis.

Generates predictions with evidence details for signal correlation and
pattern analysis.
"""

from __future__ import annotations

import json
from pathlib import Path

from aegis.pipeline import TextTriagePipeline


def collect_predictions_with_evidence(
    input_file: Path,
    output_file: Path,
    label: str | None = None,
) -> int:
    """Analyze messages and save predictions with full evidence details.
    
    Output format:
    {
      "predicted": "HIGH_RISK",
      "stage_0_resolved": true,
      "backend": "CPU",
      "evidence": [
        {"signal": "otp_request", "strength": "strong", "details": "..."},
        ...
      ],
      "expected": "SCAM"  # optional, if label provided
    }
    """

    pipeline = TextTriagePipeline()
    results = []

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.rstrip("\n\r")
                if not line:
                    continue

                result = pipeline.analyze(line)

                # Convert evidence to JSON-serializable format
                evidence_list = []
                for evidence_item in result.evidence:
                    evidence_list.append({
                        "signal": evidence_item.signal,
                        "strength": evidence_item.strength.value,
                        "source": evidence_item.source.value,
                        "details": evidence_item.details,
                        "span": evidence_item.span,
                    })

                pred = {
                    "predicted": result.assessment.state.value,
                    "stage_0_resolved": result.screening.resolved,
                    "stage_1_invoked": result.stage_1_invoked,
                    "backend": result.execution_backend,
                    "evidence": evidence_list,
                }

                if label:
                    pred["expected"] = label

                results.append(pred)

    except FileNotFoundError:
        print(f"Error: input file not found: {input_file}")
        return 1
    except IOError as e:
        print(f"Error reading input file: {e}")
        return 1

    # Write results
    output_lines = [json.dumps(pred, ensure_ascii=False) for pred in results]

    try:
        with open(output_file, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(output_lines))
            if output_lines:
                f.write("\n")
        print(f"✓ Wrote {len(results)} predictions with evidence to {output_file}")
    except IOError as e:
        print(f"Error writing output file: {e}")
        return 1

    return 0
