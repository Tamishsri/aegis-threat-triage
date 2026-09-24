"""A restrained terminal result view with risk-first hierarchy."""

from __future__ import annotations

from aegis.pipeline import AnalysisResult


def render_result(result: AnalysisResult) -> str:
    """Render the actual assessment without adding claims or hidden scores."""

    lines = [
        "AEGIS - Evidence-First Threat Triage",
        "=" * 44,
        f"RISK: {result.assessment.state.value.replace('_', ' ')}",
        "",
        "WHY",
        result.explanation.summary,
        "",
        "EVIDENCE",
    ]
    if result.evidence:
        for evidence in result.evidence:
            label = evidence.signal.replace("_", " ").title()
            lines.append(f"- {label} - {evidence.strength.value.title()}")
            lines.append(f"  {evidence.details} [{evidence.extractor}]")
    else:
        lines.append("- No evidence items were retained.")

    lines.extend(["", "WHAT TO DO"])
    lines.extend(f"- {action}" for action in result.explanation.recommended_actions)

    lines.extend(
        [
            "",
            "SYSTEM STATUS",
            "- Local analysis: enabled",
            f"- Network: {result.network_status}",
            f"- AI acceleration: {result.execution_backend}",
            f"- Stage 0 resolved: {'yes' if result.screening.resolved else 'no'} ({result.screening.reason.value})",
            f"- Stage 1 requested: {'yes' if result.stage_1_requested else 'no'}",
            f"- Stage 1 invoked: {'yes' if result.stage_1_invoked else 'no'}",
            f"- Semantic analysis: {result.semantic_status}",
        ]
    )
    return "\n".join(lines)
