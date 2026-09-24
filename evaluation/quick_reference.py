#!/usr/bin/env python
"""Quick reference for common AEGIS workflows and commands.

This is a simple text reference that can be invoked from the command line.
Run: python evaluation/quick_reference.py
"""

from __future__ import annotations

WORKFLOWS = {
    "analyze_single_message": {
        "description": "Analyze a single text message",
        "commands": [
            'python -m aegis text "Your message here"',
            'python run.py text "Your message here"',
        ],
    },
    "batch_analysis": {
        "description": "Analyze multiple messages from a file (one per line)",
        "commands": [
            "python -m aegis text --file messages.txt",
            "python -m aegis text --file messages.txt --output predictions.jsonl",
            'python -m aegis text --file messages.txt --output predictions.jsonl --label SCAM',
        ],
    },
    "json_output": {
        "description": "Get structured JSON output for programmatic use",
        "commands": [
            'python -m aegis text "message" --json',
            'python -m aegis text --file messages.txt --output predictions.jsonl --json',
        ],
    },
    "stdin_input": {
        "description": "Read input from stdin (piped or redirected)",
        "commands": [
            'echo "message" | python -m aegis text --stdin',
            "python -m aegis text --stdin < message.txt",
            'Get-Content message.txt | python -m aegis text --stdin',
        ],
    },
    "evaluate": {
        "description": "Run evaluation metrics on predictions",
        "commands": [
            "python evaluation/metrics.py --input predictions.jsonl --positive-label SCAM",
            "python evaluation/metrics.py --input predictions.jsonl --positive-label SCAM --output report.json",
        ],
    },
    "analyze_errors": {
        "description": "Analyze misclassifications and confusion patterns",
        "commands": [
            "python evaluation/analyze_misclassifications.py --input predictions.jsonl",
            "python evaluation/analyze_misclassifications.py --input predictions.jsonl --output analysis.json",
        ],
    },
    "view_policy": {
        "description": "Display current risk policy configuration",
        "commands": [
            "python evaluation/validate_policy.py",
        ],
    },
    "interactive": {
        "description": "Interactive prompt mode",
        "commands": [
            "python -m aegis",
            "python run.py",
        ],
    },
}


def print_reference() -> None:
    """Display quick reference for common workflows."""

    print()
    print("=" * 70)
    print("AEGIS QUICK REFERENCE")
    print("=" * 70)
    print()

    for workflow_id, workflow in WORKFLOWS.items():
        print(f"[{workflow_id}] {workflow['description']}")
        print("-" * 70)
        for cmd in workflow["commands"]:
            print(f"  $ {cmd}")
        print()


def main() -> int:
    print_reference()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
