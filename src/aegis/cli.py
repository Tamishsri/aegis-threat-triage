"""Dependency-free CLI demonstration for the working text pipeline."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from aegis import __version__
from aegis.pipeline import TextTriagePipeline
from aegis.ui import render_result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Local, evidence-first pre-action threat triage.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subcommands = parser.add_subparsers(dest="command")

    text = subcommands.add_parser("text", help="Analyze a text message locally.")
    text.add_argument("message", nargs="?", help="Text to analyze. Use --stdin for piped input.")
    text.add_argument("--stdin", action="store_true", help="Read text from standard input.")
    text.add_argument("--json", action="store_true", help="Print a JSON result instead of the terminal view.")
    text.add_argument("--file", type=str, help="Analyze messages from a file (one per line).")
    text.add_argument("--output", type=str, help="Save JSONL results to a file (only with --file).")
    text.add_argument("--label", type=str, help="Assign a label to predictions in output JSONL (use with --file).")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        return _interactive()
    if args.command == "text":
        if args.file:
            if args.message is not None or args.stdin:
                parser.error("Use --file alone, not with a message or --stdin.")
            return _batch_analyze_file(args.file, args.output, args.label)
        if args.stdin:
            if args.message is not None:
                parser.error("Pass either a message or --stdin, not both.")
            message = sys.stdin.read()
        else:
            message = args.message
        if message is None:
            parser.error("A text message, --stdin, or --file is required.")
        return _analyze_and_print(message, as_json=args.json)
    parser.error(f"Unsupported command: {args.command}")
    return 2


def _interactive() -> int:
    print("AEGIS - Evidence-First Threat Triage")
    print("Paste one message for local analysis, then press Enter.")
    try:
        message = input("> ")
    except EOFError:
        print("No text received.", file=sys.stderr)
        return 2
    return _analyze_and_print(message, as_json=False)


def _analyze_and_print(message: str, *, as_json: bool) -> int:
    result = TextTriagePipeline().analyze(message)
    if as_json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(render_result(result))
    return 0


def _batch_analyze_file(file_path: str, output_path: str | None, label: str | None) -> int:
    """Analyze messages from a file and output JSONL predictions for evaluation."""

    pipeline = TextTriagePipeline()
    results = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.rstrip("\n\r")
                if not line:
                    continue
                result = pipeline.analyze(line)
                pred = {
                    "predicted": result.assessment.state.value,
                    "stage_0_resolved": result.screening.resolved,
                    "stage_1_invoked": result.stage_1_invoked,
                    "backend": result.execution_backend,
                }
                if label:
                    pred["expected"] = label
                results.append(pred)
    except FileNotFoundError:
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        return 1
    except IOError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return 1

    output_lines = [json.dumps(pred, ensure_ascii=False) for pred in results]

    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8", newline="\n") as f:
                f.write("\n".join(output_lines))
                if output_lines:
                    f.write("\n")
            print(f"Wrote {len(results)} predictions to {output_path}")
        except IOError as e:
            print(f"Error writing output file: {e}", file=sys.stderr)
            return 1
    else:
        for line in output_lines:
            print(line)

    return 0
