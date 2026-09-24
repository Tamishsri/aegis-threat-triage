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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        return _interactive()
    if args.command == "text":
        if args.stdin:
            if args.message is not None:
                parser.error("Pass either a message or --stdin, not both.")
            message = sys.stdin.read()
        else:
            message = args.message
        if message is None:
            parser.error("A text message or --stdin is required.")
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
