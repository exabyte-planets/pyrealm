"""Command-line interface for conservative Realm data recovery."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pyrealm_forensics.models import Analysis, analysis_dict
from pyrealm_forensics.parser import analyze_realm, carve_realm

EXIT_RECOGNIZED = 0
EXIT_OPERATIONAL_ERROR = 1
EXIT_NO_HEADER = 3


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid int value: {text!r}") from None
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyrealm-recover",
        description="Inspect and conservatively recover data from Realm database files.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    inspect = subcommands.add_parser("inspect", help="identify and summarize a Realm file")
    inspect.add_argument("realm", type=Path)
    inspect.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    carve = subcommands.add_parser("carve", help="carve arrays and strings into a new directory")
    carve.add_argument("realm", type=Path)
    carve.add_argument("--output", "-o", type=Path, required=True)
    carve.add_argument("--min-string", type=_positive_int, default=4)

    return parser


def _human_summary(analysis: Analysis) -> str:
    lines = [
        f"Classification: {analysis.classification}",
        f"Path: {analysis.path}",
        f"SHA-256: {analysis.sha256}",
        f"Size: {analysis.file_size} bytes",
        f"Entropy: {analysis.entropy:.3f} bits/byte",
        f"Arrays: {len(analysis.arrays)}",
    ]
    header = analysis.header
    if header:
        lines.extend(
            [
                f"Format slots: {header.format_slots}",
                f"Active root: 0x{header.active_top_ref:x}",
                f"Inactive root: 0x{header.inactive_top_ref:x}",
            ]
        )
    lines.extend(f"Warning: {warning}" for warning in analysis.warnings)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Run the command-line interface.

    Exit codes: 0 for a recognized plaintext Realm, 1 for operational errors
    (unreadable input, existing output directory), 3 when the input was analyzed
    but no Realm header was recognized. Argparse reserves 2 for usage errors, so
    the no-header status deliberately avoids it.
    """
    args = _parser().parse_args(argv)
    try:
        if args.command == "inspect":
            analysis = analyze_realm(args.realm)
            if args.json:
                print(json.dumps(analysis_dict(analysis), indent=2))
            else:
                print(_human_summary(analysis))
        elif args.command == "carve":
            analysis = carve_realm(args.realm, args.output, args.min_string)
            print(_human_summary(analysis))
            print(f"Results: {args.output.resolve()}")
        else:
            raise AssertionError(f"unhandled command: {args.command}")
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        if isinstance(error, ValueError):
            print(
                "suggestion: preserve the source and try another copy; malformed data prevented "
                "safe analysis",
                file=sys.stderr,
            )
        return EXIT_OPERATIONAL_ERROR
    return EXIT_RECOGNIZED if analysis.header is not None else EXIT_NO_HEADER
