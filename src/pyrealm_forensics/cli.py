"""Command-line interface for pyrealm-forensics."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pyrealm_forensics.models import Analysis, analysis_dict
from pyrealm_forensics.parser import analyze_realm, carve_realm


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyrealm",
        description="Read-only structural analysis and carving of Realm database files.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    inspect = subcommands.add_parser("inspect", help="identify and summarize a Realm file")
    inspect.add_argument("realm", type=Path)
    inspect.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    carve = subcommands.add_parser("carve", help="carve arrays and strings into a new directory")
    carve.add_argument("realm", type=Path)
    carve.add_argument("--output", "-o", type=Path, required=True)
    carve.add_argument("--min-string", type=int, default=4)
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
    """Run the command-line interface."""
    args = _parser().parse_args(argv)
    if args.command == "inspect":
        analysis = analyze_realm(args.realm)
        if args.json:
            print(json.dumps(analysis_dict(analysis), indent=2))
        else:
            print(_human_summary(analysis))
        return 0 if analysis.header is not None else 2

    analysis = carve_realm(args.realm, args.output, args.min_string)
    print(_human_summary(analysis))
    print(f"Results: {args.output.resolve()}")
    return 0 if analysis.header is not None else 2
