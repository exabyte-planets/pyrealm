"""Command-line interface for pyrealm-forensics."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pyrealm_forensics.models import Analysis, analysis_dict
from pyrealm_forensics.parser import analyze_realm, carve_realm
from pyrealm_forensics.reader import open_realm


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

    schema = subcommands.add_parser("schema", help="print the logical Realm schema as JSON")
    schema.add_argument("realm", type=Path)
    schema.add_argument("--key-file", type=Path)

    dump = subcommands.add_parser("dump", help="write logical records as JSON Lines")
    dump.add_argument("realm", type=Path)
    dump.add_argument("--key-file", type=Path)
    dump.add_argument("--table", required=True)
    dump.add_argument("--query", help="Realm Query Language expression")
    dump.add_argument(
        "--arg",
        action="append",
        default=[],
        help="JSON-encoded positional query parameter; repeat for multiple parameters",
    )
    dump.add_argument("--expand-links", type=int, default=0, metavar="DEPTH")
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

    if args.command == "carve":
        analysis = carve_realm(args.realm, args.output, args.min_string)
        print(_human_summary(analysis))
        print(f"Results: {args.output.resolve()}")
        return 0 if analysis.header is not None else 2

    realm = open_realm(args.realm, key_file=args.key_file)
    if args.command == "schema":
        print(
            json.dumps(
                [
                    {
                        "name": table.name,
                        "key": table.key,
                        "primary_key": table.primary_key,
                        "embedded": table.embedded,
                        "asymmetric": table.asymmetric,
                        "properties": [
                            {
                                "name": prop.name,
                                "public_name": prop.public_name,
                                "key": prop.key,
                                "type": prop.type,
                                "collection": prop.collection,
                                "nullable": prop.nullable,
                                "primary_key": prop.primary_key,
                                "indexed": prop.indexed,
                                "link_target": prop.link_target,
                                "link_origin_property": prop.link_origin_property,
                            }
                            for prop in table.properties
                        ],
                    }
                    for table in realm.schema
                ],
                indent=2,
            )
        )
        return 0

    if args.expand_links < 0:
        raise ValueError("--expand-links must be at least 0")
    parameters = [json.loads(value) for value in args.arg]
    table = realm.table(args.table)
    if args.query:
        records = table.where(args.query, *parameters)
    else:
        if parameters:
            raise ValueError("--arg requires --query")
        records = table.all()
    for record in records:
        print(
            json.dumps(
                record.to_dict(
                    expand_links=args.expand_links > 0,
                    max_depth=args.expand_links,
                ),
                separators=(",", ":"),
            )
        )
    return 0
