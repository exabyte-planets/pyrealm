from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pyrealm_forensics.cli import _human_summary, _parser, main
from pyrealm_forensics.models import Analysis, ArrayNode, RealmHeader


def analysis(*, with_header: bool = True) -> Analysis:
    header = (
        RealmHeader(
            top_refs=(24, 0),
            format_slots=(10, 11),
            reserved=0,
            flags=0,
            active_slot=0,
            active_top_ref=24,
            inactive_top_ref=0,
            streaming=False,
        )
        if with_header
        else None
    )
    arrays = (
        ArrayNode(
            offset=24,
            byte_size=8,
            payload_size=0,
            element_count=0,
            width=0,
            width_scheme=0,
            has_refs=False,
            inner_bptree=False,
            context_flag=False,
            child_refs=(),
            reachability="active",
        ),
    )
    return Analysis(
        path="/evidence/sample.realm",
        sha256="abc123",
        file_size=32,
        classification="plaintext-realm" if with_header else "not-a-plain-realm",
        entropy=1.25,
        header=header,
        arrays=arrays,
        warnings=("test warning",),
    )


class CliTests(unittest.TestCase):
    def test_parser_builds_inspect_and_carve_arguments(self) -> None:
        parser = _parser()
        inspect = parser.parse_args(["inspect", "sample.realm", "--json"])
        carve = parser.parse_args(
            ["carve", "sample.realm", "-o", "results", "--min-string", "7"]
        )

        self.assertEqual((inspect.command, inspect.realm, inspect.json), (
            "inspect",
            Path("sample.realm"),
            True,
        ))
        self.assertEqual((carve.output, carve.min_string), (Path("results"), 7))

    def test_human_summary_includes_header_arrays_and_warnings(self) -> None:
        summary = _human_summary(analysis())

        self.assertIn("Classification: plaintext-realm", summary)
        self.assertIn("Entropy: 1.250 bits/byte", summary)
        self.assertIn("Arrays: 1", summary)
        self.assertIn("Format slots: (10, 11)", summary)
        self.assertIn("Active root: 0x18", summary)
        self.assertIn("Warning: test warning", summary)

    def test_human_summary_omits_header_lines_when_unrecognized(self) -> None:
        summary = _human_summary(analysis(with_header=False))
        self.assertNotIn("Format slots:", summary)
        self.assertNotIn("Active root:", summary)

    def test_main_inspect_prints_human_output_and_returns_success(self) -> None:
        result = analysis()
        stdout = io.StringIO()
        with (
            patch("pyrealm_forensics.cli.analyze_realm", return_value=result) as analyze,
            contextlib.redirect_stdout(stdout),
        ):
            status = main(["inspect", "sample.realm"])

        self.assertEqual(status, 0)
        analyze.assert_called_once_with(Path("sample.realm"))
        self.assertIn("Classification: plaintext-realm", stdout.getvalue())

    def test_main_inspect_prints_json_and_returns_two_without_header(self) -> None:
        result = analysis(with_header=False)
        stdout = io.StringIO()
        with (
            patch("pyrealm_forensics.cli.analyze_realm", return_value=result),
            contextlib.redirect_stdout(stdout),
        ):
            status = main(["inspect", "sample.bin", "--json"])

        self.assertEqual(status, 2)
        self.assertEqual(json.loads(stdout.getvalue())["header"], None)

    def test_main_carve_passes_options_and_prints_output_path(self) -> None:
        result = analysis()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results"
            stdout = io.StringIO()
            with (
                patch("pyrealm_forensics.cli.carve_realm", return_value=result) as carve,
                contextlib.redirect_stdout(stdout),
            ):
                status = main(
                    ["carve", "sample.realm", "--output", str(output), "--min-string", "9"]
                )

        self.assertEqual(status, 0)
        carve.assert_called_once_with(Path("sample.realm"), output, 9)
        self.assertIn(f"Results: {output.resolve()}", stdout.getvalue())

    def test_main_carve_returns_two_without_header(self) -> None:
        with (
            patch(
                "pyrealm_forensics.cli.carve_realm",
                return_value=analysis(with_header=False),
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            status = main(["carve", "sample.bin", "-o", "results"])
        self.assertEqual(status, 2)


if __name__ == "__main__":
    unittest.main()
