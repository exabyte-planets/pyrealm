from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

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


def test_parser_builds_inspect_and_carve_arguments() -> None:
    parser = _parser()
    inspect = parser.parse_args(["inspect", "sample.realm", "--json"])
    carve = parser.parse_args(["carve", "sample.realm", "-o", "results", "--min-string", "7"])

    assert (inspect.command, inspect.realm, inspect.json) == (
        "inspect",
        Path("sample.realm"),
        True,
    )
    assert (carve.output, carve.min_string) == (Path("results"), 7)


def test_human_summary_includes_header_arrays_and_warnings() -> None:
    summary = _human_summary(analysis())

    assert "Classification: plaintext-realm" in summary
    assert "Entropy: 1.250 bits/byte" in summary
    assert "Arrays: 1" in summary
    assert "Format slots: (10, 11)" in summary
    assert "Active root: 0x18" in summary
    assert "Warning: test warning" in summary


def test_human_summary_omits_header_lines_when_unrecognized() -> None:
    summary = _human_summary(analysis(with_header=False))
    assert "Format slots:" not in summary
    assert "Active root:" not in summary


def test_main_inspect_prints_human_output_and_returns_success(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    analyze = Mock(return_value=analysis())
    monkeypatch.setattr("pyrealm_forensics.cli.analyze_realm", analyze)

    status = main(["inspect", "sample.realm"])

    assert status == 0
    analyze.assert_called_once_with(Path("sample.realm"))
    assert "Classification: plaintext-realm" in capsys.readouterr().out


def test_main_inspect_prints_json_and_returns_three_without_header(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "pyrealm_forensics.cli.analyze_realm", Mock(return_value=analysis(with_header=False))
    )

    status = main(["inspect", "sample.bin", "--json"])

    assert status == 3
    assert json.loads(capsys.readouterr().out)["header"] is None


def test_main_carve_passes_options_and_prints_output_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "results"
    carve = Mock(return_value=analysis())
    monkeypatch.setattr("pyrealm_forensics.cli.carve_realm", carve)

    status = main(["carve", "sample.realm", "--output", str(output), "--min-string", "9"])

    assert status == 0
    carve.assert_called_once_with(Path("sample.realm"), output, 9)
    assert f"Results: {output.resolve()}" in capsys.readouterr().out


def test_main_carve_returns_three_without_header(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "pyrealm_forensics.cli.carve_realm", Mock(return_value=analysis(with_header=False))
    )

    status = main(["carve", "sample.bin", "-o", "results"])

    assert status == 3
    capsys.readouterr()


def test_main_reports_missing_input_as_operational_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    status = main(["inspect", str(tmp_path / "missing.realm")])

    captured = capsys.readouterr()
    assert status == 1
    assert "error:" in captured.err
    assert captured.out == ""


def test_main_reports_existing_output_as_operational_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "results"
    output.mkdir()

    status = main(["carve", str(tmp_path / "missing.realm"), "-o", str(output)])

    assert status == 1
    assert "already exists" in capsys.readouterr().err


def test_parser_rejects_non_positive_min_string() -> None:
    with pytest.raises(SystemExit):
        _parser().parse_args(["carve", "sample.realm", "-o", "results", "--min-string", "0"])
