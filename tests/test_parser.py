from __future__ import annotations

import hashlib
import io
import json
import mmap
import struct
from pathlib import Path
from typing import cast

import pytest

from pyrealm_forensics.models import ArrayNode, RealmHeader
from pyrealm_forensics.parser import (
    STREAMING_COOKIE,
    _add_references,
    _array_size,
    _classify_nodes,
    _extract_strings,
    _parse_header,
    _reachable,
    _sample_entropy,
    _scan_array_candidates,
    _sha256,
    _utf8_strings,
    analyze_realm,
    carve_realm,
)


def array(flags: int, values: bytes, count: int) -> bytes:
    padding = (-len(values)) % 8
    return b"AAAA" + bytes([flags]) + count.to_bytes(3, "big") + values + b"\x00" * padding


def synthetic_realm() -> bytes:
    active_root = 24
    inactive_root = 48
    active_data = 72
    inactive_data = 96
    header = struct.pack("<QQ", active_root, inactive_root) + b"T-DB" + b"\x0a\x0a" + b"\x00\x00"
    ref_flags = 0x44  # references, 8-bit adaptive width, bit-width scheme
    text_flags = 0x10  # no refs, ignore-width scheme => payload is element count
    return b"".join(
        [
            header,
            array(ref_flags, struct.pack("<B", active_data), 1),
            b"\x00" * 8,
            array(ref_flags, struct.pack("<B", inactive_data), 1),
            b"\x00" * 8,
            array(text_flags, b"current!", 8),
            b"\x00" * 8,
            array(text_flags, b"previous", 8),
            b"\x00" * 8,
            array(text_flags, b"deleted?", 8),
        ]
    )


def node(
    offset: int,
    *,
    child_refs: tuple[int, ...] = (),
    has_refs: bool = False,
    width: int = 8,
    width_scheme: int = 0,
    element_count: int = 0,
    payload_size: int = 0,
) -> ArrayNode:
    return ArrayNode(
        offset=offset,
        byte_size=8 + payload_size,
        payload_size=payload_size,
        element_count=element_count,
        width=width,
        width_scheme=width_scheme,
        has_refs=has_refs,
        inner_bptree=False,
        context_flag=False,
        child_refs=child_refs,
        reachability="orphan",
    )


def header(active: int, inactive: int = 0) -> RealmHeader:
    return RealmHeader(
        top_refs=(active, inactive),
        format_slots=(10, 10),
        reserved=0,
        flags=0,
        active_slot=0,
        active_top_ref=active,
        inactive_top_ref=inactive,
        streaming=False,
    )


def mmap_compatible(data: bytes) -> mmap.mmap:
    """Treat immutable bytes as the mmap-compatible read interface used by parser helpers."""
    return cast(mmap.mmap, data)


class TestParser:
    def test_sha256_hashes_full_stream_and_rewinds_it(self) -> None:
        contents = b"realm evidence" * 100
        stream = io.BytesIO(contents)

        assert _sha256(stream) == hashlib.sha256(contents).hexdigest()
        assert stream.tell() == 0

    def test_sample_entropy_handles_empty_and_uniform_data(self) -> None:
        assert _sample_entropy(mmap_compatible(b"")) == 0.0
        assert _sample_entropy(mmap_compatible(b"\x00" * 100)) == 0.0
        assert _sample_entropy(mmap_compatible(bytes(range(256)))) == pytest.approx(8.0)

    def test_sample_entropy_samples_both_ends_of_large_data(self) -> None:
        half = 1024 * 1024
        data = b"\x00" * half + b"\xff" * half
        assert _sample_entropy(mmap_compatible(data)) == pytest.approx(1.0, abs=1e-4)

    def test_parse_header_rejects_short_bad_magic_and_invalid_stream(self) -> None:
        assert _parse_header(mmap_compatible(b"")) is None
        assert _parse_header(mmap_compatible(b"\x00" * 24)) is None
        incomplete = struct.pack("<QQ", 0xFFFFFFFFFFFFFFFF, 0) + b"T-DB" + b"\0" * 4
        assert _parse_header(mmap_compatible(incomplete)) is None
        invalid_cookie = incomplete + struct.pack("<QQ", 24, 0)
        assert _parse_header(mmap_compatible(invalid_cookie)) is None

    def test_parse_header_selects_active_slot(self) -> None:
        data = struct.pack("<QQ", 24, 48) + b"T-DB" + bytes((9, 10, 7, 1))
        parsed = _parse_header(mmap_compatible(data))

        assert parsed is not None
        assert parsed.active_slot == 1
        assert parsed.active_top_ref == 48
        assert parsed.inactive_top_ref == 24
        assert parsed.format_slots == (9, 10)
        assert parsed.reserved == 7
        assert not parsed.streaming

    def test_parse_header_reads_streaming_footer(self) -> None:
        data = (
            struct.pack("<QQ", 0xFFFFFFFFFFFFFFFF, 123)
            + b"T-DB"
            + bytes((9, 10, 0, 0))
            + struct.pack("<QQ", 72, STREAMING_COOKIE)
        )
        parsed = _parse_header(mmap_compatible(data))

        assert parsed is not None
        assert parsed.streaming
        assert parsed.active_top_ref == 72
        assert parsed.inactive_top_ref == 0

    def test_parse_header_uses_selected_slot_after_streaming_conversion(self) -> None:
        data = struct.pack("<QQ", 0xFFFFFFFFFFFFFFFF, 24) + b"T-DB" + bytes((9, 10, 0, 1))

        parsed = _parse_header(mmap_compatible(data))

        assert parsed is not None
        assert not parsed.streaming
        assert parsed.active_top_ref == 24
        assert parsed.inactive_top_ref == 0

    def test_array_size_supports_each_width_scheme(self) -> None:
        assert _array_size(0x02, 9) == (16, 8, 2)
        assert _array_size(0x0A, 5) == (24, 16, 2)
        assert _array_size(0x12, 9) == (24, 16, 2)
        assert _array_size(0x1A, 9) is None

    def test_scan_array_candidates_filters_invalid_candidates(self) -> None:
        valid = array(0x10, b"abc", 3)
        invalid_scheme = b"AAAA" + bytes((0x18,)) + (1).to_bytes(3, "big")
        truncated = b"AAAA" + bytes((0x10,)) + (100).to_bytes(3, "big")
        data = b"\0" * 24 + valid + invalid_scheme + truncated

        candidates = _scan_array_candidates(mmap_compatible(data))

        assert tuple(candidates) == (24,)
        assert candidates[24].payload_size == 8
        assert candidates[24].element_count == 3

    def test_add_references_deduplicates_valid_even_node_offsets(self) -> None:
        parent = node(
            24,
            has_refs=True,
            width=64,
            element_count=5,
            payload_size=40,
        )
        child = node(80)
        values = struct.pack("<QQQQQ", 80, 80, 81, 0, 999)
        data = b"\0" * 32 + values + b"\0" * 32

        result = _add_references(mmap_compatible(data), {24: parent, 80: child})

        assert result[24].child_refs == (80,)
        assert result[80].child_refs == ()

    def test_add_references_ignores_non_reference_array_layouts(self) -> None:
        original = node(0, has_refs=True, width=4, width_scheme=1, element_count=1)
        result = _add_references(mmap_compatible(b"\0" * 16), {0: original})
        assert result[0].child_refs == ()

    def test_reachable_handles_missing_roots_cycles_and_duplicates(self) -> None:
        nodes = {
            8: node(8, child_refs=(16, 16)),
            16: node(16, child_refs=(8, 24)),
            24: node(24),
        }
        assert _reachable(nodes, 999) == set()
        assert _reachable(nodes, 8) == {8, 16, 24}

    def test_classify_nodes_covers_every_reachability(self) -> None:
        nodes = {
            8: node(8, child_refs=(24,)),
            16: node(16, child_refs=(24,)),
            24: node(24),
            32: node(32),
        }
        classified = _classify_nodes(nodes, header(8, 16))
        assert [item.reachability for item in classified] == [
            "active",
            "inactive",
            "shared",
            "orphan",
        ]

    def test_classifies_active_inactive_and_orphan_arrays(self, tmp_path: Path) -> None:
        path = tmp_path / "sample.realm"
        path.write_bytes(synthetic_realm())

        analysis = analyze_realm(path)

        assert analysis.classification == "plaintext-realm"
        assert [node.reachability for node in analysis.arrays] == [
            "active",
            "inactive",
            "active",
            "inactive",
            "orphan",
        ]

    def test_carves_strings_without_modifying_source(self, tmp_path: Path) -> None:
        path = tmp_path / "sample.realm"
        output = tmp_path / "results"
        original = synthetic_realm()
        path.write_bytes(original)

        carve_realm(path, output)

        csv_text = (output / "strings.csv").read_text()
        assert "current!" in csv_text
        assert "previous" in csv_text
        assert "deleted?" in csv_text
        assert path.read_bytes() == original

    def test_missing_magic_is_only_possible_encryption(self, tmp_path: Path) -> None:
        path = tmp_path / "encrypted.realm"
        path.write_bytes(bytes(range(256)) * 16)

        analysis = analyze_realm(path)

        assert analysis.classification == "possible-encrypted-or-unsupported-realm"
        assert analysis.header is None

    def test_headerless_classification_uses_content_not_filename(self, tmp_path: Path) -> None:
        carved = tmp_path / "file0001.bin"
        carved.write_bytes(bytes(range(256)) * 16)
        renamed = tmp_path / "renamed.realm"
        renamed.write_bytes(b"low entropy content")

        carved_analysis = analyze_realm(carved)
        renamed_analysis = analyze_realm(renamed)

        assert carved_analysis.classification == "possible-encrypted-or-unsupported-realm"
        assert renamed_analysis.classification == "not-a-plain-realm"
        assert any(".realm" in warning for warning in renamed_analysis.warnings)

    def test_non_realm_file_and_empty_file_have_specific_classifications(
        self, tmp_path: Path
    ) -> None:
        ordinary = tmp_path / "sample.bin"
        ordinary.write_bytes(b"not a realm")
        empty = tmp_path / "empty.realm"
        empty.touch()

        non_realm = analyze_realm(ordinary)
        empty_result = analyze_realm(empty)

        assert non_realm.classification == "not-a-plain-realm"
        assert "not a recognized plaintext Realm" in non_realm.warnings[0]
        assert empty_result.classification == "empty"
        assert empty_result.entropy == 0.0

    def test_plaintext_analysis_reports_header_warnings(self, tmp_path: Path) -> None:
        raw_header = struct.pack("<QQ", 80, 88) + b"T-DB" + bytes((10, 10, 1, 0))
        path = tmp_path / "warnings.realm"
        path.write_bytes(raw_header)

        analysis = analyze_realm(path)

        assert analysis.warnings == (
            "The active top reference did not resolve to a recognized array; the file "
            "may use an unsupported format or be damaged.",
            "The inactive top reference did not resolve to a recognized array.",
            "The reserved Realm header byte is non-zero.",
        )

    def test_utf8_strings_handles_multibyte_invalid_and_minimum_length(self) -> None:
        payload = b"\xffno\x00caf\xc3\xa9\t\x00end"
        assert _utf8_strings(payload, 4) == [(4, "café\t")]
        assert _utf8_strings(b"tail", 4) == [(0, "tail")]

    def test_extract_strings_finds_both_encodings_and_skips_reference_arrays(self) -> None:
        payload = b"hello\x00\x00" + "world".encode("utf-16le")
        text_node = node(0, payload_size=len(payload))
        reference_node = text_node._replace(has_refs=True)
        data = b"A" * 8 + payload

        extracted = _extract_strings(mmap_compatible(data), (text_node,), 4)
        skipped = _extract_strings(mmap_compatible(data), (reference_node,), 4)

        assert [(item.encoding, item.value, item.file_offset) for item in extracted] == [
            ("utf-8", "hello", 8),
            ("utf-16le", "world", 15),
        ]
        assert skipped == []

    def test_extract_strings_honors_minimum_below_four_for_utf16(self) -> None:
        payload = b"\x00\x00" + "hi".encode("utf-16le")
        text_node = node(0, payload_size=len(payload))
        data = b"A" * 8 + payload

        extracted = _extract_strings(mmap_compatible(data), (text_node,), 2)

        assert [(item.encoding, item.value) for item in extracted] == [("utf-16le", "hi")]

    def test_carve_validates_minimum_before_creating_output(self, tmp_path: Path) -> None:
        output = tmp_path / "results"

        with pytest.raises(ValueError, match="at least 1"):
            carve_realm(tmp_path / "missing.realm", output, 0)

        assert not output.exists()

    def test_carve_writes_empty_reports_for_unrecognized_input(self, tmp_path: Path) -> None:
        path = tmp_path / "sample.bin"
        output = tmp_path / "results"
        path.write_bytes(b"not a realm")

        analysis = carve_realm(path, output)

        summary = json.loads((output / "summary.json").read_text())
        assert summary["classification"] == analysis.classification
        assert (output / "arrays.jsonl").read_text() == ""
        assert (output / "strings.csv").read_text().splitlines() == [
            "file_offset,array_offset,encoding,reachability,value"
        ]

    def test_carve_refuses_to_overwrite_existing_directory(self, tmp_path: Path) -> None:
        path = tmp_path / "sample.realm"
        output = tmp_path / "results"
        path.write_bytes(synthetic_realm())
        output.mkdir()

        with pytest.raises(FileExistsError):
            carve_realm(path, output)

    def test_carve_checks_output_before_reading_the_source(self, tmp_path: Path) -> None:
        output = tmp_path / "results"
        output.mkdir()

        with pytest.raises(FileExistsError):
            carve_realm(tmp_path / "missing.realm", output)
