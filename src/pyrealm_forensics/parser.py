"""Conservative, read-only Realm structure parsing and carving."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import mmap
import re
import struct
from collections import Counter
from pathlib import Path
from typing import BinaryIO

from pyrealm_forensics.models import (
    Analysis,
    ArrayNode,
    CarvedString,
    RealmHeader,
    analysis_dict,
)

FILE_HEADER_SIZE = 24
ARRAY_HEADER_SIZE = 8
REALM_MAGIC = b"T-DB"
ARRAY_SIGNATURE = b"AAAA"
STREAMING_COOKIE = 0x3034125237E526C8
WIDTHS = (0, 1, 2, 4, 8, 16, 32, 64)
ENCRYPTION_BLOCK_SIZE = 4096
ENCRYPTED_ENTROPY_THRESHOLD = 7.5


def _utf16le_pattern(minimum: int) -> re.Pattern[bytes]:
    """Build a printable UTF-16LE run matcher honoring the caller's minimum length.

    Compiling per extraction keeps the requested minimum authoritative for both
    encodings instead of silently imposing a fixed floor on UTF-16 strings.
    """
    return re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum)


def _sha256(file: BinaryIO) -> str:
    """Hash the complete evidence stream, then rewind it for subsequent parsing.

    A digest ties generated reports to the exact input bytes. Reading in bounded
    chunks avoids loading a potentially large database into memory, and rewinding
    lets callers continue to use the same open file without coordinating offsets.
    """
    digest = hashlib.sha256()
    for chunk in iter(lambda: file.read(1024 * 1024), b""):
        digest.update(chunk)
    file.seek(0)
    return digest.hexdigest()


def _sample_entropy(data: mmap.mmap) -> float:
    """Estimate byte entropy from at most 1 MiB spread across the file.

    Entropy is useful context when a Realm header is absent, but it cannot prove
    encryption. Sampling both ends keeps analysis bounded while avoiding a bias
    toward metadata commonly concentrated at the beginning of database files.
    """
    if not data:
        return 0.0
    sample_size = min(len(data), 1024 * 1024)
    if sample_size == len(data):
        sample = data[:]
    else:
        half = sample_size // 2
        sample = data[:half] + data[-half:]
    counts = Counter(sample)
    total = len(sample)
    entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())
    return entropy if entropy > 0.0 else 0.0


def _parse_header(data: mmap.mmap) -> RealmHeader | None:
    """Decode a Realm header only when its identifying invariants are present.

    Normal Realm files retain two top references so a transaction can switch the
    active slot atomically. Streaming files instead place their top reference in a
    cookie-protected footer. Returning ``None`` for truncated or invalid variants
    prevents arbitrary bytes from being treated as trustworthy structural roots.
    """
    if len(data) < FILE_HEADER_SIZE or data[16:20] != REALM_MAGIC:
        return None
    top_refs = struct.unpack_from("<QQ", data, 0)
    format_slots = (data[20], data[21])
    flags = data[23]
    active_slot = flags & 1
    streaming = active_slot == 0 and top_refs[0] == 0xFFFFFFFFFFFFFFFF
    if streaming:
        if len(data) < FILE_HEADER_SIZE + 16:
            return None
        footer_top_ref, cookie = struct.unpack_from("<QQ", data, len(data) - 16)
        if cookie != STREAMING_COOKIE:
            return None
        active_top_ref = footer_top_ref
        inactive_top_ref = 0
    else:
        active_top_ref = top_refs[active_slot]
        inactive_top_ref = top_refs[active_slot ^ 1]
        if inactive_top_ref == 0xFFFFFFFFFFFFFFFF:
            inactive_top_ref = 0
    return RealmHeader(
        top_refs=top_refs,
        format_slots=format_slots,
        reserved=data[22],
        flags=flags,
        active_slot=active_slot,
        active_top_ref=active_top_ref,
        inactive_top_ref=inactive_top_ref,
        streaming=streaming,
    )


def _array_size(flags: int, element_count: int) -> tuple[int, int, int] | None:
    """Calculate an array's aligned on-disk size from its encoded layout flags.

    Realm uses different width schemes for bit-packed, byte-scaled, and
    width-independent payloads. Centralizing that arithmetic keeps candidate
    validation consistent; the reserved fourth scheme is rejected because its
    size cannot be inferred safely. Payloads are rounded to Realm's 8-byte
    alignment before the fixed header is added.
    """
    width_scheme = (flags >> 3) & 0x03
    width = WIDTHS[flags & 0x07]
    if width_scheme == 0:
        payload_size = (element_count * width + 7) // 8
    elif width_scheme == 1:
        payload_size = element_count * width
    elif width_scheme == 2:
        payload_size = element_count
    else:
        return None
    payload_size = (payload_size + 7) & ~7
    return ARRAY_HEADER_SIZE + payload_size, payload_size, width


def _scan_array_candidates(data: mmap.mmap) -> dict[int, ArrayNode]:
    """Find structurally plausible Realm arrays without assuming they are live.

    Carving starts from the ``AAAA`` signature so it can recover disconnected
    data, but a signature alone is weak evidence. Alignment, recognized sizing,
    and file-bound checks reduce false positives. Candidates begin as orphans;
    reachability is assigned only after their reference graph is constructed.
    """
    candidates: dict[int, ArrayNode] = {}
    offset = data.find(ARRAY_SIGNATURE, FILE_HEADER_SIZE)
    while offset != -1:
        if offset % 8 == 0 and offset + ARRAY_HEADER_SIZE <= len(data):
            flags = data[offset + 4]
            element_count = int.from_bytes(data[offset + 5 : offset + 8], "big")
            sizing = _array_size(flags, element_count)
            if sizing is not None:
                byte_size, payload_size, width = sizing
                if byte_size >= ARRAY_HEADER_SIZE and offset + byte_size <= len(data):
                    candidates[offset] = ArrayNode(
                        offset=offset,
                        byte_size=byte_size,
                        payload_size=payload_size,
                        element_count=element_count,
                        width=width,
                        width_scheme=(flags >> 3) & 0x03,
                        has_refs=bool(flags & 0x40),
                        inner_bptree=bool(flags & 0x80),
                        context_flag=bool(flags & 0x20),
                        child_refs=(),
                        reachability="orphan",
                    )
        offset = data.find(ARRAY_SIGNATURE, offset + 1)
    return candidates


def _add_references(data: mmap.mmap, nodes: dict[int, ArrayNode]) -> dict[int, ArrayNode]:
    """Attach child edges that resolve to other validated array candidates.

    Only bit-width arrays explicitly marked as containing references are decoded.
    Realm can store tagged or inline values in similar integer fields, so odd,
    null, and unknown offsets are excluded. Requiring a target in ``nodes`` keeps
    graph traversal inside structures already validated by the scanner.
    """
    result: dict[int, ArrayNode] = {}
    for offset, node in nodes.items():
        refs: list[int] = []
        if node.has_refs and node.width in (8, 16, 32, 64) and node.width_scheme == 0:
            payload_start = offset + ARRAY_HEADER_SIZE
            element_size = node.width // 8
            for index in range(node.element_count):
                start = payload_start + index * element_size
                value = int.from_bytes(data[start : start + element_size], "little")
                if value and value & 1 == 0 and value in nodes:
                    refs.append(value)
        result[offset] = node._replace(child_refs=tuple(dict.fromkeys(refs)))
    return result


def _reachable(nodes: dict[int, ArrayNode], root: int) -> set[int]:
    """Return all validated nodes reachable from one top reference.

    An iterative traversal avoids recursion limits on deeply nested databases.
    The visited set also makes cycles and duplicate references harmless. A root
    that was not recognized yields an empty set rather than inventing structure.
    """
    if root not in nodes:
        return set()
    seen: set[int] = set()
    pending = [root]
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        pending.extend(ref for ref in nodes[current].child_refs if ref not in seen)
    return seen


def _classify_nodes(nodes: dict[int, ArrayNode], header: RealmHeader) -> tuple[ArrayNode, ...]:
    """Label arrays by membership in the active and inactive transaction graphs.

    Comparing both roots distinguishes current data from the previous snapshot,
    shared structures, and disconnected remnants that may be useful for forensic
    recovery. Sorting by file offset makes reports deterministic.
    """
    active = _reachable(nodes, header.active_top_ref)
    inactive = _reachable(nodes, header.inactive_top_ref)
    classified: list[ArrayNode] = []
    for offset in sorted(nodes):
        if offset in active and offset in inactive:
            reachability = "shared"
        elif offset in active:
            reachability = "active"
        elif offset in inactive:
            reachability = "inactive"
        else:
            reachability = "orphan"
        classified.append(nodes[offset]._replace(reachability=reachability))
    return tuple(classified)


def _top_reference_warning(label: str, reference: int, file_size: int) -> str | None:
    """Explain an impossible root while allowing orphan carving to continue."""
    if reference == 0:
        return None
    if reference % 8:
        reason = "is not 8-byte aligned"
    elif reference < FILE_HEADER_SIZE:
        reason = "points inside the file header"
    elif reference >= file_size:
        reason = "points beyond the end of the file"
    else:
        return None
    return (
        f"The {label} top reference {reason}; the file is damaged or incomplete. "
        "Preserve the source and try carving orphan arrays or obtaining another copy."
    )


def _analyze(path: Path, minimum_string: int | None) -> tuple[Analysis, list[CarvedString]]:
    """Analyze one open mapping, optionally carving strings from the same bytes.

    The source is resolved and opened read-only, hashed for provenance, and
    memory-mapped to avoid copying the full database. Extracting strings inside
    the same mapping guarantees the digest, structural offsets, and carved
    strings all describe the identical bytes, and avoids a second open and page
    walk over potentially large evidence.
    """
    resolved = path.expanduser().resolve(strict=True)
    with resolved.open("rb") as file:
        digest = _sha256(file)
        if resolved.stat().st_size == 0:
            empty = Analysis(
                path=str(resolved),
                sha256=digest,
                file_size=0,
                classification="empty",
                entropy=0.0,
                header=None,
                arrays=(),
                warnings=("The file is empty.",),
            )
            return empty, []
        with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as data:
            entropy = _sample_entropy(data)
            header = _parse_header(data)
            if header is None:
                return _classify_headerless(resolved, digest, data, entropy), []
            nodes = _add_references(data, _scan_array_candidates(data))
            arrays = _classify_nodes(nodes, header)
            warnings: list[str] = []
            for label, reference in (
                ("active", header.active_top_ref),
                ("inactive", header.inactive_top_ref),
            ):
                warning = _top_reference_warning(label, reference, len(data))
                if warning is not None:
                    warnings.append(warning)
            if header.active_top_ref not in nodes:
                warnings.append(
                    "The active top reference did not resolve to a recognized array; the file "
                    "may use an unsupported format or be damaged."
                )
            if header.inactive_top_ref and header.inactive_top_ref not in nodes:
                warnings.append("The inactive top reference did not resolve to a recognized array.")
            if header.reserved:
                warnings.append("The reserved Realm header byte is non-zero.")
            strings: list[CarvedString] = []
            if minimum_string is not None and arrays:
                strings = _extract_strings(data, arrays, minimum_string)
            analysis = Analysis(
                path=str(resolved),
                sha256=digest,
                file_size=len(data),
                classification="plaintext-realm",
                entropy=entropy,
                header=header,
                arrays=arrays,
                warnings=tuple(warnings),
            )
            return analysis, strings


def _classify_headerless(resolved: Path, digest: str, data: mmap.mmap, entropy: float) -> Analysis:
    """Classify a file without a Realm header from its content, not its name.

    Encrypted Realms are organized in 4096-byte blocks of high-entropy data, so
    those content signals decide the classification; recovered evidence often
    arrives without its original filename, which is therefore reported only as
    corroborating (or contradicting) metadata. Neither signal can prove
    encryption: damaged and unsupported Realm formats can look the same.
    """
    encrypted_layout = (
        entropy >= ENCRYPTED_ENTROPY_THRESHOLD and len(data) % ENCRYPTION_BLOCK_SIZE == 0
    )
    if encrypted_layout:
        classification = "possible-encrypted-or-unsupported-realm"
        warning = (
            "The T-DB header is absent, but high byte entropy and a 4096-byte-aligned size "
            "are consistent with an encrypted, damaged, or unsupported Realm; these signals "
            "alone cannot distinguish them."
        )
    else:
        classification = "not-a-plain-realm"
        warning = "The T-DB header is absent; this is not a recognized plaintext Realm."
    warnings = [warning]
    if resolved.suffix.lower() == ".realm" and not encrypted_layout:
        warnings.append(
            "The filename suffix is .realm, but the content does not resemble an encrypted Realm."
        )
    return Analysis(
        path=str(resolved),
        sha256=digest,
        file_size=len(data),
        classification=classification,
        entropy=entropy,
        header=None,
        arrays=(),
        warnings=tuple(warnings),
    )


def analyze_realm(path: Path) -> Analysis:
    """Inspect a possible Realm file and return conservative structural metadata.

    A missing header is not called encryption: content signals only change the
    reported possibility because damaged and unsupported Realm formats can look
    the same. For recognized plaintext files, warnings expose header
    inconsistencies instead of hiding partial results.
    """
    return _analyze(path, None)[0]


def _utf8_strings(payload: bytes, minimum: int) -> list[tuple[int, str]]:
    """Carve printable UTF-8 runs while retaining byte-accurate offsets.

    Decoding one code point at a time allows scanning to resume immediately after
    malformed bytes, which is important for partially overwritten data. Length is
    measured in characters rather than encoded bytes so multibyte text obeys the
    same minimum as ASCII text.
    """
    results: list[tuple[int, str]] = []
    start: int | None = None
    chars: list[str] = []
    index = 0
    while index < len(payload):
        lead = payload[index]
        width = 1 if lead < 0x80 else 2 if lead < 0xE0 else 3 if lead < 0xF0 else 4
        try:
            char = payload[index : index + width].decode("utf-8")
        except UnicodeDecodeError:
            char = ""
        if char and (char.isprintable() or char in "\t"):
            if start is None:
                start = index
            chars.append(char)
            index += width
            continue
        if start is not None and len(chars) >= minimum:
            results.append((start, "".join(chars)))
        start = None
        chars = []
        index += 1
    if start is not None and len(chars) >= minimum:
        results.append((start, "".join(chars)))
    return results


def _extract_strings(
    data: mmap.mmap, nodes: tuple[ArrayNode, ...], minimum: int
) -> list[CarvedString]:
    """Extract printable UTF-8 and UTF-16LE strings from non-reference payloads.

    Reference arrays are skipped because interpreting encoded pointers as text
    produces misleading evidence. Each result retains its absolute file offset,
    containing array, and reachability classification so consumers can separate
    current values from inactive or orphaned remnants.
    """
    strings: list[CarvedString] = []
    utf16le_printable = _utf16le_pattern(minimum) if minimum <= len(data) // 2 else None
    for node in nodes:
        if node.has_refs:
            continue
        payload_start = node.offset + ARRAY_HEADER_SIZE
        payload = data[payload_start : payload_start + node.payload_size]
        for relative_offset, value in _utf8_strings(payload, minimum):
            strings.append(
                CarvedString(
                    file_offset=payload_start + relative_offset,
                    array_offset=node.offset,
                    encoding="utf-8",
                    value=value,
                    reachability=node.reachability,
                )
            )
        if utf16le_printable is None:
            continue
        for match in utf16le_printable.finditer(payload):
            strings.append(
                CarvedString(
                    file_offset=payload_start + match.start(),
                    array_offset=node.offset,
                    encoding="utf-16le",
                    value=match.group().decode("utf-16le"),
                    reachability=node.reachability,
                )
            )
    return strings


def carve_realm(path: Path, output: Path, minimum_string: int = 4) -> Analysis:
    """Write analysis, array metadata, and carved strings to a new directory.

    Refusing an existing directory protects prior results from accidental
    overwrite and keeps every output set attributable to one invocation; both
    preconditions are checked before the potentially expensive analysis pass.
    Reports are still created for unrecognized inputs, preserving the digest,
    classification, and warnings even when no safe string extraction is possible.
    """
    if minimum_string < 1:
        raise ValueError("minimum_string must be at least 1")
    if output.exists():
        raise FileExistsError(f"output directory already exists: {output}")
    analysis, strings = _analyze(path, minimum_string)
    output.mkdir(parents=True, exist_ok=False)
    with (output / "summary.json").open("w", encoding="utf-8") as file:
        json.dump(analysis_dict(analysis), file, indent=2)
        file.write("\n")
    with (output / "arrays.jsonl").open("w", encoding="utf-8") as file:
        for node in analysis.arrays:
            file.write(json.dumps(node._asdict(), sort_keys=True))
            file.write("\n")
    with (output / "strings.csv").open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "file_offset",
                "array_offset",
                "encoding",
                "reachability",
                "value",
            ],
        )
        writer.writeheader()
        for item in strings:
            writer.writerow(item._asdict())
    return analysis
