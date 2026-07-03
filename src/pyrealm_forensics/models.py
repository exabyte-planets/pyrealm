"""Data models emitted by the Realm structural scanner."""

from __future__ import annotations

from typing import Literal, NamedTuple

Reachability = Literal["active", "shared", "inactive", "orphan"]


class RealmHeader(NamedTuple):
    """The fixed 24-byte Realm file header."""

    top_refs: tuple[int, int]
    format_slots: tuple[int, int]
    reserved: int
    flags: int
    active_slot: int
    active_top_ref: int
    inactive_top_ref: int
    streaming: bool


class ArrayNode(NamedTuple):
    """A structurally valid, on-disk Realm array."""

    offset: int
    byte_size: int
    payload_size: int
    element_count: int
    width: int
    width_scheme: int
    has_refs: bool
    inner_bptree: bool
    context_flag: bool
    child_refs: tuple[int, ...]
    reachability: Reachability


class CarvedString(NamedTuple):
    """A printable string found inside an array payload."""

    file_offset: int
    array_offset: int
    encoding: Literal["utf-8", "utf-16le"]
    value: str
    reachability: Reachability


class Analysis(NamedTuple):
    """Top-level analysis result."""

    path: str
    sha256: str
    file_size: int
    classification: str
    entropy: float
    header: RealmHeader | None
    arrays: tuple[ArrayNode, ...]
    warnings: tuple[str, ...]


def analysis_dict(analysis: Analysis) -> dict[str, object]:
    """Return an Analysis as a recursively JSON-compatible object mapping."""
    result: dict[str, object] = dict(analysis._asdict())
    result["header"] = analysis.header._asdict() if analysis.header is not None else None
    result["arrays"] = [node._asdict() for node in analysis.arrays]
    return result
