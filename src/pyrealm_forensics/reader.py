"""Pythonic, read-only access to logical records in Realm files."""

from __future__ import annotations

import base64
import datetime as dt
import decimal
import uuid
import weakref
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast, overload

from pyrealm_forensics import _native


class RealmError(Exception):
    """Base exception for logical Realm access."""


class RealmOpenError(RealmError):
    """Raised when Realm Core cannot open a database immutably."""


class RealmQueryError(RealmError):
    """Raised when Realm Core rejects or cannot execute an RQL query."""


@dataclass(frozen=True, slots=True)
class RealmTimestamp:
    """A Realm timestamp without losing nanosecond precision."""

    seconds: int
    nanoseconds: int

    @property
    def datetime(self) -> dt.datetime:
        """Return the closest UTC Python datetime."""
        return dt.datetime.fromtimestamp(self.seconds, dt.UTC).replace(
            microsecond=self.nanoseconds // 1_000
        )


@dataclass(frozen=True, slots=True)
class RealmObjectId:
    """A Realm ObjectId represented by its canonical hexadecimal string."""

    value: str

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class PropertySchema:
    """One property in a Realm class."""

    name: str
    public_name: str | None
    key: int
    type: str
    collection: str
    nullable: bool
    primary_key: bool
    indexed: bool
    link_target: str | None
    link_origin_property: str | None


@dataclass(frozen=True, slots=True)
class TableSchema:
    """The logical schema for a Realm class/table."""

    name: str
    key: int
    primary_key: str | None
    embedded: bool
    asymmetric: bool
    properties: tuple[PropertySchema, ...]


class RealmLink(Mapping[str, object]):
    """A lazy link to another Realm record."""

    __slots__ = ("_realm_ref", "object_key", "table_key")

    def __init__(self, realm: Realm, table_key: int, object_key: int) -> None:
        self._realm_ref = weakref.ref(realm)
        self.table_key = table_key
        self.object_key = object_key

    @property
    def table_name(self) -> str:
        return self._realm()._schema_by_key[self.table_key].name

    def resolve(self) -> Record:
        """Resolve and cache the target record."""
        return self._realm()._record(self.table_key, self.object_key)

    def __getitem__(self, key: str) -> object:
        return self.resolve()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.resolve())

    def __len__(self) -> int:
        return len(self.resolve())

    def __hash__(self) -> int:
        return hash((id(self._realm_ref()), self.table_key, self.object_key))

    def __repr__(self) -> str:
        return f"RealmLink(table={self.table_name!r}, key={self.object_key})"

    def _realm(self) -> Realm:
        realm = self._realm_ref()
        if realm is None:
            raise RealmError("the Realm owning this link has been released")
        return realm


class Record(Mapping[str, object]):
    """A lazily converted mapping for one logical Realm object."""

    __slots__ = (
        "__weakref__",
        "_converted",
        "_raw",
        "_realm_ref",
        "object_key",
        "table_key",
    )

    def __init__(self, realm: Realm, raw: dict[str, object]) -> None:
        self._realm_ref = weakref.ref(realm)
        self.table_key = cast(int, raw.pop("__table_key__"))
        self.object_key = cast(int, raw.pop("__object_key__"))
        self._raw = raw
        self._converted: dict[str, object] = {}

    @property
    def table_name(self) -> str:
        return self._realm()._schema_by_key[self.table_key].name

    def __getitem__(self, key: str) -> object:
        if key in self._converted:
            return self._converted[key]
        try:
            raw = self._raw[key]
        except KeyError:
            raise KeyError(key) from None
        converted = self._realm()._convert(raw)
        self._converted[key] = converted
        return converted

    def __iter__(self) -> Iterator[str]:
        return iter(self._raw)

    def __len__(self) -> int:
        return len(self._raw)

    def __repr__(self) -> str:
        return f"Record(table={self.table_name!r}, key={self.object_key}, fields={len(self)})"

    def to_dict(self, *, expand_links: bool = False, max_depth: int = 1) -> dict[str, object]:
        """Convert to built-in containers with controlled link expansion."""
        if max_depth < 0:
            raise ValueError("max_depth must be at least 0")
        return self._to_dict(expand_links, max_depth, set())

    def _to_dict(
        self,
        expand_links: bool,
        remaining_depth: int,
        seen: set[tuple[int, int]],
    ) -> dict[str, object]:
        identity = (self.table_key, self.object_key)
        if identity in seen:
            return {"$ref": {"table": self.table_name, "key": self.object_key}}
        seen.add(identity)
        result = {
            key: self._realm()._plain_value(self[key], expand_links, remaining_depth, seen)
            for key in self
        }
        seen.remove(identity)
        return result

    def _realm(self) -> Realm:
        realm = self._realm_ref()
        if realm is None:
            raise RealmError("the Realm owning this record has been released")
        return realm


class Results(Sequence[Record]):
    """A lazy Realm Core result set."""

    __slots__ = ("_native", "_realm")

    def __init__(self, realm: Realm, native: _native.NativeResults) -> None:
        self._realm = realm
        self._native = native

    def __len__(self) -> int:
        return len(self._native)

    @overload
    def __getitem__(self, index: int) -> Record: ...

    @overload
    def __getitem__(self, index: slice) -> list[Record]: ...

    def __getitem__(self, index: int | slice) -> Record | list[Record]:
        if isinstance(index, slice):
            return [
                self._realm._record_from_raw(self._native[item])
                for item in range(*index.indices(len(self)))
            ]
        return self._realm._record_from_raw(self._native[index])

    def __iter__(self) -> Iterator[Record]:
        for index in range(len(self)):
            item = self[index]
            assert isinstance(item, Record)
            yield item


class Table:
    """A read-only Realm class/table."""

    __slots__ = ("_realm", "schema")

    def __init__(self, realm: Realm, schema: TableSchema) -> None:
        self._realm = realm
        self.schema = schema

    @property
    def name(self) -> str:
        return self.schema.name

    def __len__(self) -> int:
        return self._realm._native.count(self.name)

    def __iter__(self) -> Iterator[Record]:
        return iter(self.all())

    def all(self) -> Results:
        """Return all logical records."""
        return Results(self._realm, self._realm._native.all(self.name))

    def where(self, query: str, *parameters: object) -> Results:
        """Execute a parameterized Realm Query Language expression."""
        try:
            native = self._realm._native.query(self.name, query, *parameters)
        except _native.NativeError as error:
            raise RealmQueryError(str(error)) from error
        return Results(self._realm, native)

    def get_by_key(self, object_key: int) -> Record:
        """Read a record by Realm's internal object key."""
        return self._realm._record(self.schema.key, object_key)

    def __repr__(self) -> str:
        return f"Table(name={self.name!r}, records={len(self)})"


class Realm:
    """An immutable logical view of a Realm database."""

    __slots__ = (
        "__weakref__",
        "_native",
        "_record_cache",
        "_schema_by_key",
        "_schema_by_name",
        "path",
        "schema",
    )

    def __init__(self, path: Path, native: _native.NativeRealm) -> None:
        self.path = path
        self._native = native
        self.schema = tuple(
            TableSchema(
                name=item["name"],
                key=item["key"],
                primary_key=item["primary_key"],
                embedded=item["embedded"],
                asymmetric=item["asymmetric"],
                properties=tuple(PropertySchema(**prop) for prop in item["properties"]),
            )
            for item in native.schema()
        )
        self._schema_by_name = {item.name: item for item in self.schema}
        self._schema_by_key = {item.key: item for item in self.schema}
        self._record_cache: weakref.WeakValueDictionary[tuple[int, int], Record] = (
            weakref.WeakValueDictionary()
        )

    @property
    def core_version(self) -> str:
        return self._native.core_version

    @property
    def table_names(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.schema)

    def table(self, name: str) -> Table:
        """Return a table by its logical class name."""
        try:
            schema = self._schema_by_name[name]
        except KeyError:
            raise KeyError(f"Realm table not found: {name}") from None
        return Table(self, schema)

    def __getitem__(self, name: str) -> Table:
        return self.table(name)

    def __enter__(self) -> Realm:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the immutable Realm view."""
        try:
            self._native.close()
        except _native.NativeError as error:
            raise RealmError(str(error)) from error

    def _record(self, table_key: int, object_key: int) -> Record:
        identity = (table_key, object_key)
        cached = self._record_cache.get(identity)
        if cached is not None:
            return cached
        try:
            raw = self._native.record(table_key, object_key)
        except _native.NativeError as error:
            raise RealmError(str(error)) from error
        return self._record_from_raw(raw)

    def _record_from_raw(self, raw: dict[str, object]) -> Record:
        identity = (
            cast(int, raw["__table_key__"]),
            cast(int, raw["__object_key__"]),
        )
        cached = self._record_cache.get(identity)
        if cached is not None:
            return cached
        record = Record(self, dict(raw))
        self._record_cache[identity] = record
        return record

    def _convert(self, value: object) -> object:
        if isinstance(value, _native.NativeLink):
            return RealmLink(self, value.table_key, value.object_key)
        if isinstance(value, _native.NativeTimestamp):
            return RealmTimestamp(value.seconds, value.nanoseconds)
        if isinstance(value, _native.NativeObjectId):
            return RealmObjectId(value.value)
        if isinstance(value, _native.NativeDecimal128):
            return decimal.Decimal(value.value)
        if isinstance(value, list):
            return tuple(self._convert(item) for item in value)
        if isinstance(value, set):
            return frozenset(self._convert(item) for item in value)
        if isinstance(value, dict):
            return {key: self._convert(item) for key, item in value.items()}
        return value

    def _plain_value(
        self,
        value: object,
        expand_links: bool,
        remaining_depth: int,
        seen: set[tuple[int, int]],
    ) -> object:
        if isinstance(value, RealmLink):
            if expand_links and remaining_depth > 0:
                return value.resolve()._to_dict(expand_links, remaining_depth - 1, seen)
            return {"$ref": {"table": value.table_name, "key": value.object_key}}
        if isinstance(value, RealmTimestamp):
            return {
                "$timestamp": {
                    "seconds": value.seconds,
                    "nanoseconds": value.nanoseconds,
                }
            }
        if isinstance(value, RealmObjectId):
            return {"$objectId": value.value}
        if isinstance(value, decimal.Decimal):
            return {"$decimal128": str(value)}
        if isinstance(value, bytes):
            return {"$binary": base64.b64encode(value).decode("ascii")}
        if isinstance(value, uuid.UUID):
            return {"$uuid": str(value)}
        if isinstance(value, tuple | frozenset):
            return [self._plain_value(item, expand_links, remaining_depth, seen) for item in value]
        if isinstance(value, dict):
            return {
                str(key): self._plain_value(item, expand_links, remaining_depth, seen)
                for key, item in value.items()
            }
        return value


def open_realm(
    path: str | Path,
    *,
    key: bytes | None = None,
    key_file: str | Path | None = None,
) -> Realm:
    """Open a Realm database immutably without format upgrades."""
    if key is not None and key_file is not None:
        raise ValueError("pass either key or key_file, not both")
    resolved = Path(path).expanduser().resolve(strict=True)
    key_data = key
    if key_file is not None:
        key_data = Path(key_file).expanduser().resolve(strict=True).read_bytes()
    if key_data is None:
        key_data = b""
    if len(key_data) not in (0, 64):
        raise ValueError("Realm encryption keys must contain exactly 64 bytes")
    try:
        native = _native.NativeRealm(str(resolved), key_data)
    except _native.NativeError as error:
        raise RealmOpenError(str(error)) from error
    return Realm(resolved, native)
