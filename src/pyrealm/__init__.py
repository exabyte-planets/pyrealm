"""Read-only logical access to Realm database files."""

from pyrealm.reader import (
    PropertySchema,
    Realm,
    RealmError,
    RealmLink,
    RealmObjectId,
    RealmOpenError,
    RealmQueryError,
    RealmTimestamp,
    Record,
    Results,
    Table,
    TableSchema,
    open_realm,
)

__all__ = [
    "PropertySchema",
    "Realm",
    "RealmError",
    "RealmLink",
    "RealmObjectId",
    "RealmOpenError",
    "RealmQueryError",
    "RealmTimestamp",
    "Record",
    "Results",
    "Table",
    "TableSchema",
    "open_realm",
]
