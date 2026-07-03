from __future__ import annotations

import datetime as dt
import hashlib
import tarfile
from pathlib import Path

import pytest

from pyrealm import (
    RealmError,
    RealmLink,
    RealmOpenError,
    RealmQueryError,
    RealmTimestamp,
    open_realm,
)

FIXTURES = Path(__file__).parent / "fixtures"
ENCRYPTED_REALM = FIXTURES / "encrypted.realm"
ENCRYPTION_KEY = FIXTURES / "encrypted.key"
ANDROID_SNAPSHOT = (
    Path(__file__).parent / "data" / "im.vector.app-2026-07-02-snapshot-after-second-deleted.tar"
)
ANDROID_KEY = Path(__file__).parent / "data" / "disk_store.key"
ANDROID_REALM_MEMBER = (
    "data/user/0/im.vector.app/files/ae58dbb4f7f1b37b167cf2cfbb323d01/disk_store.realm"
)


@pytest.fixture
def realm():
    return open_realm(ENCRYPTED_REALM, key_file=ENCRYPTION_KEY)


def test_opens_encrypted_realm_immutably_without_side_files(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.realm"
    evidence.write_bytes(ENCRYPTED_REALM.read_bytes())
    before = hashlib.sha256(evidence.read_bytes()).digest()

    realm = open_realm(evidence, key_file=ENCRYPTION_KEY)

    assert realm.core_version == "13.27.0"
    assert realm.table_names == ("Event", "Person")
    assert hashlib.sha256(evidence.read_bytes()).digest() == before
    assert not evidence.with_suffix(".realm.lock").exists()
    assert not evidence.with_suffix(".realm.note").exists()
    assert not evidence.with_suffix(".realm.management").exists()


def test_rejects_wrong_length_and_wrong_value_keys() -> None:
    with pytest.raises(ValueError, match="64 bytes"):
        open_realm(ENCRYPTED_REALM, key=b"short")

    with pytest.raises(RealmOpenError):
        open_realm(ENCRYPTED_REALM, key=b"\xff" * 64)


def test_exposes_schema_and_records(realm) -> None:
    people = realm.table("Person")

    assert len(people) == 2
    assert people.schema.primary_key == "id"
    assert [prop.name for prop in people.schema.properties] == ["id", "name", "age", "friend"]
    assert people.schema.properties[-1].link_target == "Person"
    assert [record["name"] for record in people] == ["Alice", "Bob"]


def test_executes_parameterized_rql_with_sorting(realm) -> None:
    results = realm["Event"].where("priority >= $0 SORT(priority DESC)", 2)

    assert len(results) == 1
    assert results[0]["title"] == "Review evidence"
    assert results[-1] is results[0]
    assert results[:1] == [results[0]]


def test_reports_rql_parse_errors(realm) -> None:
    with pytest.raises(RealmQueryError, match="parse Realm query"):
        realm["Event"].where("not valid RQL")


def test_resolves_and_caches_links_lazily(realm) -> None:
    alice = realm["Person"].where("name == $0", "Alice")[0]
    friend = alice["friend"]

    assert isinstance(friend, RealmLink)
    assert friend.table_name == "Person"
    assert friend["name"] == "Bob"
    assert friend.resolve() is friend.resolve()
    assert friend["friend"].resolve() is alice


def test_serializes_links_as_references_or_depth_limited_records(realm) -> None:
    alice = realm["Person"].where("name == $0", "Alice")[0]

    assert alice.to_dict()["friend"] == {"$ref": {"table": "Person", "key": 1}}
    expanded = alice.to_dict(expand_links=True, max_depth=2)
    assert expanded["friend"]["name"] == "Bob"
    assert expanded["friend"]["friend"] == {"$ref": {"table": "Person", "key": 0}}


def test_timestamp_datetime_handles_pre_epoch_and_out_of_range() -> None:
    pre_epoch = RealmTimestamp(seconds=-2, nanoseconds=-500_000_000)
    assert pre_epoch.datetime == dt.datetime(1969, 12, 31, 23, 59, 57, 500_000, tzinfo=dt.UTC)

    with pytest.raises(RealmError, match="outside the datetime range"):
        _ = RealmTimestamp(seconds=2**62, nanoseconds=0).datetime


def test_links_obey_the_hash_equality_contract(realm) -> None:
    bob_friend = realm["Person"].where("name == $0", "Bob")[0]["friend"]
    event_owner = realm["Event"].where("id == $0", 10)[0]["owner"]

    assert isinstance(bob_friend, RealmLink)
    assert isinstance(event_owner, RealmLink)
    assert bob_friend is not event_owner
    assert bob_friend == event_owner
    assert hash(bob_friend) == hash(event_owner)
    assert len({bob_friend, event_owner}) == 1


def test_use_after_close_raises_the_public_realm_error() -> None:
    realm = open_realm(ENCRYPTED_REALM, key_file=ENCRYPTION_KEY)
    people = realm["Person"]
    results = people.all()
    realm.close()

    assert len(results) == 2  # the count was snapshotted when the query ran
    with pytest.raises(RealmError):
        results[0]
    with pytest.raises(RealmError):
        len(people)


def test_rejects_unknown_tables_and_ambiguous_key_sources(realm) -> None:
    with pytest.raises(KeyError, match="table not found"):
        realm.table("Missing")
    with pytest.raises(ValueError, match="either key or key_file"):
        open_realm(ENCRYPTED_REALM, key=b"\0" * 64, key_file=ENCRYPTION_KEY)


@pytest.mark.skipif(
    not ANDROID_SNAPSHOT.exists() or not ANDROID_KEY.exists(),
    reason="private Android integration fixture is unavailable",
)
def test_opens_selected_android_snapshot_without_modification(tmp_path: Path) -> None:
    evidence = tmp_path / "disk_store.realm"
    with tarfile.open(ANDROID_SNAPSHOT) as archive:
        source = archive.extractfile(ANDROID_REALM_MEMBER)
        assert source is not None
        evidence.write_bytes(source.read())
    before = hashlib.sha256(evidence.read_bytes()).digest()

    realm = open_realm(evidence, key_file=ANDROID_KEY)

    assert len(realm.schema) == 46
    assert len(realm["EventEntity"]) == 58_427
    assert hashlib.sha256(evidence.read_bytes()).digest() == before
