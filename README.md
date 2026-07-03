# pyrealm-forensics

`pyrealm` provides read-only logical access, structural scanning, and conservative carving for
Android Realm files. Logical access uses a pinned Realm Core build to open encrypted or plaintext
Realm files immutably, discover their schema, iterate records, resolve links, and execute Realm
Query Language expressions.

The structural scanner identifies the Realm header, walks both copy-on-write root trees,
inventories Realm arrays, and extracts printable strings from active, inactive, and orphaned
arrays.

It does **not** claim that every orphan is deleted evidence or reconstruct complete logical
records. Realm is column-oriented; correlating carved columns into records is version- and
schema-sensitive. Preserve the source file and validate every result against app context.

## Install and run

```sh
UV_CACHE_DIR=.uv-cache uv sync
uv run pyrealm inspect evidence/default.realm
uv run pyrealm inspect evidence/default.realm --json
uv run pyrealm carve evidence/default.realm -o results/default
```

Open an encrypted Realm using a raw 64-byte key file:

```python
from pyrealm_forensics import open_realm

with open_realm("evidence/disk_store.realm", key_file="evidence/disk_store.key") as realm:
    print(realm.table_names)

    events = realm["EventEntity"].where(
        "roomId == $0 AND type == $1 SORT(originServerTs DESC) LIMIT(100)",
        room_id,
        "m.room.message",
    )
    for event in events:
        print(event["eventId"], event["content"])
```

Object links are lazy mappings. Accessing a linked field resolves it once and caches the record:

```python
sender = event["senderEntity"]
print(sender["displayName"])

serializable = event.to_dict(expand_links=True, max_depth=2)
```

Inspect the logical schema or dump records as JSON Lines:

```sh
uv run pyrealm schema evidence/disk_store.realm --key-file evidence/disk_store.key
uv run pyrealm dump evidence/disk_store.realm \
  --key-file evidence/disk_store.key \
  --table EventEntity \
  --query 'type == $0 SORT(originServerTs DESC) LIMIT(100)' \
  --arg '"m.room.message"'
```

Logical opening is immutable and disables Realm file-format upgrades. Unsupported historical
formats fail explicitly rather than modifying the source.

The output directory is intentionally required to be new. It contains:

- `summary.json`: source hash, header, warnings, and array inventory
- `arrays.jsonl`: one structural array candidate per line
- `strings.csv`: printable strings with byte offsets and reachability classification

Reachability means:

- `active`: reachable only from the committed root selected by header bit 0
- `shared`: reachable from both roots
- `inactive`: reachable only from the alternate root; often a prior transaction, not proof of deletion
- `orphan`: valid array signature not reachable from either root; a carving candidate, not proof of deletion

See [docs/realm_android.md](docs/realm_android.md) for acquisition, internals, encryption,
limitations, and related projects.

The supplied Element Classic control is summarized in
[docs/element_baseline.md](docs/element_baseline.md). It demonstrates why inactive/orphan
structures cannot by themselves establish deletion.

## Development

```sh
UV_CACHE_DIR=.uv-cache uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run ty check src tests
```

Logical record reading targets the current committed Realm state first. Schema-aware access
to inactive snapshots and deleted logical records remains future work.
