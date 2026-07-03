# pyrealm-forensics

This distribution provides two deliberately separate interfaces:

- `pyrealm`: a Python library for read-only access to live logical data.
- `pyrealm-recover`: a forensic CLI for structural inspection and conservative recovery.

Both interfaces open evidence immutably, but they solve different problems. The library uses
Realm Core to expose the current committed schema and records. The recovery CLI scans on-disk
structures, including data not reachable from the current root.

## Installation

```sh
UV_CACHE_DIR=.uv-cache uv sync
```

## Python library

Application code imports `pyrealm`. It can open encrypted or plaintext Realm files, discover
their schema, iterate records, resolve links, and execute parameterized Realm Query Language
expressions:

```python
from pyrealm import open_realm

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

Normal iteration raises `RealmError` when a record cannot be decoded. To salvage later records
from a damaged result set, use `events.iter_valid(callback)`; the callback receives the failed
index and error. Without a callback, skipped indexes are emitted as runtime warnings.

Object links are lazy mappings. Accessing a linked field resolves it once and caches the record:

```python
sender = event["senderEntity"]
print(sender["displayName"])

serializable = event.to_dict(expand_links=True, max_depth=2)
```

Logical opening disables Realm file-format upgrades. Unsupported historical formats fail
explicitly rather than modifying the source. The library only exposes the current committed
state; it does not recover deleted records. On an open failure, preserve the source, verify the
64-byte encryption key and source copy, then use `pyrealm-recover inspect` or `carve` for partial
recovery.

## Recovery CLI

The `pyrealm-recover` command identifies the Realm header, walks both copy-on-write root trees,
inventories Realm arrays, and extracts printable strings from active, inactive, and orphaned
arrays:

```sh
uv run pyrealm-recover inspect evidence/default.realm
uv run pyrealm-recover inspect evidence/default.realm --json
uv run pyrealm-recover carve evidence/default.realm -o results/default
```

The output directory is intentionally required to be new. It contains:

- `summary.json`: source hash, header, warnings, and array inventory
- `arrays.jsonl`: one structural array candidate per line
- `strings.csv`: printable strings with byte offsets and reachability classification

Reachability means:

- `active`: reachable only from the committed root selected by header bit 0
- `shared`: reachable from both roots
- `inactive`: reachable only from the alternate root; often a prior transaction, not proof of deletion
- `orphan`: valid array signature not reachable from either root; a carving candidate, not proof of deletion

The CLI does **not** claim that every orphan is deleted evidence or reconstruct complete logical
records. Realm is column-oriented; correlating carved columns into records is version- and
schema-sensitive. Preserve the source file and validate every result against app context.

## Development

```sh
UV_CACHE_DIR=.uv-cache uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run ty check src tests
```

Schema-aware access to inactive snapshots and deleted logical records remains future work.

## Releases

GitHub Actions checks linting, formatting, types, and tests on every pull request and push to
`main`. It also builds and tests CPython 3.11–3.14 wheels for Linux x86-64, macOS x86-64 and
Apple silicon, and Windows x86-64.

Releases are published to PyPI from version tags using trusted publishing:

1. Create a GitHub environment named `pypi`.
2. In the PyPI project settings, add a GitHub trusted publisher for the `Release` workflow,
   environment `pypi`, and workflow file `release.yml`.
3. Update `project.version` in `pyproject.toml`, merge the change to `main`, then tag that commit:

   ```sh
   git tag -a v0.2.0 -m "v0.2.0"
   git push origin v0.2.0
   ```

The workflow refuses to publish when the tag and `project.version` differ. No PyPI API token is
stored in GitHub.
