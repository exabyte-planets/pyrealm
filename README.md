# pyrealm-forensics

`pyrealm` is a read-only structural scanner and conservative carver for Android Realm files.
It identifies the Realm header, walks both copy-on-write root trees, inventories Realm arrays,
and extracts printable strings from active, inactive, and orphaned arrays.

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
uv run python -m unittest discover -s tests
uv run ruff check .
uv run ruff format --check .
uv run ty check
```
