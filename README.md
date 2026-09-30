# Lattice Workbench

Lattice Workbench is a small, local-first knowledge workspace baseline. It stores Markdown documents with stable identifiers and tags, supports deterministic text search, and derives outgoing and incoming wiki-link relationships.

The baseline intentionally uses only Node.js built-ins so it is easy to run, inspect, and extend.

## Run

```bash
npm test
npm run demo
```

The demo creates an in-memory workspace, adds linked notes, searches their content, and prints a JSON summary. Product data is not sent to an external service.

## Current contract

- Document identifiers and titles are required and unique.
- Markdown bodies may contain `[[document-id]]` links.
- Tags are normalized to lowercase and deduplicated.
- Search matches titles, Markdown bodies, and tags.
- Backlinks are derived from the current document set.

## JSON snapshots

Workspace state can be exported as a versioned, checksummed JSON snapshot and later
imported back. Bodies (including links to documents that do not exist) are
preserved verbatim, and snapshots never share references with workspace state.

### `workspace.exportJSON()`

Returns a plain object shaped like:

```json
{
  "version": 1,
  "documents": [
    { "id": "welcome", "title": "Welcome", "body": "See [[architecture]].", "tags": ["intro"] }
  ],
  "checksum": "…"
}
```

- Key order is fixed: `version`, `documents`, `checksum`; each document uses
  `id`, `title`, `body`, `tags`.
- `documents` is sorted by `id` in Unicode code-point order.
- `checksum` is the lowercase-hex SHA-256 of the UTF-8 bytes of
  `JSON.stringify({ version, documents })` after the documents have been
  normalized and sorted.
- Mutating the returned object or its arrays never affects the workspace.

### `workspace.importJSON(data, { mode, dryRun })`

`data` may be a snapshot object or a JSON string. Documents may appear in any
order; they use the same validation and normalization as `add()` (tags must be
an array of strings) and the checksum must match the normalized payload.

- `mode` (`"merge"` or `"replace"`, required):
  - `merge` keeps existing documents. An incoming document with an existing id
    whose normalized fields are all identical is skipped. A changed same-id
    document, or a new document whose normalized title collides with another
    document, raises `IMPORT_CONFLICT`; the error carries an `ids` array of
    every conflicting incoming id, deduplicated and code-point sorted.
  - `replace` discards the current state and installs the snapshot wholesale.
- `dryRun` (boolean, default `false`) returns the projected result snapshot
  without modifying state.
- The return value is a fresh result snapshot. On success search and derived
  links immediately reflect the new state; on any failure the state is
  unchanged.

Error codes (thrown as `SnapshotError` with a `code` property):

| Code | When |
| --- | --- |
| `INVALID_SNAPSHOT` | Unsupported version, missing/extra fields, wrong types, illegal document, duplicate id, duplicate normalized title, or checksum mismatch (including malformed JSON text). |
| `IMPORT_CONFLICT` | A merge has same-id content differences or post-merge title collisions; `error.ids` lists all of them. |
| `INVALID_OPTIONS` | Unknown options, a mode other than `merge`/`replace`, or a non-boolean `dryRun`. |

### `migrate` command

```bash
node src/cli.js migrate <base> <incoming> <output> <mode> [--dry-run]
```

Loads the `base` snapshot into a fresh workspace, imports `incoming` with the
given mode, and writes the resulting snapshot to `output`. `output` may be the
same path as `base` (the file is replaced atomically via a staging file).

- On success, standard output contains exactly one line: the result snapshot
  JSON (the same bytes written to `output`).
- With `--dry-run`, the projected snapshot is printed but `output` is neither
  created nor modified.
- On failure, standard error contains exactly one JSON line with a `code`,
  standard output is empty, the process exits with status `1`, and inputs and
  any existing output are left untouched.
- Parse failures report `INVALID_SNAPSHOT`; file read/write failures report
  `IO_ERROR`; other codes mirror the API (`IMPORT_CONFLICT`, `INVALID_OPTIONS`).
