# Lattice Workbench

Lattice Workbench is a small, local-first knowledge workspace baseline. It stores Markdown documents with stable identifiers and tags, supports deterministic text search, and derives outgoing and incoming wiki-link relationships.

The baseline intentionally uses only Node.js built-ins so it is easy to run, inspect, and extend.

## Run

```bash
npm test
npm run demo
node src/cli.js serve <snapshot> [--port <port>]
```

The demo creates an in-memory workspace, adds linked notes, searches their content, and prints a JSON summary. Product data is not sent to an external service.

## Local content service

`serve` exposes a snapshot file over a local HTTP API so an editor can read and
write documents, with writes persisted to disk and surviving restarts.

```bash
node src/cli.js serve notes.json --port 3000
```

- Listens on `127.0.0.1`; the default port is `3000` and `--port 0` binds an
  ephemeral port.
- On success, standard output contains exactly one JSON line with the actual
  address, e.g. `{"host":"127.0.0.1","port":3000,"url":"http://127.0.0.1:3000"}`.
- If the snapshot file does not exist, the service starts from an empty
  workspace; the file is created only on the first successful write.
- If the file exists but cannot be read or fails checksum validation, the
  process exits with status `1`, writes one JSON error line to standard
  error, and does not overwrite the file.

### HTTP API

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/documents` | List documents |
| `GET` | `/documents/:id` | Read one document |
| `POST` | `/documents` | Create a document |
| `PUT` | `/documents/:id` | Replace a document |
| `DELETE` | `/documents/:id` | Delete a document |
| `GET` | `/search?q=...` | Search titles, bodies, and tags |
| `GET` | `/documents/:id/links` | Outgoing and incoming wiki-links |

- `POST` and `PUT` bodies are complete documents (`id`, `title`, `body`,
  `tags`). A path id that differs from the body id returns `400`.
- Reading, replacing, or deleting a missing document returns `404`.
- Duplicate ids, or titles that match after trimming (case-sensitive), return
  `409`. Tags are normalized; bodies are stored verbatim.
- Writes return `201` (create) or `200` (replace/delete) with the post-commit
  snapshot and its `ETag` header.

### Optimistic concurrency

Read responses carry an `ETag` header whose value is the current workspace
checksum in double quotes. Every write must carry an `If-Match` header with
the same format:

- Missing `If-Match` → `428` `IF_MATCH_REQUIRED`
- Malformed `If-Match` → `400` `INVALID_IF_MATCH`
- Stale checksum → `412` `CHECKSUM_MISMATCH`

Writes are serialized: of two concurrent writes sharing a checksum, only the
first to commit succeeds; the rest get `412`. Reads always see a complete
pre- or post-commit state.

### Persistence

A write is acknowledged only after the version-1 snapshot has been written to
disk atomically. If the save fails, the response is `500` `IO_ERROR`, the
in-memory workspace, query results, and the original file are unchanged, and
the service keeps accepting requests. Deleting a document leaves `[[links]]`
in other documents' bodies untouched; links and search reflect commits
immediately. Request bodies over 1 MiB return `413`; invalid JSON or document
fields return `400`. All error responses carry a stable `code` and never
change content.

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
