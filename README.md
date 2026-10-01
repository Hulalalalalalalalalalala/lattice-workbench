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

### `serve` command

```bash
node src/cli.js serve <snapshot> [--port <port>] [--history <file>]
```

Serves one workspace over HTTP on `127.0.0.1` (default port `3000`; `--port 0`
picks an ephemeral port). On successful startup standard output contains
exactly one JSON line with the actual address, e.g.
`{"host":"127.0.0.1","port":3000}`.

- If `<snapshot>` does not exist, the server starts from an empty workspace and
  the file is only created by the first successful write. If the file exists
  but cannot be read or fails snapshot validation, standard error contains one
  JSON error line, the process exits with status `1`, and the file is left
  untouched.
- `GET /documents` lists documents, `GET /documents/:id` reads one,
  `POST /documents` adds a document, `PUT /documents/:id` replaces one
  wholesale (path and body ids must match), `DELETE /documents/:id` removes
  one. `GET /search?q=...` and `GET /documents/:id/links` use the existing
  search and link semantics. Bodies are stored verbatim and tags are
  normalized as usual.
- Read responses carry a double-quoted `ETag` holding the current workspace
  checksum. Write requests must send a matching `If-Match`: a missing header
  is `428`, a malformed one `400`, and a stale checksum `412`. Of concurrent
  content-changing writes built on the same checksum, exactly one commits.
- Successful writes return the post-commit snapshot and its `ETag` (`201` for
  creates, `200` for replace/delete) and are only confirmed after the
  version-1 snapshot file has been saved; a failed save answers `500` with
  `IO_ERROR` and leaves memory, query results, and the original file
  unchanged.
- Duplicate ids or duplicate trimmed titles are `409` (titles stay
  case-sensitive), missing documents `404`, a path/body id mismatch or invalid
  JSON/document fields `400`, and bodies over 1 MiB `413`. Every failure
  response carries a stable `code` and never changes the stored content.

### History

When `--history <file>` is given, the server keeps a per-document revision log
alongside the version-1 snapshot. Without it, behavior is unchanged.

- When no history file exists yet, every document already in the snapshot gets
  a revision-1 `baseline`; documents created later start at revision 1 with a
  `create`. Each create, replace, delete, and restore appends one revision to
  the same id's sequence, which continues across deletes and re-creates. A
  replace or restore whose normalized content equals the current content still
  succeeds but does not append a revision.
- The history file is versioned and checksummed like the snapshot, but its
  checksum never mixes with the snapshot's. Current content and history are
  committed together; if either cannot be saved, `500` with `IO_ERROR` is
  returned and memory, queries, history, and the files stay as they were. A
  journal written before the commit's renames lets a process killed mid-save
  present either the pre-commit or the post-commit complete state on restart.
- If the history file cannot be read, startup fails with `IO_ERROR`; if it is
  corrupted or cannot be restored to a state consistent with the snapshot,
  startup fails with `INVALID_HISTORY`. Either way the process exits `1`,
  standard error contains exactly one JSON line with the `code`, and the
  original files are left untouched. Passing the same path for the snapshot and
  the history is rejected with `INVALID_OPTIONS`.

#### `GET /documents/:id/history`

Returns the document's revisions in ascending order, each shaped
`{ "revision", "action", "document" }`. `action` is one of `baseline`,
`create`, `replace`, `delete`, `restore`; a delete record's `document` is
`null` and every other record carries the full document as it was at that
revision. Deleted documents remain queryable; a document that never appeared
in the history answers `404` with `NOT_FOUND`.

#### `POST /documents/:id/restore`

```json
{ "revision": 2 }
```

Restores the title, body, and tags of the given revision, including for a
deleted document. The body must be an object containing only a positive
integer `revision`; anything else answers `400` with `INVALID_REVISION`, as
does selecting a delete revision. A missing revision answers `404` with
`NOT_FOUND`. If the restored title collides with another document's title, the
answer is `409` with `CONFLICT`. On success the response is `200` with the
current snapshot and its `ETag`, and a `restore` revision is appended; the
document's old records are unchanged. Restore follows the existing `If-Match`
check and the 1 MiB request limit, never rewrites other documents' bodies, and
updates search and derived links to the restored content.
