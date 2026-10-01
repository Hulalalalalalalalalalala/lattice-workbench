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
| `INVALID_MARKDOWN` | A markdown package cannot be exported or imported: unencodable body, malformed manifest, duplicate id or normalized title, illegal UTF-8, checksum mismatch, missing or extra files, a symbolic link, subdirectory, or illegal filename in the package, or a symlinked input directory. |
| `IMPORT_CONFLICT` | A merge has same-id content differences or post-merge title collisions; `error.ids` lists all of them. |
| `INVALID_OPTIONS` | Unknown options, a mode other than `merge`/`replace`, a non-boolean `dryRun`, an export target that is a symlink or contains the source snapshot, or an import output inside the input directory. |

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

### `export-md` command

```bash
node src/cli.js export-md <snapshot> <output-dir>
```

Exports a version-1 JSON snapshot as a markdown package: a directory containing
`manifest.json` and one `<id>.md` file per document. The body files hold the
original UTF-8 content verbatim (newlines and dangling links preserved, no
added trailing newline).

```json
{
  "version": 1,
  "documents": [
    { "id": "welcome", "title": "Welcome", "tags": ["intro"], "file": "welcome.md", "sha256": "…" }
  ],
  "checksum": "…"
}
```

- Key order is fixed: `version`, `documents`, `checksum`; each document uses
  `id`, `title`, `tags`, `file`, `sha256`.
- `documents` is sorted by `id` in Unicode code-point order; `file` is exactly
  `<id>.md`; `sha256` is the lowercase-hex SHA-256 of the body file's raw bytes.
- The manifest `checksum` is the snapshot checksum of the JSON content, so a
  round trip rebuilds the same snapshot.
- Repeated exports of the same snapshot produce byte-identical packages; an
  empty workspace exports an empty, round-trippable package.
- Bodies that cannot be losslessly encoded as UTF-8 (unpaired surrogates)
  report `INVALID_MARKDOWN`.
- The output directory is replaced wholesale if it exists (old files do not
  linger). It is assembled in a sibling staging directory and only installed
  once every byte is written, so a kill mid-export leaves either the previous
  package or a complete new one; a retry recovers.
- On success, standard output contains exactly one line: the manifest JSON.
- Failures leave the source snapshot and any existing output untouched;
  standard output is empty, standard error is one JSON line with a `code`, and
  the process exits with status `1`.

### `import-md` command

```bash
node src/cli.js import-md <base> <input-dir> <output> <mode> [--dry-run]
```

Loads the `base` snapshot into a fresh workspace, imports the markdown package
as incoming documents with the given mode (`merge` or `replace`), and writes
the resulting snapshot to `output`. `output` may be the same path as `base`.

- The package is validated as a whole before anything is imported: the input
  directory must not itself be a symbolic link, and the package may contain
  only `manifest.json` and `<id>.md` regular files (no symlinks,
  subdirectories, or illegal filenames; nothing outside the package is read).
- The manifest must have exactly `version`, `documents`, `checksum` with the
  right types; each entry must have exactly `id`, `title`, `tags`, `file`,
  `sha256`. Ids must be unique, titles unique after normalization, `file` must
  equal `<id>.md`, and every body file must be valid UTF-8 with a matching
  SHA-256. Missing or extra files are rejected, and the checksum of the
  rebuilt snapshot must match the manifest.
- Titles and tags are normalized by the existing document rules (trimmed
  titles; lowercased, deduplicated, sorted tags).
- `merge` and `replace` follow the existing conflict and `ids` rules.
- On success, standard output contains exactly one line: the result snapshot
  JSON (the same bytes written to `output`).
- With `--dry-run`, the projected snapshot is printed and every validation
  runs, but `output` is neither created nor modified.
- Validation failures report `INVALID_MARKDOWN`; parse failures of the base
  snapshot report `INVALID_SNAPSHOT`; read/write failures report `IO_ERROR`;
  other codes mirror the API (`IMPORT_CONFLICT`, `INVALID_OPTIONS`).

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

#### Persistent history (`--history <file>`)

Passing `--history <file>` enables a durable, per-document revision ledger in
addition to the version-1 content snapshot. Without it the server behaves
exactly as before and the history routes are absent.

- On first use, every document already in the snapshot receives a revision 1
  `baseline` record; documents created later start at revision 1 with a
  `create`. Revisions are consecutive per document across `create`, `replace`,
  `delete`, and `restore`. Recreating a previously deleted id keeps counting
  upward. Failed requests never consume a revision, and a `replace` or
  `restore` whose normalized content is unchanged still returns `200` but does
  not append a record (and does not touch the files).
- The history file is created by the first successful write, not at startup.
  It is a checksummed JSON document (`version`, `history`, `snapshot`,
  `checksum`) whose `snapshot` field binds the ledger to the checksum of the
  current content snapshot; the version-1 snapshot format and the JSON
  migration paths are unchanged and never carry history data.
- `GET /documents/:id/history` returns the document's records in ascending
  `revision` order, each `{ revision, action, document }` with `action` one of
  `baseline/create/replace/delete/restore`. The `document` is the full
  document as it existed at that revision, or `null` for a `delete` record.
  Deleted documents remain queryable; an id that never existed returns
  `404`/`NOT_FOUND`.
- `POST /documents/:id/restore` takes `{ "revision": n }` and restores that
  revision's title, body, and tags — including for a currently deleted
  document. It answers `200` with the current snapshot and its `ETag`, leaves
  all older records intact, and appends a new `restore` record. It applies the
  same `If-Match` precondition and 1 MiB body limit as other writes.
  - `404`/`NOT_FOUND`: the document never existed, or the revision does not.
  - `400`/`INVALID_REVISION`: the body is not an object containing only a
    positive integer `revision`, or the selected revision is a `delete`.
  - `409`/`CONFLICT`: the restored title clashes with another document.
  - Restore never edits another document's body; search and bidirectional
    links follow the current content.
- Content snapshot and history are committed together: the history file is
  installed first (embedding the new content checksum), then the snapshot. If
  the process is killed mid-commit, restart lands entirely on the pre-commit
  or the post-commit state; a kill after success is acknowledged is always
  reconstructed from the ledger. Any save failure answers `500`/`IO_ERROR` and
  leaves in-memory state, query results, history, and both files as they were.
- Startup errors exit `1` after writing exactly one JSON line containing a
  `code` to standard error, leaving the files untouched:
  - `INVALID_OPTIONS`: the snapshot and history paths resolve to the same file.
  - `IO_ERROR`: an existing history file cannot be read.
  - `INVALID_HISTORY`: the history is corrupt, or it cannot be reconciled to a
    single consistent state with the snapshot.
