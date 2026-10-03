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
- Only references in ordinary prose create relationships; code samples and escaped references stay literal text (see below).
- Tags are normalized to lowercase and deduplicated.
- Search matches titles, Markdown bodies, and tags (including code samples).
- Backlinks are derived from the current document set.

### Wiki-link recognition

A relationship exists only when a valid `[[document-id]]` reference appears in
ordinary prose. The workspace query (`workspace.links`) and
`GET /documents/:id/links` share one recognizer, so both always agree:

- **Fenced code blocks:** a fence opens on a line starting with zero to three
  spaces followed by at least three consecutive backticks (`` ``` ``) or
  tildes (`~~~`), optionally followed by an info string such as a language
  name. It closes only on a line whose marker is the same symbol, at least as
  long as the opener, preceded by at most three spaces, and followed by only
  spaces or tabs. A different marker, a too-short run, or trailing text does
  not close it; without a closing fence every later reference (to the end of
  the body) is ignored. Prose after a closed fence is recognized again.
- **Inline code:** a span is wrapped in two equal-length runs of backticks and
  may cross line boundaries; shorter or longer backtick runs inside it do not
  end it. References inside a span produce no relationship. If no closing run
  of the same length exists, the opening run is treated as ordinary text and
  later references still count. Inline code never crosses a fenced-block
  boundary.
- **Escaped references:** when the run of backslashes immediately before the
  first `[` is odd (e.g. `\[[id]]`), the reference is literal; an even run
  still recognizes it.
- References that never close (`[[id`) or name a target that does not satisfy
  the identifier rules are simply ignored; they never make a links query
  fail. LF and CRLF bodies parse identically.

Everything else is unchanged: targets normalize by the same case rule,
duplicate references appear once in the existing order, not-yet-existing
targets stay in `outgoing`, `incoming` lists only existing documents that
really reference the target (never the document itself), and a target present
in both prose and code is still linked. Bodies are always stored verbatim —
code and escapes are preserved in the body, in search results, and in JSON and
Markdown imports/exports; querying links never edits a body, tags, or history.
Editing a body, restoring a history revision, or importing content refreshes
the derived relationships immediately; deleting a target never rewrites the
referring document's body.

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

### `export-md` / `import-md` commands

A version-1 snapshot can also be exchanged as a directory of plain Markdown
files. Round-tripping a snapshot through the directory format and back
reproduces the snapshot byte-for-byte, so bodies, search results, and
outgoing/incoming wiki links are unchanged; an empty workspace round-trips as
well.

```bash
node src/cli.js export-md <snapshot> <output-directory>
node src/cli.js import-md <base> <input-directory> <output> <mode> [--dry-run]
```

The package directory contains `manifest.json` and one `<id>.md` per document:

- Each `*.md` holds only that document's original UTF-8 body bytes. Newlines
  and dangling `[[...]]` links are preserved verbatim; nothing is added or
  escaped.
- `manifest.json` has exactly `version`, `documents`, and `checksum`, in that
  order. `version` is `1`; `checksum` is the bound version-1 content snapshot
  checksum (the same value the JSON snapshot carries).
- Each document entry has exactly `id`, `title`, `tags`, `file`, and
  `sha256`. `file` must equal `<id>.md`, and `sha256` is the lowercase-hex
  SHA-256 of the body file's raw bytes. Entries are sorted by `id` in Unicode
  code-point order.
- Repeating an export of the same snapshot writes byte-identical files.

`export-md` prints exactly one line: the manifest JSON (the same bytes written
to `manifest.json`). An existing target directory is replaced wholesale via a
sibling staging directory (`<output>.export.tmp`) and a single rename, with the
previous directory briefly held in `<output>.old.tmp`, so old files never
linger and a retry after the process was killed completes a fresh package.

The source snapshot is user input and is never cleaned up with the export's
working directories: it must not be the output directory or either fixed
staging/backup directory, and must not live inside any of them. Such a layout
is refused with `INVALID_OPTIONS` before the snapshot is read and before
anything is deleted or moved, whether or not the target directory already
exists, so the source and every pre-existing entry are left untouched.

`import-md` normalizes titles and tags under the existing document rules,
verifies every file digest and the rebuilt snapshot's bound checksum, then
applies the package to the `base` snapshot: `merge` uses the existing conflict
and `ids` rules (including `IMPORT_CONFLICT`), while `replace` installs the
package wholesale. On success it prints one line — the result snapshot JSON,
the same bytes saved to `output` (which may equal `base`) — and search and
derived links immediately reflect the result. `--dry-run` runs every
validation check and prints the projection without creating or modifying the
output.

Error reporting matches `migrate`: on failure standard output is empty,
standard error is exactly one JSON line carrying a `code`, the process exits
`1`, and inputs and any existing output are left untouched.

| Code | When |
| --- | --- |
| `INVALID_MARKDOWN` | Manifest version/field/type errors, duplicate ids or normalized titles, illegal UTF-8, a digest or checksum mismatch, a missing or extra file, an un-encodable body on export, or a package whose input directory is itself a symlink or contains a symlink, subdirectory, special file, or illegal file name. |
| `INVALID_OPTIONS` | Wrong argument count or mode, an unknown flag (including `--dry-run` for `export-md`), an export target that is a symlink, or an export source snapshot that is the output, staging, or backup directory or lies inside one of them, or an import output placed inside the input package. Path aliases are compared by their resolved real locations. |
| `IO_ERROR` | Any failure reading an input or writing the package/snapshot. |

The package is read strictly: symlinked directories or entries are refused and
no content outside the directory is ever followed.

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

#### Tag organization

- `GET /tags` returns the current tags as `{ "tag", "count" }` pairs, counting
  how many live documents carry each tag. The list is sorted by tag in Unicode
  code-point order, an empty workspace returns `[]`, and the response carries
  the current workspace `ETag`. Deleted documents and history revisions are not
  counted; the counts reflect every committed change immediately.
- `POST /tags/rewrite` reorganizes tags across all documents with a body of
  `{ "rules": [{ "from", "to" }], "dryRun"? }`. `rules` is an array of 1 to 100
  entries; `from` is the source tag and `to` is the target tag or `null` to
  remove the tag. Names are trimmed and lowercased on both sides, and targets
  that already exist merge into the existing tag with duplicates removed.
  - Rules act on the pre-rewrite tags, so `a→b` followed by `b→c` moves the
    original `a` to `b` and the original `b` to `c`; newly produced names are
    never rewritten a second time. This also allows swapping two names. All
    other tags, document ids, titles, bodies, and links are untouched, and more
    than 100 affected documents are all processed.
  - The body may contain only `rules` and an optional boolean `dryRun`, and
    each rule exactly `from` and `to`. Bad structure, fields, or types, a name
    that normalizes to empty, a duplicate normalized source, or an out-of-range
    rule count answers `400`/`INVALID_TAG_RULES`. If any source tag is not used
    by a live document, the whole request answers `404`/`TAG_NOT_FOUND`.
    Malformed JSON, oversized bodies, and `If-Match` handling follow the
    existing write behavior — including previews, which also require
    `If-Match`. Of concurrent content-changing writes built on the same old
    checksum, at most one commits.
  - Success answers `200` with `{ "snapshot", "changedIds" }`. `snapshot` is
    the result snapshot in the existing format with a matching `ETag`;
    `changedIds` lists only the ids whose tags actually changed, sorted by code
    point. `dryRun` defaults to `false`; when `true` the projected result is
    returned and queries, history, and files are unchanged. When the tag set is
    completely unchanged the current snapshot and an empty `changedIds` are
    returned without writing a file or adding a revision.
  - With history enabled, each actually-changed document gets exactly one
    appended `replace` record; old revisions keep their original tags, so a
    later restore updates the counts again. Success is confirmed only after the
    whole save completes: a save failure answers `500`/`IO_ERROR` and leaves
    content, counts, search, history, and files exactly as they were, and a
    restart after a kill mid-commit lands entirely on the pre- or post-rewrite
    state. The migration formats stay unchanged.

#### Merging offline edits

- `POST /snapshots/reconcile` imports an offline-edited snapshot while keeping
  non-conflicting online edits made since the export. The body is exactly
  `{ "base", "incoming", "dryRun"? }`: `base` is the snapshot the offline
  editing started from, `incoming` the edited result, both plain version-1
  snapshot objects in the existing format (JSON strings are not accepted
  here). Both snapshots must pass the existing validation; JSON and Markdown
  import behavior is unchanged.
  - For a document present in all three snapshots, `title`, `body`, and
    `tags` are each compared with the base independently: a field changed on
    only one side is kept, both sides changing a field to the same normalized
    value is accepted, and both sides changing the same field to different
    values conflicts. Changes to different fields are both kept. Bodies are
    compared as complete strings and preserved verbatim; tags are compared as
    one normalized group, never merged piece by piece.
  - An id absent from the base and added on one side is kept; both sides
    adding the same id is accepted only when the normalized documents are
    identical, otherwise it conflicts. A deletion on one side against an
    unchanged or also-deleted other side deletes the document; a deletion
    meeting a modification conflicts.
  - The final title set must be unique, while title swaps are permitted. A
    duplicate final title is a conflict only when no field/add/delete
    conflicts were found, and every involved document is reported.
  - A conflict answers `409`/`RECONCILE_CONFLICT`; `conflicts` is a
    deduplicated list of `{ "id", "fields" }` entries covering every field or
    add/delete conflict, sorted by id and then field name in Unicode
    code-point order. Field conflicts use `title`/`body`/`tags`; a divergent
    same-id addition or a delete-meets-modify case uses `document`; final
    title duplicates use `title`.
  - Bad request structure answers `400`/`INVALID_OPTIONS`; a snapshot that
    fails validation answers `400`/`INVALID_SNAPSHOT`. Malformed JSON, bodies
    over 1 MiB, and `If-Match` follow the existing write rules — previews
    require `If-Match` as well, and of concurrent commits built on the same
    checksum at most one succeeds.
  - Success answers `200` with the result snapshot and its `ETag`.
    `dryRun` (default `false`) returns only the projected result: queries,
    history, and files are unchanged. When the result equals the current
    content, no file is written and no revision is appended. A real commit is
    atomic: search, tag counts, and bidirectional links reflect it
    immediately; a save failure answers `500`/`IO_ERROR` and leaves content,
    history, and files exactly as they were, and a restart after an
    interrupted commit lands entirely on the pre- or post-commit state.
  - With history enabled, each changed document gets exactly one appended
    record: `create` for a new or reappearing id (its revision continues the
    id's existing chain), `replace` for a modification, and `delete` for a
    removal; older records are never changed.

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
