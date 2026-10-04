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
sibling staging directory and a single rename, so old files never linger and a
retry after the process was killed completes a fresh package. The fixed
staging (`<output-directory>.export.tmp`) and backup
(`<output-directory>.old.tmp`) locations are cleared at the start of an export,
so a source snapshot that is either location itself or a file inside it — just
like one inside the target directory — is rejected with `INVALID_OPTIONS`
before anything is read, cleared, moved, or written; names that merely resemble
those scratch paths elsewhere on disk are unaffected.

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
| `INVALID_OPTIONS` | Wrong argument count or mode, an unknown flag (including `--dry-run` for `export-md`), an export target that is a symlink, or a source snapshot that is or lies inside the export's output, staging, or backup location, or an import output placed inside the input package. Path aliases are compared by their resolved real locations (including the real parent of a not-yet-created output). |
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
  one, and `POST /batch` applies several writes in one atomic commit (see
  "Batch changes (`POST /batch`)" below). `GET /search?q=...` and
  `GET /documents/:id/links` use the existing search and link semantics.
  Bodies are stored verbatim and tags are normalized as usual.
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
- Write bodies must be valid UTF-8. A lone continuation byte, a truncated or
  overlong multibyte sequence, an encoded surrogate code point, or bytes
  beyond the Unicode range answers `400`/`INVALID_JSON` rather than being
  silently replaced with U+FFFD; a U+FFFD that was itself encoded validly is
  ordinary text and kept. JSON escapes keep their usual string semantics. The
  1 MiB limit is measured on the raw bytes, so an oversized body that also
  contains illegal bytes still answers `413`/`PAYLOAD_TOO_LARGE`, and a
  multibyte character split across transport chunks decodes identically to the
  same body sent in one frame. The rule applies to every write route,
  including batch, tag rewrite, reconcile, and restore (whose other body
  errors stay `INVALID_REVISION`), and to dry-run previews.

#### Batch changes (`POST /batch`)

`POST /batch` applies 1 to 100 write operations in one atomic commit. The
body is exactly `{ "operations": [...], "dryRun"? }`; each operation targets
one document id, no id may appear twice, and every operation is validated
before anything is applied, so any error rejects the whole batch and leaves
every document untouched. Operation shapes:

- `{ "type": "create", "document": {...} }` and
  `{ "type": "replace", "document": {...} }` carry a complete document using
  the same fields and rules as the single-document routes. A `create` whose
  id already exists answers `409`/`CONFLICT`; a `replace` (or `delete`) whose
  id does not exist answers `404`/`NOT_FOUND`.
- `{ "type": "delete", "id": "..." }` removes one document.
- `{ "type": "restore", "id": "...", "revision": n }` is available only with
  history enabled and follows the single-document restore rules.
- `dryRun` is an optional boolean and defaults to `false`: `true` returns the
  projected result without writing; omit it or set it `false` to commit.

Like every other write, a batch requires a matching `If-Match` — previews
included. A successful batch always answers `200` (even when it contains
creates, which answer `201` on the single-document route) with the complete
result snapshot and the `ETag` matching that snapshot's `checksum`.

A `replace` is a wholesale replacement, just like `PUT /documents/:id`: only
the identifier is taken from the existing document, while title, body, and
tags all come from the request. A request meant to change only the title must
therefore carry the existing body and tags too, or those fields are replaced
as well.

##### Example: swapping two titles in one batch

Suppose the snapshot already holds these two documents. `GET /documents`
returns them with the current workspace `ETag`:

```http
HTTP/1.1 200 OK
content-type: application/json; charset=utf-8
etag: "6828c68d9f44d68c8f2bff56ad8762f3e6b26517306ed460bce0f095ca3d3d39"
```

```json
[
  {
    "id": "design-notes",
    "title": "Design Notes",
    "body": "See [[release-plan]] for rollout dates.",
    "tags": ["draft", "planning"]
  },
  {
    "id": "release-plan",
    "title": "Release Plan",
    "body": "Cut the branch on Monday.",
    "tags": ["ops"]
  }
]
```

To exchange the titles, send two `replace` operations in one request — each
document's body and tags are carried over unchanged. First preview with
`"dryRun": true` and the `ETag` from the read above as `If-Match`:

```http
POST /batch HTTP/1.1
content-type: application/json
if-match: "6828c68d9f44d68c8f2bff56ad8762f3e6b26517306ed460bce0f095ca3d3d39"
```

```json
{
  "operations": [
    {
      "type": "replace",
      "document": {
        "id": "design-notes",
        "title": "Release Plan",
        "body": "See [[release-plan]] for rollout dates.",
        "tags": ["draft", "planning"]
      }
    },
    {
      "type": "replace",
      "document": {
        "id": "release-plan",
        "title": "Design Notes",
        "body": "Cut the branch on Monday.",
        "tags": ["ops"]
      }
    }
  ],
  "dryRun": true
}
```

The preview answers `200` with the projected result snapshot and the `ETag`
of that projection:

```http
HTTP/1.1 200 OK
content-type: application/json; charset=utf-8
etag: "87737020e7cfa2257301fefa00d7117881ebb4529bc9460f985c00d2e1554b61"
```

```json
{
  "version": 1,
  "documents": [
    {
      "id": "design-notes",
      "title": "Release Plan",
      "body": "See [[release-plan]] for rollout dates.",
      "tags": ["draft", "planning"]
    },
    {
      "id": "release-plan",
      "title": "Design Notes",
      "body": "Cut the branch on Monday.",
      "tags": ["ops"]
    }
  ],
  "checksum": "87737020e7cfa2257301fefa00d7117881ebb4529bc9460f985c00d2e1554b61"
}
```

Nothing has been saved: reading `GET /documents` again still returns the
original titles and the original `ETag` `6828…`. The preview's `ETag`
identifies the *projected* result; it is not the version of the stored
content, so sending it as `If-Match` on a write fails:

```http
HTTP/1.1 412 Precondition Failed
content-type: application/json; charset=utf-8

{"code":"PRECONDITION_FAILED","message":"If-Match checksum is stale"}
```

Before committing for real, read the documents once more to reconfirm the
fields you are keeping and to take the `ETag` of the current saved content
(here still `6828…`). Then repeat the request with `dryRun` omitted or set to
`false`:

```http
POST /batch HTTP/1.1
content-type: application/json
if-match: "6828c68d9f44d68c8f2bff56ad8762f3e6b26517306ed460bce0f095ca3d3d39"
```

```json
{
  "operations": [
    {
      "type": "replace",
      "document": {
        "id": "design-notes",
        "title": "Release Plan",
        "body": "See [[release-plan]] for rollout dates.",
        "tags": ["draft", "planning"]
      }
    },
    {
      "type": "replace",
      "document": {
        "id": "release-plan",
        "title": "Design Notes",
        "body": "Cut the branch on Monday.",
        "tags": ["ops"]
      }
    }
  ]
}
```

The commit answers `200` with the full result snapshot — the two titles have
swapped together, while ids, bodies, and tags are unchanged (the
`[[release-plan]]` link in the body still resolves, since links key off ids)
— and its `ETag` is the checksum of that snapshot:

```http
HTTP/1.1 200 OK
content-type: application/json; charset=utf-8
etag: "87737020e7cfa2257301fefa00d7117881ebb4529bc9460f985c00d2e1554b61"
```

```json
{
  "version": 1,
  "documents": [
    {
      "id": "design-notes",
      "title": "Release Plan",
      "body": "See [[release-plan]] for rollout dates.",
      "tags": ["draft", "planning"]
    },
    {
      "id": "release-plan",
      "title": "Design Notes",
      "body": "Cut the branch on Monday.",
      "tags": ["ops"]
    }
  ],
  "checksum": "87737020e7cfa2257301fefa00d7117881ebb4529bc9460f985c00d2e1554b61"
}
```

Why the batch swap is allowed:

- Titles are compared after trimming surrounding whitespace, and the
  comparison is case-sensitive (`"Design Notes"`, `"  Design Notes  "`, and
  `"design notes"` are three different titles).
- Uniqueness is checked against the document set produced by the **whole**
  batch, never against intermediate states. After both replacements the
  titles are `Release Plan` and `Design Notes` once each, so the batch
  commits; putting the two operations in either order projects the same
  result (identical checksum).
- The same exchange cannot be done as two single-document
  `PUT /documents/:id` requests: each PUT checks its new title against the
  other *currently stored* documents, so the first request already collides
  — e.g. trying to give `design-notes` the title `Design Notes` while
  `release-plan` still holds it answers `409`/`CONFLICT` with
  `"title already in use: Design Notes"`, and nothing changes. Only a batch
  evaluates the swap as one final state.

Two failure conditions bear directly on a swap:

- **Duplicate title after the whole batch — `409`/`CONFLICT`.** If the
  projected set still contains a repeated trimmed title (for example both
  replaces end on `Design Notes`, or one new title merely adds whitespace
  around another document's title), the answer is `409` with
  `"title conflict in batch: …"` and both documents stay exactly as they
  were; neither replacement is applied partially.
- **Stale `If-Match` at commit time — `412`/`PRECONDITION_FAILED`.** If the
  workspace changed between your read and the commit (including mistakenly
  reusing a preview `ETag`), the answer is `412` with `"If-Match checksum is
  stale"`. Re-read the documents, reconfirm the fields to keep, and decide
  whether to resubmit against the new `ETag`.

A preview writes neither the snapshot file nor any history; a failed batch
changes neither memory nor the saved files. With history enabled, a
successful swap appends exactly one `replace` record to each of the two
documents' chains; previews and failures append no records.

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
  - `INVALID_OPTIONS`: the snapshot path resolves to the same real location as
    the history file or its backup (`<history>.bak`, the location the old
    history is moved to during a commit). Relative/absolute spellings, `.`/`..`
    segments, and symlinked directories or files count as aliases once they
    point at the same location, even before the files exist (the real parent
    directory is resolved). This check runs before any content is read, so it
    wins over a corrupt snapshot or history. Files with the same name in
    different real directories do not conflict, and a name that merely ends in
    `.bak` without being that history's backup location is allowed.
  - `IO_ERROR`: an existing history file cannot be read.
  - `INVALID_HISTORY`: the history is corrupt, or it cannot be reconciled to a
    single consistent state with the snapshot.
