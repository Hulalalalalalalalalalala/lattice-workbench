# Lattice Workbench

Lattice Workbench is a small, local-first knowledge workspace baseline. It stores Markdown documents with stable identifiers and tags, supports deterministic text search, and derives outgoing and incoming wiki-link relationships.

The baseline intentionally uses only Node.js built-ins so it is easy to run, inspect, and extend.

## Run

```bash
npm test
npm run demo
node src/cli.js migrate <base> <incoming> <output> <mode> [--dry-run]
```

The demo creates an in-memory workspace, adds linked notes, searches their content, and prints a JSON summary. Product data is not sent to an external service.

## Current contract

- Document identifiers and titles are required and unique.
- Markdown bodies may contain `[[document-id]]` links.
- Tags are normalized to lowercase and deduplicated.
- Search matches titles, Markdown bodies, and tags.
- Backlinks are derived from the current document set.

This is the initial product baseline. Persistence, content APIs, permissions, version history, migration, richer indexing, and operational safeguards are expected to evolve through normal product work.

## Snapshots

A workspace can be exported as a versioned snapshot:

```js
const snapshot = workspace.exportJSON();
// { version: 1, documents, checksum }
```

- `documents` is sorted by id in ascending code-point order; each document has the key order `id`, `title`, `body`, `tags`.
- `checksum` is the lowercase hex SHA-256 of the UTF-8 bytes of `JSON.stringify({ version, documents })`, computed over the normalized, sorted documents.
- Bodies and dangling links are preserved. The returned value does not share references with the workspace.

Import a snapshot with `workspace.importJSON(data, { mode, dryRun })`:

- `mode: 'replace'` replaces the workspace contents with the snapshot.
- `mode: 'merge'` keeps existing documents; incoming documents with the same id and identical normalized fields are skipped, and new documents are added.
- `dryRun: true` returns the would-be result without changing state.
- Documents are validated and normalized with the same rules as `add`; `tags` must be an array of strings. Out-of-order documents are accepted, and the checksum is verified.
- Failures leave the workspace unchanged. Errors carry a `code`:
  - `INVALID_OPTIONS` — missing/unsupported `mode`, non-boolean `dryRun`, or unknown options.
  - `INVALID_SNAPSHOT` — unsupported version, missing or extra fields, wrong types, invalid documents, duplicate ids or normalized titles, or a checksum mismatch.
  - `IMPORT_CONFLICT` — a merge could not proceed; the error carries `ids`, a deduped, code-point-sorted array of every conflicting id (same-id content mismatches and post-merge title collisions on both sides).

## CLI migration

```bash
node src/cli.js migrate <base> <incoming> <output> <mode> [--dry-run]
```

Builds a workspace from the `base` snapshot, imports `incoming` with the given mode, and writes the result snapshot to `output`. Standard output prints exactly one line of result JSON. `--dry-run` prints the result without creating or modifying `output`; `output` may be the same path as `base`.

On failure, standard output is empty and standard error prints exactly one line of JSON containing the error `code` (and `ids` for `IMPORT_CONFLICT`), and the process exits with status 1. Parse failures report `INVALID_SNAPSHOT`; file read/write failures report `IO_ERROR`; all other codes follow the import contract above. Inputs and any existing output are left untouched.
