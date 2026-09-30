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

This is the initial product baseline. Persistence, content APIs, permissions, version history, migration, richer indexing, and operational safeguards are expected to evolve through normal product work.
