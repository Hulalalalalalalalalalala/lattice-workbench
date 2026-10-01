import http from 'node:http';
import { SnapshotError, Workspace } from './workspace.js';
import { appendRecord, recordsFor } from './history.js';

const MAX_BODY_BYTES = 1024 * 1024;
const ETAG_PATTERN = /^"[0-9a-f]{64}"$/u;
const ID_PATTERN = /^[a-z0-9][a-z0-9._-]*$/u;
const DOCUMENT_FIELDS = new Set(['id', 'title', 'body', 'tags']);

class HttpError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
  }
}

function sendJson(res, status, payload, etag) {
  const headers = { 'content-type': 'application/json; charset=utf-8' };
  if (etag) headers.etag = etag;
  res.writeHead(status, headers);
  res.end(JSON.stringify(payload));
}

async function readBody(req) {
  const declared = Number(req.headers['content-length']);
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    req.resume();
    throw new HttpError(413, 'PAYLOAD_TOO_LARGE', 'request body exceeds 1 MiB');
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      throw new HttpError(413, 'PAYLOAD_TOO_LARGE', 'request body exceeds 1 MiB');
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(400, 'INVALID_JSON', 'request body is not valid JSON');
  }
}

function validateDocument(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new HttpError(400, 'INVALID_DOCUMENT', 'document must be an object');
  }
  for (const key of Object.keys(data)) {
    if (!DOCUMENT_FIELDS.has(key)) {
      throw new HttpError(400, 'INVALID_DOCUMENT', `unknown document field: ${key}`);
    }
  }
  for (const key of ['id', 'title', 'body']) {
    if (typeof data[key] !== 'string' || !data[key].trim()) {
      throw new HttpError(400, 'INVALID_DOCUMENT', `${key} must be a non-empty string`);
    }
  }
  if (!ID_PATTERN.test(data.id)) {
    throw new HttpError(400, 'INVALID_DOCUMENT', 'id must be URL-safe lowercase text');
  }
  if (data.tags !== undefined && (!Array.isArray(data.tags) || data.tags.some((tag) => typeof tag !== 'string'))) {
    throw new HttpError(400, 'INVALID_DOCUMENT', 'tags must be an array of strings');
  }
  const tags = [...new Set(data.tags.map((tag) => tag.trim().toLowerCase()).filter(Boolean))].sort();
  return { id: data.id, title: data.title.trim(), body: data.body, tags };
}

function sameDocument(a, b) {
  return a.id === b.id && a.title === b.title && a.body === b.body
    && a.tags.length === b.tags.length && a.tags.every((tag, i) => tag === b.tags[i]);
}

function copyOf(workspace) {
  const candidate = new Workspace();
  for (const document of workspace.list()) candidate.add(document);
  return candidate;
}

// A document server holds one Workspace and, when history is enabled, its
// per-document revision log. Every committed change is persisted through
// `commit(snapshot, history)` before the in-memory state is swapped, so a
// failed save leaves memory, queries, history, and the files untouched.
export function createDocumentServer({ workspace, history = null, commit }) {
  let current = workspace;
  let historyState = history;

  const currentEtag = () => `"${current.exportJSON().checksum}"`;

  function requireIfMatch(req) {
    const value = req.headers['if-match'];
    if (value === undefined) {
      throw new HttpError(428, 'PRECONDITION_REQUIRED', 'write requests require an If-Match header');
    }
    if (!ETAG_PATTERN.test(value)) {
      throw new HttpError(400, 'INVALID_IF_MATCH', 'If-Match must be a double-quoted checksum');
    }
    if (value !== currentEtag()) {
      throw new HttpError(412, 'PRECONDITION_FAILED', 'If-Match checksum is stale');
    }
  }

  function assertTitleFree(candidate, title, excludeId) {
    const trimmed = title.trim();
    for (const existing of candidate.list()) {
      if (existing.id === excludeId) continue;
      if (existing.title === trimmed) {
        throw new HttpError(409, 'CONFLICT', `title already in use: ${trimmed}`);
      }
    }
  }

  // Persists the next snapshot and history together, and only then installs
  // them. Everything here is synchronous, so a commit is atomic with respect
  // to other requests.
  function persist(nextWorkspace, nextHistory) {
    const snapshot = nextWorkspace.exportJSON();
    commit(snapshot, nextHistory);
    current = nextWorkspace;
    historyState = nextHistory;
    return snapshot;
  }

  async function createDocument(req, res) {
    const text = await readBody(req);
    requireIfMatch(req);
    const document = validateDocument(parseJson(text));
    if (current.get(document.id)) {
      throw new HttpError(409, 'CONFLICT', `document already exists: ${document.id}`);
    }
    const candidate = copyOf(current);
    assertTitleFree(candidate, document.title);
    candidate.add(document);
    const nextHistory = historyState ? appendRecord(historyState, document.id, 'create', document) : null;
    const snapshot = persist(candidate, nextHistory);
    sendJson(res, 201, snapshot, `"${snapshot.checksum}"`);
  }

  async function replaceDocument(req, res, id) {
    const text = await readBody(req);
    requireIfMatch(req);
    const document = validateDocument(parseJson(text));
    if (document.id !== id) {
      throw new HttpError(400, 'ID_MISMATCH', `path id ${id} does not match body id ${document.id}`);
    }
    const existing = current.get(id);
    if (!existing) {
      throw new HttpError(404, 'NOT_FOUND', `document not found: ${id}`);
    }
    // A replace that leaves the normalized content unchanged still succeeds,
    // but does not consume a revision.
    if (sameDocument(existing, document)) {
      sendJson(res, 200, current.exportJSON(), currentEtag());
      return;
    }
    const candidate = copyOf(current);
    candidate.remove(id);
    assertTitleFree(candidate, document.title, id);
    candidate.add(document);
    const nextHistory = historyState ? appendRecord(historyState, id, 'replace', document) : null;
    const snapshot = persist(candidate, nextHistory);
    sendJson(res, 200, snapshot, `"${snapshot.checksum}"`);
  }

  function deleteDocument(req, res, id) {
    requireIfMatch(req);
    if (!current.get(id)) {
      throw new HttpError(404, 'NOT_FOUND', `document not found: ${id}`);
    }
    const candidate = copyOf(current);
    candidate.remove(id);
    const nextHistory = historyState ? appendRecord(historyState, id, 'delete', null) : null;
    const snapshot = persist(candidate, nextHistory);
    sendJson(res, 200, snapshot, `"${snapshot.checksum}"`);
  }

  async function restoreDocument(req, res, id) {
    const text = await readBody(req);
    requireIfMatch(req);
    const body = parseJson(text);
    if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).length !== 1 || !Number.isInteger(body.revision) || body.revision <= 0) {
      throw new HttpError(400, 'INVALID_REVISION', 'body must contain only a positive integer revision');
    }
    if (!historyState) {
      throw new HttpError(404, 'NOT_FOUND', `document not found: ${id}`);
    }
    const records = recordsFor(historyState, id);
    if (!records) {
      throw new HttpError(404, 'NOT_FOUND', `document not found: ${id}`);
    }
    const record = records.find((candidate) => candidate.revision === body.revision);
    if (!record) {
      throw new HttpError(404, 'NOT_FOUND', `revision not found: ${body.revision}`);
    }
    if (record.action === 'delete') {
      throw new HttpError(400, 'INVALID_REVISION', 'cannot restore a deleted revision');
    }
    const restored = record.document;
    const existing = current.get(id);
    // A restore that leaves the normalized content unchanged still succeeds,
    // but does not consume a revision.
    if (existing && sameDocument(existing, restored)) {
      sendJson(res, 200, current.exportJSON(), currentEtag());
      return;
    }
    const candidate = copyOf(current);
    if (existing) candidate.remove(id);
    assertTitleFree(candidate, restored.title, id);
    candidate.add(restored);
    const nextHistory = appendRecord(historyState, id, 'restore', restored);
    const snapshot = persist(candidate, nextHistory);
    sendJson(res, 200, snapshot, `"${snapshot.checksum}"`);
  }

  function readHistory(req, res, id) {
    if (!historyState) {
      throw new HttpError(404, 'NOT_FOUND', `document not found: ${id}`);
    }
    const records = recordsFor(historyState, id);
    if (!records) {
      throw new HttpError(404, 'NOT_FOUND', `document not found: ${id}`);
    }
    sendJson(res, 200, records, currentEtag());
  }

  async function handle(req, res) {
    const url = new URL(req.url, 'http://127.0.0.1');
    const segments = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
    const [resource, id, relation] = segments;

    if (resource === 'documents' && segments.length === 1) {
      if (req.method === 'GET') {
        sendJson(res, 200, current.list(), currentEtag());
        return;
      }
      if (req.method === 'POST') {
        await createDocument(req, res);
        return;
      }
    } else if (resource === 'documents' && segments.length === 2) {
      if (req.method === 'GET') {
        const document = current.get(id);
        if (!document) throw new HttpError(404, 'NOT_FOUND', `document not found: ${id}`);
        sendJson(res, 200, document, currentEtag());
        return;
      }
      if (req.method === 'PUT') {
        await replaceDocument(req, res, id);
        return;
      }
      if (req.method === 'DELETE') {
        deleteDocument(req, res, id);
        return;
      }
    } else if (resource === 'documents' && segments.length === 3 && relation === 'links' && req.method === 'GET') {
      const links = current.links(id);
      if (!links) throw new HttpError(404, 'NOT_FOUND', `document not found: ${id}`);
      sendJson(res, 200, links, currentEtag());
      return;
    } else if (resource === 'documents' && segments.length === 3 && relation === 'history' && req.method === 'GET') {
      readHistory(req, res, id);
      return;
    } else if (resource === 'documents' && segments.length === 3 && relation === 'restore' && req.method === 'POST') {
      await restoreDocument(req, res, id);
      return;
    } else if (resource === 'search' && segments.length === 1 && req.method === 'GET') {
      sendJson(res, 200, current.search(url.searchParams.get('q') ?? ''), currentEtag());
      return;
    }
    throw new HttpError(404, 'NOT_FOUND', `no route for ${req.method} ${url.pathname}`);
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((error) => {
      if (res.headersSent) {
        res.destroy(error);
        return;
      }
      const status = error instanceof HttpError ? error.status : 500;
      const code = error instanceof HttpError ? error.code
        : error instanceof SnapshotError ? error.code
          : 'INTERNAL_ERROR';
      sendJson(res, status, { code, message: error.message });
    });
  });
  return server;
}
