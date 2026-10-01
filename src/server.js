import http from 'node:http';
import { SnapshotError, Workspace } from './workspace.js';
import { sameDocument } from './history.js';

const MAX_BODY_BYTES = 1024 * 1024;
const MAX_BATCH_OPERATIONS = 100;
const ETAG_PATTERN = /^"[0-9a-f]{64}"$/u;
const ID_PATTERN = /^[a-z0-9][a-z0-9._-]*$/u;
const DOCUMENT_FIELDS = new Set(['id', 'title', 'body', 'tags']);
const OPERATION_FIELDS = {
  create: ['document'],
  replace: ['document'],
  delete: ['id'],
  restore: ['id', 'revision'],
};

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
  return { id: data.id, title: data.title, body: data.body, tags: data.tags ?? [] };
}

// Validates one batch operation's shape. Structural problems (unknown action,
// missing/extra fields, wrong field types) report INVALID_BATCH; the document
// payload itself is validated exactly like a single-document write, and a
// malformed restore revision follows the single-restore rule.
function parseOperation(raw, index) {
  const location = `operations[${index}]`;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new HttpError(400, 'INVALID_BATCH', `${location} must be an object`);
  }
  const fields = OPERATION_FIELDS[raw.type];
  if (!fields) {
    throw new HttpError(400, 'INVALID_BATCH', `${location} has an unknown action`);
  }
  const expected = new Set(['type', ...fields]);
  for (const key of Object.keys(raw)) {
    if (!expected.has(key)) {
      throw new HttpError(400, 'INVALID_BATCH', `${location} has unknown field: ${key}`);
    }
  }
  for (const key of expected) {
    if (!Object.hasOwn(raw, key)) {
      throw new HttpError(400, 'INVALID_BATCH', `${location} is missing field: ${key}`);
    }
  }
  if (raw.type === 'create' || raw.type === 'replace') {
    return { type: raw.type, document: validateDocument(raw.document) };
  }
  if (typeof raw.id !== 'string') {
    throw new HttpError(400, 'INVALID_BATCH', `${location}.id must be a string`);
  }
  if (raw.type === 'delete') {
    return { type: 'delete', id: raw.id };
  }
  if (!Number.isInteger(raw.revision) || raw.revision < 1) {
    throw new HttpError(400, 'INVALID_REVISION', 'revision must be a positive integer');
  }
  return { type: 'restore', id: raw.id, revision: raw.revision };
}

// Validates the batch envelope: exactly `operations` plus an optional boolean
// `dryRun`, 1-100 operations, and no id targeted by more than one operation.
function parseBatch(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new HttpError(400, 'INVALID_BATCH', 'batch must be an object');
  }
  for (const key of Object.keys(data)) {
    if (key !== 'operations' && key !== 'dryRun') {
      throw new HttpError(400, 'INVALID_BATCH', `unknown batch field: ${key}`);
    }
  }
  if (data.dryRun !== undefined && typeof data.dryRun !== 'boolean') {
    throw new HttpError(400, 'INVALID_BATCH', 'dryRun must be a boolean');
  }
  if (!Array.isArray(data.operations)
    || data.operations.length === 0
    || data.operations.length > MAX_BATCH_OPERATIONS) {
    throw new HttpError(400, 'INVALID_BATCH', `operations must be an array of 1 to ${MAX_BATCH_OPERATIONS} items`);
  }
  const operations = data.operations.map((raw, index) => parseOperation(raw, index));
  const targets = new Set();
  for (const operation of operations) {
    const target = operation.type === 'create' || operation.type === 'replace'
      ? operation.document.id
      : operation.id;
    if (targets.has(target)) {
      throw new HttpError(400, 'INVALID_BATCH', `duplicate target id: ${target}`);
    }
    targets.add(target);
  }
  return { operations, dryRun: data.dryRun ?? false };
}

// A document server holds one Workspace and, when a history store is supplied,
// a per-document revision ledger. Every committed change is persisted through
// `save(snapshot, historySnapshot)` before the in-memory state is swapped, so a
// failed save leaves memory, queries, history, and the original files
// untouched. Everything here is synchronous, so a commit is atomic with
// respect to other requests.
export function createDocumentServer({ workspace, save, history = null }) {
  let current = workspace;
  let ledger = history;

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

  function assertTitleFree(candidate, title) {
    const trimmed = title.trim();
    for (const existing of candidate.list()) {
      if (existing.title === trimmed) {
        throw new HttpError(409, 'CONFLICT', `title already in use: ${trimmed}`);
      }
    }
  }

  // Builds the next state on a candidate workspace and lets `mutate` append to
  // the next ledger. The callback returns false to signal a content-preserving
  // write (normalized content unchanged): the request still succeeds, but no
  // revision is appended and nothing is persisted. With `dryRun` the projected
  // snapshot is returned without saving or swapping the live state.
  function commit(mutate, dryRun = false) {
    const candidate = new Workspace();
    for (const document of current.list()) candidate.add(document);
    const nextLedger = ledger ? ledger.clone() : null;
    const changed = mutate(candidate, nextLedger);
    if (changed === false) {
      return current.exportJSON();
    }
    const snapshot = candidate.exportJSON();
    if (!dryRun) {
      save(snapshot, nextLedger ? nextLedger.exportJSON(snapshot.checksum) : null);
      current = candidate;
      ledger = nextLedger;
    }
    return snapshot;
  }

  async function createDocument(req, res) {
    const text = await readBody(req);
    requireIfMatch(req);
    const document = validateDocument(parseJson(text));
    const snapshot = commit((candidate, nextLedger) => {
      if (candidate.get(document.id)) {
        throw new HttpError(409, 'CONFLICT', `document already exists: ${document.id}`);
      }
      assertTitleFree(candidate, document.title);
      candidate.add(document);
      if (nextLedger) nextLedger.record(document.id, 'create', candidate.get(document.id));
    });
    sendJson(res, 201, snapshot, `"${snapshot.checksum}"`);
  }

  async function replaceDocument(req, res, id) {
    const text = await readBody(req);
    requireIfMatch(req);
    const document = validateDocument(parseJson(text));
    if (document.id !== id) {
      throw new HttpError(400, 'ID_MISMATCH', `path id ${id} does not match body id ${document.id}`);
    }
    if (!current.get(id)) {
      throw new HttpError(404, 'NOT_FOUND', `document not found: ${id}`);
    }
    const before = current.get(id);
    const snapshot = commit((candidate, nextLedger) => {
      candidate.remove(id);
      assertTitleFree(candidate, document.title);
      candidate.add(document);
      const stored = candidate.get(id);
      // A replace whose normalized content is identical succeeds without
      // consuming a revision or touching the files.
      if (sameDocument(before, stored)) return false;
      if (nextLedger) nextLedger.record(id, 'replace', stored);
      return true;
    });
    sendJson(res, 200, snapshot, `"${snapshot.checksum}"`);
  }

  function deleteDocument(req, res, id) {
    requireIfMatch(req);
    if (!current.get(id)) {
      throw new HttpError(404, 'NOT_FOUND', `document not found: ${id}`);
    }
    const snapshot = commit((candidate, nextLedger) => {
      candidate.remove(id);
      if (nextLedger) nextLedger.record(id, 'delete', null);
    });
    sendJson(res, 200, snapshot, `"${snapshot.checksum}"`);
  }

  function historyDocument(req, res, id) {
    if (!ledger) throw new HttpError(404, 'NOT_FOUND', `no route for GET /documents/${id}/history`);
    const entries = ledger.entries(id);
    if (!entries) throw new HttpError(404, 'NOT_FOUND', `document never existed: ${id}`);
    sendJson(res, 200, entries, currentEtag());
  }

  async function restoreDocument(req, res, id) {
    if (!ledger) throw new HttpError(404, 'NOT_FOUND', `no route for POST /documents/${id}/restore`);
    const text = await readBody(req);
    requireIfMatch(req);
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      throw new HttpError(400, 'INVALID_REVISION', 'request body must be an object containing only a positive integer revision');
    }
    if (!data || typeof data !== 'object' || Array.isArray(data)
      || Object.keys(data).length !== 1 || !Object.hasOwn(data, 'revision')
      || !Number.isInteger(data.revision) || data.revision < 1) {
      throw new HttpError(400, 'INVALID_REVISION', 'request body must be an object containing only a positive integer revision');
    }
    const chain = ledger.entries(id);
    if (!chain) throw new HttpError(404, 'NOT_FOUND', `document never existed: ${id}`);
    const target = ledger.entry(id, data.revision);
    if (!target) throw new HttpError(404, 'NOT_FOUND', `unknown revision ${data.revision} for document ${id}`);
    if (target.action === 'delete') {
      throw new HttpError(400, 'INVALID_REVISION', `revision ${data.revision} of document ${id} is a delete and cannot be restored`);
    }
    const before = current.get(id);
    const snapshot = commit((candidate, nextLedger) => {
      candidate.remove(id);
      assertTitleFree(candidate, target.document.title);
      candidate.add(target.document);
      const stored = candidate.get(id);
      // Restoring the already-current content succeeds without a new record.
      if (before && sameDocument(before, stored)) return false;
      nextLedger.record(id, 'restore', stored);
      return true;
    });
    sendJson(res, 200, snapshot, `"${snapshot.checksum}"`);
  }

  // Resolves every operation against the same pre-commit state: existence,
  // revision chains, and restore targets never see the effects of the other
  // operations in the batch.
  function prepareBatch(operations) {
    if (!ledger && operations.some((operation) => operation.type === 'restore')) {
      throw new HttpError(404, 'NOT_FOUND', 'restore requires history to be enabled');
    }
    return operations.map((operation) => {
      if (operation.type === 'create') {
        if (current.get(operation.document.id)) {
          throw new HttpError(409, 'CONFLICT', `document already exists: ${operation.document.id}`);
        }
        return operation;
      }
      if (operation.type === 'replace' || operation.type === 'delete') {
        const id = operation.type === 'replace' ? operation.document.id : operation.id;
        const before = current.get(id);
        if (!before) throw new HttpError(404, 'NOT_FOUND', `document not found: ${id}`);
        return { ...operation, before };
      }
      const chain = ledger.entries(operation.id);
      if (!chain) throw new HttpError(404, 'NOT_FOUND', `document never existed: ${operation.id}`);
      const target = ledger.entry(operation.id, operation.revision);
      if (!target) {
        throw new HttpError(404, 'NOT_FOUND', `unknown revision ${operation.revision} for document ${operation.id}`);
      }
      if (target.action === 'delete') {
        throw new HttpError(400, 'INVALID_REVISION', `revision ${operation.revision} of document ${operation.id} is a delete and cannot be restored`);
      }
      return { ...operation, before: current.get(operation.id), target: target.document };
    });
  }

  async function batchDocuments(req, res) {
    const text = await readBody(req);
    requireIfMatch(req);
    const { operations, dryRun } = parseBatch(parseJson(text));
    const prepared = prepareBatch(operations);
    const snapshot = commit((candidate, nextLedger) => {
      let changed = false;
      for (const operation of prepared) {
        if (operation.type === 'create') {
          candidate.add(operation.document);
          if (nextLedger) nextLedger.record(operation.document.id, 'create', candidate.get(operation.document.id));
          changed = true;
        } else if (operation.type === 'replace') {
          candidate.remove(operation.document.id);
          candidate.add(operation.document);
          const stored = candidate.get(operation.document.id);
          // A replace whose normalized content is identical appends no record.
          if (!sameDocument(operation.before, stored)) {
            if (nextLedger) nextLedger.record(operation.document.id, 'replace', stored);
            changed = true;
          }
        } else if (operation.type === 'delete') {
          candidate.remove(operation.id);
          if (nextLedger) nextLedger.record(operation.id, 'delete', null);
          changed = true;
        } else {
          candidate.remove(operation.id);
          candidate.add(operation.target);
          const stored = candidate.get(operation.id);
          // Restoring the already-current content appends no record.
          if (!operation.before || !sameDocument(operation.before, stored)) {
            if (nextLedger) nextLedger.record(operation.id, 'restore', stored);
            changed = true;
          }
        }
      }
      // Titles are only judged on the final set, so swapping titles or reusing
      // a freed title does not depend on the order of operations.
      const titles = new Set();
      for (const document of candidate.list()) {
        if (titles.has(document.title)) {
          throw new HttpError(409, 'CONFLICT', `title already in use: ${document.title}`);
        }
        titles.add(document.title);
      }
      return changed;
    }, dryRun);
    sendJson(res, 200, snapshot, `"${snapshot.checksum}"`);
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
      historyDocument(req, res, id);
      return;
    } else if (resource === 'documents' && segments.length === 3 && relation === 'restore' && req.method === 'POST') {
      await restoreDocument(req, res, id);
      return;
    } else if (resource === 'batch' && segments.length === 1 && req.method === 'POST') {
      await batchDocuments(req, res);
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
