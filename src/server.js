import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { SnapshotError, Workspace, buildSnapshot } from './workspace.js';

const MAX_BODY_BYTES = 1024 * 1024;
const ID_PATTERN = /^[a-z0-9][a-z0-9._-]*$/u;
const IF_MATCH_PATTERN = /^"([0-9a-f]{64})"$/i;

class HttpError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
  }
}

function normalizeTags(tags) {
  if (!Array.isArray(tags)) throw new Error('tags must be an array');
  const normalized = [];
  const seen = new Set();
  for (const tag of tags) {
    if (typeof tag !== 'string') throw new Error('tags must be an array of strings');
    const value = tag.trim().toLowerCase();
    if (value && !seen.has(value)) {
      seen.add(value);
      normalized.push(value);
    }
  }
  return normalized.sort();
}

function validateDocument(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new HttpError(400, 'INVALID_DOCUMENT', 'document must be an object');
  }
  for (const key of ['id', 'title', 'body']) {
    if (typeof input[key] !== 'string' || !input[key].trim()) {
      throw new HttpError(400, 'INVALID_DOCUMENT', `${key} must be a non-empty string`);
    }
  }
  if (!ID_PATTERN.test(input.id)) {
    throw new HttpError(400, 'INVALID_DOCUMENT', 'id must be URL-safe lowercase text');
  }
  if (!('tags' in input)) {
    return {
      id: input.id,
      title: input.title.trim(),
      body: input.body,
      tags: [],
    };
  }
  if (!Array.isArray(input.tags) || input.tags.some((tag) => typeof tag !== 'string')) {
    throw new HttpError(400, 'INVALID_DOCUMENT', 'tags must be an array of strings');
  }
  for (const key of Object.keys(input)) {
    if (key !== 'id' && key !== 'title' && key !== 'body' && key !== 'tags') {
      throw new HttpError(400, 'INVALID_DOCUMENT', `unknown field: ${key}`);
    }
  }
  return {
    id: input.id,
    title: input.title.trim(),
    body: input.body,
    tags: normalizeTags(input.tags),
  };
}

function atomicWrite(file, content) {
  const directory = path.dirname(path.resolve(file));
  const temp = path.join(directory, `.${path.basename(file)}.${process.pid}.tmp`);
  try {
    fs.writeFileSync(temp, content, 'utf8');
    fs.renameSync(temp, file);
  } catch (error) {
    try {
      fs.rmSync(temp, { force: true });
    } catch {
      // best-effort cleanup of the staging file
    }
    throw new SnapshotError('IO_ERROR', `cannot write snapshot file ${file}: ${error.message}`);
  }
}

export function createLatticeServer({ workspace, file }) {
  const server = http.createServer((request, response) => {
    handle(request, response).catch((error) => {
      if (!response.headersSent) {
        sendError(response, error);
      } else {
        response.end();
      }
    });
  });

  // All mutating requests are serialized through this queue: the file is
  // written and the in-memory workspace is committed while the next write
  // waits, so two concurrent writes sharing a checksum cannot both succeed.
  let writeQueue = Promise.resolve();

  function currentChecksum() {
    return workspace.exportJSON().checksum;
  }

  function sendJson(response, status, payload, headers = {}) {
    const body = JSON.stringify(payload);
    response.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      ...headers,
    });
    response.end(body);
  }

  function sendError(response, error) {
    const status = error.status ?? 500;
    const code = error.code ?? 'IO_ERROR';
    const payload = { code };
    if (typeof error.message === 'string') payload.message = error.message;
    sendJson(response, status, payload);
  }

  function readBody(request) {
    return new Promise((resolve, reject) => {
      let size = 0;
      let settled = false;
      const chunks = [];
      request.on('data', (chunk) => {
        if (settled) return;
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          settled = true;
          reject(new HttpError(413, 'PAYLOAD_TOO_LARGE', 'request body exceeds 1 MiB'));
          return;
        }
        chunks.push(chunk);
      });
      request.on('end', () => {
        if (settled) return;
        settled = true;
        resolve(Buffer.concat(chunks).toString('utf8'));
      });
      request.on('error', (error) => {
        if (settled) return;
        settled = true;
        reject(new HttpError(400, 'INVALID_JSON', `failed to read request body: ${error.message}`));
      });
    });
  }

  function parseBody(text) {
    if (text === '') throw new HttpError(400, 'INVALID_JSON', 'request body is empty');
    try {
      return JSON.parse(text);
    } catch {
      throw new HttpError(400, 'INVALID_JSON', 'request body is not valid JSON');
    }
  }

  function checkPreconditions(request) {
    const header = request.headers['if-match'];
    if (header === undefined) {
      throw new HttpError(428, 'IF_MATCH_REQUIRED', 'If-Match header is required');
    }
    const match = IF_MATCH_PATTERN.exec(header.trim());
    if (!match) {
      throw new HttpError(400, 'INVALID_IF_MATCH', 'If-Match must be a double-quoted checksum');
    }
    if (match[1].toLowerCase() !== currentChecksum()) {
      throw new HttpError(412, 'CHECKSUM_MISMATCH', 'If-Match checksum does not match the current workspace');
    }
  }

  function enqueueWrite(task) {
    const run = writeQueue.then(() => task());
    writeQueue = run.catch(() => {
      // Keep the queue alive after a failed write.
    });
    return run;
  }

  function findTitleOwner(title, excludeId) {
    return workspace.list().some((document) => document.title === title && document.id !== excludeId);
  }

  function commitSnapshot(response, status, snapshot) {
    // Persist first: the in-memory workspace only advances once the version-1
    // snapshot is safely on disk. A failure leaves memory, queries, and the
    // original file untouched.
    atomicWrite(file, `${JSON.stringify(snapshot)}\n`);
    workspace.importJSON(snapshot, { mode: 'replace' });
    sendJson(response, status, snapshot, { ETag: `"${snapshot.checksum}"` });
  }

  function listDocuments(response) {
    sendJson(response, 200, { documents: workspace.list() }, { ETag: `"${currentChecksum()}"` });
  }

  function searchDocuments(url, response) {
    const query = url.searchParams.get('q') ?? '';
    sendJson(response, 200, { documents: workspace.search(query) }, { ETag: `"${currentChecksum()}"` });
  }

  function readDocument(id, response) {
    const document = workspace.get(id);
    if (!document) throw new HttpError(404, 'NOT_FOUND', `document not found: ${id}`);
    sendJson(response, 200, document, { ETag: `"${currentChecksum()}"` });
  }

  function readLinks(id, response) {
    const links = workspace.links(id);
    if (!links) throw new HttpError(404, 'NOT_FOUND', `document not found: ${id}`);
    sendJson(response, 200, links, { ETag: `"${currentChecksum()}"` });
  }

  async function createDocument(request, response) {
    const document = validateDocument(parseBody(await readBody(request)));
    await enqueueWrite(async () => {
      checkPreconditions(request);
      if (workspace.get(document.id)) {
        throw new HttpError(409, 'DUPLICATE_ID', `document already exists: ${document.id}`);
      }
      if (findTitleOwner(document.title)) {
        throw new HttpError(409, 'DUPLICATE_TITLE', `title already exists: ${document.title}`);
      }
      const documents = workspace.list();
      documents.push(document);
      commitSnapshot(response, 201, buildSnapshot(documents));
    });
  }

  async function updateDocument(id, request, response) {
    const document = validateDocument(parseBody(await readBody(request)));
    await enqueueWrite(async () => {
      if (document.id !== id) {
        throw new HttpError(400, 'INVALID_DOCUMENT', 'document id in path and body must match');
      }
      checkPreconditions(request);
      if (!workspace.get(id)) {
        throw new HttpError(404, 'NOT_FOUND', `document not found: ${id}`);
      }
      if (findTitleOwner(document.title, id)) {
        throw new HttpError(409, 'DUPLICATE_TITLE', `title already exists: ${document.title}`);
      }
      const documents = workspace.list().map((candidate) => (candidate.id === id ? document : candidate));
      commitSnapshot(response, 200, buildSnapshot(documents));
    });
  }

  async function deleteDocument(id, request, response) {
    await enqueueWrite(async () => {
      checkPreconditions(request);
      if (!workspace.get(id)) {
        throw new HttpError(404, 'NOT_FOUND', `document not found: ${id}`);
      }
      const documents = workspace.list().filter((candidate) => candidate.id !== id);
      commitSnapshot(response, 200, buildSnapshot(documents));
    });
  }

  async function handle(request, response) {
    const url = new URL(request.url, 'http://127.0.0.1');
    let segments;
    try {
      segments = url.pathname.split('/').filter((segment) => segment !== '').map(decodeURIComponent);
    } catch {
      throw new HttpError(404, 'NOT_FOUND', 'unknown route');
    }

    if (request.method === 'POST' || request.method === 'PUT') {
      const contentLength = request.headers['content-length'];
      if (contentLength !== undefined && Number(contentLength) > MAX_BODY_BYTES) {
        throw new HttpError(413, 'PAYLOAD_TOO_LARGE', 'request body exceeds 1 MiB');
      }
    }

    if (segments.length === 1 && segments[0] === 'documents') {
      if (request.method === 'GET') return listDocuments(response);
      if (request.method === 'POST') return await createDocument(request, response);
      throw new HttpError(405, 'METHOD_NOT_ALLOWED', 'method not allowed');
    }

    if (segments.length === 1 && segments[0] === 'search') {
      if (request.method === 'GET') return searchDocuments(url, response);
      throw new HttpError(405, 'METHOD_NOT_ALLOWED', 'method not allowed');
    }

    if (segments.length === 2 && segments[0] === 'documents') {
      const id = segments[1];
      if (request.method === 'GET') return readDocument(id, response);
      if (request.method === 'PUT') return await updateDocument(id, request, response);
      if (request.method === 'DELETE') return await deleteDocument(id, request, response);
      throw new HttpError(405, 'METHOD_NOT_ALLOWED', 'method not allowed');
    }

    if (segments.length === 3 && segments[0] === 'documents' && segments[2] === 'links') {
      const id = segments[1];
      if (request.method === 'GET') return readLinks(id, response);
      throw new HttpError(405, 'METHOD_NOT_ALLOWED', 'method not allowed');
    }

    throw new HttpError(404, 'NOT_FOUND', 'unknown route');
  }

  return server;
}

export function startServer({ workspace, file, host = '127.0.0.1', port = 3000 }) {
  const server = createLatticeServer({ workspace, file });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      const address = server.address();
      resolve({ server, host: address.address, port: address.port });
    });
  });
}

export function loadWorkspace(file) {
  const workspace = new Workspace();
  if (!fs.existsSync(file)) return workspace;
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (error) {
    throw new SnapshotError('IO_ERROR', `cannot read snapshot file ${file}: ${error.message}`);
  }
  workspace.importJSON(text, { mode: 'replace' });
  return workspace;
}
