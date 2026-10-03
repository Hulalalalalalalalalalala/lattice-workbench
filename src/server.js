import http from 'node:http';
import { SnapshotError, Workspace, normalizeTags } from './workspace.js';
import { sameDocument } from './history.js';
import { reconcileSnapshots } from './reconcile.js';

const MAX_BODY_BYTES = 1024 * 1024;
// Bodies must be valid UTF-8: a fatal decode rejects lone continuation
// bytes, truncated or overlong multibyte sequences, surrogate code points,
// and out-of-range sequences instead of letting them surface as U+FFFD.
const fatalDecoder = new TextDecoder('utf-8', { fatal: true });
const ETAG_PATTERN = /^"[0-9a-f]{64}"$/u;
const ID_PATTERN = /^[a-z0-9][a-z0-9._-]*$/u;
const DOCUMENT_FIELDS = new Set(['id', 'title', 'body', 'tags']);
const BATCH_ACTIONS = new Set(['create', 'replace', 'delete', 'restore']);
const MAX_BATCH_OPERATIONS = 100;
const TAG_RULE_FIELDS = ['from', 'to'];
const MAX_TAG_RULES = 100;

function compareCodePoints(a, b) {
  const left = Array.from(a, (char) => char.codePointAt(0));
  const right = Array.from(b, (char) => char.codePointAt(0));
  for (let i = 0; i < Math.min(left.length, right.length); i += 1) {
    if (left[i] !== right[i]) return left[i] - right[i];
  }
  return left.length - right.length;
}

function sameTags(a, b) {
  return a.length === b.length && a.every((tag, i) => tag === b[i]);
}

class HttpError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
    for (const [key, value] of Object.entries(extra)) this[key] = value;
  }
}

function sendJson(res, status, payload, etag) {
  const headers = { 'content-type': 'application/json; charset=utf-8' };
  if (etag) headers.etag = etag;
  res.writeHead(status, headers);
  res.end(JSON.stringify(payload));
}

// Reads and size-limits the raw request bytes. The byte count, not the
// decoded character count, is compared against the 1 MiB limit. A multibyte
// character split across transport chunks is reassembled by Buffer.concat, so
// the framing never affects later decoding.
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
  return Buffer.concat(chunks);
}

// Strictly decodes a request body as UTF-8: a lone continuation byte, a
// truncated or overlong multibyte sequence, an encoded surrogate code point,
// or bytes beyond the Unicode range are rejected instead of silently becoming
// U+FFFD in a stored document. (A U+FFFD that was itself encoded validly is
// ordinary text and decodes fine.) JSON escapes such as "\uD800" are untouched
// by this layer and keep their existing string semantics.
function decodeJsonBody(bytes) {
  try {
    return fatalDecoder.decode(bytes);
  } catch {
    throw new HttpError(400, 'INVALID_JSON', 'request body is not valid UTF-8');
  }
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

// Validates the batch envelope and every operation, returning normalized
// `{ operations, dryRun }`. Structural problems (bad envelope shape, unknown
// type, wrong fields, missing id, non-string id) are INVALID_BATCH; document
// content problems follow the single-document rules (INVALID_DOCUMENT), and a
// revision that is not a positive integer is INVALID_REVISION.
function validateBatchRequest(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new HttpError(400, 'INVALID_BATCH', 'batch body must be an object');
  }
  for (const key of Object.keys(data)) {
    if (key !== 'operations' && key !== 'dryRun') {
      throw new HttpError(400, 'INVALID_BATCH', `unknown batch field: ${key}`);
    }
  }
  if (!Array.isArray(data.operations)) {
    throw new HttpError(400, 'INVALID_BATCH', 'operations must be an array');
  }
  if (data.operations.length < 1 || data.operations.length > MAX_BATCH_OPERATIONS) {
    throw new HttpError(400, 'INVALID_BATCH', `operations must contain 1 to ${MAX_BATCH_OPERATIONS} items`);
  }
  const dryRun = data.dryRun === undefined ? false : data.dryRun;
  if (typeof dryRun !== 'boolean') {
    throw new HttpError(400, 'INVALID_BATCH', 'dryRun must be a boolean');
  }

  const operations = data.operations.map((op, index) => {
    if (!op || typeof op !== 'object' || Array.isArray(op)) {
      throw new HttpError(400, 'INVALID_BATCH', `operations[${index}] must be an object`);
    }
    const type = op.type;
    if (typeof type !== 'string' || !BATCH_ACTIONS.has(type)) {
      throw new HttpError(400, 'INVALID_BATCH', `operations[${index}] has an unknown type`);
    }
    const expectedKeys = type === 'create' || type === 'replace'
      ? ['type', 'document']
      : type === 'delete'
        ? ['type', 'id']
        : ['type', 'id', 'revision'];
    const keys = Object.keys(op);
    if (keys.length !== expectedKeys.length || !expectedKeys.every((key) => keys.includes(key))) {
      throw new HttpError(400, 'INVALID_BATCH', `operations[${index}] has invalid fields for ${type}`);
    }

    if (type === 'create' || type === 'replace') {
      if (!op.document || typeof op.document !== 'object' || Array.isArray(op.document)) {
        throw new HttpError(400, 'INVALID_BATCH', `operations[${index}] document must be an object`);
      }
      return { type, document: validateDocument(op.document) };
    }

    if (typeof op.id !== 'string') {
      throw new HttpError(400, 'INVALID_BATCH', `operations[${index}] id must be a string`);
    }

    if (type === 'delete') {
      return { type, id: op.id };
    }

    // restore: the envelope is structurally valid; the revision value itself
    // follows the single-document restore rules.
    if (op.revision === undefined) {
      throw new HttpError(400, 'INVALID_BATCH', `operations[${index}] restore requires a revision`);
    }
    if (!Number.isInteger(op.revision) || op.revision < 1) {
      throw new HttpError(400, 'INVALID_REVISION', `operations[${index}] revision must be a positive integer`);
    }
    return { type, id: op.id, revision: op.revision };
  });

  // Every operation targets a distinct document id.
  const seen = new Set();
  for (const op of operations) {
    const id = op.type === 'create' || op.type === 'replace' ? op.document.id : op.id;
    if (seen.has(id)) {
      throw new HttpError(400, 'INVALID_BATCH', `duplicate target id in batch: ${id}`);
    }
    seen.add(id);
  }

  return { operations, dryRun };
}

// Counts current tag usage across the live documents. Deleted documents are
// absent from the workspace and therefore never counted; history is ignored.
function tagStats(workspace) {
  const counts = new Map();
  for (const document of workspace.list()) {
    for (const tag of document.tags) counts.set(tag, (counts.get(tag) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([tag, count]) => ({ tag, count }))
    .sort((a, b) => compareCodePoints(a.tag, b.tag));
}

// Validates the rewrite envelope and every rule, returning normalized
// `{ rules, dryRun }` as `[{ from, to }]` pairs of trimmed, lowercased names
// (`to` stays `null` for removals). Structural problems, empty normalized
// names, duplicate sources, and out-of-range rule counts are INVALID_TAG_RULES.
function validateTagRules(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new HttpError(400, 'INVALID_TAG_RULES', 'rewrite body must be an object');
  }
  for (const key of Object.keys(data)) {
    if (key !== 'rules' && key !== 'dryRun') {
      throw new HttpError(400, 'INVALID_TAG_RULES', `unknown rewrite field: ${key}`);
    }
  }
  if (!Array.isArray(data.rules)) {
    throw new HttpError(400, 'INVALID_TAG_RULES', 'rules must be an array');
  }
  if (data.rules.length < 1 || data.rules.length > MAX_TAG_RULES) {
    throw new HttpError(400, 'INVALID_TAG_RULES', `rules must contain 1 to ${MAX_TAG_RULES} items`);
  }
  const dryRun = data.dryRun === undefined ? false : data.dryRun;
  if (typeof dryRun !== 'boolean') {
    throw new HttpError(400, 'INVALID_TAG_RULES', 'dryRun must be a boolean');
  }

  const rules = data.rules.map((rule, index) => {
    if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
      throw new HttpError(400, 'INVALID_TAG_RULES', `rules[${index}] must be an object`);
    }
    const keys = Object.keys(rule);
    if (keys.length !== TAG_RULE_FIELDS.length || !TAG_RULE_FIELDS.every((key) => keys.includes(key))) {
      throw new HttpError(400, 'INVALID_TAG_RULES', `rules[${index}] must contain exactly from and to`);
    }
    if (typeof rule.from !== 'string') {
      throw new HttpError(400, 'INVALID_TAG_RULES', `rules[${index}].from must be a string`);
    }
    if (typeof rule.to !== 'string' && rule.to !== null) {
      throw new HttpError(400, 'INVALID_TAG_RULES', `rules[${index}].to must be a string or null`);
    }
    const from = rule.from.trim().toLowerCase();
    const to = rule.to === null ? null : rule.to.trim().toLowerCase();
    if (!from) {
      throw new HttpError(400, 'INVALID_TAG_RULES', `rules[${index}].from must not be blank`);
    }
    if (to !== null && !to) {
      throw new HttpError(400, 'INVALID_TAG_RULES', `rules[${index}].to must not be blank`);
    }
    return { from, to };
  });

  const seen = new Set();
  for (const { from } of rules) {
    if (seen.has(from)) {
      throw new HttpError(400, 'INVALID_TAG_RULES', `duplicate source tag after normalization: ${from}`);
    }
    seen.add(from);
  }

  return { rules, dryRun };
}

// Validates the reconcile envelope `{ base, incoming, dryRun? }`, where base
// and incoming are version-1 snapshot objects (strings are not accepted at
// this layer; malformed JSON is rejected earlier by the shared body parser).
// Snapshot contents themselves are validated by normalizeSnapshot via the
// reconcile core, which reports INVALID_SNAPSHOT.
function validateReconcileRequest(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new HttpError(400, 'INVALID_OPTIONS', 'reconcile body must be an object');
  }
  for (const key of Object.keys(data)) {
    if (key !== 'base' && key !== 'incoming' && key !== 'dryRun') {
      throw new HttpError(400, 'INVALID_OPTIONS', `unknown reconcile field: ${key}`);
    }
  }
  if (!data.base || typeof data.base !== 'object' || Array.isArray(data.base)) {
    throw new HttpError(400, 'INVALID_OPTIONS', 'base must be a snapshot object');
  }
  if (!data.incoming || typeof data.incoming !== 'object' || Array.isArray(data.incoming)) {
    throw new HttpError(400, 'INVALID_OPTIONS', 'incoming must be a snapshot object');
  }
  const dryRun = data.dryRun === undefined ? false : data.dryRun;
  if (typeof dryRun !== 'boolean') {
    throw new HttpError(400, 'INVALID_OPTIONS', 'dryRun must be a boolean');
  }
  return { base: data.base, incoming: data.incoming, dryRun };
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

  // The single commit rule shared by every write entry point (single-document
  // edits and restores, batches, tag rewrites, and snapshot reconciles).
  // `mutate` runs against a candidate workspace copied from the live state
  // plus a cloned ledger, applying its content changes and appending one
  // history record per actually-changed document. It returns a result value to
  // commit the projected state, or false to signal a content-preserving
  // request (normalized content unchanged): the request still succeeds with
  // the current snapshot and ETag, but no revision is consumed and nothing is
  // persisted. With `dryRun` the projected snapshot and result are returned
  // without persisting or swapping state. Otherwise the snapshot — and, when
  // history is enabled, the ledger bound to its checksum — is saved first, and
  // the in-memory state swaps in only after the save succeeds, so a failed
  // save leaves memory, queries, history, and the original files untouched.
  // Everything here is synchronous, so a commit is atomic with respect to
  // other requests.
  function commit(mutate, { dryRun = false } = {}) {
    const candidate = new Workspace();
    for (const document of current.list()) candidate.add(document);
    const nextLedger = ledger ? ledger.clone() : null;
    const result = mutate(candidate, nextLedger);
    if (result === false) {
      return { snapshot: current.exportJSON(), result: null };
    }
    const snapshot = candidate.exportJSON();
    if (!dryRun) {
      save(snapshot, nextLedger ? nextLedger.exportJSON(snapshot.checksum) : null);
      current = candidate;
      ledger = nextLedger;
    }
    return { snapshot, result };
  }

  // Applies every operation in one atomic commit. Existence and
  // restore-version checks all run against the pre-commit state, so a batch is
  // rejected whole if any operation would fail. Title conflicts are checked
  // against the final projected set, making swaps and release-then-reuse
  // independent of operation order. Each actually-changed document appends one
  // record; a normalized-identical replace or restore appends nothing. Returns
  // `{ snapshot, changed }` without persisting when `dryRun` is true or the
  // batch is content-preserving.
  function commitBatch(operations, dryRun) {
    // Pre-commit state checks.
    for (const op of operations) {
      if (op.type === 'create') {
        if (current.get(op.document.id)) {
          throw new HttpError(409, 'CONFLICT', `document already exists: ${op.document.id}`);
        }
      } else if (op.type === 'replace') {
        if (!current.get(op.document.id)) {
          throw new HttpError(404, 'NOT_FOUND', `document not found: ${op.document.id}`);
        }
      } else if (op.type === 'delete') {
        if (!current.get(op.id)) {
          throw new HttpError(404, 'NOT_FOUND', `document not found: ${op.id}`);
        }
      } else if (op.type === 'restore') {
        if (!ledger) {
          throw new HttpError(404, 'NOT_FOUND', 'history is not enabled');
        }
        const chain = ledger.entries(op.id);
        if (!chain) {
          throw new HttpError(404, 'NOT_FOUND', `document never existed: ${op.id}`);
        }
        const target = ledger.entry(op.id, op.revision);
        if (!target) {
          throw new HttpError(404, 'NOT_FOUND', `unknown revision ${op.revision} for document ${op.id}`);
        }
        if (target.action === 'delete') {
          throw new HttpError(400, 'INVALID_REVISION', `revision ${op.revision} of document ${op.id} is a delete and cannot be restored`);
        }
      }
    }

    const { snapshot, result } = commit((candidate, nextLedger) => {
      let changed = false;
      for (const op of operations) {
        if (op.type === 'create') {
          candidate.add(op.document);
          if (nextLedger) nextLedger.record(op.document.id, 'create', candidate.get(op.document.id));
          changed = true;
        } else if (op.type === 'replace') {
          const before = current.get(op.document.id);
          candidate.remove(op.document.id);
          candidate.add(op.document);
          const stored = candidate.get(op.document.id);
          if (!sameDocument(before, stored)) {
            if (nextLedger) nextLedger.record(op.document.id, 'replace', stored);
            changed = true;
          }
        } else if (op.type === 'delete') {
          candidate.remove(op.id);
          if (nextLedger) nextLedger.record(op.id, 'delete', null);
          changed = true;
        } else if (op.type === 'restore') {
          const before = current.get(op.id);
          const target = ledger.entry(op.id, op.revision);
          candidate.remove(op.id);
          candidate.add(target.document);
          const stored = candidate.get(op.id);
          if (!before || !sameDocument(before, stored)) {
            nextLedger.record(op.id, 'restore', stored);
            changed = true;
          }
        }
      }

      // Title conflicts are checked against the final projected set, so
      // operation order cannot make a swap or release-then-reuse fail.
      const titles = new Set();
      for (const document of candidate.list()) {
        if (titles.has(document.title)) {
          throw new HttpError(409, 'CONFLICT', `title conflict in batch: ${document.title}`);
        }
        titles.add(document.title);
      }

      return changed;
    }, { dryRun });
    return { snapshot, changed: result === true };
  }

  async function createDocument(req, res) {
    const bytes = await readBody(req);
    requireIfMatch(req);
    const document = validateDocument(parseJson(decodeJsonBody(bytes)));
    const { snapshot } = commit((candidate, nextLedger) => {
      if (candidate.get(document.id)) {
        throw new HttpError(409, 'CONFLICT', `document already exists: ${document.id}`);
      }
      assertTitleFree(candidate, document.title);
      candidate.add(document);
      if (nextLedger) nextLedger.record(document.id, 'create', candidate.get(document.id));
      return true;
    });
    sendJson(res, 201, snapshot, `"${snapshot.checksum}"`);
  }

  async function replaceDocument(req, res, id) {
    const bytes = await readBody(req);
    requireIfMatch(req);
    const document = validateDocument(parseJson(decodeJsonBody(bytes)));
    if (document.id !== id) {
      throw new HttpError(400, 'ID_MISMATCH', `path id ${id} does not match body id ${document.id}`);
    }
    if (!current.get(id)) {
      throw new HttpError(404, 'NOT_FOUND', `document not found: ${id}`);
    }
    const before = current.get(id);
    const { snapshot } = commit((candidate, nextLedger) => {
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
    const { snapshot } = commit((candidate, nextLedger) => {
      candidate.remove(id);
      if (nextLedger) nextLedger.record(id, 'delete', null);
      return true;
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
    const bytes = await readBody(req);
    requireIfMatch(req);
    // Bad UTF-8 is an INVALID_JSON transport-level failure; only once the
    // bytes decode do the restore-specific parse/shape rules apply, which
    // keep reporting INVALID_REVISION as before.
    const text = decodeJsonBody(bytes);
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
    const { snapshot } = commit((candidate, nextLedger) => {
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

  async function batch(req, res) {
    const bytes = await readBody(req);
    requireIfMatch(req);
    const data = parseJson(decodeJsonBody(bytes));
    const { operations, dryRun } = validateBatchRequest(data);
    const { snapshot } = commitBatch(operations, dryRun);
    sendJson(res, 200, snapshot, `"${snapshot.checksum}"`);
  }

  function listTags(req, res) {
    sendJson(res, 200, tagStats(current), currentEtag());
  }

  // Applies the tag rules to the pre-rewrite tag set of every document. Each
  // original tag is looked up once, so a rule result is never itself rewritten
  // (a→b then b→c moves the original `a` straight to `b`) and swaps resolve
  // because `to` names are carried independently of the source keys. Returns
  // `{ snapshot, changedIds }` without persisting when `dryRun` is true or the
  // rewrite leaves the tag set unchanged.
  function commitTagRewrite(rules, dryRun) {
    const mapping = new Map(rules.map((rule) => [rule.from, rule.to]));

    // Every source must be used by at least one currently-live document.
    const used = new Set();
    for (const document of current.list()) {
      for (const tag of document.tags) used.add(tag);
    }
    for (const from of mapping.keys()) {
      if (!used.has(from)) throw new HttpError(404, 'TAG_NOT_FOUND', `tag not in use: ${from}`);
    }

    const { snapshot, result } = commit((candidate, nextLedger) => {
      const changedIds = [];
      for (const document of current.list()) {
        if (!document.tags.some((tag) => mapping.has(tag))) continue;
        // A null target removes the tag; mapped results are emitted as-is
        // without a second lookup, so new names are never chained further.
        const nextTags = normalizeTags(
          document.tags.flatMap((tag) => {
            if (!mapping.has(tag)) return [tag];
            const target = mapping.get(tag);
            return target === null ? [] : [target];
          }),
        );
        if (sameTags(document.tags, nextTags)) continue;
        const updated = { id: document.id, title: document.title, body: document.body, tags: nextTags };
        candidate.remove(document.id);
        candidate.add(updated);
        if (nextLedger) nextLedger.record(document.id, 'replace', candidate.get(document.id));
        changedIds.push(document.id);
      }
      // Tag set unchanged: report the current snapshot and no file/version work.
      if (changedIds.length === 0) return false;
      changedIds.sort(compareCodePoints);
      return changedIds;
    }, { dryRun });
    return { snapshot, changedIds: result ?? [] };
  }

  async function rewriteTags(req, res) {
    const bytes = await readBody(req);
    requireIfMatch(req);
    const { rules, dryRun } = validateTagRules(parseJson(decodeJsonBody(bytes)));
    const { snapshot, changedIds } = commitTagRewrite(rules, dryRun);
    sendJson(res, 200, { snapshot, changedIds }, `"${snapshot.checksum}"`);
  }

  // Merges an offline-edited incoming snapshot back against its base, keeping
  // non-conflicting online edits. The merge is computed against the current
  // live state; field/add/delete/title conflicts reject the whole request.
  // Each actually-changed document appends one ledger record (create for new
  // or reappearing ids, replace for edits, delete for removals), continuing
  // that id's revision sequence. Returns `{ snapshot, changedIds }` without
  // persisting when `dryRun` is true or the merge leaves the content equal to
  // the current state.
  function commitReconcile(base, incoming, dryRun) {
    const currentSnapshot = current.exportJSON();
    const result = reconcileSnapshots(currentSnapshot, base, incoming);
    if (result.conflicts.length > 0) {
      throw new HttpError(409, 'RECONCILE_CONFLICT', 'reconcile conflicts detected', {
        conflicts: result.conflicts,
      });
    }

    const { snapshot } = commit((candidate, nextLedger) => {
      if (result.snapshot.checksum === currentSnapshot.checksum) return false;
      for (const document of current.list()) candidate.remove(document.id);
      for (const document of result.snapshot.documents) candidate.add(document);
      if (nextLedger) {
        for (const id of result.changedIds) {
          const stored = candidate.get(id);
          if (stored) {
            // A previously-deleted id that reappears continues its chain with a
            // create; a changed live document gets a replace.
            const action = current.get(id) ? 'replace' : 'create';
            nextLedger.record(id, action, stored);
          } else {
            nextLedger.record(id, 'delete', null);
          }
        }
      }
      return true;
    }, { dryRun });
    return { snapshot, changedIds: result.changedIds };
  }

  async function reconcile(req, res) {
    const bytes = await readBody(req);
    requireIfMatch(req);
    const { base, incoming, dryRun } = validateReconcileRequest(parseJson(decodeJsonBody(bytes)));
    try {
      const snapshot = commitReconcile(base, incoming, dryRun).snapshot;
      sendJson(res, 200, snapshot, `"${snapshot.checksum}"`);
    } catch (error) {
      // Both snapshots must pass the existing validation; surface those
      // failures as INVALID_SNAPSHOT rather than an internal error. Save
      // failures keep their 500/IO_ERROR semantics.
      if (error instanceof SnapshotError && error.code === 'INVALID_SNAPSHOT') {
        throw new HttpError(400, 'INVALID_SNAPSHOT', error.message);
      }
      throw error;
    }
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
      await batch(req, res);
      return;
    } else if (resource === 'tags' && segments.length === 1 && req.method === 'GET') {
      listTags(req, res);
      return;
    } else if (resource === 'tags' && segments.length === 2 && id === 'rewrite' && req.method === 'POST') {
      await rewriteTags(req, res);
      return;
    } else if (resource === 'snapshots' && segments.length === 2 && id === 'reconcile' && req.method === 'POST') {
      await reconcile(req, res);
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
      const payload = { code, message: error.message };
      if (Array.isArray(error.conflicts)) payload.conflicts = error.conflicts;
      sendJson(res, status, payload);
    });
  });
  return server;
}
