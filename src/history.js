import crypto from 'node:crypto';
import { SnapshotError, snapshotFromDocuments } from './workspace.js';

const HISTORY_VERSION = 1;
const HISTORY_KEYS = ['version', 'history', 'snapshot', 'checksum'];
const ENTRY_KEYS = ['revision', 'action', 'document'];
const DOCUMENT_KEYS = ['id', 'title', 'body', 'tags'];
const ACTIONS = new Set(['baseline', 'create', 'replace', 'delete', 'restore']);
const CHECKSUM_PATTERN = /^[0-9a-f]{64}$/u;
const ID_PATTERN = /^[a-z0-9][a-z0-9._-]*$/u;

export class HistoryError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'HistoryError';
    this.code = code;
  }
}

function compareCodePoints(a, b) {
  const left = Array.from(a, (char) => char.codePointAt(0));
  const right = Array.from(b, (char) => char.codePointAt(0));
  for (let i = 0; i < Math.min(left.length, right.length); i += 1) {
    if (left[i] !== right[i]) return left[i] - right[i];
  }
  return left.length - right.length;
}

// A stored document uses the normalized snapshot shape: trimmed title, body
// verbatim, tags lowercased, deduplicated, and sorted.
function canonicalDocument(document) {
  const tags = [...new Set(
    document.tags.map((tag) => String(tag).trim().toLowerCase()).filter(Boolean),
  )].sort();
  return {
    id: document.id,
    title: document.title.trim(),
    body: document.body,
    tags,
  };
}

function hashHistory(history, snapshotChecksum) {
  return crypto
    .createHash('sha256')
    .update(JSON.stringify({ version: HISTORY_VERSION, history, snapshot: snapshotChecksum }), 'utf8')
    .digest('hex');
}

export function sameDocument(a, b) {
  return a.id === b.id && a.title === b.title && a.body === b.body
    && a.tags.length === b.tags.length && a.tags.every((tag, i) => tag === b.tags[i]);
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function sameKeys(object, expected) {
  const keys = Object.keys(object);
  return keys.length === expected.length && expected.every((key) => keys.includes(key));
}

function canonicalRecords(records) {
  const history = {};
  for (const id of [...records.keys()].sort(compareCodePoints)) {
    history[id] = records.get(id).map((entry) => ({
      revision: entry.revision,
      action: entry.action,
      document: entry.document === null ? null : canonicalDocument(entry.document),
    }));
  }
  return history;
}

// Replays the final state of every document chain. Documents whose final entry
// is a delete are absent; their ids are returned in `deleted`.
function replay(records) {
  const documents = new Map();
  const deleted = new Set();
  for (const [id, entries] of records) {
    const last = entries[entries.length - 1];
    if (last.document === null) {
      deleted.add(id);
    } else {
      documents.set(id, canonicalDocument(last.document));
      deleted.delete(id);
    }
  }
  return { documents, deleted };
}

// Validates the checksummed history payload, replays every per-document chain,
// and verifies the embedded snapshot checksum matches the replayed content.
// Returns { records, snapshotChecksum }.
export function parseHistory(data) {
  let raw = data;
  if (typeof raw === 'string') {
    try {
      raw = JSON.parse(raw);
    } catch {
      throw new HistoryError('INVALID_HISTORY', 'history is not valid JSON');
    }
  }
  if (!isPlainObject(raw)) throw new HistoryError('INVALID_HISTORY', 'history must be an object');
  if (!sameKeys(raw, HISTORY_KEYS)) {
    throw new HistoryError('INVALID_HISTORY', 'history must contain exactly version, history, snapshot, and checksum');
  }
  if (raw.version !== HISTORY_VERSION) {
    throw new HistoryError('INVALID_HISTORY', `unsupported history version: ${String(raw.version)}`);
  }
  if (typeof raw.snapshot !== 'string' || !CHECKSUM_PATTERN.test(raw.snapshot)) {
    throw new HistoryError('INVALID_HISTORY', 'snapshot must be a lowercase SHA-256 checksum');
  }
  if (typeof raw.checksum !== 'string' || !CHECKSUM_PATTERN.test(raw.checksum)) {
    throw new HistoryError('INVALID_HISTORY', 'checksum must be a lowercase SHA-256 checksum');
  }
  if (!isPlainObject(raw.history)) {
    throw new HistoryError('INVALID_HISTORY', 'history records must be an object');
  }

  const records = new Map();
  for (const id of Object.keys(raw.history)) {
    if (!ID_PATTERN.test(id)) {
      throw new HistoryError('INVALID_HISTORY', `invalid document id in history: ${id}`);
    }
    const entries = raw.history[id];
    if (!Array.isArray(entries) || entries.length === 0) {
      throw new HistoryError('INVALID_HISTORY', `history for ${id} must be a non-empty array`);
    }
    let alive = false;
    const replayed = [];
    entries.forEach((entry, index) => {
      const revision = index + 1;
      if (!isPlainObject(entry) || !sameKeys(entry, ENTRY_KEYS)) {
        throw new HistoryError('INVALID_HISTORY', `${id}@${revision} must contain exactly revision, action, and document`);
      }
      if (entry.revision !== revision) {
        throw new HistoryError('INVALID_HISTORY', `${id}@${revision} revisions must be consecutive starting at 1`);
      }
      if (typeof entry.action !== 'string' || !ACTIONS.has(entry.action)) {
        throw new HistoryError('INVALID_HISTORY', `${id}@${revision} has an unknown action`);
      }
      if (index === 0) {
        // A chain is born either as an import baseline or as the first create.
        if (entry.action !== 'baseline' && entry.action !== 'create') {
          throw new HistoryError('INVALID_HISTORY', `${id} history must start with a baseline or create entry`);
        }
      } else if (entry.action === 'baseline') {
        throw new HistoryError('INVALID_HISTORY', `${id} has more than one baseline entry`);
      } else if (alive && entry.action === 'create') {
        throw new HistoryError('INVALID_HISTORY', `${id}@${revision} recreates a living document`);
      } else if (!alive && entry.action !== 'create' && entry.action !== 'restore') {
        throw new HistoryError('INVALID_HISTORY', `${id}@${revision} follows a delete without a recreate or restore`);
      }

      const document = entry.document;
      if (entry.action === 'delete') {
        if (document !== null) {
          throw new HistoryError('INVALID_HISTORY', `${id}@${revision} delete entry must carry a null document`);
        }
        alive = false;
      } else {
        if (!isPlainObject(document) || !sameKeys(document, DOCUMENT_KEYS)) {
          throw new HistoryError('INVALID_HISTORY', `${id}@${revision} must carry a full document`);
        }
        if (document.id !== id || !ID_PATTERN.test(document.id)) {
          throw new HistoryError('INVALID_HISTORY', `${id}@${revision} document id does not match its history chain`);
        }
        if (typeof document.body !== 'string' || !document.body.trim()) {
          throw new HistoryError('INVALID_HISTORY', `${id}@${revision} body must be a non-empty string`);
        }
        if (typeof document.title !== 'string' || document.title.trim() !== document.title || !document.title.trim()) {
          throw new HistoryError('INVALID_HISTORY', `${id}@${revision} title must be a normalized non-empty string`);
        }
        if (!Array.isArray(document.tags) || document.tags.some((tag) => typeof tag !== 'string')) {
          throw new HistoryError('INVALID_HISTORY', `${id}@${revision} tags must be an array of strings`);
        }
        const normalized = [...new Set(document.tags.map((tag) => tag.trim().toLowerCase()).filter(Boolean))].sort();
        if (normalized.length !== document.tags.length || normalized.some((tag, i) => tag !== document.tags[i])) {
          throw new HistoryError('INVALID_HISTORY', `${id}@${revision} tags must be normalized`);
        }
        alive = true;
      }
      replayed.push({
        revision,
        action: entry.action,
        document: document === null ? null : canonicalDocument(document),
      });
    });
    records.set(id, replayed);
  }

  const canonical = canonicalRecords(records);
  if (hashHistory(canonical, raw.snapshot) !== raw.checksum) {
    throw new HistoryError('INVALID_HISTORY', 'checksum does not match history contents');
  }
  // The embedded snapshot checksum must be exactly what replaying the chains
  // produces; a history that fails this cannot be brought to a consistent
  // state.
  const { documents } = replay(records);
  if (snapshotFromDocuments(documents.values()).checksum !== raw.snapshot) {
    throw new HistoryError('INVALID_HISTORY', 'history replay does not match its embedded snapshot');
  }
  return { records, snapshotChecksum: raw.snapshot };
}

export class HistoryStore {
  #records;
  #snapshotChecksum;

  constructor(records = new Map(), snapshotChecksum = null) {
    this.#records = records;
    this.#snapshotChecksum = snapshotChecksum;
  }

  // Revision 1 baselines for every document currently in the snapshot.
  static baseline(documents) {
    const records = new Map();
    for (const document of documents) {
      records.set(document.id, [{ revision: 1, action: 'baseline', document: canonicalDocument(document) }]);
    }
    const snapshot = snapshotFromDocuments([...records.values()].map((entries) => entries[0].document));
    return new HistoryStore(records, snapshot.checksum);
  }

  static fromParsed({ records, snapshotChecksum }) {
    return new HistoryStore(records, snapshotChecksum);
  }

  clone() {
    const copy = new Map();
    for (const [id, entries] of this.#records) {
      copy.set(id, entries.map((entry) => ({
        revision: entry.revision,
        action: entry.action,
        document: entry.document === null ? null : canonicalDocument(entry.document),
      })));
    }
    return new HistoryStore(copy, this.#snapshotChecksum);
  }

  get snapshotChecksum() {
    return this.#snapshotChecksum;
  }

  has(id) {
    return this.#records.has(id);
  }

  entries(id) {
    const entries = this.#records.get(id);
    if (!entries) return null;
    return entries.map((entry) => ({
      revision: entry.revision,
      action: entry.action,
      document: entry.document === null ? null : canonicalDocument(entry.document),
    }));
  }

  entry(id, revision) {
    const entries = this.#records.get(id);
    if (!entries) return null;
    const found = entries.find((entry) => entry.revision === revision);
    if (!found) return null;
    return {
      revision: found.revision,
      action: found.action,
      document: found.document === null ? null : canonicalDocument(found.document),
    };
  }

  // Appends the next consecutive revision for a document. Callers prepare the
  // append on a clone and swap stores in only after the commit is persisted, so
  // a failed save never consumes a revision.
  record(id, action, document) {
    const entries = this.#records.get(id) ?? [];
    const entry = {
      revision: entries.length + 1,
      action,
      document: document === null ? null : canonicalDocument(document),
    };
    entries.push(entry);
    this.#records.set(id, entries);
    return {
      revision: entry.revision,
      action: entry.action,
      document: entry.document === null ? null : canonicalDocument(entry.document),
    };
  }

  // Renders the history file bound to a freshly exported content snapshot.
  exportJSON(snapshotChecksum) {
    const checksum = snapshotChecksum ?? this.#snapshotChecksum;
    const history = canonicalRecords(this.#records);
    return { version: HISTORY_VERSION, history, snapshot: checksum, checksum: hashHistory(history, checksum) };
  }

  // The current documents implied by replaying every chain.
  replayedDocuments() {
    return replay(this.#records).documents;
  }
}

// Loads and validates a history file. Read failures report IO_ERROR (the file
// existed but could not be opened); malformed contents report INVALID_HISTORY.
export function loadHistoryFile(file, readFile) {
  let text;
  try {
    text = readFile(file);
  } catch (error) {
    throw new SnapshotError('IO_ERROR', `cannot read history file ${file}: ${error.message}`);
  }
  try {
    return HistoryStore.fromParsed(parseHistory(text));
  } catch (error) {
    if (error instanceof HistoryError) {
      throw new SnapshotError('INVALID_HISTORY', error.message);
    }
    throw error;
  }
}
