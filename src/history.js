import crypto from 'node:crypto';
import { SnapshotError } from './workspace.js';

const HISTORY_VERSION = 1;
const HISTORY_KEYS = ['version', 'documents', 'checksum'];
const RECORD_KEYS = ['revision', 'action', 'document'];
const ACTIONS = new Set(['baseline', 'create', 'replace', 'delete', 'restore']);
const ID_PATTERN = /^[a-z0-9][a-z0-9._-]*$/u;

function compareCodePoints(a, b) {
  const left = Array.from(a, (char) => char.codePointAt(0));
  const right = Array.from(b, (char) => char.codePointAt(0));
  for (let i = 0; i < Math.min(left.length, right.length); i += 1) {
    if (left[i] !== right[i]) return left[i] - right[i];
  }
  return left.length - right.length;
}

function normalizeTags(tags) {
  return [...new Set(tags.map((tag) => String(tag).trim().toLowerCase()).filter(Boolean))].sort();
}

function normalizeDocument(input) {
  return {
    id: input.id,
    title: input.title.trim(),
    body: input.body,
    tags: normalizeTags(input.tags ?? []),
  };
}

function historyChecksum(documents) {
  const payload = JSON.stringify({ version: HISTORY_VERSION, documents });
  return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
}

// A history file maps each document id to a contiguous, per-document sequence
// of records starting at revision 1. It is versioned and checksummed like the
// snapshot, but its checksum never mixes with the snapshot's.
export function newHistory() {
  const documents = {};
  return { version: HISTORY_VERSION, documents, checksum: historyChecksum(documents) };
}

export function appendRecord(history, id, action, document) {
  const previous = history.documents[id] ?? [];
  const records = [...previous, { revision: previous.length + 1, action, document }];
  const documents = Object.fromEntries(
    [...Object.entries(history.documents), [id, records]]
      .sort(([a], [b]) => compareCodePoints(a, b)),
  );
  return { version: HISTORY_VERSION, documents, checksum: historyChecksum(documents) };
}

export function recordsFor(history, id) {
  const records = history.documents[id];
  if (!records) return null;
  return records.map((record) => ({
    revision: record.revision,
    action: record.action,
    document: record.document
      ? { id: record.document.id, title: record.document.title, body: record.document.body, tags: [...record.document.tags] }
      : null,
  }));
}

function validateHistoryDocument(input, id) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new SnapshotError('INVALID_HISTORY', `history record for ${id} must carry a document`);
  }
  const keys = Object.keys(input);
  if (keys.length !== 4 || !['id', 'title', 'body', 'tags'].every((key) => keys.includes(key))) {
    throw new SnapshotError('INVALID_HISTORY', `history record for ${id} has an invalid document`);
  }
  for (const key of ['id', 'title', 'body']) {
    if (typeof input[key] !== 'string' || !input[key].trim()) {
      throw new SnapshotError('INVALID_HISTORY', `history record for ${id} has an invalid document`);
    }
  }
  if (!ID_PATTERN.test(input.id) || input.id !== id) {
    throw new SnapshotError('INVALID_HISTORY', `history record for ${id} has a mismatched document id`);
  }
  if (!Array.isArray(input.tags) || input.tags.some((tag) => typeof tag !== 'string')) {
    throw new SnapshotError('INVALID_HISTORY', `history record for ${id} has invalid tags`);
  }
  return normalizeDocument(input);
}

// Parses and validates a history file's text. Throws INVALID_HISTORY on any
// structural or checksum problem.
export function loadHistory(text) {
  let raw;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new SnapshotError('INVALID_HISTORY', 'history is not valid JSON');
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new SnapshotError('INVALID_HISTORY', 'history must be an object');
  }
  const rawKeys = Object.keys(raw);
  if (rawKeys.length !== HISTORY_KEYS.length || !HISTORY_KEYS.every((key) => rawKeys.includes(key))) {
    throw new SnapshotError('INVALID_HISTORY', 'history must contain exactly version, documents, and checksum');
  }
  if (raw.version !== HISTORY_VERSION) {
    throw new SnapshotError('INVALID_HISTORY', `unsupported history version: ${String(raw.version)}`);
  }
  if (typeof raw.checksum !== 'string') {
    throw new SnapshotError('INVALID_HISTORY', 'history checksum must be a string');
  }
  if (!raw.documents || typeof raw.documents !== 'object' || Array.isArray(raw.documents)) {
    throw new SnapshotError('INVALID_HISTORY', 'history documents must be an object');
  }

  const documents = {};
  for (const [id, rawRecords] of Object.entries(raw.documents)) {
    if (!ID_PATTERN.test(id)) {
      throw new SnapshotError('INVALID_HISTORY', `invalid document id in history: ${id}`);
    }
    if (!Array.isArray(rawRecords) || rawRecords.length === 0) {
      throw new SnapshotError('INVALID_HISTORY', `history for ${id} must be a non-empty array`);
    }
    const records = [];
    rawRecords.forEach((rawRecord, index) => {
      if (!rawRecord || typeof rawRecord !== 'object' || Array.isArray(rawRecord)) {
        throw new SnapshotError('INVALID_HISTORY', `history record ${id}[${index}] must be an object`);
      }
      const keys = Object.keys(rawRecord);
      if (keys.length !== RECORD_KEYS.length || !RECORD_KEYS.every((key) => keys.includes(key))) {
        throw new SnapshotError('INVALID_HISTORY', `history record ${id}[${index}] has invalid fields`);
      }
      if (!Number.isInteger(rawRecord.revision) || rawRecord.revision !== index + 1) {
        throw new SnapshotError('INVALID_HISTORY', `history for ${id} has a non-contiguous revision sequence`);
      }
      if (!ACTIONS.has(rawRecord.action)) {
        throw new SnapshotError('INVALID_HISTORY', `history record ${id}[${index}] has an unknown action`);
      }
      if (index === 0 && rawRecord.action !== 'baseline' && rawRecord.action !== 'create') {
        throw new SnapshotError('INVALID_HISTORY', `history for ${id} must start with a baseline or create`);
      }
      let document = null;
      if (rawRecord.action === 'delete') {
        if (rawRecord.document !== null) {
          throw new SnapshotError('INVALID_HISTORY', `delete record ${id}[${index}] must carry a null document`);
        }
      } else {
        document = validateHistoryDocument(rawRecord.document, id);
      }
      records.push({ revision: index + 1, action: rawRecord.action, document });
    });
    documents[id] = records;
  }

  const sorted = Object.fromEntries(
    Object.entries(documents).sort(([a], [b]) => compareCodePoints(a, b)),
  );
  if (historyChecksum(sorted) !== raw.checksum) {
    throw new SnapshotError('INVALID_HISTORY', 'history checksum does not match its contents');
  }
  return { version: HISTORY_VERSION, documents: sorted, checksum: historyChecksum(sorted) };
}

function sameDocument(a, b) {
  return a.id === b.id && a.title === b.title && a.body === b.body
    && a.tags.length === b.tags.length && a.tags.every((tag, i) => tag === b.tags[i]);
}

// Cross-checks a loaded history against the current snapshot: every live
// document must end with a non-delete record matching its current content,
// and every id absent from the snapshot must end with a delete record.
export function assertHistoryConsistent(workspace, history) {
  for (const document of workspace.list()) {
    const records = history.documents[document.id];
    if (!records || records.length === 0) {
      throw new SnapshotError('INVALID_HISTORY', `history is missing document: ${document.id}`);
    }
    const last = records[records.length - 1];
    if (last.action === 'delete' || last.document === null) {
      throw new SnapshotError('INVALID_HISTORY', `history for ${document.id} ends with a delete while the document exists`);
    }
    if (!sameDocument(last.document, document)) {
      throw new SnapshotError('INVALID_HISTORY', `history for ${document.id} does not match the current snapshot`);
    }
  }
  for (const [id, records] of Object.entries(history.documents)) {
    if (!workspace.get(id)) {
      const last = records[records.length - 1];
      if (last.action !== 'delete' || last.document !== null) {
        throw new SnapshotError('INVALID_HISTORY', `history for ${id} ends with a non-delete while the document is absent`);
      }
    }
  }
}
