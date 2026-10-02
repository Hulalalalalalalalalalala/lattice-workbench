import crypto from 'node:crypto';

const LINK_TARGET = /[a-z0-9][a-z0-9._-]*/giu;
const FENCE_LINE = /^ {0,3}(`{3,}|~{3,})(.*)$/u;
const SNAPSHOT_VERSION = 1;
const SNAPSHOT_KEYS = ['version', 'documents', 'checksum'];
const DOCUMENT_KEYS = ['id', 'title', 'body', 'tags'];

export function normalizeTags(tags) {
  if (!Array.isArray(tags)) throw new TypeError('tags must be an array');
  return [...new Set(tags.map((tag) => String(tag).trim().toLowerCase()).filter(Boolean))].sort();
}

export function assertDocument(input) {
  if (!input || typeof input !== 'object') throw new TypeError('document must be an object');
  for (const key of ['id', 'title', 'body']) {
    if (typeof input[key] !== 'string' || !input[key].trim()) throw new TypeError(`${key} must be a non-empty string`);
  }
  if (!/^[a-z0-9][a-z0-9._-]*$/u.test(input.id)) throw new TypeError('id must be URL-safe lowercase text');
}

// Matches a fenced-code-block line: 0-3 leading spaces, a run of at least
// three identical backticks or tildes, then an optional info string. Returns
// null for any other line.
function fenceOf(line) {
  const match = FENCE_LINE.exec(line);
  if (!match) return null;
  return { char: match[1][0], length: match[1].length, info: match[2] };
}

// Scans a stretch of ordinary prose (never inside a fence) for wiki links.
// Inline code spans of equal-length backtick runs are skipped; a run with no
// matching closer is literal text and later links still count. A [[ whose first
// bracket is immediately preceded by an odd run of backslashes is escaped.
function scanProse(region) {
  const found = [];
  const length = region.length;
  let index = 0;
  while (index < length) {
    const char = region[index];
    if (char === '`') {
      let runEnd = index;
      while (runEnd < length && region[runEnd] === '`') runEnd += 1;
      const runLength = runEnd - index;
      let search = runEnd;
      let close = -1;
      while (search < length) {
        if (region[search] === '`') {
          let spanEnd = search;
          while (spanEnd < length && region[spanEnd] === '`') spanEnd += 1;
          if (spanEnd - search === runLength) {
            close = search;
            break;
          }
          search = spanEnd;
        } else {
          search += 1;
        }
      }
      if (close === -1) {
        index = runEnd;
      } else {
        index = close + runLength;
      }
    } else if (char === '[' && region[index + 1] === '[') {
      let backslashes = 0;
      let cursor = index - 1;
      while (cursor >= 0 && region[cursor] === '\\') {
        backslashes += 1;
        cursor -= 1;
      }
      if (backslashes % 2 === 1) {
        index += 2;
        continue;
      }
      const targetStart = index + 2;
      LINK_TARGET.lastIndex = targetStart;
      const match = LINK_TARGET.exec(region);
      if (
        match
        && match.index === targetStart
        && region[targetStart + match[0].length] === ']'
        && region[targetStart + match[0].length + 1] === ']'
      ) {
        found.push(match[0].toLowerCase());
        index = targetStart + match[0].length + 2;
      } else {
        index += 1;
      }
    } else {
      index += 1;
    }
  }
  return found;
}

// Extracts the wiki-link targets that count as relationships from a body:
// links in ordinary prose only. Fenced code blocks and inline code spans are
// ignored, escaped brackets are literal, and malformed or dangling references
// are skipped without affecting anything else.
function linksFrom(body) {
  const text = body.replace(/\r\n?/gu, '\n');
  const lines = text.split('\n');
  const found = [];
  let inFence = false;
  let fenceChar = '';
  let fenceLength = 0;
  let regionStart = 0;
  let lineStart = 0;
  for (const line of lines) {
    const nextStart = lineStart + line.length + 1;
    if (inFence) {
      const closing = fenceOf(line);
      if (closing && closing.char === fenceChar && closing.length >= fenceLength && /^[ \t]*$/u.test(closing.info)) {
        inFence = false;
        regionStart = nextStart;
      }
    } else {
      const opening = fenceOf(line);
      if (opening) {
        found.push(...scanProse(text.slice(regionStart, lineStart)));
        inFence = true;
        fenceChar = opening.char;
        fenceLength = opening.length;
      }
    }
    lineStart = nextStart;
  }
  if (!inFence) found.push(...scanProse(text.slice(regionStart)));
  return [...new Set(found)];
}

export class SnapshotError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.name = 'SnapshotError';
    this.code = code;
    for (const [key, value] of Object.entries(extra)) this[key] = value;
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

function hashDocuments(documents) {
  const payload = JSON.stringify({ version: SNAPSHOT_VERSION, documents });
  return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
}

function buildSnapshot(documents) {
  const canonical = [...documents]
    .map((document) => ({
      id: document.id,
      title: document.title,
      body: document.body,
      tags: structuredClone(document.tags),
    }))
    .sort((a, b) => compareCodePoints(a.id, b.id));
  return { version: SNAPSHOT_VERSION, documents: canonical, checksum: hashDocuments(canonical) };
}

// Builds a version-1 snapshot from any iterable of normalized documents.
// Exported so the history ledger can derive the same checksum the workspace
// would produce without instantiating one.
export function snapshotFromDocuments(documents) {
  return buildSnapshot(documents);
}

function sameKeys(object, expected) {
  const keys = Object.keys(object);
  return keys.length === expected.length && expected.every((key) => keys.includes(key));
}

function validateOptions(options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new SnapshotError('INVALID_OPTIONS', 'options must be an object');
  }
  for (const key of Object.keys(options)) {
    if (key !== 'mode' && key !== 'dryRun') throw new SnapshotError('INVALID_OPTIONS', `unknown option: ${key}`);
  }
  if (options.mode !== 'merge' && options.mode !== 'replace') {
    throw new SnapshotError('INVALID_OPTIONS', "mode must be 'merge' or 'replace'");
  }
  const dryRun = options.dryRun === undefined ? false : options.dryRun;
  if (typeof dryRun !== 'boolean') throw new SnapshotError('INVALID_OPTIONS', 'dryRun must be a boolean');
  return { mode: options.mode, dryRun };
}

// Validates and normalizes a version-1 snapshot (object or JSON string),
// enforcing the document rules, uniqueness constraints, and bound checksum.
// Exported so other import paths (reconcile) share the exact same checks.
export function normalizeSnapshot(data) {
  let raw = data;
  if (typeof raw === 'string') {
    try {
      raw = JSON.parse(raw);
    } catch {
      throw new SnapshotError('INVALID_SNAPSHOT', 'snapshot is not valid JSON');
    }
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new SnapshotError('INVALID_SNAPSHOT', 'snapshot must be an object');
  }
  if (!sameKeys(raw, SNAPSHOT_KEYS)) {
    throw new SnapshotError('INVALID_SNAPSHOT', 'snapshot must contain exactly version, documents, and checksum');
  }
  if (typeof raw.version !== 'number' || raw.version !== SNAPSHOT_VERSION) {
    throw new SnapshotError('INVALID_SNAPSHOT', `unsupported snapshot version: ${String(raw.version)}`);
  }
  if (typeof raw.checksum !== 'string') {
    throw new SnapshotError('INVALID_SNAPSHOT', 'checksum must be a string');
  }
  if (!Array.isArray(raw.documents)) {
    throw new SnapshotError('INVALID_SNAPSHOT', 'documents must be an array');
  }

  const documents = [];
  const ids = new Set();
  const titles = new Set();
  raw.documents.forEach((input, index) => {
    const location = `documents[${index}]`;
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new SnapshotError('INVALID_SNAPSHOT', `${location} must be an object`);
    }
    if (!sameKeys(input, DOCUMENT_KEYS)) {
      throw new SnapshotError('INVALID_SNAPSHOT', `${location} must contain exactly id, title, body, and tags`);
    }
    if (!Array.isArray(input.tags) || input.tags.some((tag) => typeof tag !== 'string')) {
      throw new SnapshotError('INVALID_SNAPSHOT', `${location}.tags must be an array of strings`);
    }
    try {
      assertDocument(input);
    } catch (error) {
      throw new SnapshotError('INVALID_SNAPSHOT', `${location}: ${error.message}`);
    }
    const document = {
      id: input.id,
      title: input.title.trim(),
      body: input.body,
      tags: normalizeTags(input.tags),
    };
    if (ids.has(document.id)) {
      throw new SnapshotError('INVALID_SNAPSHOT', `duplicate document id: ${document.id}`);
    }
    if (titles.has(document.title)) {
      throw new SnapshotError('INVALID_SNAPSHOT', `duplicate normalized title: ${document.title}`);
    }
    ids.add(document.id);
    titles.add(document.title);
    documents.push(document);
  });

  const canonical = documents.sort((a, b) => compareCodePoints(a.id, b.id));
  if (hashDocuments(canonical) !== raw.checksum) {
    throw new SnapshotError('INVALID_SNAPSHOT', 'checksum does not match snapshot contents');
  }
  return canonical;
}

function sameDocument(a, b) {
  return a.id === b.id && a.title === b.title && a.body === b.body
    && a.tags.length === b.tags.length && a.tags.every((tag, i) => tag === b.tags[i]);
}

export class Workspace {
  #documents = new Map();

  add(input) {
    assertDocument(input);
    if (this.#documents.has(input.id)) throw new Error(`document already exists: ${input.id}`);
    const document = Object.freeze({ id: input.id, title: input.title.trim(), body: input.body, tags: normalizeTags(input.tags ?? []) });
    this.#documents.set(document.id, document);
    return structuredClone(document);
  }

  get(id) {
    const document = this.#documents.get(id);
    return document ? structuredClone(document) : null;
  }

  remove(id) {
    return this.#documents.delete(id);
  }

  list() {
    return [...this.#documents.values()].map((document) => structuredClone(document)).sort((a, b) => a.id.localeCompare(b.id));
  }

  search(query) {
    const needle = String(query).trim().toLowerCase();
    if (!needle) return [];
    return this.list().filter((document) => [document.title, document.body, ...document.tags].some((value) => value.toLowerCase().includes(needle)));
  }

  links(id) {
    const document = this.#documents.get(id);
    if (!document) return null;
    const outgoing = [...new Set(linksFrom(document.body))].sort();
    const incoming = [...this.#documents.values()]
      .filter((candidate) => candidate.id !== id && linksFrom(candidate.body).includes(id))
      .map((candidate) => candidate.id)
      .sort();
    return { outgoing, incoming };
  }

  exportJSON() {
    return buildSnapshot(this.#documents.values());
  }

  importJSON(data, options = {}) {
    const { mode, dryRun } = validateOptions(options);
    const incoming = normalizeSnapshot(data);

    let next;
    if (mode === 'replace') {
      next = new Map(incoming.map((document) => [document.id, Object.freeze(structuredClone(document))]));
    } else {
      // Derive conflicts against the projected state after applying every
      // incoming document: a moved-away title frees up for a newcomer, while
      // a moved-into title can newly collide.
      next = new Map(this.#documents);
      const incomingIds = new Set();
      const effective = new Map(this.#documents);
      const conflicts = new Set();
      for (const document of incoming) {
        incomingIds.add(document.id);
        const current = this.#documents.get(document.id);
        if (current && !sameDocument(current, document)) conflicts.add(document.id);
        effective.set(document.id, Object.freeze(structuredClone(document)));
      }
      const titleOwners = new Map();
      for (const document of effective.values()) {
        const owner = titleOwners.get(document.title);
        if (owner === undefined) {
          titleOwners.set(document.title, document.id);
        } else if (incomingIds.has(document.id) || incomingIds.has(owner)) {
          if (incomingIds.has(document.id)) conflicts.add(document.id);
          if (incomingIds.has(owner)) conflicts.add(owner);
        }
      }
      if (conflicts.size > 0) {
        throw new SnapshotError(
          'IMPORT_CONFLICT',
          'merge conflicts detected for incoming document ids',
          { ids: [...conflicts].sort(compareCodePoints) },
        );
      }
      for (const document of incoming) {
        next.set(document.id, Object.freeze(structuredClone(document)));
      }
    }

    const snapshot = buildSnapshot(next.values());
    if (!dryRun) this.#documents = next;
    return snapshot;
  }
}
