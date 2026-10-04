import crypto from 'node:crypto';

const SNAPSHOT_VERSION = 1;
const SNAPSHOT_KEYS = ['version', 'documents', 'checksum'];
const DOCUMENT_KEYS = ['id', 'title', 'body', 'tags'];
const ID_NAME_PATTERN = /^[a-z0-9][a-z0-9._-]*$/iu;

// A fenced code block opens on a line starting with 0-3 spaces and at least
// three consecutive backticks or tildes (any trailing text is the info
// string); the opener captures which marker and how wide it is.
const FENCE_OPEN_PATTERN = /^ {0,3}(`{3,}|~{3,})/u;

function fenceClosePattern(marker, length) {
  // A closing fence must use the same marker, run at least as long as the
  // opener, allow 0-3 leading spaces, and carry only spaces/tabs afterwards.
  const escaped = marker === '`' ? '`' : '~';
  return new RegExp(`^ {0,3}(${escaped})\\1{${length - 1},}[ \\t]*$`, 'u');
}

// Extracts the valid [[id]] references a document body makes from ordinary
// prose. References inside fenced code blocks or inline code spans are kept
// verbatim in the body but produce no relationship, as does a reference whose
// first bracket is immediately preceded by an odd run of backslashes. LF and
// CRLF endings parse identically. Shared by workspace.links() and the links
// HTTP route, so both always follow the same rules.
export function linksFrom(body) {
  const targets = [];
  const lines = String(body).split('\n');

  // Prose lines accumulated between fenced blocks; inline code spans may
  // cross physical lines, so each region is scanned as one joined segment.
  let prose = [];
  let fence = null; // non-null (with its closing pattern) inside a fence

  const flush = () => {
    if (prose.length > 0) {
      scanProse(prose.join('\n'), targets);
      prose = [];
    }
  };

  for (const rawLine of lines) {
    // The trailing CR of a CRLF ending is never part of fence syntax.
    const line = rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine;
    if (fence) {
      if (fence.test(line)) fence = null;
      // The other marker, a shorter run, or trailing text cannot close it,
      // and an unclosed fence ignores everything through the body end.
      continue;
    }
    const open = FENCE_OPEN_PATTERN.exec(line);
    if (open) {
      flush();
      fence = fenceClosePattern(open[1][0], open[1].length);
    } else {
      prose.push(line);
    }
  }
  // Prose after an unclosed fence is discarded along with the fence body.
  if (!fence) flush();
  return targets;
}

// Scans one fence-free segment for references, skipping inline code spans.
// A span opens on a backtick run and closes on the first later run of exactly
// the same length (shorter or longer runs stay inside it and never act as
// openers themselves); spans may cross newlines but never reach across the
// fence boundaries that delimit segments.
function scanProse(segment, targets) {
  const chars = Array.from(segment);
  const spans = codeSpanIntervals(chars); // sorted, non-overlapping [start, end)
  let i = 0;
  let spanIndex = 0;
  while (i < chars.length) {
    if (spanIndex < spans.length && i === spans[spanIndex][0]) {
      i = spans[spanIndex][1];
      spanIndex += 1;
      continue;
    }
    if (chars[i] === '[') {
      const reference = readReference(chars, i);
      if (reference) {
        if (countBackslashesBefore(chars, i) % 2 === 0) {
          targets.push(reference.name.toLowerCase());
        }
        i = reference.end;
        continue;
      }
    }
    i += 1;
  }
}

function runLength(chars, start, marker) {
  let n = 0;
  while (start + n < chars.length && chars[start + n] === marker) n += 1;
  return n;
}

// Builds inline-code intervals in one linear pass. Backtick runs are listed
// left to right; `nearestSame[k]` indexes the next run of the same width
// (precomputed right to left). A run with a match spans to that match and
// consumes every run in between as code content; an unmatched run is literal
// and scanning continues right after it.
function codeSpanIntervals(chars) {
  const runs = [];
  for (let i = 0; i < chars.length;) {
    if (chars[i] === '`') {
      const length = runLength(chars, i, '`');
      runs.push([i, i + length, length]);
      i += length;
    } else {
      i += 1;
    }
  }
  const nearestSame = new Array(runs.length).fill(-1);
  const lastSeen = new Map();
  for (let k = runs.length - 1; k >= 0; k -= 1) {
    const length = runs[k][2];
    if (lastSeen.has(length)) nearestSame[k] = lastSeen.get(length);
    lastSeen.set(length, k);
  }
  const intervals = [];
  for (let k = 0; k < runs.length;) {
    const close = nearestSame[k];
    if (close === -1) {
      k += 1; // unmatched opening run: ordinary text
    } else {
      intervals.push([runs[k][0], runs[close][1]]);
      k = close + 1;
    }
  }
  return intervals;
}

function countBackslashesBefore(chars, index) {
  let n = 0;
  for (let i = index - 1; i >= 0 && chars[i] === '\\'; i -= 1) n += 1;
  return n;
}

// Returns { name, end } for a syntactically complete, id-shaped [[reference]]
// beginning at `index`, or null when the brackets do not close or the target
// does not satisfy the existing identifier rules.
function readReference(chars, index) {
  if (chars[index + 1] !== '[') return null;
  let j = index + 2;
  while (j < chars.length && chars[j] !== ']') j += 1;
  if (j >= chars.length || chars[j + 1] !== ']') return null;
  const name = chars.slice(index + 2, j).join('');
  if (!ID_NAME_PATTERN.test(name)) return null;
  return { name, end: j + 2 };
}

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
    // Titles are unique across the workspace, compared case-sensitively after
    // trimming surrounding whitespace — the same rule snapshot import
    // enforces, so anything added here can always be exported and re-imported.
    const title = input.title.trim();
    for (const existing of this.#documents.values()) {
      if (existing.title === title) throw new Error(`title already in use: ${title}`);
    }
    const document = Object.freeze({ id: input.id, title, body: input.body, tags: normalizeTags(input.tags ?? []) });
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
