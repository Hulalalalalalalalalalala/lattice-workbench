import { createHash } from 'node:crypto';

const LINK_PATTERN = /\[\[([a-z0-9][a-z0-9._-]*)\]\]/giu;
const SNAPSHOT_VERSION = 1;

function fail(code, message, extra) {
  const error = new Error(message);
  error.code = code;
  if (extra) Object.assign(error, extra);
  throw error;
}

function normalizeTags(tags) {
  if (!Array.isArray(tags)) throw new TypeError('tags must be an array');
  return [...new Set(tags.map((tag) => String(tag).trim().toLowerCase()).filter(Boolean))].sort();
}

function assertDocument(input) {
  if (!input || typeof input !== 'object') throw new TypeError('document must be an object');
  for (const key of ['id', 'title', 'body']) {
    if (typeof input[key] !== 'string' || !input[key].trim()) throw new TypeError(`${key} must be a non-empty string`);
  }
  if (!/^[a-z0-9][a-z0-9._-]*$/u.test(input.id)) throw new TypeError('id must be URL-safe lowercase text');
}

function linksFrom(body) {
  return [...body.matchAll(LINK_PATTERN)].map((match) => match[1].toLowerCase());
}

function codePointCompare(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

function snapshotDocuments(documents) {
  return documents
    .slice()
    .sort((a, b) => codePointCompare(a.id, b.id))
    .map((document) => ({
      id: document.id,
      title: document.title,
      body: document.body,
      tags: [...document.tags],
    }));
}

function checksumFor(documents) {
  const payload = JSON.stringify({ version: SNAPSHOT_VERSION, documents });
  return createHash('sha256').update(payload, 'utf8').digest('hex');
}

function sameTags(a, b) {
  return a.length === b.length && a.every((tag, index) => tag === b[index]);
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
    const documents = snapshotDocuments([...this.#documents.values()]);
    return { version: SNAPSHOT_VERSION, documents, checksum: checksumFor(documents) };
  }

  importJSON(data, options) {
    if (!options || typeof options !== 'object' || Array.isArray(options)) {
      fail('INVALID_OPTIONS', 'options must be an object');
    }
    const { mode, dryRun = false } = options;
    for (const key of Object.keys(options)) {
      if (key !== 'mode' && key !== 'dryRun') fail('INVALID_OPTIONS', `unsupported option: ${key}`);
    }
    if (mode !== 'merge' && mode !== 'replace') {
      fail('INVALID_OPTIONS', 'mode must be merge or replace');
    }
    if (typeof dryRun !== 'boolean') {
      fail('INVALID_OPTIONS', 'dryRun must be a boolean');
    }

    const incoming = this.#parseSnapshot(data);

    if (mode === 'replace') {
      if (!dryRun) this.#documents = new Map(incoming.map((document) => [document.id, document]));
      return this.#snapshotFrom(incoming);
    }

    const titleOwners = new Map();
    for (const document of this.#documents.values()) {
      titleOwners.set(document.title, document.id);
    }

    const conflicts = new Set();
    const additions = [];
    for (const document of incoming) {
      const existing = this.#documents.get(document.id);
      if (existing) {
        const identical = existing.title === document.title
          && existing.body === document.body
          && sameTags(existing.tags, document.tags);
        if (!identical) conflicts.add(document.id);
      } else if (titleOwners.has(document.title)) {
        conflicts.add(document.id);
        conflicts.add(titleOwners.get(document.title));
      } else {
        additions.push(document);
        titleOwners.set(document.title, document.id);
      }
    }

    if (conflicts.size > 0) {
      fail('IMPORT_CONFLICT', 'merge conflict: conflicting documents', { ids: [...conflicts].sort(codePointCompare) });
    }

    const merged = new Map(this.#documents);
    for (const document of additions) merged.set(document.id, document);

    if (!dryRun) this.#documents = merged;
    return this.#snapshotFrom([...merged.values()]);
  }

  #parseSnapshot(data) {
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      fail('INVALID_SNAPSHOT', 'snapshot must be an object');
    }
    const keys = Object.keys(data).sort();
    if (keys.length !== 3 || keys[0] !== 'checksum' || keys[1] !== 'documents' || keys[2] !== 'version') {
      fail('INVALID_SNAPSHOT', 'snapshot must have exactly version, documents, checksum');
    }
    if (data.version !== SNAPSHOT_VERSION) {
      fail('INVALID_SNAPSHOT', `unsupported snapshot version: ${data.version}`);
    }
    if (!Array.isArray(data.documents)) {
      fail('INVALID_SNAPSHOT', 'documents must be an array');
    }
    if (typeof data.checksum !== 'string' || !/^[0-9a-f]{64}$/u.test(data.checksum)) {
      fail('INVALID_SNAPSHOT', 'checksum must be a lowercase hex SHA-256 string');
    }

    const seenIds = new Set();
    const normalized = data.documents.map((document) => {
      if (!document || typeof document !== 'object' || Array.isArray(document)) {
        fail('INVALID_SNAPSHOT', 'document must be an object');
      }
      const documentKeys = Object.keys(document).sort();
      if (documentKeys.length !== 4
        || documentKeys[0] !== 'body'
        || documentKeys[1] !== 'id'
        || documentKeys[2] !== 'tags'
        || documentKeys[3] !== 'title') {
        fail('INVALID_SNAPSHOT', 'document must have exactly id, title, body, tags');
      }
      try {
        assertDocument(document);
      } catch {
        fail('INVALID_SNAPSHOT', 'invalid document');
      }
      if (!Array.isArray(document.tags) || !document.tags.every((tag) => typeof tag === 'string')) {
        fail('INVALID_SNAPSHOT', 'tags must be an array of strings');
      }
      if (seenIds.has(document.id)) {
        fail('INVALID_SNAPSHOT', `duplicate document id: ${document.id}`);
      }
      seenIds.add(document.id);
      return { id: document.id, title: document.title.trim(), body: document.body, tags: normalizeTags(document.tags) };
    });

    const seenTitles = new Set();
    for (const document of normalized) {
      if (seenTitles.has(document.title)) {
        fail('INVALID_SNAPSHOT', `duplicate document title: ${document.title}`);
      }
      seenTitles.add(document.title);
    }

    normalized.sort((a, b) => codePointCompare(a.id, b.id));
    if (checksumFor(normalized) !== data.checksum) {
      fail('INVALID_SNAPSHOT', 'checksum mismatch');
    }
    return normalized;
  }

  #snapshotFrom(documents) {
    const documentsView = snapshotDocuments(documents);
    return { version: SNAPSHOT_VERSION, documents: documentsView, checksum: checksumFor(documentsView) };
  }
}
