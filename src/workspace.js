const LINK_PATTERN = /\[\[([a-z0-9][a-z0-9._-]*)\]\]/giu;

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
}
