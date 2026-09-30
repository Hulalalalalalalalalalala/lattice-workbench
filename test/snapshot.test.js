import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { SnapshotError, Workspace } from '../src/workspace.js';

function snapshotOf(documents) {
  const workspace = new Workspace();
  for (const document of documents) workspace.add(document);
  return workspace.exportJSON();
}

function canonicalChecksum(snapshot) {
  return crypto
    .createHash('sha256')
    .update(JSON.stringify({ version: 1, documents: snapshot.documents }), 'utf8')
    .digest('hex');
}

test('exportJSON uses the fixed key order and canonical checksum', () => {
  const snapshot = snapshotOf([
    { id: 'welcome', title: '欢迎', body: 'see [[ghost]] for dangling links', tags: ['Intro', 'intro'] },
  ]);
  const raw = JSON.stringify(snapshot);
  assert.match(raw, /^\{"version":1,"documents":\[\{"id"/u);
  assert.match(raw, /\],"checksum":"[0-9a-f]{64}"\}$/u);
  assert.deepEqual(Object.keys(snapshot), ['version', 'documents', 'checksum']);
  assert.deepEqual(Object.keys(snapshot.documents[0]), ['id', 'title', 'body', 'tags']);
  assert.equal(snapshot.version, 1);
  assert.equal(snapshot.checksum, canonicalChecksum(snapshot));
  assert.equal(snapshot.checksum, snapshot.checksum.toLowerCase());
});

test('exportJSON sorts documents by id code point, unlike list() locale order', () => {
  // '.' is U+002E and '_' is U+005F, while localeCompare ranks the underscore first.
  const snapshot = snapshotOf([
    { id: 'a_b', title: 'Underscore', body: 'body text', tags: [] },
    { id: 'a.b', title: 'Dot', body: 'body text', tags: [] },
  ]);
  assert.deepEqual(snapshot.documents.map((document) => document.id), ['a.b', 'a_b']);
});

test('exportJSON preserves bodies, tags, and dangling links verbatim', () => {
  const snapshot = snapshotOf([
    { id: 'note', title: 'Note', body: '[[missing-one]] and [[missing.two]]', tags: ['A', 'b'] },
  ]);
  assert.equal(snapshot.documents[0].body, '[[missing-one]] and [[missing.two]]');
  assert.deepEqual(snapshot.documents[0].tags, ['a', 'b']);
});

test('exportJSON does not share internal references', () => {
  const workspace = new Workspace();
  workspace.add({ id: 'note', title: 'Note', body: 'Body', tags: ['tag'] });
  const first = workspace.exportJSON();
  first.documents[0].title = 'Hijacked';
  first.documents[0].tags.push('hijacked');
  const second = workspace.exportJSON();
  assert.equal(second.documents[0].title, 'Note');
  assert.deepEqual(second.documents[0].tags, ['tag']);
});

test('exportJSON on an empty workspace has a stable checksum', () => {
  const snapshot = new Workspace().exportJSON();
  assert.deepEqual(snapshot, { version: 1, documents: [], checksum: canonicalChecksum(snapshot) });
  assert.deepEqual(new Workspace().exportJSON(), snapshot);
});

test('importJSON accepts out-of-order documents when the checksum matches', () => {
  const original = snapshotOf([
    { id: 'a', title: 'A', body: 'a body', tags: [] },
    { id: 'b', title: 'B', body: 'b body', tags: ['x'] },
  ]);
  const shuffled = structuredClone(original);
  shuffled.documents.reverse();
  const workspace = new Workspace();
  const result = workspace.importJSON(shuffled, { mode: 'replace' });
  assert.deepEqual(result, original);
  assert.deepEqual(workspace.exportJSON(), original);
});

test('importJSON accepts a JSON string as well as an object', () => {
  const snapshot = snapshotOf([{ id: 'a', title: 'A', body: 'body text', tags: [] }]);
  const workspace = new Workspace();
  workspace.importJSON(JSON.stringify(snapshot), { mode: 'replace' });
  assert.deepEqual(workspace.exportJSON(), snapshot);
});

test('merge keeps existing documents and adds new ones', () => {
  const base = snapshotOf([{ id: 'a', title: 'A', body: 'old [[c]]', tags: ['keep'] }]);
  const incoming = snapshotOf([
    { id: 'b', title: 'B', body: 'links [[a]]', tags: ['new'] },
    { id: 'c', title: 'C', body: 'dangling [[nowhere]]', tags: [] },
  ]);
  const workspace = new Workspace();
  workspace.importJSON(base, { mode: 'replace' });
  const result = workspace.importJSON(incoming, { mode: 'merge' });
  assert.deepEqual(result.documents.map((document) => document.id), ['a', 'b', 'c']);
  assert.equal(workspace.get('a').body, 'old [[c]]');
  assert.deepEqual(workspace.links('a'), { outgoing: ['c'], incoming: ['b'] });
  assert.deepEqual(workspace.links('c'), { outgoing: ['nowhere'], incoming: ['a'] });
  assert.deepEqual(workspace.search('new').map((document) => document.id), ['b']);
});

test('merge skips incoming documents identical after normalization', () => {
  const base = snapshotOf([{ id: 'a', title: 'A', body: 'same', tags: ['x', 'y'] }]);
  // The checksum pins the normalized, sorted payload; the raw text may still
  // carry surrounding whitespace or equivalent tag casing/duplicates.
  const equivalent = {
    ...base,
    documents: [{ id: 'a', title: '  A   ', body: 'same', tags: [' X ', 'Y', 'y', ''] }],
  };
  const workspace = new Workspace();
  workspace.importJSON(base, { mode: 'replace' });
  assert.doesNotThrow(() => workspace.importJSON(equivalent, { mode: 'merge' }));
  assert.deepEqual(workspace.exportJSON(), base);
});

test('merge reports all conflicting ids, deduplicated and code-point sorted', () => {
  const base = snapshotOf([
    { id: 'a', title: 'Alpha', body: 'original', tags: [] },
    { id: 'b', title: 'Taken Title', body: 'base body', tags: [] },
    { id: 'dup', title: 'Will Collide', body: 'base body', tags: [] },
  ]);
  const conflicting = snapshotOf([
    { id: 'a', title: 'Alpha', body: 'changed body', tags: [] },
    { id: 'a.b', title: 'Taken Title', body: 'newcomer stealing a title', tags: [] },
    { id: 'dup', title: 'Will Collide', body: 'changed as well', tags: [] },
  ]);
  const workspace = new Workspace();
  workspace.importJSON(base, { mode: 'replace' });
  assert.throws(
    () => workspace.importJSON(conflicting, { mode: 'merge' }),
    (error) => {
      assert.ok(error instanceof SnapshotError);
      assert.equal(error.code, 'IMPORT_CONFLICT');
      assert.deepEqual(error.ids, ['a', 'a.b', 'dup']);
      return true;
    },
  );
  assert.deepEqual(workspace.exportJSON(), base);
});

test('merge treats same-id title or tag differences as conflicts', () => {
  const base = snapshotOf([
    { id: 'a', title: 'A', body: 'body', tags: ['one'] },
  ]);
  const changedTitle = snapshotOf([{ id: 'a', title: 'A2', body: 'body', tags: ['one'] }]);
  const changedTags = snapshotOf([{ id: 'a', title: 'A', body: 'body', tags: ['two'] }]);
  for (const snapshot of [changedTitle, changedTags]) {
    const workspace = new Workspace();
    workspace.importJSON(base, { mode: 'replace' });
    assert.throws(() => workspace.importJSON(snapshot, { mode: 'merge' }), { code: 'IMPORT_CONFLICT' });
    assert.deepEqual(workspace.exportJSON(), base);
  }
});

test('merge title moves: a moved-away title frees up for a newcomer', () => {
  // x renames T -> T2 (a content change) while newcomer y takes the freed
  // title T. Only x is a conflict; y must not be reported just because the
  // pre-merge owner still held T.
  const base = snapshotOf([{ id: 'x', title: 'T', body: 'body', tags: [] }]);
  const renameAndReuse = snapshotOf([
    { id: 'x', title: 'T2', body: 'body', tags: [] },
    { id: 'y', title: 'T', body: 'newcomer body', tags: [] },
  ]);
  const workspace = new Workspace();
  workspace.importJSON(base, { mode: 'replace' });
  assert.throws(
    () => workspace.importJSON(renameAndReuse, { mode: 'merge' }),
    (error) => error.code === 'IMPORT_CONFLICT' && error.ids.length === 1 && error.ids[0] === 'x',
  );
  assert.deepEqual(workspace.exportJSON(), base);

  // Renaming into a title owned by an untouched existing document conflicts.
  const baseTwo = snapshotOf([
    { id: 'x', title: 'T', body: 'body', tags: [] },
    { id: 'z', title: 'T2', body: 'existing owner', tags: [] },
  ]);
  const renameIntoOwner = snapshotOf([{ id: 'x', title: 'T2', body: 'changed body', tags: [] }]);
  const other = new Workspace();
  other.importJSON(baseTwo, { mode: 'replace' });
  assert.throws(
    () => other.importJSON(renameIntoOwner, { mode: 'merge' }),
    (error) => error.code === 'IMPORT_CONFLICT' && error.ids.length === 1 && error.ids[0] === 'x',
  );
  assert.deepEqual(other.exportJSON(), baseTwo);
});

test('replace discards documents absent from the snapshot', () => {
  const base = snapshotOf([{ id: 'old', title: 'Old', body: '[[gone]]', tags: [] }]);
  const incoming = snapshotOf([{ id: 'new', title: 'New', body: 'body text', tags: [] }]);
  const workspace = new Workspace();
  workspace.importJSON(base, { mode: 'replace' });
  workspace.importJSON(incoming, { mode: 'replace' });
  assert.equal(workspace.get('old'), null);
  assert.deepEqual(workspace.list().map((document) => document.id), ['new']);
});

test('dryRun returns the projected snapshot without changing state', () => {
  const base = snapshotOf([{ id: 'a', title: 'A', body: 'body text', tags: [] }]);
  const incoming = snapshotOf([{ id: 'b', title: 'B', body: 'body text', tags: [] }]);

  const mergeWorkspace = new Workspace();
  mergeWorkspace.importJSON(base, { mode: 'replace' });
  const projected = mergeWorkspace.importJSON(incoming, { mode: 'merge', dryRun: true });
  assert.deepEqual(projected.documents.map((document) => document.id), ['a', 'b']);
  assert.deepEqual(mergeWorkspace.exportJSON(), base);

  const replaceWorkspace = new Workspace();
  replaceWorkspace.importJSON(base, { mode: 'replace' });
  const replaced = replaceWorkspace.importJSON(incoming, { mode: 'replace', dryRun: true });
  assert.deepEqual(replaced.documents.map((document) => document.id), ['b']);
  assert.deepEqual(replaceWorkspace.exportJSON(), base);
});

test('dryRun defaults to false', () => {
  const workspace = new Workspace();
  workspace.importJSON(snapshotOf([{ id: 'a', title: 'A', body: 'body text', tags: [] }]), { mode: 'replace' });
  assert.deepEqual(workspace.list().map((document) => document.id), ['a']);
});

test('importJSON results never share references with the workspace', () => {
  const snapshot = snapshotOf([{ id: 'a', title: 'A', body: 'body text', tags: ['tag'] }]);
  const workspace = new Workspace();
  const result = workspace.importJSON(snapshot, { mode: 'replace' });
  snapshot.documents[0].tags.push('input-mutation');
  result.documents[0].tags.push('result-mutation');
  assert.deepEqual(workspace.get('a').tags, ['tag']);
  assert.deepEqual(workspace.exportJSON().documents[0].tags, ['tag']);
});

test('invalid options raise INVALID_OPTIONS', () => {
  const snapshot = new Workspace().exportJSON();
  const cases = [
    undefined,
    null,
    [],
    {},
    { mode: 'upsert' },
    { mode: 'merge', dryRun: 'yes' },
    { mode: 'merge', dryRun: null },
    { mode: 'merge', dryRun: 0 },
    { mode: 'merge', unknown: true },
    'merge',
  ];
  for (const options of cases) {
    assert.throws(() => new Workspace().importJSON(snapshot, options), { code: 'INVALID_OPTIONS' });
  }
});

const INVALID_SNAPSHOTS = [
  ['malformed JSON string', '{not json'],
  ['JSON null', null],
  ['JSON array', []],
  ['JSON string', 'snapshot'],
  ['JSON number', 1],
  ['missing version', (() => { const s = new Workspace().exportJSON(); delete s.version; return s; })()],
  ['missing documents', (() => { const s = new Workspace().exportJSON(); delete s.documents; return s; })()],
  ['missing checksum', (() => { const s = new Workspace().exportJSON(); delete s.checksum; return s; })()],
  ['extra top-level field', (() => { const s = new Workspace().exportJSON(); s.extra = 1; return s; })()],
  ['unsupported numeric version', (() => { const s = new Workspace().exportJSON(); s.version = 2; return s; })()],
  ['string version', (() => { const s = new Workspace().exportJSON(); s.version = '1'; return s; })()],
  ['documents not an array', (() => { const s = new Workspace().exportJSON(); s.documents = {}; return s; })()],
  ['non-string checksum', (() => { const s = new Workspace().exportJSON(); s.checksum = 123; return s; })()],
  ['document is null', (() => { const s = snapshotOf([]); s.documents = [null]; return s; })()],
  ['document missing body', (() => { const s = snapshotOf([]); s.documents = [{ id: 'a', title: 'A', tags: [] }]; return s; })()],
  ['document missing tags', (() => { const s = snapshotOf([]); s.documents = [{ id: 'a', title: 'A', body: 'body text' }]; return s; })()],
  ['document with extra field', (() => {
    const s = snapshotOf([{ id: 'a', title: 'A', body: 'body text', tags: [] }]);
    s.documents[0].extra = true;
    return s;
  })()],
  ['tags is not an array', (() => {
    const s = snapshotOf([]); s.documents = [{ id: 'a', title: 'A', body: 'body text', tags: 'x' }]; return s;
  })()],
  ['tags contains a number', (() => {
    const s = snapshotOf([]); s.documents = [{ id: 'a', title: 'A', body: 'body text', tags: [1] }]; return s;
  })()],
  ['tags contains null', (() => {
    const s = snapshotOf([]); s.documents = [{ id: 'a', title: 'A', body: 'body text', tags: [null] }]; return s;
  })()],
  ['invalid id', (() => {
    const s = snapshotOf([]); s.documents = [{ id: 'Bad Id', title: 'A', body: 'body text', tags: [] }]; return s;
  })()],
  ['blank title', (() => {
    const s = snapshotOf([]); s.documents = [{ id: 'a', title: '   ', body: 'body text', tags: [] }]; return s;
  })()],
  ['non-string body', (() => {
    const s = snapshotOf([]); s.documents = [{ id: 'a', title: 'A', body: 1, tags: [] }]; return s;
  })()],
  ['duplicate ids', (() => {
    const s = snapshotOf([]);
    s.documents = [
      { id: 'a', title: 'A', body: 'body text', tags: [] },
      { id: 'a', title: 'B', body: 'body text', tags: [] },
    ];
    return s;
  })()],
  ['duplicate normalized titles', (() => {
    const s = snapshotOf([]);
    s.documents = [
      { id: 'a', title: 'Same', body: 'body text', tags: [] },
      { id: 'b', title: '  Same ', body: 'body text', tags: [] },
    ];
    return s;
  })()],
  ['bad checksum', (() => {
    const s = snapshotOf([{ id: 'a', title: 'A', body: 'body text', tags: [] }]);
    s.checksum = `${'0'.repeat(64)}`;
    return s;
  })()],
  ['tampered body with stale checksum', (() => {
    const s = snapshotOf([{ id: 'a', title: 'A', body: 'original', tags: [] }]);
    s.documents[0].body = 'tampered';
    return s;
  })()],
];

for (const [label, data] of INVALID_SNAPSHOTS) {
  test(`invalid snapshot rejected: ${label}`, () => {
    const workspace = new Workspace();
    workspace.add({ id: 'existing', title: 'Existing', body: 'body text', tags: [] });
    const before = workspace.exportJSON();
    assert.throws(
      () => workspace.importJSON(data, { mode: 'merge' }),
      (error) => error instanceof SnapshotError && error.code === 'INVALID_SNAPSHOT',
    );
    assert.deepEqual(workspace.exportJSON(), before);
  });
}

test('titles are only trimmed for uniqueness, not case-folded', () => {
  const snapshot = snapshotOf([]);
  snapshot.documents = [
    { id: 'a', title: 'Case', body: 'body text', tags: [] },
    { id: 'b', title: 'case', body: 'body text', tags: [] },
  ];
  snapshot.checksum = canonicalChecksum(snapshot);
  const workspace = new Workspace();
  assert.doesNotThrow(() => workspace.importJSON(snapshot, { mode: 'replace' }));
  assert.deepEqual(workspace.list().map((document) => document.id), ['a', 'b']);
});
