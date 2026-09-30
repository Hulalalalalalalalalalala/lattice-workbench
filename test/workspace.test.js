import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { Workspace } from '../src/workspace.js';

function checksumOf(documents) {
  return createHash('sha256').update(JSON.stringify({ version: 1, documents }), 'utf8').digest('hex');
}

function snapshotOf(workspace) {
  return workspace.exportJSON();
}

test('normalizes tags and derives backlinks', () => {
  const workspace = new Workspace();
  workspace.add({ id: 'alpha', title: 'Alpha', body: 'See [[beta]] and [[beta]].', tags: ['Search', 'search'] });
  workspace.add({ id: 'beta', title: 'Beta', body: 'A target document.', tags: [] });
  assert.deepEqual(workspace.get('alpha').tags, ['search']);
  assert.deepEqual(workspace.links('alpha'), { outgoing: ['beta'], incoming: [] });
  assert.deepEqual(workspace.links('beta'), { outgoing: [], incoming: ['alpha'] });
});

test('searches titles, bodies, and tags without exposing internal values', () => {
  const workspace = new Workspace();
  workspace.add({ id: 'release', title: 'Release Notes', body: 'Stable migration contract.', tags: ['History'] });
  const result = workspace.search('history');
  assert.equal(result.length, 1);
  result[0].tags.push('mutated');
  assert.deepEqual(workspace.get('release').tags, ['history']);
});

test('rejects duplicate and malformed identifiers', () => {
  const workspace = new Workspace();
  workspace.add({ id: 'valid-id', title: 'Valid', body: 'Body' });
  assert.throws(() => workspace.add({ id: 'valid-id', title: 'Again', body: 'Body' }), /already exists/u);
  assert.throws(() => workspace.add({ id: 'Not Valid', title: 'Bad', body: 'Body' }), /URL-safe/u);
});

test('exportJSON uses the documented key order and checksum', () => {
  const workspace = new Workspace();
  workspace.add({ id: 'b', title: 'Beta', body: '[[a]]', tags: ['Z', 'a'] });
  workspace.add({ id: 'a', title: 'Alpha', body: 'hello', tags: ['y'] });
  const snapshot = workspace.exportJSON();

  assert.deepEqual(Object.keys(snapshot), ['version', 'documents', 'checksum']);
  assert.equal(snapshot.version, 1);
  assert.deepEqual(snapshot.documents.map((document) => document.id), ['a', 'b']);
  assert.deepEqual(Object.keys(snapshot.documents[0]), ['id', 'title', 'body', 'tags']);
  assert.deepEqual(snapshot.documents[0].tags, ['y']);
  assert.deepEqual(snapshot.documents[1].tags, ['a', 'z']);
  assert.equal(snapshot.checksum, checksumOf(snapshot.documents));
  assert.match(snapshot.checksum, /^[0-9a-f]{64}$/u);
});

test('exportJSON does not share internal references', () => {
  const workspace = new Workspace();
  workspace.add({ id: 'a', title: 'Alpha', body: 'body', tags: ['x'] });
  const snapshot = workspace.exportJSON();
  snapshot.documents[0].tags.push('mutated');
  snapshot.documents[0].body = 'mutated';
  assert.deepEqual(workspace.get('a').tags, ['x']);
  assert.equal(workspace.get('a').body, 'body');
});

test('exportJSON preserves dangling links', () => {
  const workspace = new Workspace();
  workspace.add({ id: 'a', title: 'Alpha', body: '[[ghost]] and [[gone]]', tags: [] });
  const snapshot = workspace.exportJSON();
  assert.equal(snapshot.documents[0].body, '[[ghost]] and [[gone]]');
  const restored = new Workspace();
  restored.importJSON(snapshot, { mode: 'replace' });
  assert.deepEqual(restored.links('a').outgoing, ['ghost', 'gone']);
  assert.deepEqual(restored.links('a').incoming, []);
});

test('importJSON replace round-trips and syncs queries and links', () => {
  const source = new Workspace();
  source.add({ id: 'b', title: 'Beta', body: '[[a]]', tags: ['x'] });
  source.add({ id: 'a', title: 'Alpha', body: 'hello', tags: ['y'] });
  const snapshot = snapshotOf(source);

  const target = new Workspace();
  const result = target.importJSON(snapshot, { mode: 'replace' });
  assert.deepEqual(result, snapshot);
  assert.deepEqual(target.list().map((document) => document.id), ['a', 'b']);
  assert.equal(target.search('alpha').length, 1);
  assert.deepEqual(target.links('b'), { outgoing: ['a'], incoming: [] });
  assert.deepEqual(target.links('a'), { outgoing: [], incoming: ['b'] });
});

test('importJSON accepts out-of-order documents', () => {
  const source = new Workspace();
  source.add({ id: 'a', title: 'Alpha', body: 'x', tags: [] });
  source.add({ id: 'b', title: 'Beta', body: 'y', tags: [] });
  const snapshot = snapshotOf(source);
  const shuffled = { version: 1, documents: [...snapshot.documents].reverse(), checksum: snapshot.checksum };

  const target = new Workspace();
  target.importJSON(shuffled, { mode: 'replace' });
  assert.deepEqual(target.list().map((document) => document.id), ['a', 'b']);
});

test('importJSON dryRun does not change state and returns the result snapshot', () => {
  const base = new Workspace();
  base.add({ id: 'a', title: 'Alpha', body: 'x', tags: [] });
  const incoming = new Workspace();
  incoming.add({ id: 'b', title: 'Beta', body: 'y', tags: [] });

  const before = snapshotOf(base);
  const dryResult = base.importJSON(snapshotOf(incoming), { mode: 'merge', dryRun: true });
  assert.deepEqual(snapshotOf(base), before);
  assert.deepEqual(base.list().map((document) => document.id), ['a']);
  assert.deepEqual(dryResult.documents.map((document) => document.id), ['a', 'b']);

  const replaceDry = base.importJSON(snapshotOf(incoming), { mode: 'replace', dryRun: true });
  assert.deepEqual(base.list().map((document) => document.id), ['a']);
  assert.deepEqual(replaceDry.documents.map((document) => document.id), ['b']);
});

test('importJSON merge skips identical documents and adds new ones', () => {
  const workspace = new Workspace();
  workspace.add({ id: 'a', title: 'Alpha', body: 'x', tags: ['t'] });
  const incoming = new Workspace();
  incoming.add({ id: 'a', title: 'Alpha', body: 'x', tags: ['T'] });
  incoming.add({ id: 'b', title: 'Beta', body: 'y', tags: [] });

  const result = workspace.importJSON(snapshotOf(incoming), { mode: 'merge' });
  assert.deepEqual(result.documents.map((document) => document.id), ['a', 'b']);
  assert.deepEqual(workspace.list().map((document) => document.id), ['a', 'b']);
});

test('importJSON merge replace drops documents absent from incoming', () => {
  const workspace = new Workspace();
  workspace.add({ id: 'a', title: 'Alpha', body: 'x', tags: [] });
  workspace.add({ id: 'b', title: 'Beta', body: 'y', tags: [] });
  const incoming = new Workspace();
  incoming.add({ id: 'a', title: 'Alpha', body: 'x', tags: [] });
  workspace.importJSON(snapshotOf(incoming), { mode: 'replace' });
  assert.deepEqual(workspace.list().map((document) => document.id), ['a']);
});

test('importJSON merge reports content conflicts with the conflicting ids', () => {
  const base = new Workspace();
  base.add({ id: 'a', title: 'Alpha', body: 'orig', tags: [] });
  const incoming = new Workspace();
  incoming.add({ id: 'a', title: 'Alpha', body: 'changed', tags: [] });
  incoming.add({ id: 'c', title: 'Gamma', body: 'z', tags: [] });

  let error;
  try {
    base.importJSON(snapshotOf(incoming), { mode: 'merge' });
  } catch (caught) {
    error = caught;
  }
  assert.equal(error.code, 'IMPORT_CONFLICT');
  assert.deepEqual(error.ids, ['a']);
  assert.equal(base.get('a').body, 'orig');
  assert.equal(base.get('c'), null);
});

test('importJSON merge reports title conflicts on both sides, deduped and sorted', () => {
  const base = new Workspace();
  base.add({ id: 'a', title: 'Alpha', body: 'x', tags: [] });
  const incoming = new Workspace();
  incoming.add({ id: 'b', title: ' Alpha ', body: 'y', tags: [] });

  let error;
  try {
    base.importJSON(snapshotOf(incoming), { mode: 'merge' });
  } catch (caught) {
    error = caught;
  }
  assert.equal(error.code, 'IMPORT_CONFLICT');
  assert.deepEqual(error.ids, ['a', 'b']);
  assert.deepEqual(base.list().map((document) => document.id), ['a']);
});

test('importJSON merge dedupes ids across content and title conflicts', () => {
  const base = new Workspace();
  base.add({ id: 'a', title: 'Alpha', body: 'orig', tags: [] });
  base.add({ id: 'c', title: 'Gamma', body: 'z', tags: [] });
  const incoming = new Workspace();
  incoming.add({ id: 'a', title: 'Alpha', body: 'changed', tags: [] });
  incoming.add({ id: 'b', title: 'Gamma', body: 'y', tags: [] });

  let error;
  try {
    base.importJSON(snapshotOf(incoming), { mode: 'merge' });
  } catch (caught) {
    error = caught;
  }
  assert.equal(error.code, 'IMPORT_CONFLICT');
  assert.deepEqual(error.ids, ['a', 'b', 'c']);
});

test('importJSON rejects invalid options', () => {
  const workspace = new Workspace();
  const snapshot = snapshotOf(workspace);
  for (const options of [undefined, null, {}, { mode: 'bogus' }, { mode: 'merge', dryRun: 'yes' }, { mode: 'merge', extra: true }, { dryRun: true }]) {
    assert.throws(() => workspace.importJSON(snapshot, options), (error) => error.code === 'INVALID_OPTIONS');
  }
});

test('importJSON rejects malformed snapshots with INVALID_SNAPSHOT', () => {
  const workspace = new Workspace();
  const valid = snapshotOf(workspace);
  const cases = [
    ['not an object', null],
    ['array', []],
    ['unsupported version', { version: 2, documents: [], checksum: '0'.repeat(64) }],
    ['missing version', { documents: [], checksum: '0'.repeat(64) }],
    ['extra field', { ...valid, extra: true }],
    ['documents not array', { version: 1, documents: 'nope', checksum: '0'.repeat(64) }],
    ['checksum not string', { version: 1, documents: [], checksum: 123 }],
    ['checksum bad format', { version: 1, documents: [], checksum: 'Z'.repeat(64) }],
    ['document not object', { version: 1, documents: [null], checksum: '0'.repeat(64) }],
    ['document missing keys', { version: 1, documents: [{ id: 'a', title: 'A', body: 'b' }], checksum: '0'.repeat(64) }],
    ['document extra keys', { version: 1, documents: [{ id: 'a', title: 'A', body: 'b', tags: [], extra: 1 }], checksum: '0'.repeat(64) }],
    ['tags not array', { version: 1, documents: [{ id: 'a', title: 'A', body: 'b', tags: 'x' }], checksum: '0'.repeat(64) }],
    ['tags with non-string', { version: 1, documents: [{ id: 'a', title: 'A', body: 'b', tags: [1] }], checksum: '0'.repeat(64) }],
    ['duplicate ids', { version: 1, documents: [{ id: 'a', title: 'A', body: 'b', tags: [] }, { id: 'a', title: 'B', body: 'c', tags: [] }], checksum: '0'.repeat(64) }],
    ['invalid document id', { version: 1, documents: [{ id: 'Bad Id', title: 'A', body: 'b', tags: [] }], checksum: '0'.repeat(64) }],
  ];
  for (const [name, data] of cases) {
    assert.throws(() => workspace.importJSON(data, { mode: 'replace' }), (error) => error.code === 'INVALID_SNAPSHOT', name);
  }
});

test('importJSON rejects duplicate normalized titles', () => {
  const source = new Workspace();
  source.add({ id: 'a', title: 'Same', body: 'x', tags: [] });
  source.add({ id: 'b', title: ' Same ', body: 'y', tags: [] });
  let error;
  try {
    new Workspace().importJSON(snapshotOf(source), { mode: 'replace' });
  } catch (caught) {
    error = caught;
  }
  assert.equal(error.code, 'INVALID_SNAPSHOT');
});

test('importJSON rejects a tampered checksum', () => {
  const source = new Workspace();
  source.add({ id: 'a', title: 'Alpha', body: 'x', tags: [] });
  const snapshot = snapshotOf(source);
  assert.throws(
    () => new Workspace().importJSON({ ...snapshot, checksum: '0'.repeat(64) }, { mode: 'replace' }),
    (error) => error.code === 'INVALID_SNAPSHOT',
  );
});

test('importJSON leaves state untouched when validation fails', () => {
  const workspace = new Workspace();
  workspace.add({ id: 'a', title: 'Alpha', body: 'x', tags: [] });
  const before = snapshotOf(workspace);
  assert.throws(() => workspace.importJSON({ version: 2, documents: [], checksum: '0'.repeat(64) }, { mode: 'replace' }));
  assert.deepEqual(snapshotOf(workspace), before);
});
