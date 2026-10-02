import assert from 'node:assert/strict';
import test from 'node:test';
import { Workspace, SnapshotError } from '../src/workspace.js';
import { reconcileSnapshots } from '../src/reconcile.js';

function snapshotOf(documents) {
  const workspace = new Workspace();
  for (const document of documents) workspace.add(document);
  return workspace.exportJSON();
}

function doc(id, patch = {}) {
  return { id, title: id.toUpperCase(), body: `${id} body`, tags: [], ...patch };
}

function ids(snapshot) {
  return snapshot.documents.map((document) => document.id);
}

function mapOf(result) {
  return new Map(result.snapshot.documents.map((document) => [document.id, document]));
}

// --- field merge ------------------------------------------------------------

test('a field changed on only one side is kept, even if the other side edited a different field', () => {
  const base = snapshotOf([doc('a', { title: 'A', body: 'base', tags: ['t'] })]);
  const current = snapshotOf([doc('a', { title: 'A2', body: 'base', tags: ['t'] })]);
  const incoming = snapshotOf([doc('a', { title: 'A', body: 'base', tags: ['u'] })]);
  const result = reconcileSnapshots(current, base, incoming);
  assert.deepEqual(result.conflicts, []);
  const merged = mapOf(result).get('a');
  assert.deepEqual(merged, { id: 'a', title: 'A2', body: 'base', tags: ['u'] });
  assert.deepEqual(result.changedIds, ['a']);
});

test('body edits on opposite sides both survive because they touch different fields from a title edit', () => {
  const base = snapshotOf([doc('a', { title: 'A', body: 'base', tags: [] })]);
  const current = snapshotOf([doc('a', { title: 'A', body: 'base', tags: ['online'] })]);
  const incoming = snapshotOf([doc('a', { title: 'A', body: 'offline body', tags: [] })]);
  const merged = mapOf(reconcileSnapshots(current, base, incoming)).get('a');
  assert.deepEqual(merged, { id: 'a', title: 'A', body: 'offline body', tags: ['online'] });
});

test('both sides changing the same field to the same value is accepted', () => {
  const base = snapshotOf([doc('a', { title: 'A', body: 'base', tags: ['t'] })]);
  const current = snapshotOf([doc('a', { title: 'A', body: 'base', tags: ['z'] })]);
  const incoming = snapshotOf([doc('a', { title: 'A', body: 'base', tags: ['Z', 'z'] })]);
  const result = reconcileSnapshots(current, base, incoming);
  assert.deepEqual(result.conflicts, []);
  assert.deepEqual(mapOf(result).get('a').tags, ['z']);
});

test('both sides changing the same field differently conflicts and names the field', () => {
  const base = snapshotOf([doc('a', { title: 'A', body: 'base', tags: ['t'] })]);
  const cases = [
    ['title', doc('a', { title: 'A' }), (d) => ({ ...d, title: 'X' }), (d) => ({ ...d, title: 'Y' })],
    ['body', doc('a', { body: 'base' }), (d) => ({ ...d, body: 'X' }), (d) => ({ ...d, body: 'Y' })],
    ['tags', doc('a', { tags: ['t'] }), (d) => ({ ...d, tags: ['x'] }), (d) => ({ ...d, tags: ['y'] })],
  ];
  for (const [field, baseDoc, curPatch, incPatch] of cases) {
    const baseSnapshot = snapshotOf([baseDoc]);
    const current = snapshotOf([curPatch(baseDoc)]);
    const incoming = snapshotOf([incPatch(baseDoc)]);
    const result = reconcileSnapshots(current, baseSnapshot, incoming);
    assert.deepEqual(result.conflicts, [{ id: 'a', fields: [field] }], `field ${field}`);
  }
});

test('bodies compare as whole strings and are preserved verbatim', () => {
  const base = snapshotOf([doc('a', { body: 'line1\nline2  [[ghost]]\n' })]);
  const incoming = snapshotOf([doc('a', { body: 'line1\nline2  [[ghost]]\n\nedited' })]);
  const result = reconcileSnapshots(base, base, incoming);
  assert.equal(mapOf(result).get('a').body, 'line1\nline2  [[ghost]]\n\nedited');
});

test('tags compare as one normalized group: equivalent normalization is not a change', () => {
  const base = snapshotOf([doc('a', { tags: ['x', 'y'] })]);
  const incoming = snapshotOf([doc('a', { tags: [' Y ', 'X', 'y'] })]);
  const result = reconcileSnapshots(base, base, incoming);
  assert.deepEqual(result.conflicts, []);
  assert.deepEqual(result.changedIds, []);
});

test('unrelated documents edited on opposite sides are both kept', () => {
  const base = snapshotOf([doc('a', { body: 'old' }), doc('b', { body: 'old' })]);
  const current = snapshotOf([doc('a', { body: 'online' }), doc('b', { body: 'old' })]);
  const incoming = snapshotOf([doc('a', { body: 'old' }), doc('b', { body: 'offline' })]);
  const result = reconcileSnapshots(current, base, incoming);
  assert.deepEqual(result.conflicts, []);
  const merged = mapOf(result);
  assert.equal(merged.get('a').body, 'online');
  assert.equal(merged.get('b').body, 'offline');
  // Relative to the current (online) state, only b changed.
  assert.deepEqual(result.changedIds, ['b']);
});

// --- adds and deletes -------------------------------------------------------

test('a document added on only one side is kept', () => {
  const base = snapshotOf([doc('a')]);
  const addedOnline = snapshotOf([doc('a'), doc('online')]);
  const addedOffline = snapshotOf([doc('a'), doc('offline')]);
  assert.deepEqual(ids(reconcileSnapshots(addedOnline, base, base).snapshot), ['a', 'online']);
  assert.deepEqual(ids(reconcileSnapshots(base, base, addedOffline).snapshot), ['a', 'offline']);
});

test('both sides adding the same id accepts only identical normalized documents', () => {
  const base = snapshotOf([]);
  const identical = snapshotOf([doc('n', { title: 'N', body: 'b', tags: ['T'] })]);
  const identicalNormalized = snapshotOf([doc('n', { title: ' N ', body: 'b', tags: ['t', 'T'] })]);
  assert.deepEqual(reconcileSnapshots(identical, base, identicalNormalized).conflicts, []);

  const online = snapshotOf([doc('n', { title: 'N1' })]);
  const offline = snapshotOf([doc('n', { title: 'N2' })]);
  assert.deepEqual(reconcileSnapshots(online, base, offline).conflicts, [{ id: 'n', fields: ['document'] }]);
});

test('one side deleting while the other left the document untouched deletes; both deleting deletes', () => {
  const base = snapshotOf([doc('a'), doc('b')]);
  // Incoming deletes both; online left them alone.
  const one = reconcileSnapshots(base, base, snapshotOf([]));
  assert.deepEqual(one.conflicts, []);
  assert.deepEqual(ids(one.snapshot), []);

  // Both delete a; online additionally keeps b untouched.
  const currentDeletedA = snapshotOf([doc('b')]);
  const incomingDeletedA = snapshotOf([doc('b')]);
  const two = reconcileSnapshots(currentDeletedA, base, incomingDeletedA);
  assert.deepEqual(ids(two.snapshot), ['b']);
  assert.deepEqual(two.conflicts, []);
});

test('a delete meeting a modification on the other side conflicts on document', () => {
  const base = snapshotOf([doc('a', { body: 'old' })]);
  // Online modifies, incoming deletes.
  const onlineModified = snapshotOf([doc('a', { body: 'new' })]);
  const deleted = snapshotOf([]);
  const result = reconcileSnapshots(onlineModified, base, deleted);
  assert.deepEqual(result.conflicts, [{ id: 'a', fields: ['document'] }]);
  assert.deepEqual(ids(result.snapshot), ['a']);

  // Online deletes, incoming modifies: same conflict, surviving content kept.
  const reverse = reconcileSnapshots(deleted, base, onlineModified);
  assert.deepEqual(reverse.conflicts, [{ id: 'a', fields: ['document'] }]);
  assert.equal(mapOf(reverse).get('a').body, 'new');
});

// --- title uniqueness --------------------------------------------------------

test('final titles must be unique and swaps are allowed', () => {
  const base = snapshotOf([doc('a', { title: 'A' }), doc('b', { title: 'B' })]);
  // Pure swap: no conflicts.
  const swapped = snapshotOf([doc('a', { title: 'B' }), doc('b', { title: 'A' })]);
  const swap = reconcileSnapshots(swapped, base, base);
  assert.deepEqual(swap.conflicts, []);

  // Both sides rename a A -> C identically, and the offline fork adds a new
  // document taking the freed title A: the final title set is unique.
  const current = snapshotOf([doc('a', { title: 'C' }), doc('b', { title: 'B' })]);
  const incoming = snapshotOf([
    doc('a', { title: 'C' }), doc('b', { title: 'B' }), doc('d', { title: 'A' }),
  ]);
  const result = reconcileSnapshots(current, base, incoming);
  assert.deepEqual(result.conflicts, []);
  assert.deepEqual(mapOf(result).get('a').title, 'C');
  assert.deepEqual(mapOf(result).get('d').title, 'A');
});

test('duplicate final titles report every involved document with field title', () => {
  const base = snapshotOf([doc('a', { title: 'A' }), doc('b', { title: 'B' }), doc('c', { title: 'C' })]);
  // Online renames a to T; offline leaves a at A and adds d titled T.
  const current = snapshotOf([
    doc('a', { title: 'T' }), doc('b', { title: 'B' }), doc('c', { title: 'C' }),
  ]);
  const incoming = snapshotOf([
    doc('a', { title: 'A' }), doc('b', { title: 'B' }), doc('c', { title: 'C' }),
    doc('d', { title: 'T' }),
  ]);
  const result = reconcileSnapshots(current, base, incoming);
  assert.deepEqual(result.conflicts, [{ id: 'a', fields: ['title'] }, { id: 'd', fields: ['title'] }]);
});

test('field/add/delete conflicts suppress title-duplicate reporting', () => {
  const base = snapshotOf([doc('a', { title: 'A', body: 'old' })]);
  // Body conflict on a, and the projection would also contain duplicate
  // titles: only the field conflict is reported.
  const current = snapshotOf([
    doc('a', { title: 'T', body: 'online' }),
  ]);
  const incoming = snapshotOf([
    doc('a', { title: 'A', body: 'offline' }),
    doc('d', { title: 'T' }),
  ]);
  assert.deepEqual(reconcileSnapshots(current, base, incoming).conflicts, [
    { id: 'a', fields: ['body'] },
  ]);
});

// --- collection and ordering -------------------------------------------------

test('conflicts are deduplicated and sorted by id code point, fields by name code point', () => {
  const base = snapshotOf([
    doc('a_b', { title: 'A_b', body: 'old', tags: ['t'] }),
    doc('a.b', { title: 'A.b', body: 'old', tags: ['t'] }),
    doc('z', { title: 'Z', body: 'old', tags: ['t'] }),
  ]);
  const current = snapshotOf([
    doc('a_b', { title: 'T1', body: 'online', tags: ['x'] }),
    doc('a.b', { title: 'A.b', body: 'online', tags: ['x'] }),
    doc('z', { title: 'Z', body: 'old', tags: ['t'] }),
  ]);
  const incoming = snapshotOf([
    doc('a_b', { title: 'T3', body: 'offline', tags: ['y'] }),
    doc('a.b', { title: 'A.b', body: 'offline', tags: ['y'] }),
    doc('z', { title: 'Z', body: 'old', tags: ['t'] }),
  ]);
  const result = reconcileSnapshots(current, base, incoming);
  // '.' (U+002E) sorts before '_' (U+005F); fields order body, tags, title.
  assert.deepEqual(result.conflicts, [
    { id: 'a.b', fields: ['body', 'tags'] },
    { id: 'a_b', fields: ['body', 'tags', 'title'] },
  ]);
});

test('changedIds includes adds, edits, and deletes, sorted by code point', () => {
  const base = snapshotOf([doc('gone'), doc('keep'), doc('edit', { body: 'old' })]);
  const current = snapshotOf([doc('gone'), doc('keep'), doc('edit', { body: 'old' })]);
  const incoming = snapshotOf([
    doc('keep'),
    doc('edit', { body: 'new' }),
    doc('fresh'),
  ]);
  const result = reconcileSnapshots(current, base, incoming);
  assert.deepEqual(result.changedIds, ['edit', 'fresh', 'gone']);
});

test('an identical merge reports no changes and reproduces the current snapshot', () => {
  const current = snapshotOf([doc('a'), doc('b')]);
  const result = reconcileSnapshots(current, current, current);
  assert.deepEqual(result.snapshot, current);
  assert.deepEqual(result.changedIds, []);
  assert.deepEqual(result.conflicts, []);
});

// --- validation --------------------------------------------------------------

test('any of the three snapshots failing validation raises INVALID_SNAPSHOT', () => {
  const good = snapshotOf([doc('a')]);
  const tampered = structuredClone(good);
  tampered.documents[0].body = 'tampered';
  for (const [label, current, base, incoming] of [
    ['bad current', tampered, good, good],
    ['bad base', good, tampered, good],
    ['bad incoming', good, good, tampered],
  ]) {
    assert.throws(
      () => reconcileSnapshots(current, base, incoming),
      (error) => error instanceof SnapshotError && error.code === 'INVALID_SNAPSHOT',
      label,
    );
  }
});

test('the reconciled snapshot is a fresh object that does not share references', () => {
  const base = snapshotOf([doc('a', { tags: ['t'] })]);
  const incoming = snapshotOf([doc('a', { tags: ['u'] })]);
  const result = reconcileSnapshots(base, base, incoming);
  result.snapshot.documents[0].tags.push('hijacked');
  const again = reconcileSnapshots(base, base, incoming);
  assert.deepEqual(mapOf(again).get('a').tags, ['u']);
});
