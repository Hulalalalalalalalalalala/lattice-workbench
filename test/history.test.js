import assert from 'node:assert/strict';
import test from 'node:test';
import { HistoryError, HistoryStore, parseHistory, sameDocument } from '../src/history.js';
import { Workspace, snapshotFromDocuments } from '../src/workspace.js';

function doc(id, title = id.toUpperCase(), body = 'body text', tags = []) {
  return { id, title, body, tags };
}

function render(store) {
  const snapshot = snapshotFromDocuments(store.replayedDocuments().values());
  return JSON.stringify(store.exportJSON(snapshot.checksum));
}

test('baseline assigns revision 1 to every existing document', () => {
  const workspace = new Workspace();
  workspace.add(doc('a', 'Alpha', 'a body', ['One']));
  workspace.add(doc('b', 'Beta', 'b body', []));
  const store = HistoryStore.baseline(workspace.list());
  assert.deepEqual(store.entries('a'), [{ revision: 1, action: 'baseline', document: { id: 'a', title: 'Alpha', body: 'a body', tags: ['one'] } }]);
  assert.deepEqual(store.entries('b')[0].action, 'baseline');
  assert.equal(store.snapshotChecksum, workspace.exportJSON().checksum);
});

test('revisions append consecutively per document, including after a delete', () => {
  const store = HistoryStore.baseline([doc('a')]);
  const draft = store.clone();
  assert.equal(draft.record('a', 'replace', doc('a', 'A', 'v2')).revision, 2);
  assert.equal(draft.record('a', 'delete', null).revision, 3);
  assert.equal(draft.record('a', 'create', doc('a', 'A', 'v3')).revision, 4);
  assert.deepEqual(draft.entries('a').map((entry) => entry.action), ['baseline', 'replace', 'delete', 'create']);
  assert.equal(draft.entries('a')[2].document, null);
  // The pre-commit store is untouched when a commit is prepared on a clone.
  assert.deepEqual(store.entries('a').map((entry) => entry.action), ['baseline']);
});

test('new documents start at revision 1 with a create action', () => {
  const store = HistoryStore.baseline([]);
  const draft = store.clone();
  draft.record('new', 'create', doc('new'));
  assert.deepEqual(draft.entries('new')[0], { revision: 1, action: 'create', document: doc('new') });
});

test('exported history round-trips through parseHistory', () => {
  const store = HistoryStore.baseline([doc('a', 'A', 'b', ['X'])]);
  const draft = store.clone();
  draft.record('a', 'replace', doc('a', 'A', 'c', ['x', 'y']));
  const snapshot = snapshotFromDocuments(draft.replayedDocuments().values());
  const parsed = parseHistory(JSON.stringify(draft.exportJSON(snapshot.checksum)));
  assert.equal(parsed.snapshotChecksum, snapshot.checksum);
  const restored = HistoryStore.fromParsed(parsed);
  assert.deepEqual(restored.entries('a').map((e) => [e.revision, e.action]), [[1, 'baseline'], [2, 'replace']]);
});

test('history records never share mutable references', () => {
  const store = HistoryStore.baseline([doc('a', 'A', 'b', ['t'])]);
  const view = store.entries('a');
  view[0].document.tags.push('mutated');
  assert.deepEqual(store.entries('a')[0].document.tags, ['t']);
  const target = store.entry('a', 1);
  target.document.body = 'hijacked';
  assert.equal(store.entry('a', 1).document.body, 'b');
});

test('sameDocument compares normalized content', () => {
  assert.equal(sameDocument(doc('a', 'A', 'b', ['x']), doc('a', 'A', 'b', ['x'])), true);
  assert.equal(sameDocument(doc('a', 'A', 'b', ['x']), doc('a', 'A', 'c', ['x'])), false);
  assert.equal(sameDocument(doc('a', 'A', 'b', ['x']), doc('a', 'A', 'b', ['y'])), false);
});

const INVALID_HISTORIES = [
  ['malformed JSON', '{nope'],
  ['not an object', '[]'],
  ['extra top-level field', (() => { const s = HistoryStore.baseline([]).exportJSON('0'.repeat(64)); s.extra = 1; return s; })()],
  ['unsupported version', (() => { const s = HistoryStore.baseline([]).exportJSON('0'.repeat(64)); s.version = 2; return s; })()],
  ['bad snapshot checksum', (() => { const s = HistoryStore.baseline([]).exportJSON('0'.repeat(64)); s.snapshot = 'nope'; return s; })()],
  ['empty chain', (() => { const s = HistoryStore.baseline([]).exportJSON('0'.repeat(64)); s.history.a = []; return s; })()],
  ['non-consecutive revisions', (() => {
    const s = HistoryStore.baseline([doc('a')]); const snap = snapshotFromDocuments(s.replayedDocuments().values());
    const out = s.exportJSON(snap.checksum); out.history.a[0].revision = 2; return out;
  })()],
  ['second baseline', (() => {
    const s = HistoryStore.baseline([doc('a')]); const d = s.clone(); d.record('a', 'replace', doc('a', 'A', 'v2'));
    const out = d.exportJSON(snapshotFromDocuments(d.replayedDocuments().values()).checksum);
    out.history.a[1].action = 'baseline'; return out;
  })()],
  ['create while alive', (() => {
    const s = HistoryStore.baseline([doc('a')]); const d = s.clone(); d.record('a', 'replace', doc('a', 'A', 'v2'));
    const out = d.exportJSON(snapshotFromDocuments(d.replayedDocuments().values()).checksum);
    out.history.a[1].action = 'create'; return out;
  })()],
  ['replace after delete', (() => {
    const s = HistoryStore.baseline([doc('a')]); const d = s.clone();
    d.record('a', 'delete', null); d.record('a', 'create', doc('a', 'A', 'v2'));
    const out = d.exportJSON(snapshotFromDocuments(d.replayedDocuments().values()).checksum);
    out.history.a[2].action = 'replace'; return out;
  })()],
  ['delete with a document', (() => {
    const s = HistoryStore.baseline([doc('a')]); const d = s.clone(); d.record('a', 'delete', null);
    const out = d.exportJSON(snapshotFromDocuments(s.replayedDocuments().values()).checksum);
    out.history.a[1].document = doc('a'); return out;
  })()],
  ['document id mismatch', (() => {
    const s = HistoryStore.baseline([doc('a')]);
    const out = s.exportJSON(snapshotFromDocuments(s.replayedDocuments().values()).checksum);
    out.history.a[0].document.id = 'b'; return out;
  })()],
  ['unnormalized tags', (() => {
    const s = HistoryStore.baseline([doc('a')]);
    const out = s.exportJSON(snapshotFromDocuments(s.replayedDocuments().values()).checksum);
    out.history.a[0].document.tags = ['B', 'a']; return out;
  })()],
  ['tampered checksum', (() => {
    const s = HistoryStore.baseline([doc('a')]);
    const out = s.exportJSON(snapshotFromDocuments(s.replayedDocuments().values()).checksum);
    out.checksum = out.checksum === `${'0'.repeat(64)}` ? `${'1'.repeat(64)}` : `${'0'.repeat(64)}`;
    return out;
  })()],
  ['embedded snapshot does not match replay', (() => {
    const s = HistoryStore.baseline([doc('a', 'A', 'one')]);
    return s.exportJSON(`${'a'.repeat(64)}`);
  })()],
];

for (const [label, data] of INVALID_HISTORIES) {
  test(`invalid history rejected: ${label}`, () => {
    assert.throws(() => parseHistory(data), (error) => error instanceof HistoryError && error.code === 'INVALID_HISTORY');
  });
}
