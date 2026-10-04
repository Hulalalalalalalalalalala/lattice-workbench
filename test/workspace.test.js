import assert from 'node:assert/strict';
import test from 'node:test';
import { Workspace } from '../src/workspace.js';

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

test('rejects a duplicate trimmed title and leaves the workspace untouched', () => {
  const workspace = new Workspace();
  workspace.add({ id: 'plan', title: '项目计划', body: 'Original body.', tags: ['Roadmap'] });
  for (const title of ['项目计划', ' 项目计划 ']) {
    let error = null;
    try {
      workspace.add({ id: 'other', title, body: 'Other body.' });
    } catch (caught) {
      error = caught;
    }
    assert.ok(error instanceof Error && !(error instanceof TypeError));
    assert.equal(error.message, 'title already in use: 项目计划');
    assert.equal(workspace.get('other'), null);
  }
  // The original document is intact and every query reflects the pre-add state.
  assert.deepEqual(workspace.get('plan'), {
    id: 'plan', title: '项目计划', body: 'Original body.', tags: ['roadmap'],
  });
  assert.deepEqual(workspace.list().map((document) => document.id), ['plan']);
  assert.deepEqual(workspace.search('项目').map((document) => document.id), ['plan']);
  const snapshot = workspace.exportJSON();
  assert.throws(() => workspace.add({ id: 'other', title: '项目计划', body: 'Other body.' }), /title already in use/u);
  assert.deepEqual(workspace.exportJSON(), snapshot);
});

test('titles stay case-sensitive and are released by removal', () => {
  const workspace = new Workspace();
  workspace.add({ id: 'upper', title: 'Plan', body: 'Upper.' });
  workspace.add({ id: 'lower', title: 'plan', body: 'Lower.' });
  assert.deepEqual(workspace.list().map((document) => document.id), ['lower', 'upper']);

  // A removed document's title can be reused by a different id; before the
  // removal it cannot.
  assert.throws(() => workspace.add({ id: 'next', title: ' Plan ', body: 'Next.' }), /title already in use: Plan/u);
  assert.equal(workspace.remove('upper'), true);
  workspace.add({ id: 'next', title: ' Plan ', body: 'Next.' });
  assert.equal(workspace.get('next').title, 'Plan');
  assert.equal(workspace.get('upper'), null);
});
