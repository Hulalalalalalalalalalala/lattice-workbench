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
