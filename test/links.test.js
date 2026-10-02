import assert from 'node:assert/strict';
import test from 'node:test';
import { Workspace } from '../src/workspace.js';

// Builds a workspace with a single document whose body is the case under
// test, plus the targets it may reference. Returns the workspace and the
// source document's id.
function workspaceWith(body, targets = ['beta', 'gamma', 'delta', 'epsilon', 'zeta']) {
  const workspace = new Workspace();
  workspace.add({ id: 'source', title: 'Source', body });
  for (const target of targets) {
    workspace.add({ id: target, title: target, body: 'target body' });
  }
  return workspace;
}

function outgoing(body) {
  return workspaceWith(body).links('source').outgoing;
}

test('links in ordinary prose count as outgoing relationships', () => {
  assert.deepEqual(outgoing('see [[beta]] and [[gamma]]'), ['beta', 'gamma']);
});

test('targets are lowercased, deduplicated, and sorted', () => {
  assert.deepEqual(outgoing('[[GAMMA]] [[beta]] [[gamma]]'), ['beta', 'gamma']);
});

test('dangling or malformed references produce no relationship and no failure', () => {
  assert.deepEqual(outgoing('[[beta and [[gamma]]'), ['gamma']);
  assert.deepEqual(outgoing('[[]] [[beta]]'), ['beta']);
  assert.deepEqual(outgoing('[[beta_2]] [[gamma]]'), ['beta_2', 'gamma']);
  assert.deepEqual(outgoing('[[beta]] [[no-close'), ['beta']);
});

test('a backtick fenced code block hides its links', () => {
  assert.deepEqual(outgoing('before [[beta]]\n```\n[[gamma]]\n```\nafter [[delta]]'), ['beta', 'delta']);
});

test('a tilde fenced code block hides its links', () => {
  assert.deepEqual(outgoing('before [[beta]]\n~~~\n[[gamma]]\n~~~\nafter [[delta]]'), ['beta', 'delta']);
});

test('a fence may carry a language name', () => {
  assert.deepEqual(outgoing('```js\n[[gamma]]\n```\n[[beta]]'), ['beta']);
  assert.deepEqual(outgoing('~~~ python extra\n[[gamma]]\n~~~\n[[beta]]'), ['beta']);
});

test('a fence allows zero to three leading spaces', () => {
  assert.deepEqual(outgoing('   ```\n[[gamma]]\n   ```\n[[beta]]'), ['beta']);
});

test('four leading spaces do not open a fence', () => {
  assert.deepEqual(outgoing('    ```\n[[gamma]]\n```\n[[beta]]'), ['gamma']);
});

test('a fence is only closed by the same symbol with no fewer characters', () => {
  // Different symbol does not close: the block runs on.
  assert.deepEqual(outgoing('```\n[[gamma]]\n~~~\n[[delta]]\n```\n[[beta]]'), ['beta']);
  // Fewer characters do not close: the block runs on.
  assert.deepEqual(outgoing('````\n[[gamma]]\n```\n[[delta]]\n````\n[[beta]]'), ['beta']);
  assert.deepEqual(outgoing('~~~~\n[[gamma]]\n~~~\n[[beta]]'), []);
});

test('a closing fence may have only spaces or tabs after it', () => {
  assert.deepEqual(outgoing('```\n[[gamma]]\n```   \n[[beta]]'), ['beta']);
  assert.deepEqual(outgoing('```\n[[gamma]]\n```\t\n[[beta]]'), ['beta']);
  // Trailing text means the fence is not closed.
  assert.deepEqual(outgoing('```\n[[gamma]]\n``` x\n[[beta]]'), []);
});

test('an unclosed fence ignores links to the end of the body', () => {
  assert.deepEqual(outgoing('```\n[[gamma]]\n[[delta]]'), []);
  assert.deepEqual(outgoing('~~~\n[[gamma]]'), []);
});

test('multiple fences in one body each hide their links', () => {
  assert.deepEqual(
    outgoing('[[beta]]\n```\n[[gamma]]\n```\n[[delta]]\n~~~\n[[epsilon]]\n~~~\n[[zeta]]'),
    ['beta', 'delta', 'zeta'],
  );
});

test('LF and CRLF newlines give identical results', () => {
  const lf = 'before [[beta]]\n```\n[[gamma]]\n```\nafter [[delta]]';
  const crlf = lf.replace(/\n/gu, '\r\n');
  assert.deepEqual(outgoing(crlf), outgoing(lf));
  assert.deepEqual(outgoing('```\r\n[[gamma]]\r\n[[delta]]'), []);
});

test('inline code spans hide their links', () => {
  assert.deepEqual(outgoing('see `[[gamma]]` and [[beta]]'), ['beta']);
  assert.deepEqual(outgoing('see ``[[gamma]]`` [[beta]]'), ['beta']);
});

test('inline code may span lines', () => {
  assert.deepEqual(outgoing('see `a\n[[gamma]]\n` and [[beta]]'), ['beta']);
});

test('shorter or longer backtick runs inside a code span do not close it', () => {
  assert.deepEqual(outgoing('``a ` b`` [[beta]]'), ['beta']);
  assert.deepEqual(outgoing('x ````a```b```` [[beta]]'), ['beta']);
});

test('an unclosed inline code run is literal and later links still count', () => {
  assert.deepEqual(outgoing('`[[gamma]] and [[beta]]'), ['beta', 'gamma']);
  assert.deepEqual(outgoing('``[[gamma]] and [[beta]]'), ['beta', 'gamma']);
});

test('inline code cannot cross a fence boundary', () => {
  assert.deepEqual(outgoing('`[[gamma]]\n```\n[[delta]]\n```\n[[beta]]'), ['beta', 'gamma']);
  assert.deepEqual(outgoing('`a\n```\n[[gamma]]\n```\n[[beta]]'), ['beta']);
});

test('a backslash-escaped reference is literal', () => {
  assert.deepEqual(outgoing('\\[[gamma]] [[beta]]'), ['beta']);
  assert.deepEqual(outgoing('\\\\\\[[gamma]] [[beta]]'), ['beta']);
});

test('an even run of backslashes does not escape', () => {
  assert.deepEqual(outgoing('\\\\[[gamma]] [[beta]]'), ['beta', 'gamma']);
  assert.deepEqual(outgoing('\\\\\\\\[[gamma]] [[beta]]'), ['beta', 'gamma']);
});

test('a backslash not immediately before the bracket does not escape', () => {
  assert.deepEqual(outgoing('\\ [[gamma]] [[beta]]'), ['beta', 'gamma']);
});

test('a target in both code and prose still counts from the prose', () => {
  assert.deepEqual(outgoing('[[beta]] and `[[beta]]`'), ['beta']);
});

test('incoming links follow the same rules and exclude self references', () => {
  const workspace = new Workspace();
  workspace.add({ id: 'a', title: 'A', body: '[[b]] and `[[c]]`' });
  workspace.add({ id: 'b', title: 'B', body: '[[a]] `[[a]]`' });
  workspace.add({ id: 'c', title: 'C', body: '[[a]]' });
  workspace.add({ id: 'me', title: 'Me', body: '[[me]]' });
  assert.deepEqual(workspace.links('a'), { outgoing: ['b'], incoming: ['b', 'c'] });
  assert.deepEqual(workspace.links('b'), { outgoing: ['a'], incoming: ['a'] });
  assert.deepEqual(workspace.links('c'), { outgoing: ['a'], incoming: [] });
  assert.deepEqual(workspace.links('me'), { outgoing: ['me'], incoming: [] });
});

test('links returns null for a missing document', () => {
  const workspace = new Workspace();
  assert.equal(workspace.links('missing'), null);
});

test('links reflect the current body after edits and imports', () => {
  const workspace = new Workspace();
  workspace.add({ id: 'a', title: 'A', body: '[[beta]]' });
  workspace.add({ id: 'beta', title: 'B', body: '[[a]]' });
  assert.deepEqual(workspace.links('a').outgoing, ['beta']);
  // Editing the body updates links immediately.
  workspace.remove('a');
  workspace.add({ id: 'a', title: 'A', body: '```\n[[beta]]\n```' });
  assert.deepEqual(workspace.links('a').outgoing, []);
  // Deleting a target does not rewrite the referrer's body.
  workspace.remove('beta');
  assert.equal(workspace.get('a').body, '```\n[[beta]]\n```');
  assert.deepEqual(workspace.links('a').outgoing, []);
  // Imported content derives links from the current bodies.
  const imported = new Workspace();
  imported.importJSON(workspace.exportJSON(), { mode: 'replace' });
  assert.deepEqual(imported.links('a').outgoing, []);
});
