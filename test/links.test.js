import assert from 'node:assert/strict';
import test from 'node:test';
import { Workspace, linksFrom } from '../src/workspace.js';

// ---- Extractor: fenced code blocks ----------------------------------------

test('ignores [[references]] inside backtick and tilde fenced code blocks', () => {
  const body = [
    'See [[alpha]] first.',
    '```',
    'const x = "[[beta]]";',
    '```',
    '~~~',
    '[[gamma]]',
    '~~~',
    'Then [[delta]].',
  ].join('\n');
  assert.deepEqual(linksFrom(body), ['alpha', 'delta']);
});

test('fence openers allow up to three leading spaces and an info string', () => {
  const body = '   ```js extra\n[[beta]]\n  ```\n[[gamma]]';
  assert.deepEqual(linksFrom(body), ['gamma']);
});

test('four leading spaces do not open a fence', () => {
  assert.deepEqual(linksFrom('    ```\n[[beta]]'), ['beta']);
});

test('a different marker or a shorter run cannot close a fence', () => {
  // Tilde line cannot close a backtick fence; [[gamma]] stays inside it.
  assert.deepEqual(linksFrom('```\n[[beta]]\n~~~\n[[gamma]]'), []);
  // A three-run close is too short for a four-run opener.
  const body = '````\n[[beta]]\n```\n[[gamma]]\n````\n[[delta]]';
  assert.deepEqual(linksFrom(body), ['delta']);
});

test('a closing fence at least as long as the opener closes it', () => {
  assert.deepEqual(linksFrom('```\n[[beta]]\n`````\n[[gamma]]'), ['gamma']);
});

test('text after the closing marker keeps the fence open', () => {
  const body = '```\n[[beta]]\n``` trailing\n[[gamma]]\n```\n[[delta]]';
  assert.deepEqual(linksFrom(body), ['delta']);
});

test('an unclosed fence ignores references through the end of the body', () => {
  assert.deepEqual(linksFrom('prose [[alpha]]\n```\n[[beta]]\nmore'), ['alpha']);
});

test('fence parsing is identical for LF and CRLF bodies', () => {
  const lf = 'See [[alpha]]\n```\n[[beta]]\n```\n[[gamma]]';
  const crlf = lf.replaceAll('\n', '\r\n');
  assert.deepEqual(linksFrom(crlf), linksFrom(lf));
  assert.deepEqual(linksFrom(crlf), ['alpha', 'gamma']);
});

// ---- Extractor: inline code -----------------------------------------------

test('ignores references inside inline code', () => {
  assert.deepEqual(linksFrom('a `[[beta]]` b [[gamma]]'), ['gamma']);
});

test('inline code may use multiple backticks and span lines', () => {
  assert.deepEqual(linksFrom('``[[beta]]`` [[gamma]]'), ['gamma']);
  assert.deepEqual(linksFrom('a `[[beta]]\nnext line` [[gamma]]'), ['gamma']);
});

test('shorter or longer inner backtick runs do not end an inline span', () => {
  assert.deepEqual(linksFrom('`` [[beta]] ` `` [[gamma]]'), ['gamma']);
  assert.deepEqual(linksFrom('`` [[beta]] ``` `` [[gamma]]'), ['gamma']);
});

test('an unmatched opening backtick run is ordinary text', () => {
  assert.deepEqual(linksFrom('a `x [[beta]] end'), ['beta']);
});

test('inline code never crosses a fenced block boundary', () => {
  // The lone backtick never finds its closer, so the first reference counts;
  // the fence still opens and closes on its own marker.
  const body = '` [[beta]]\n```\n[[inside]]\n```\n[[gamma]]';
  assert.deepEqual(linksFrom(body), ['beta', 'gamma']);
});

// ---- Extractor: escapes ----------------------------------------------------

test('an odd run of preceding backslashes escapes a reference', () => {
  assert.deepEqual(linksFrom('\\[[beta]]'), []);
  assert.deepEqual(linksFrom('\\\[[beta]]'), []);
});

test('an even run of preceding backslashes keeps the reference', () => {
  assert.deepEqual(linksFrom('\\\\[[beta]]'), ['beta']);
});

test('the escape run is the backslashes immediately before the first bracket', () => {
  assert.deepEqual(linksFrom('a \\[[beta]] then [[gamma]]'), ['gamma']);
});

// ---- Extractor: malformed references --------------------------------------

test('unclosed brackets or non-identifier targets produce no link', () => {
  assert.deepEqual(linksFrom('[[beta [[gamma]]'), ['gamma']);
  assert.deepEqual(linksFrom('[[Beta!]] [[gamma]]'), ['gamma']);
  assert.deepEqual(linksFrom('[[]] [[gamma]]'), ['gamma']);
});

// ---- Workspace semantics ---------------------------------------------------

function workspaceWith(documents) {
  const workspace = new Workspace();
  for (const document of documents) workspace.add(document);
  return workspace;
}

test('code samples do not create relationships but prose references still do', () => {
  const workspace = workspaceWith([
    {
      id: 'alpha',
      title: 'Alpha',
      body: 'Prose [[beta]], sample `[[gamma]]`, and a block:\n```\n[[delta]]\n```\nend.',
      tags: [],
    },
    { id: 'beta', title: 'Beta', body: 'back to [[alpha]]', tags: [] },
    { id: 'gamma', title: 'Gamma', body: 'gamma body', tags: [] },
    { id: 'delta', title: 'Delta', body: 'delta body', tags: [] },
  ]);
  assert.deepEqual(workspace.links('alpha'), { outgoing: ['beta'], incoming: ['beta'] });
  assert.deepEqual(workspace.links('gamma'), { outgoing: [], incoming: [] });
  assert.deepEqual(workspace.links('delta'), { outgoing: [], incoming: [] });
  assert.deepEqual(workspace.links('beta'), { outgoing: ['alpha'], incoming: ['alpha'] });
});

test('a target appearing in both prose and code is still linked once', () => {
  const workspace = workspaceWith([
    { id: 'alpha', title: 'Alpha', body: '`[[beta]]` plus [[beta]] and \\[[beta]]', tags: [] },
    { id: 'beta', title: 'Beta', body: 'see [[alpha]]', tags: [] },
  ]);
  assert.deepEqual(workspace.links('alpha'), { outgoing: ['beta'], incoming: ['beta'] });
  assert.deepEqual(workspace.links('beta'), { outgoing: ['alpha'], incoming: ['alpha'] });
});

test('dangling, normalized, and self references follow the existing rules', () => {
  const workspace = workspaceWith([
    { id: 'alpha', title: 'Alpha', body: '[[GHOST]] [[ghost]] [[alpha]]', tags: [] },
  ]);
  // Case normalizes and duplicates collapse; a self reference stays in
  // outgoing but never lists the document itself under incoming.
  assert.deepEqual(workspace.links('alpha'), { outgoing: ['alpha', 'ghost'], incoming: [] });
  assert.equal(workspace.links('missing'), null);
});

test('relationships update immediately after editing and code text stays searchable', () => {
  const workspace = workspaceWith([
    { id: 'alpha', title: 'Alpha', body: 'start', tags: [] },
    { id: 'beta', title: 'Beta', body: 'beta body', tags: [] },
  ]);
  assert.deepEqual(workspace.links('beta'), { outgoing: [], incoming: [] });
  workspace.remove('alpha');
  workspace.add({
    id: 'alpha',
    title: 'Alpha',
    body: 'updated `[[beta]]`\n```\n[[beta]]\n```\nreal [[beta]]',
    tags: [],
  });
  assert.deepEqual(workspace.links('alpha'), { outgoing: ['beta'], incoming: [] });
  assert.deepEqual(workspace.links('beta'), { outgoing: [], incoming: ['alpha'] });
  // Full-text search still indexes the literal code sample.
  assert.equal(workspace.search('[[beta]]').length, 1);
  // Querying links never rewrites the stored body.
  workspace.links('alpha');
  assert.match(workspace.get('alpha').body, /```/u);
});
