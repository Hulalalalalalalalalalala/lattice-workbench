import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import test from 'node:test';
import { Workspace, snapshotFromDocuments } from '../src/workspace.js';
import { HistoryStore } from '../src/history.js';

const CLI = path.resolve('src/cli.js');

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-tags-'));
}

function writeSnapshot(file, workspace) {
  fs.writeFileSync(file, `${JSON.stringify(workspace.exportJSON())}\n`);
}

function workspaceWith(documents) {
  const workspace = new Workspace();
  for (const document of documents) workspace.add(document);
  return workspace;
}

async function startServer(args, { cwd } = {}) {
  const child = spawn(process.execPath, [CLI, 'serve', ...args], { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const address = await new Promise((resolve, reject) => {
    child.stdout.on('data', () => {
      const index = stdout.indexOf('\n');
      if (index === -1) return;
      try {
        resolve(JSON.parse(stdout.slice(0, index)));
      } catch (error) {
        reject(error);
      }
    });
    child.on('exit', (code) => reject(new Error(`server exited with status ${code}: ${stderr.trim()}`)));
  });
  return {
    child,
    address,
    url: `http://${address.host}:${address.port}`,
    stdout: () => stdout,
    stderr: () => stderr,
    stop: () => new Promise((resolve) => {
      child.once('exit', resolve);
      child.kill('SIGKILL');
    }),
  };
}

async function request(base, method, route, { body, rawBody, headers = {} } = {}) {
  const response = await fetch(`${base}${route}`, {
    method,
    headers: {
      ...(body !== undefined || rawBody !== undefined ? { 'content-type': 'application/json' } : {}),
      ...headers,
    },
    body: rawBody ?? (body !== undefined ? JSON.stringify(body) : undefined),
  });
  const text = await response.text();
  return {
    status: response.status,
    etag: response.headers.get('etag'),
    body: text ? JSON.parse(text) : null,
  };
}

const ETAG_PATTERN = /^"[0-9a-f]{64}"$/u;

// --- GET /tags ---------------------------------------------------------------

test('GET /tags returns tag counts sorted by code point with the current ETag', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: ['zeta', 'alpha', 'mu'] },
    { id: 'b', title: 'Beta', body: 'b', tags: ['alpha', 'mu'] },
    { id: 'c', title: 'Gamma', body: 'c', tags: ['alpha'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const response = await request(server.url, 'GET', '/tags');
    assert.equal(response.status, 200);
    assert.deepEqual(response.body, [
      { tag: 'alpha', count: 3 },
      { tag: 'mu', count: 2 },
      { tag: 'zeta', count: 1 },
    ]);
    assert.match(response.etag, ETAG_PATTERN);
    // The ETag is the current workspace checksum.
    const docs = await request(server.url, 'GET', '/documents');
    assert.equal(response.etag, docs.etag);
  } finally {
    await server.stop();
  }
});

test('GET /tags on an empty workspace returns an empty array', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const response = await request(server.url, 'GET', '/tags');
    assert.equal(response.status, 200);
    assert.deepEqual(response.body, []);
    assert.match(response.etag, ETAG_PATTERN);
  } finally {
    await server.stop();
  }
});

test('GET /tags updates immediately after a document write', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    let et = (await request(server.url, 'GET', '/documents')).etag;
    await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'b', tags: ['one'] },
      headers: { 'if-match': et },
    });
    et = (await request(server.url, 'GET', '/documents')).etag;
    await request(server.url, 'POST', '/documents', {
      body: { id: 'b', title: 'B', body: 'b', tags: ['one', 'two'] },
      headers: { 'if-match': et },
    });

    const tags = await request(server.url, 'GET', '/tags');
    assert.deepEqual(tags.body, [{ tag: 'one', count: 2 }, { tag: 'two', count: 1 }]);

    // Deleting a document updates the counts too.
    et = (await request(server.url, 'GET', '/documents')).etag;
    await request(server.url, 'DELETE', '/documents/a', { headers: { 'if-match': et } });
    const after = await request(server.url, 'GET', '/tags');
    // Only b remains, with tags ['one', 'two'].
    assert.deepEqual(after.body, [{ tag: 'one', count: 1 }, { tag: 'two', count: 1 }]);
  } finally {
    await server.stop();
  }
});

// --- POST /tags/rewrite: basic semantics -------------------------------------

test('rewrite renames a tag and merges into an existing target with dedupe', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: ['old', 'keep'] },
    { id: 'b', title: 'Beta', body: 'b', tags: ['old'] },
    { id: 'c', title: 'Gamma', body: 'c', tags: ['keep'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'keep' }] },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.match(response.etag, ETAG_PATTERN);
    assert.equal(response.etag, `"${response.body.snapshot.checksum}"`);
    assert.deepEqual(response.body.changedIds, ['a', 'b']);
    assert.deepEqual(response.body.snapshot.documents.find((d) => d.id === 'a').tags, ['keep']);
    assert.deepEqual(response.body.snapshot.documents.find((d) => d.id === 'b').tags, ['keep']);
    assert.deepEqual(response.body.snapshot.documents.find((d) => d.id === 'c').tags, ['keep']);

    // Stored state matches.
    const docs = await request(server.url, 'GET', '/documents');
    assert.deepEqual(docs.body.find((d) => d.id === 'a').tags, ['keep']);
    const tags = await request(server.url, 'GET', '/tags');
    assert.deepEqual(tags.body, [{ tag: 'keep', count: 3 }]);
  } finally {
    await server.stop();
  }
});

test('rewrite with to:null removes the tag', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: ['remove', 'keep'] },
    { id: 'b', title: 'Beta', body: 'b', tags: ['remove'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'remove', to: null }] },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.changedIds, ['a', 'b']);
    assert.deepEqual(response.body.snapshot.documents.find((d) => d.id === 'a').tags, ['keep']);
    assert.deepEqual(response.body.snapshot.documents.find((d) => d.id === 'b').tags, []);
    const tags = await request(server.url, 'GET', '/tags');
    assert.deepEqual(tags.body, [{ tag: 'keep', count: 1 }]);
  } finally {
    await server.stop();
  }
});

test('rewrite applies rules simultaneously: a->b and b->c chains original tags only', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: ['a', 'b'] },
    { id: 'b', title: 'Beta', body: 'b', tags: ['b'] },
    { id: 'c', title: 'Gamma', body: 'c', tags: ['a'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'a', to: 'b' }, { from: 'b', to: 'c' }] },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    // Original a -> b (not re-chained to c); original b -> c.
    assert.deepEqual(response.body.snapshot.documents.find((d) => d.id === 'a').tags, ['b', 'c']);
    assert.deepEqual(response.body.snapshot.documents.find((d) => d.id === 'b').tags, ['c']);
    assert.deepEqual(response.body.snapshot.documents.find((d) => d.id === 'c').tags, ['b']);
    assert.deepEqual(response.body.changedIds, ['a', 'b', 'c']);
  } finally {
    await server.stop();
  }
});

test('rewrite allows swapping tag names', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: ['a'] },
    { id: 'b', title: 'Beta', body: 'b', tags: ['b'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'a', to: 'b' }, { from: 'b', to: 'a' }] },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.snapshot.documents.find((d) => d.id === 'a').tags, ['b']);
    assert.deepEqual(response.body.snapshot.documents.find((d) => d.id === 'b').tags, ['a']);
    assert.deepEqual(response.body.changedIds, ['a', 'b']);
  } finally {
    await server.stop();
  }
});

test('rewrite normalizes names (trim, lowercase) before applying', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: ['Hello World'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: '  HELLO WORLD  ', to: '  New Tag  ' }] },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.snapshot.documents.find((d) => d.id === 'a').tags, ['new tag']);
  } finally {
    await server.stop();
  }
});

test('rewrite processes more than 100 affected documents', async () => {
  const cwd = tempDir();
  const docs = [];
  for (let i = 0; i < 150; i += 1) {
    docs.push({ id: `d${String(i).padStart(4, '0')}`, title: `Doc ${i}`, body: 'b', tags: ['old'] });
  }
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith(docs));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'new' }] },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.equal(response.body.changedIds.length, 150);
    assert.deepEqual(response.body.changedIds, [...response.body.changedIds].sort());
    for (const doc of response.body.snapshot.documents) {
      assert.deepEqual(doc.tags, ['new']);
    }
    const tags = await request(server.url, 'GET', '/tags');
    assert.deepEqual(tags.body, [{ tag: 'new', count: 150 }]);
  } finally {
    await server.stop();
  }
});

test('rewrite leaves ids, titles, bodies, and links untouched', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'links [[b]] and [[ghost]]', tags: ['old'] },
    { id: 'b', title: 'Beta', body: 'links [[a]]', tags: ['old'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'new' }] },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    const a = response.body.snapshot.documents.find((d) => d.id === 'a');
    assert.equal(a.title, 'Alpha');
    assert.equal(a.body, 'links [[b]] and [[ghost]]');
    const linksA = await request(server.url, 'GET', '/documents/a/links');
    assert.deepEqual(linksA.body, { outgoing: ['b', 'ghost'], incoming: ['b'] });
    const linksB = await request(server.url, 'GET', '/documents/b/links');
    assert.deepEqual(linksB.body, { outgoing: ['a'], incoming: ['a'] });
  } finally {
    await server.stop();
  }
});

// --- dryRun ------------------------------------------------------------------

test('rewrite dryRun returns the projected result without changing state or files', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  writeSnapshot(file, workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: ['old'] },
  ]));
  const server = await startServer([file, '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const before = fs.readFileSync(file, 'utf8');
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'new' }], dryRun: true },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.changedIds, ['a']);
    assert.deepEqual(response.body.snapshot.documents.find((d) => d.id === 'a').tags, ['new']);
    assert.match(response.etag, ETAG_PATTERN);

    // State and file unchanged.
    const docs = await request(server.url, 'GET', '/documents');
    assert.deepEqual(docs.body.find((d) => d.id === 'a').tags, ['old']);
    assert.equal(docs.etag, et);
    assert.equal(fs.readFileSync(file, 'utf8'), before);
  } finally {
    await server.stop();
  }
});

test('rewrite dryRun still requires If-Match', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: ['old'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const missing = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'new' }], dryRun: true },
    });
    assert.equal(missing.status, 428);

    const malformed = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'new' }], dryRun: true },
      headers: { 'if-match': 'garbage' },
    });
    assert.equal(malformed.status, 400);

    const stale = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'new' }], dryRun: true },
      headers: { 'if-match': `"${'0'.repeat(64)}"` },
    });
    assert.equal(stale.status, 412);
  } finally {
    await server.stop();
  }
});

// --- No-op rewrite -----------------------------------------------------------

test('rewrite that changes no tags returns the current snapshot and empty changedIds without writing', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  writeSnapshot(file, workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: ['old'] },
  ]));
  const server = await startServer([file, '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const before = fs.readFileSync(file, 'utf8');
    // Renaming old->old is a no-op.
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'old' }] },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.equal(response.etag, et);
    assert.deepEqual(response.body.changedIds, []);
    // The snapshot is the current on-disk snapshot, untouched.
    assert.deepEqual(response.body.snapshot, JSON.parse(before));
    assert.equal(fs.readFileSync(file, 'utf8'), before);
  } finally {
    await server.stop();
  }
});

// --- Validation errors -------------------------------------------------------

test('rewrite rejects structural and type errors with INVALID_TAG_RULES', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: ['old'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const send = (payload) => request(server.url, 'POST', '/tags/rewrite', {
      body: payload,
      headers: { 'if-match': et },
    });
    for (const [label, payload] of [
      ['not an object', []],
      ['null', null],
      ['missing rules', {}],
      ['rules not array', { rules: {} }],
      ['empty rules', { rules: [] }],
      ['too many rules', { rules: Array.from({ length: 101 }, (_, i) => ({ from: `t${i}`, to: 'x' })) }],
      ['unknown envelope field', { rules: [{ from: 'old', to: 'new' }], extra: 1 }],
      ['dryRun not boolean', { rules: [{ from: 'old', to: 'new' }], dryRun: 'yes' }],
      ['rule not object', { rules: ['nope'] }],
      ['rule missing to', { rules: [{ from: 'old' }] }],
      ['rule missing from', { rules: [{ to: 'new' }] }],
      ['rule extra field', { rules: [{ from: 'old', to: 'new', extra: 1 }] }],
      ['from not string', { rules: [{ from: 123, to: 'new' }] }],
      ['to not string or null', { rules: [{ from: 'old', to: 123 }] }],
      ['from normalizes empty', { rules: [{ from: '   ', to: 'new' }] }],
      ['to normalizes empty', { rules: [{ from: 'old', to: '   ' }] }],
      ['duplicate normalized from', { rules: [{ from: '  Old  ', to: 'x' }, { from: 'old', to: 'y' }] }],
    ]) {
      const response = await send(payload);
      assert.equal(response.status, 400, label);
      assert.equal(response.body.code, 'INVALID_TAG_RULES', label);
    }
  } finally {
    await server.stop();
  }
});

test('rewrite rejects illegal JSON and oversized bodies with existing codes', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: ['old'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const illegal = await request(server.url, 'POST', '/tags/rewrite', {
      rawBody: '{not json',
      headers: { 'if-match': et },
    });
    assert.equal(illegal.status, 400);
    assert.equal(illegal.body.code, 'INVALID_JSON');

    const oversized = await request(server.url, 'POST', '/tags/rewrite', {
      rawBody: JSON.stringify({ rules: [{ from: 'x'.repeat(1024 * 1024), to: 'new' }] }),
      headers: { 'if-match': et },
    });
    assert.equal(oversized.status, 413);
    assert.equal(oversized.body.code, 'PAYLOAD_TOO_LARGE');
  } finally {
    await server.stop();
  }
});

// --- TAG_NOT_FOUND -----------------------------------------------------------

test('rewrite rejects a source tag not used by any document with TAG_NOT_FOUND', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: ['old'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'ghost', to: 'new' }] },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 404);
    assert.equal(response.body.code, 'TAG_NOT_FOUND');

    // State unchanged.
    const docs = await request(server.url, 'GET', '/documents');
    assert.deepEqual(docs.body.find((d) => d.id === 'a').tags, ['old']);
    assert.equal(docs.etag, et);
  } finally {
    await server.stop();
  }
});

test('rewrite with one unused source among valid rules rejects the whole request', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: ['old'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'new' }, { from: 'ghost', to: 'x' }] },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 404);
    assert.equal(response.body.code, 'TAG_NOT_FOUND');
    const docs = await request(server.url, 'GET', '/documents');
    assert.deepEqual(docs.body.find((d) => d.id === 'a').tags, ['old']);
  } finally {
    await server.stop();
  }
});

test('rewrite TAG_NOT_FOUND also applies to dryRun', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: ['old'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'ghost', to: 'new' }], dryRun: true },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 404);
    assert.equal(response.body.code, 'TAG_NOT_FOUND');
  } finally {
    await server.stop();
  }
});

// --- History -----------------------------------------------------------------

test('rewrite with history appends one replace record per changed document', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: ['old'] },
    { id: 'b', title: 'Beta', body: 'b', tags: ['old'] },
    { id: 'c', title: 'Gamma', body: 'c', tags: ['keep'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--history', path.join(cwd, 'h.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'new' }] },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.changedIds, ['a', 'b']);

    // a and b each have baseline(1) + replace(2); c has only baseline(1).
    const rowsA = (await request(server.url, 'GET', '/documents/a/history')).body;
    assert.deepEqual(rowsA.map((e) => [e.revision, e.action]), [[1, 'baseline'], [2, 'replace']]);
    assert.deepEqual(rowsA[1].document.tags, ['new']);
    const rowsB = (await request(server.url, 'GET', '/documents/b/history')).body;
    assert.deepEqual(rowsB.map((e) => [e.revision, e.action]), [[1, 'baseline'], [2, 'replace']]);
    const rowsC = (await request(server.url, 'GET', '/documents/c/history')).body;
    assert.deepEqual(rowsC.map((e) => [e.revision, e.action]), [[1, 'baseline']]);
  } finally {
    await server.stop();
  }
});

test('rewrite no-op with history appends no record and does not touch files', async () => {
  const cwd = tempDir();
  const histFile = path.join(cwd, 'h.json');
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: ['old'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--history', histFile, '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'old' }] },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.changedIds, []);
    // History file was never created.
    assert.ok(!fs.existsSync(histFile));
    const rows = (await request(server.url, 'GET', '/documents/a/history')).body;
    assert.deepEqual(rows.map((e) => [e.revision, e.action]), [[1, 'baseline']]);
  } finally {
    await server.stop();
  }
});

test('rewrite dryRun with history appends no record', async () => {
  const cwd = tempDir();
  const histFile = path.join(cwd, 'h.json');
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: ['old'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--history', histFile, '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'new' }], dryRun: true },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.changedIds, ['a']);
    assert.ok(!fs.existsSync(histFile));
    const rows = (await request(server.url, 'GET', '/documents/a/history')).body;
    assert.deepEqual(rows.map((e) => [e.revision, e.action]), [[1, 'baseline']]);
  } finally {
    await server.stop();
  }
});

test('restore after a rewrite brings the old tags back and stats update', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: ['old'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--history', path.join(cwd, 'h.json'), '--port', '0']);
  try {
    let et = (await request(server.url, 'GET', '/documents')).etag;
    await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'new' }] },
      headers: { 'if-match': et },
    });
    et = (await request(server.url, 'GET', '/documents')).etag;
    const restored = await request(server.url, 'POST', '/documents/a/restore', {
      body: { revision: 1 },
      headers: { 'if-match': et },
    });
    assert.equal(restored.status, 200);
    assert.deepEqual(restored.body.documents.find((d) => d.id === 'a').tags, ['old']);
    const tags = await request(server.url, 'GET', '/tags');
    assert.deepEqual(tags.body, [{ tag: 'old', count: 1 }]);
  } finally {
    await server.stop();
  }
});

// --- Concurrency -------------------------------------------------------------

test('rewrite concurrent with another write: at most one commits per old checksum', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: ['old'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const [first, second] = await Promise.all([
      request(server.url, 'POST', '/tags/rewrite', {
        body: { rules: [{ from: 'old', to: 'new' }] },
        headers: { 'if-match': et },
      }),
      request(server.url, 'POST', '/documents', {
        body: { id: 'b', title: 'B', body: 'b', tags: [] },
        headers: { 'if-match': et },
      }),
    ]);
    const statuses = [first.status, second.status].sort();
    assert.deepEqual(statuses, [200, 412]);
  } finally {
    await server.stop();
  }
});

// --- Save failure ------------------------------------------------------------

test('rewrite failed save returns 500 IO_ERROR and leaves state and files intact', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  writeSnapshot(snapFile, workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: ['old'] },
  ]));
  // Make the directory read-only so the staging write fails with EACCES.
  fs.chmodSync(cwd, 0o500);
  const server = await startServer([snapFile, '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const failed = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'new' }] },
      headers: { 'if-match': et },
    });
    assert.equal(failed.status, 500);
    assert.equal(failed.body.code, 'IO_ERROR');

    // State, stats, and the original file are unchanged.
    const docs = await request(server.url, 'GET', '/documents');
    assert.deepEqual(docs.body.find((d) => d.id === 'a').tags, ['old']);
    assert.equal(docs.etag, et);
    const tags = await request(server.url, 'GET', '/tags');
    assert.deepEqual(tags.body, [{ tag: 'old', count: 1 }]);
    const onDisk = JSON.parse(fs.readFileSync(snapFile, 'utf8'));
    assert.deepEqual(onDisk.documents.find((d) => d.id === 'a').tags, ['old']);
  } finally {
    fs.chmodSync(cwd, 0o700);
    await server.stop();
  }
});

// --- Crash recovery atomicity ------------------------------------------------

test('rewrite restart after a kill presents a whole pre-rewrite or post-rewrite state', async () => {
  const cwd = tempDir();
  const snapshotPath = path.join(cwd, 'snap.json');
  const historyPath = path.join(cwd, 'h.json');
  const backupPath = `${historyPath}.bak`;
  const baseDocuments = [{ id: 'a', title: 'Alpha', body: 'a', tags: ['old'] }];

  const before = (() => {
    const store = HistoryStore.baseline(baseDocuments.map((d) => structuredClone(d)));
    const snapshot = snapshotFromDocuments(store.replayedDocuments().values());
    return { snapshot, history: store.exportJSON(snapshot.checksum) };
  })();
  const after = (() => {
    const store = HistoryStore.baseline(baseDocuments.map((d) => structuredClone(d)));
    const draft = store.clone();
    draft.record('a', 'replace', { id: 'a', title: 'Alpha', body: 'a', tags: ['new'] });
    const snapshot = snapshotFromDocuments(draft.replayedDocuments().values());
    return { snapshot, history: draft.exportJSON(snapshot.checksum) };
  })();

  // Window A: old history moved aside, new not installed -> pre-rewrite state.
  fs.writeFileSync(snapshotPath, JSON.stringify(before.snapshot));
  fs.writeFileSync(backupPath, JSON.stringify(before.history));
  let server = await startServer([snapshotPath, '--history', historyPath, '--port', '0']);
  try {
    const doc = await request(server.url, 'GET', '/documents/a');
    assert.deepEqual(doc.body.tags, ['old']);
    assert.ok(!fs.existsSync(backupPath));
  } finally {
    await server.stop();
  }

  // Window B: new history landed, snapshot not yet -> post-rewrite state reconstructed.
  fs.writeFileSync(snapshotPath, JSON.stringify(before.snapshot));
  fs.writeFileSync(historyPath, JSON.stringify(after.history));
  fs.writeFileSync(backupPath, JSON.stringify(before.history));
  server = await startServer([snapshotPath, '--history', historyPath, '--port', '0']);
  try {
    const doc = await request(server.url, 'GET', '/documents/a');
    assert.deepEqual(doc.body.tags, ['new']);
    const tags = await request(server.url, 'GET', '/tags');
    assert.deepEqual(tags.body, [{ tag: 'new', count: 1 }]);
    const onDisk = JSON.parse(fs.readFileSync(snapshotPath, 'utf8'));
    assert.equal(onDisk.checksum, after.snapshot.checksum);
  } finally {
    await server.stop();
  }
});
