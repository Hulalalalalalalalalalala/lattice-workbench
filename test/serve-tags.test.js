import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import test from 'node:test';
import { Workspace } from '../src/workspace.js';

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

function docMap(snapshot) {
  return new Map(snapshot.documents.map((document) => [document.id, document]));
}

// --- GET /tags --------------------------------------------------------------

test('GET /tags returns counts sorted by code point, empty array when empty, with ETag', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/tags');
    assert.equal(empty.status, 200);
    assert.deepEqual(empty.body, []);
    assert.match(empty.etag, ETAG_PATTERN);
    assert.equal(empty.etag, (await request(server.url, 'GET', '/documents')).etag);

    const et = empty.etag;
    await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'body', tags: ['Zeta', 'beta', 'beta'] },
      headers: { 'if-match': et },
    });
    let current = (await request(server.url, 'GET', '/documents')).etag;
    await request(server.url, 'POST', '/documents', {
      body: { id: 'b', title: 'B', body: 'body', tags: ['beta', 'alpha'] },
      headers: { 'if-match': current },
    });
    current = (await request(server.url, 'GET', '/documents')).etag;
    await request(server.url, 'POST', '/documents', {
      body: { id: 'c', title: 'C', body: 'body', tags: [] },
      headers: { 'if-match': current },
    });

    const tags = await request(server.url, 'GET', '/tags');
    assert.equal(tags.status, 200);
    assert.deepEqual(tags.body, [
      { tag: 'alpha', count: 1 },
      { tag: 'beta', count: 2 },
      { tag: 'zeta', count: 1 },
    ]);
    assert.match(tags.etag, ETAG_PATTERN);

    // Deleting the only user of a tag drops it and updates counts immediately.
    current = (await request(server.url, 'GET', '/documents')).etag;
    await request(server.url, 'DELETE', '/documents/b', { headers: { 'if-match': current } });
    const after = await request(server.url, 'GET', '/tags');
    assert.deepEqual(after.body, [
      { tag: 'beta', count: 1 },
      { tag: 'zeta', count: 1 },
    ]);
  } finally {
    await server.stop();
  }
});

// --- rewrite semantics ------------------------------------------------------

test('rewrite renames tags, normalizes names, and merges with dedup', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'body', tags: ['Old', 'keep'] },
    { id: 'b', title: 'B', body: 'body', tags: ['old', 'new'] },
    { id: 'c', title: 'C', body: 'body', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/tags')).etag;
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: ' OLD ', to: ' NEW ' }] },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.equal(response.etag, `"${response.body.snapshot.checksum}"`);
    const documents = docMap(response.body.snapshot);
    assert.deepEqual(documents.get('a').tags, ['keep', 'new']);
    assert.deepEqual(documents.get('b').tags, ['new']);
    assert.deepEqual(documents.get('c').tags, []);
    assert.deepEqual(response.body.changedIds, ['a', 'b']);

    const tags = await request(server.url, 'GET', '/tags');
    assert.deepEqual(tags.body, [
      { tag: 'keep', count: 1 },
      { tag: 'new', count: 2 },
    ]);
    assert.equal(tags.etag, response.etag);

    // Titles, bodies, and ids are preserved in the saved file.
    const reloaded = new Workspace();
    reloaded.importJSON(fs.readFileSync(path.join(cwd, 'snap.json'), 'utf8'), { mode: 'replace' });
    assert.deepEqual(reloaded.get('a'), { id: 'a', title: 'A', body: 'body', tags: ['keep', 'new'] });
  } finally {
    await server.stop();
  }
});

test('rewrite applies rules to the pre-rewrite set and does not chain new names', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'body', tags: ['a', 'b'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/tags')).etag;
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'a', to: 'b' }, { from: 'b', to: 'c' }] },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    // Original a -> b, original b -> c, the fresh `b` is not rewritten to c.
    assert.deepEqual(docMap(response.body.snapshot).get('a').tags, ['b', 'c']);
    assert.deepEqual(response.body.changedIds, ['a']);
  } finally {
    await server.stop();
  }
});

test('rewrite supports swapping two tag names', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'body', tags: ['x'] },
    { id: 'b', title: 'B', body: 'body', tags: ['y'] },
    { id: 'c', title: 'C', body: 'body', tags: ['x', 'y'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/tags')).etag;
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'x', to: 'y' }, { from: 'y', to: 'x' }] },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    const documents = docMap(response.body.snapshot);
    assert.deepEqual(documents.get('a').tags, ['y']);
    assert.deepEqual(documents.get('b').tags, ['x']);
    assert.deepEqual(documents.get('c').tags, ['x', 'y']);
    assert.deepEqual(response.body.changedIds.sort(), ['a', 'b']);
  } finally {
    await server.stop();
  }
});

test('rewrite with a null target removes tags', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'body', tags: ['drop', 'keep'] },
    { id: 'b', title: 'B', body: 'body', tags: ['drop'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/tags')).etag;
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'drop', to: null }] },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    const documents = docMap(response.body.snapshot);
    assert.deepEqual(documents.get('a').tags, ['keep']);
    assert.deepEqual(documents.get('b').tags, []);
    assert.deepEqual(response.body.changedIds, ['a', 'b']);
    assert.deepEqual((await request(server.url, 'GET', '/tags')).body, [{ tag: 'keep', count: 1 }]);
  } finally {
    await server.stop();
  }
});

test('changedIds lists only documents whose normalized tags actually change', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'body', tags: ['t'] },
    { id: 'b', title: 'B', body: 'body', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/tags')).etag;
    // Renaming to the same normalized name is a no-op for the document set.
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 't', to: ' T ' }] },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.changedIds, []);
    assert.equal(response.body.snapshot.checksum, et.slice(1, -1));
  } finally {
    await server.stop();
  }
});

test('rewrite processes more than 100 affected documents', async () => {
  const cwd = tempDir();
  const documents = [];
  for (let i = 0; i < 150; i += 1) {
    documents.push({ id: `d${String(i).padStart(3, '0')}`, title: `D${i}`, body: 'body', tags: ['old'] });
  }
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith(documents));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/tags')).etag;
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'new' }] },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.equal(response.body.changedIds.length, 150);
    assert.deepEqual((await request(server.url, 'GET', '/tags')).body, [{ tag: 'new', count: 150 }]);
  } finally {
    await server.stop();
  }
});

// --- dry run ----------------------------------------------------------------

test('dryRun returns the projection without changing queries, history, or files', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  writeSnapshot(file, workspaceWith([
    { id: 'a', title: 'A', body: 'body [[b]]', tags: ['old'] },
  ]));
  const before = fs.readFileSync(file, 'utf8');
  const server = await startServer([file, '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/tags')).etag;
    const preview = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'new' }], dryRun: true },
      headers: { 'if-match': et },
    });
    assert.equal(preview.status, 200);
    assert.deepEqual(docMap(preview.body.snapshot).get('a').tags, ['new']);
    assert.deepEqual(preview.body.changedIds, ['a']);

    // Nothing changed: live state, ETag, and file all stay at the baseline.
    const live = await request(server.url, 'GET', '/documents/a');
    assert.deepEqual(live.body.tags, ['old']);
    assert.equal(live.etag, et);
    assert.deepEqual((await request(server.url, 'GET', '/tags')).body, [{ tag: 'old', count: 1 }]);
    assert.equal(fs.readFileSync(file, 'utf8'), before);

    // A real commit using the same precondition then succeeds.
    const commit = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'new' }] },
      headers: { 'if-match': et },
    });
    assert.equal(commit.status, 200);
    assert.equal(commit.etag, preview.etag);
  } finally {
    await server.stop();
  }
});

test('dryRun requires If-Match like a real write', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'body', tags: ['old'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const missing = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'new' }], dryRun: true },
    });
    assert.equal(missing.status, 428);
    assert.equal(missing.body.code, 'PRECONDITION_REQUIRED');

    const et = (await request(server.url, 'GET', '/tags')).etag;
    const malformed = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'new' }], dryRun: true },
      headers: { 'if-match': 'garbage' },
    });
    assert.equal(malformed.status, 400);
    assert.equal(malformed.body.code, 'INVALID_IF_MATCH');
  } finally {
    await server.stop();
  }
});

// --- validation -------------------------------------------------------------

test('malformed rewrite requests return 400 INVALID_TAG_RULES', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'body', tags: ['old'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/tags')).etag;
    const send = async (payload, { raw = false } = {}) => {
      const response = await request(server.url, 'POST', '/tags/rewrite', raw
        ? { rawBody: payload, headers: { 'if-match': et } }
        : { body: payload, headers: { 'if-match': et } });
      assert.equal(response.status, 400, `${raw ? payload : JSON.stringify(payload)} -> ${response.status}`);
      assert.equal(response.body.code, 'INVALID_TAG_RULES');
      return response;
    };

    // Malformed JSON keeps the existing INVALID_JSON behavior.
    const badJson = await request(server.url, 'POST', '/tags/rewrite', {
      rawBody: '{not json',
      headers: { 'if-match': et },
    });
    assert.equal(badJson.status, 400);
    assert.equal(badJson.body.code, 'INVALID_JSON');

    await send({});
    await send({ rules: 'nope' });
    await send({ rules: [] });
    await send({ rules: Array.from({ length: 101 }, () => ({ from: 'old', to: 'new' })) });
    await send({ rules: [{ from: 'old', to: 'new' }], dryRun: 'yes' });
    await send({ rules: [{ from: 'old', to: 'new' }], extra: 1 });
    await send({ rules: ['nope'] });
    await send({ rules: [null] });
    await send({ rules: [{ from: 'old' }] });
    await send({ rules: [{ to: 'new' }] });
    await send({ rules: [{ from: 'old', to: 'new', x: 1 }] });
    await send({ rules: [{ from: 1, to: 'new' }] });
    await send({ rules: [{ from: 'old', to: 2 }] });
    await send({ rules: [{ from: '  ', to: 'new' }] });
    await send({ rules: [{ from: 'old', to: '   ' }] });
    await send({ rules: [{ from: 'Old', to: 'new' }, { from: 'old', to: 'other' }] });

    // None of the failed requests changed the state.
    assert.equal((await request(server.url, 'GET', '/tags')).etag, et);
  } finally {
    await server.stop();
  }
});

test('a source tag not used by any live document returns 404 TAG_NOT_FOUND for the whole request', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'body', tags: ['old', 'keep'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/tags')).etag;
    const missing = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'x' }, { from: 'ghost', to: 'y' }] },
      headers: { 'if-match': et },
    });
    assert.equal(missing.status, 404);
    assert.equal(missing.body.code, 'TAG_NOT_FOUND');

    // Even a valid rule in the same batch did not apply.
    assert.deepEqual((await request(server.url, 'GET', '/tags')).body, [
      { tag: 'keep', count: 1 },
      { tag: 'old', count: 1 },
    ]);
  } finally {
    await server.stop();
  }
});

test('a stale If-Match is 412 and concurrent same-checksum writes commit once', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'body', tags: ['old'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/tags')).etag;
    const [first, second] = await Promise.all([
      request(server.url, 'POST', '/tags/rewrite', {
        body: { rules: [{ from: 'old', to: 'one' }] },
        headers: { 'if-match': et },
      }),
      request(server.url, 'POST', '/tags/rewrite', {
        body: { rules: [{ from: 'old', to: 'two' }] },
        headers: { 'if-match': et },
      }),
    ]);
    const statuses = [first.status, second.status].sort();
    assert.deepEqual(statuses, [200, 412]);
    const loser = first.status === 412 ? first : second;
    assert.equal(loser.body.code, 'PRECONDITION_FAILED');

    const tags = await request(server.url, 'GET', '/tags');
    assert.equal(tags.body.length, 1);
    assert.ok(['one', 'two'].includes(tags.body[0].tag));
  } finally {
    await server.stop();
  }
});

test('an oversized rewrite body is 413', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/tags')).etag;
    const oversized = await request(server.url, 'POST', '/tags/rewrite', {
      rawBody: JSON.stringify({ rules: [{ from: 'old', to: 'x'.repeat(1024 * 1024) }] }),
      headers: { 'if-match': et },
    });
    assert.equal(oversized.status, 413);
    assert.equal(oversized.body.code, 'PAYLOAD_TOO_LARGE');
  } finally {
    await server.stop();
  }
});

test('a failed rewrite save returns 500 IO_ERROR and leaves memory, counts, and file intact', async () => {
  const cwd = tempDir();
  const dataDir = path.join(cwd, 'data');
  fs.mkdirSync(dataDir);
  const file = path.join(dataDir, 'snap.json');
  const server = await startServer([file, '--port', '0']);
  try {
    let et = (await request(server.url, 'GET', '/tags')).etag;
    const seeded = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'body', tags: ['old'] },
      headers: { 'if-match': et },
    });
    assert.equal(seeded.status, 201);
    assert.ok(fs.existsSync(file));

    // Remove the backing directory so the next atomic save cannot stage.
    fs.rmSync(dataDir, { recursive: true, force: true });
    et = (await request(server.url, 'GET', '/tags')).etag;
    const failed = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'new' }] },
      headers: { 'if-match': et },
    });
    assert.equal(failed.status, 500);
    assert.equal(failed.body.code, 'IO_ERROR');

    // In-memory content and counts are unchanged and the service keeps serving.
    const doc = await request(server.url, 'GET', '/documents/a');
    assert.deepEqual(doc.body.tags, ['old']);
    const tags = await request(server.url, 'GET', '/tags');
    assert.deepEqual(tags.body, [{ tag: 'old', count: 1 }]);
    assert.equal(tags.etag, et);

    // Once the directory is back, the same rewrite commits.
    fs.mkdirSync(dataDir);
    const retry = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'new' }] },
      headers: { 'if-match': et },
    });
    assert.equal(retry.status, 200);
    assert.deepEqual(retry.body.changedIds, ['a']);
  } finally {
    await server.stop();
  }
});

// --- history ----------------------------------------------------------------

function startHistory(cwd) {
  return startServer([
    path.join(cwd, 'snap.json'), '--history', path.join(cwd, 'history.json'), '--port', '0',
  ]);
}

test('history: rewrite appends one replace record per changed document and restore updates counts', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'body', tags: ['old', 'keep'] },
    { id: 'b', title: 'B', body: 'body', tags: ['old'] },
    { id: 'c', title: 'C', body: 'body', tags: [] },
  ]));
  const server = await startHistory(cwd);
  try {
    const et = (await request(server.url, 'GET', '/tags')).etag;
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'old', to: 'new' }, { from: 'keep', to: null }] },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.changedIds, ['a', 'b']);

    const rowsA = (await request(server.url, 'GET', '/documents/a/history')).body;
    assert.deepEqual(rowsA.map((entry) => entry.action), ['baseline', 'replace']);
    assert.deepEqual(rowsA[0].document.tags, ['keep', 'old']);
    assert.deepEqual(rowsA[1].document.tags, ['new']);
    const rowsB = (await request(server.url, 'GET', '/documents/b/history')).body;
    assert.deepEqual(rowsB.map((entry) => entry.action), ['baseline', 'replace']);
    // Document c was untouched: only its baseline exists.
    const rowsC = (await request(server.url, 'GET', '/documents/c/history')).body;
    assert.deepEqual(rowsC.map((entry) => entry.action), ['baseline']);

    // Restore a's baseline; the old tags return and counts update.
    const current = (await request(server.url, 'GET', '/documents')).etag;
    const restored = await request(server.url, 'POST', '/documents/a/restore', {
      body: { revision: 1 },
      headers: { 'if-match': current },
    });
    assert.equal(restored.status, 200);
    assert.deepEqual((await request(server.url, 'GET', '/documents/a')).body.tags, ['keep', 'old']);
    assert.deepEqual((await request(server.url, 'GET', '/tags')).body, [
      { tag: 'keep', count: 1 },
      { tag: 'new', count: 1 },
      { tag: 'old', count: 1 },
    ]);
  } finally {
    await server.stop();
  }

  // Restart reconstructs the whole state from snapshot + ledger.
  const restarted = await startHistory(cwd);
  try {
    const tags = await request(restarted.url, 'GET', '/tags');
    assert.deepEqual(tags.body, [
      { tag: 'keep', count: 1 },
      { tag: 'new', count: 1 },
      { tag: 'old', count: 1 },
    ]);
    const rowsA = (await request(restarted.url, 'GET', '/documents/a/history')).body;
    assert.deepEqual(rowsA.map((entry) => entry.action), ['baseline', 'replace', 'restore']);
  } finally {
    await restarted.stop();
  }
});

test('history: a no-op rewrite appends no records and writes neither file', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'body', tags: ['t'] },
  ]));
  const server = await startHistory(cwd);
  try {
    const et = (await request(server.url, 'GET', '/tags')).etag;
    const response = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 't', to: 't' }] },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.changedIds, []);
    assert.equal(response.etag, et);
    assert.deepEqual((await request(server.url, 'GET', '/documents/a/history')).body.map((entry) => entry.action), ['baseline']);
  } finally {
    await server.stop();
  }
});

test('history: deleted documents are not counted and cannot satisfy TAG_NOT_FOUND', async () => {
  const cwd = tempDir();
  const server = await startHistory(cwd);
  try {
    let et = (await request(server.url, 'GET', '/tags')).etag;
    await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'body', tags: ['gone'] },
      headers: { 'if-match': et },
    });
    et = (await request(server.url, 'GET', '/documents')).etag;
    await request(server.url, 'DELETE', '/documents/a', { headers: { 'if-match': et } });

    assert.deepEqual((await request(server.url, 'GET', '/tags')).body, []);
    const rewrite = await request(server.url, 'POST', '/tags/rewrite', {
      body: { rules: [{ from: 'gone', to: 'other' }] },
      headers: { 'if-match': (await request(server.url, 'GET', '/tags')).etag },
    });
    assert.equal(rewrite.status, 404);
    assert.equal(rewrite.body.code, 'TAG_NOT_FOUND');
  } finally {
    await server.stop();
  }
});
