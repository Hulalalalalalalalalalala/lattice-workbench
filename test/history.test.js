import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import test from 'node:test';
import { Workspace } from '../src/workspace.js';

const CLI = path.resolve('src/cli.js');

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-history-'));
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

async function startServerFailure(args, { cwd } = {}) {
  const child = spawn(process.execPath, [CLI, 'serve', ...args], { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const status = await new Promise((resolve) => child.on('exit', resolve));
  return { status, stdout, stderr };
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

test('history: existing documents get revision-1 baselines; new documents start at 1 with create', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  const histFile = path.join(cwd, 'history.json');
  writeSnapshot(snapFile, workspaceWith([
    { id: 'a', title: 'Alpha', body: 'body a', tags: ['One'] },
    { id: 'b', title: 'Beta', body: 'body b', tags: [] },
  ]));
  const server = await startServer([snapFile, '--history', histFile, '--port', '0']);
  try {
    const historyA = await request(server.url, 'GET', '/documents/a/history');
    assert.equal(historyA.status, 200);
    assert.deepEqual(historyA.body, [
      { revision: 1, action: 'baseline', document: { id: 'a', title: 'Alpha', body: 'body a', tags: ['one'] } },
    ]);
    const historyB = await request(server.url, 'GET', '/documents/b/history');
    assert.deepEqual(historyB.body, [
      { revision: 1, action: 'baseline', document: { id: 'b', title: 'Beta', body: 'body b', tags: [] } },
    ]);

    const listed = await request(server.url, 'GET', '/documents');
    const created = await request(server.url, 'POST', '/documents', {
      body: { id: 'c', title: 'Gamma', body: 'body c', tags: ['Two'] },
      headers: { 'if-match': listed.etag },
    });
    assert.equal(created.status, 201);
    const historyC = await request(server.url, 'GET', '/documents/c/history');
    assert.deepEqual(historyC.body, [
      { revision: 1, action: 'create', document: { id: 'c', title: 'Gamma', body: 'body c', tags: ['two'] } },
    ]);
  } finally {
    await server.stop();
  }
});

test('history: replace and delete append revisions; re-create after delete continues the sequence', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  const histFile = path.join(cwd, 'history.json');
  const server = await startServer([snapFile, '--history', histFile, '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const created = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'v1', tags: [] },
      headers: { 'if-match': empty.etag },
    });

    const replaced = await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: 'A2', body: 'v2', tags: ['x'] },
      headers: { 'if-match': created.etag },
    });
    assert.equal(replaced.status, 200);

    const removed = await request(server.url, 'DELETE', '/documents/a', {
      headers: { 'if-match': replaced.etag },
    });
    assert.equal(removed.status, 200);

    // The deleted document's history is still queryable, ending in a delete.
    const historyAfterDelete = await request(server.url, 'GET', '/documents/a/history');
    assert.equal(historyAfterDelete.status, 200);
    assert.deepEqual(historyAfterDelete.body.map((r) => [r.revision, r.action, r.document]), [
      [1, 'create', { id: 'a', title: 'A', body: 'v1', tags: [] }],
      [2, 'replace', { id: 'a', title: 'A2', body: 'v2', tags: ['x'] }],
      [3, 'delete', null],
    ]);

    // Re-creating the same id continues the revision sequence.
    const recreated = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A3', body: 'v3', tags: [] },
      headers: { 'if-match': removed.etag },
    });
    assert.equal(recreated.status, 201);
    const historyAfterRecreate = await request(server.url, 'GET', '/documents/a/history');
    assert.deepEqual(historyAfterRecreate.body.map((r) => [r.revision, r.action]), [
      [1, 'create'], [2, 'replace'], [3, 'delete'], [4, 'create'],
    ]);
    assert.deepEqual(historyAfterRecreate.body[3].document, { id: 'a', title: 'A3', body: 'v3', tags: [] });
  } finally {
    await server.stop();
  }
});

test('history: a replace that leaves normalized content unchanged succeeds without appending', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  const histFile = path.join(cwd, 'history.json');
  const server = await startServer([snapFile, '--history', histFile, '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const created = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'body', tags: ['One'] },
      headers: { 'if-match': empty.etag },
    });

    // Whitespace in the title and tag casing/duplicates normalize away.
    const unchanged = await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: '  A  ', body: 'body', tags: ['one', 'ONE'] },
      headers: { 'if-match': created.etag },
    });
    assert.equal(unchanged.status, 200);
    assert.equal(unchanged.etag, created.etag);

    const history = await request(server.url, 'GET', '/documents/a/history');
    assert.deepEqual(history.body.map((r) => [r.revision, r.action]), [[1, 'create']]);
  } finally {
    await server.stop();
  }
});

test('history: GET history for a document that never existed is 404 NOT_FOUND', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  const histFile = path.join(cwd, 'history.json');
  const server = await startServer([snapFile, '--history', histFile, '--port', '0']);
  try {
    const history = await request(server.url, 'GET', '/documents/ghost/history');
    assert.equal(history.status, 404);
    assert.equal(history.body.code, 'NOT_FOUND');
  } finally {
    await server.stop();
  }
});

test('restore: restores title, body, and tags and appends a restore revision', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  const histFile = path.join(cwd, 'history.json');
  const server = await startServer([snapFile, '--history', histFile, '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const created = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'Original', body: 'original body', tags: ['one'] },
      headers: { 'if-match': empty.etag },
    });
    const replaced = await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: 'Changed', body: 'changed body', tags: ['two'] },
      headers: { 'if-match': created.etag },
    });

    const restored = await request(server.url, 'POST', '/documents/a/restore', {
      body: { revision: 1 },
      headers: { 'if-match': replaced.etag },
    });
    assert.equal(restored.status, 200);
    assert.equal(restored.etag, `"${restored.body.checksum}"`);
    assert.deepEqual(restored.body.documents, [
      { id: 'a', title: 'Original', body: 'original body', tags: ['one'] },
    ]);

    // Search and links reflect the restored content.
    const search = await request(server.url, 'GET', '/search?q=original');
    assert.deepEqual(search.body.map((d) => d.id), ['a']);

    const history = await request(server.url, 'GET', '/documents/a/history');
    assert.deepEqual(history.body.map((r) => [r.revision, r.action, r.document]), [
      [1, 'create', { id: 'a', title: 'Original', body: 'original body', tags: ['one'] }],
      [2, 'replace', { id: 'a', title: 'Changed', body: 'changed body', tags: ['two'] }],
      [3, 'restore', { id: 'a', title: 'Original', body: 'original body', tags: ['one'] }],
    ]);
  } finally {
    await server.stop();
  }
});

test('restore: can restore a deleted document; a second delete then restore keeps sequence', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  const histFile = path.join(cwd, 'history.json');
  const server = await startServer([snapFile, '--history', histFile, '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const created = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'body', tags: [] },
      headers: { 'if-match': empty.etag },
    });
    const removed = await request(server.url, 'DELETE', '/documents/a', {
      headers: { 'if-match': created.etag },
    });
    assert.equal(removed.status, 200);

    const restored = await request(server.url, 'POST', '/documents/a/restore', {
      body: { revision: 1 },
      headers: { 'if-match': removed.etag },
    });
    assert.equal(restored.status, 200);
    assert.deepEqual(restored.body.documents, [
      { id: 'a', title: 'A', body: 'body', tags: [] },
    ]);

    const history = await request(server.url, 'GET', '/documents/a/history');
    assert.deepEqual(history.body.map((r) => [r.revision, r.action]), [
      [1, 'create'], [2, 'delete'], [3, 'restore'],
    ]);
  } finally {
    await server.stop();
  }
});

test('restore: missing revision is 404; delete revision is 400 INVALID_REVISION', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  const histFile = path.join(cwd, 'history.json');
  const server = await startServer([snapFile, '--history', histFile, '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const created = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'body', tags: [] },
      headers: { 'if-match': empty.etag },
    });
    const removed = await request(server.url, 'DELETE', '/documents/a', {
      headers: { 'if-match': created.etag },
    });

    const missing = await request(server.url, 'POST', '/documents/a/restore', {
      body: { revision: 99 },
      headers: { 'if-match': removed.etag },
    });
    assert.equal(missing.status, 404);
    assert.equal(missing.body.code, 'NOT_FOUND');

    const deletedRevision = await request(server.url, 'POST', '/documents/a/restore', {
      body: { revision: 2 },
      headers: { 'if-match': removed.etag },
    });
    assert.equal(deletedRevision.status, 400);
    assert.equal(deletedRevision.body.code, 'INVALID_REVISION');
  } finally {
    await server.stop();
  }
});

test('restore: malformed revision bodies are 400 INVALID_REVISION', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  const histFile = path.join(cwd, 'history.json');
  const server = await startServer([snapFile, '--history', histFile, '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const created = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'body', tags: [] },
      headers: { 'if-match': empty.etag },
    });
    for (const body of [
      null,
      [],
      {},
      { revision: 0 },
      { revision: -1 },
      { revision: 1.5 },
      { revision: '1' },
      { revision: 1, extra: 2 },
    ]) {
      const response = await request(server.url, 'POST', '/documents/a/restore', {
        body,
        headers: { 'if-match': created.etag },
      });
      assert.equal(response.status, 400, JSON.stringify(body));
      assert.equal(response.body.code, 'INVALID_REVISION', JSON.stringify(body));
    }
  } finally {
    await server.stop();
  }
});

test('restore: title conflict with another document is 409 CONFLICT', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  const histFile = path.join(cwd, 'history.json');
  const server = await startServer([snapFile, '--history', histFile, '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const createdA = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'Alpha', body: 'body a', tags: [] },
      headers: { 'if-match': empty.etag },
    });
    const createdB = await request(server.url, 'POST', '/documents', {
      body: { id: 'b', title: 'Beta', body: 'body b', tags: [] },
      headers: { 'if-match': createdA.etag },
    });
    // Rename a away from Alpha, then b into Alpha.
    const renamedA = await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: 'Gamma', body: 'body a', tags: [] },
      headers: { 'if-match': createdB.etag },
    });
    assert.equal(renamedA.status, 200);
    const renamedB = await request(server.url, 'PUT', '/documents/b', {
      body: { id: 'b', title: 'Alpha', body: 'body b', tags: [] },
      headers: { 'if-match': renamedA.etag },
    });
    assert.equal(renamedB.status, 200);

    // Restoring a to revision 1 (Alpha) now collides with b's Alpha.
    const conflict = await request(server.url, 'POST', '/documents/a/restore', {
      body: { revision: 1 },
      headers: { 'if-match': renamedB.etag },
    });
    assert.equal(conflict.status, 409);
    assert.equal(conflict.body.code, 'CONFLICT');

    // a is unchanged by the failed restore.
    const after = await request(server.url, 'GET', '/documents/a');
    assert.equal(after.body.title, 'Gamma');
  } finally {
    await server.stop();
  }
});

test('restore: a no-op restore succeeds without appending a revision', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  const histFile = path.join(cwd, 'history.json');
  const server = await startServer([snapFile, '--history', histFile, '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const created = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'body', tags: ['one'] },
      headers: { 'if-match': empty.etag },
    });
    const restored = await request(server.url, 'POST', '/documents/a/restore', {
      body: { revision: 1 },
      headers: { 'if-match': created.etag },
    });
    assert.equal(restored.status, 200);
    assert.equal(restored.etag, created.etag);
    const history = await request(server.url, 'GET', '/documents/a/history');
    assert.deepEqual(history.body.map((r) => [r.revision, r.action]), [[1, 'create']]);
  } finally {
    await server.stop();
  }
});

test('history persists across restarts and continues the sequence', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  const histFile = path.join(cwd, 'history.json');
  const server = await startServer([snapFile, '--history', histFile, '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const created = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'v1', tags: [] },
      headers: { 'if-match': empty.etag },
    });
    const replaced = await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: 'A2', body: 'v2', tags: [] },
      headers: { 'if-match': created.etag },
    });
    assert.equal(replaced.status, 200);
  } finally {
    await server.stop();
  }

  const restarted = await startServer([snapFile, '--history', histFile, '--port', '0']);
  try {
    const history = await request(restarted.url, 'GET', '/documents/a/history');
    assert.deepEqual(history.body.map((r) => [r.revision, r.action]), [
      [1, 'create'], [2, 'replace'],
    ]);

    const listed = await request(restarted.url, 'GET', '/documents');
    const restored = await request(restarted.url, 'POST', '/documents/a/restore', {
      body: { revision: 1 },
      headers: { 'if-match': listed.etag },
    });
    assert.equal(restored.status, 200);
    const historyAfter = await request(restarted.url, 'GET', '/documents/a/history');
    assert.deepEqual(historyAfter.body.map((r) => [r.revision, r.action]), [
      [1, 'create'], [2, 'replace'], [3, 'restore'],
    ]);
  } finally {
    await restarted.stop();
  }
});

test('history: no --history flag keeps the original behavior and routes are absent', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  const server = await startServer([snapFile, '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const created = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'body', tags: [] },
      headers: { 'if-match': empty.etag },
    });
    assert.equal(created.status, 201);

    const history = await request(server.url, 'GET', '/documents/a/history');
    assert.equal(history.status, 404);

    const restore = await request(server.url, 'POST', '/documents/a/restore', {
      body: { revision: 1 },
      headers: { 'if-match': created.etag },
    });
    assert.equal(restore.status, 404);
  } finally {
    await server.stop();
  }
});

test('history: same snapshot and history path is INVALID_OPTIONS', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  const failure = await startServerFailure([file, '--history', file, '--port', '0']);
  assert.equal(failure.status, 1);
  assert.equal(failure.stdout, '');
  assert.equal(JSON.parse(failure.stderr.trim()).code, 'INVALID_OPTIONS');
});

test('history: an unreadable history file is IO_ERROR', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  const histFile = path.join(cwd, 'history-dir');
  fs.mkdirSync(histFile);
  const failure = await startServerFailure([snapFile, '--history', histFile, '--port', '0']);
  assert.equal(failure.status, 1);
  assert.equal(failure.stdout, '');
  assert.equal(JSON.parse(failure.stderr.trim()).code, 'IO_ERROR');
});

test('history: a corrupted history file is INVALID_HISTORY and leaves files untouched', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  const histFile = path.join(cwd, 'history.json');
  writeSnapshot(snapFile, workspaceWith([{ id: 'a', title: 'A', body: 'body', tags: [] }]));
  fs.writeFileSync(histFile, '{broken json');
  const failure = await startServerFailure([snapFile, '--history', histFile, '--port', '0']);
  assert.equal(failure.status, 1);
  assert.equal(failure.stdout, '');
  assert.equal(JSON.parse(failure.stderr.trim()).code, 'INVALID_HISTORY');
  assert.equal(fs.readFileSync(histFile, 'utf8'), '{broken json');
});

test('history: a history inconsistent with the snapshot is INVALID_HISTORY', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  const histFile = path.join(cwd, 'history.json');
  writeSnapshot(snapFile, workspaceWith([{ id: 'a', title: 'A', body: 'body', tags: [] }]));
  // History ends with a delete while the snapshot still holds the document.
  fs.writeFileSync(histFile, JSON.stringify({
    version: 1,
    documents: { a: [{ revision: 1, action: 'delete', document: null }] },
    checksum: '0'.repeat(64),
  }));
  const failure = await startServerFailure([snapFile, '--history', histFile, '--port', '0']);
  assert.equal(failure.status, 1);
  assert.equal(JSON.parse(failure.stderr.trim()).code, 'INVALID_HISTORY');
});

test('history: a history with a bad checksum is INVALID_HISTORY', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  const histFile = path.join(cwd, 'history.json');
  writeSnapshot(snapFile, workspaceWith([{ id: 'a', title: 'A', body: 'body', tags: [] }]));
  fs.writeFileSync(histFile, JSON.stringify({
    version: 1,
    documents: {
      a: [{ revision: 1, action: 'baseline', document: { id: 'a', title: 'A', body: 'body', tags: [] } }],
    },
    checksum: '0'.repeat(64),
  }));
  const failure = await startServerFailure([snapFile, '--history', histFile, '--port', '0']);
  assert.equal(failure.status, 1);
  assert.equal(JSON.parse(failure.stderr.trim()).code, 'INVALID_HISTORY');
});

test('history: the history file is checksummed and does not mix with the snapshot', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  const histFile = path.join(cwd, 'history.json');
  const server = await startServer([snapFile, '--history', histFile, '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'body', tags: [] },
      headers: { 'if-match': empty.etag },
    });
  } finally {
    await server.stop();
  }
  const snapshot = JSON.parse(fs.readFileSync(snapFile, 'utf8'));
  const history = JSON.parse(fs.readFileSync(histFile, 'utf8'));
  assert.equal(snapshot.version, 1);
  assert.equal(history.version, 1);
  assert.equal(Object.keys(snapshot).join(','), 'version,documents,checksum');
  assert.equal(Object.keys(history).join(','), 'version,documents,checksum');
  // The snapshot checksum is unchanged by the history feature.
  const reimported = new Workspace();
  reimported.importJSON(JSON.stringify(snapshot), { mode: 'replace' });
  assert.equal(reimported.exportJSON().checksum, snapshot.checksum);
});

test('history: a leftover journal is replayed on restart', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  const histFile = path.join(cwd, 'history.json');
  writeSnapshot(snapFile, workspaceWith([{ id: 'a', title: 'A', body: 'old', tags: [] }]));
  // Simulate a committed transaction whose journal was left behind.
  const newSnapshot = workspaceWith([{ id: 'a', title: 'A', body: 'new', tags: [] }]).exportJSON();
  const newHistory = {
    version: 1,
    documents: {
      a: [
        { revision: 1, action: 'baseline', document: { id: 'a', title: 'A', body: 'old', tags: [] } },
        { revision: 2, action: 'replace', document: { id: 'a', title: 'A', body: 'new', tags: [] } },
      ],
    },
    checksum: null,
  };
  const { loadHistory } = await import('../src/history.js');
  // Recompute the history checksum through the module by loading a valid text.
  const historyText = JSON.stringify({
    version: 1,
    documents: newHistory.documents,
    checksum: '0'.repeat(64),
  });
  // Build a properly checksummed history via a small helper.
  const { createHash } = await import('node:crypto');
  const checksum = createHash('sha256')
    .update(JSON.stringify({ version: 1, documents: newHistory.documents }))
    .digest('hex');
  const journal = { version: 1, snapshot: `${JSON.stringify(newSnapshot)}\n`, history: `${JSON.stringify({ version: 1, documents: newHistory.documents, checksum })}\n` };
  const journalFile = path.join(cwd, `.${path.basename(snapFile)}.txn`);
  fs.writeFileSync(journalFile, JSON.stringify(journal));

  const server = await startServer([snapFile, '--history', histFile, '--port', '0']);
  try {
    const doc = await request(server.url, 'GET', '/documents/a');
    assert.equal(doc.body.body, 'new');
    const history = await request(server.url, 'GET', '/documents/a/history');
    assert.deepEqual(history.body.map((r) => [r.revision, r.action]), [
      [1, 'baseline'], [2, 'replace'],
    ]);
    // The journal was consumed.
    assert.ok(!fs.existsSync(journalFile));
  } finally {
    await server.stop();
  }
});

test('history: restore follows If-Match and the 1 MiB limit', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  const histFile = path.join(cwd, 'history.json');
  const server = await startServer([snapFile, '--history', histFile, '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const created = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'body', tags: [] },
      headers: { 'if-match': empty.etag },
    });

    const missing = await request(server.url, 'POST', '/documents/a/restore', {
      body: { revision: 1 },
    });
    assert.equal(missing.status, 428);

    const stale = await request(server.url, 'POST', '/documents/a/restore', {
      body: { revision: 1 },
      headers: { 'if-match': empty.etag },
    });
    assert.equal(stale.status, 412);

    const oversized = await request(server.url, 'POST', '/documents/a/restore', {
      rawBody: JSON.stringify({ revision: 1, padding: 'x'.repeat(1024 * 1024) }),
      headers: { 'if-match': created.etag },
    });
    assert.equal(oversized.status, 413);
  } finally {
    await server.stop();
  }
});

test('history: a failed commit leaves memory, queries, history, and files intact', async () => {
  const cwd = tempDir();
  const snapFile = path.join(cwd, 'snap.json');
  // A history file in a non-existent directory: startup finds no history file
  // (so baselines are held in memory), but every commit fails to write it.
  const histFile = path.join(cwd, 'no-such-dir', 'history.json');
  const server = await startServer([snapFile, '--history', histFile, '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const created = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'body', tags: [] },
      headers: { 'if-match': empty.etag },
    });
    assert.equal(created.status, 500);
    assert.equal(created.body.code, 'IO_ERROR');

    // The service keeps accepting requests and the state is unchanged.
    const listed = await request(server.url, 'GET', '/documents');
    assert.equal(listed.status, 200);
    assert.deepEqual(listed.body, []);
    assert.equal(listed.etag, empty.etag);

    // The snapshot file was not created either.
    assert.ok(!fs.existsSync(snapFile));
  } finally {
    await server.stop();
  }
});
