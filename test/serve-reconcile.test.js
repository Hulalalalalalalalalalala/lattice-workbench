import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import test from 'node:test';
import { Workspace } from '../src/workspace.js';

const CLI = path.resolve('src/cli.js');

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-reconcile-'));
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

function docMap(snapshot) {
  return new Map(snapshot.documents.map((document) => [document.id, document]));
}

// Builds a snapshot from a list of documents (for base/incoming).
function snap(documents) {
  return workspaceWith(documents).exportJSON();
}

// --- Basic three-way merge ---------------------------------------------------

test('reconcile keeps non-conflicting changes from both sides', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'original body', tags: ['one'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    // Online: change the body.
    await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: 'Alpha', body: 'online body', tags: ['one'] },
      headers: { 'if-match': et },
    });
    const onlineEtag = (await request(server.url, 'GET', '/documents')).etag;

    // Offline: change the title.
    const base = snap([{ id: 'a', title: 'Alpha', body: 'original body', tags: ['one'] }]);
    const incoming = snap([{ id: 'a', title: 'Alpha v2', body: 'original body', tags: ['one'] }]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': onlineEtag },
    });
    assert.equal(response.status, 200);
    assert.equal(response.etag, `"${response.body.checksum}"`);
    const doc = docMap(response.body).get('a');
    assert.equal(doc.title, 'Alpha v2');
    assert.equal(doc.body, 'online body');
    assert.deepEqual(doc.tags, ['one']);

    // The stored state matches.
    const listed = await request(server.url, 'GET', '/documents');
    assert.deepEqual(listed.body, response.body.documents);
  } finally {
    await server.stop();
  }
});

test('reconcile merges different fields changed on each side', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'T', body: 'B', tags: ['x'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    // Online: change body and tags.
    await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: 'T', body: 'online body', tags: ['y'] },
      headers: { 'if-match': et },
    });
    const onlineEtag = (await request(server.url, 'GET', '/documents')).etag;

    // Offline: change title only.
    const base = snap([{ id: 'a', title: 'T', body: 'B', tags: ['x'] }]);
    const incoming = snap([{ id: 'a', title: 'T2', body: 'B', tags: ['x'] }]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': onlineEtag },
    });
    assert.equal(response.status, 200);
    const doc = docMap(response.body).get('a');
    assert.equal(doc.title, 'T2');
    assert.equal(doc.body, 'online body');
    assert.deepEqual(doc.tags, ['y']);
  } finally {
    await server.stop();
  }
});

test('reconcile accepts identical changes from both sides', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'T', body: 'B', tags: ['x'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    // Online: change title to T2.
    await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: 'T2', body: 'B', tags: ['x'] },
      headers: { 'if-match': et },
    });
    const onlineEtag = (await request(server.url, 'GET', '/documents')).etag;

    // Offline: also change title to T2 (same).
    const base = snap([{ id: 'a', title: 'T', body: 'B', tags: ['x'] }]);
    const incoming = snap([{ id: 'a', title: 'T2', body: 'B', tags: ['x'] }]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': onlineEtag },
    });
    assert.equal(response.status, 200);
    const doc = docMap(response.body).get('a');
    assert.equal(doc.title, 'T2');
    assert.equal(doc.body, 'B');
    assert.deepEqual(doc.tags, ['x']);
  } finally {
    await server.stop();
  }
});

// --- Field conflicts ---------------------------------------------------------

test('reconcile reports field conflicts when both sides change a field differently', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'T', body: 'B', tags: ['x'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    // Online: change title to online-title.
    await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: 'online-title', body: 'B', tags: ['x'] },
      headers: { 'if-match': et },
    });
    const onlineEtag = (await request(server.url, 'GET', '/documents')).etag;

    // Offline: change title to offline-title.
    const base = snap([{ id: 'a', title: 'T', body: 'B', tags: ['x'] }]);
    const incoming = snap([{ id: 'a', title: 'offline-title', body: 'B', tags: ['x'] }]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': onlineEtag },
    });
    assert.equal(response.status, 409);
    assert.equal(response.body.code, 'RECONCILE_CONFLICT');
    assert.deepEqual(response.body.conflicts, [{ id: 'a', fields: ['title'] }]);

    // State unchanged.
    const doc = (await request(server.url, 'GET', '/documents/a')).body;
    assert.equal(doc.title, 'online-title');
  } finally {
    await server.stop();
  }
});

test('reconcile collects all field conflicts across documents, sorted by id', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'T', body: 'B', tags: ['x'] },
    { id: 'b', title: 'U', body: 'C', tags: ['y'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    // Online: change a's title and b's body.
    await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: 'online-a', body: 'B', tags: ['x'] },
      headers: { 'if-match': et },
    });
    const et2 = (await request(server.url, 'GET', '/documents')).etag;
    await request(server.url, 'PUT', '/documents/b', {
      body: { id: 'b', title: 'U', body: 'online-b', tags: ['y'] },
      headers: { 'if-match': et2 },
    });
    const onlineEtag = (await request(server.url, 'GET', '/documents')).etag;

    // Offline: change a's title and b's body differently.
    const base = snap([
      { id: 'a', title: 'T', body: 'B', tags: ['x'] },
      { id: 'b', title: 'U', body: 'C', tags: ['y'] },
    ]);
    const incoming = snap([
      { id: 'a', title: 'offline-a', body: 'B', tags: ['x'] },
      { id: 'b', title: 'U', body: 'offline-c', tags: ['y'] },
    ]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': onlineEtag },
    });
    assert.equal(response.status, 409);
    assert.deepEqual(response.body.conflicts, [
      { id: 'a', fields: ['title'] },
      { id: 'b', fields: ['body'] },
    ]);
  } finally {
    await server.stop();
  }
});

test('reconcile sorts fields by code point within a conflict', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'T', body: 'B', tags: ['x'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    // Online: change all fields.
    await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: 'online-title', body: 'online-body', tags: ['online-tag'] },
      headers: { 'if-match': et },
    });
    const onlineEtag = (await request(server.url, 'GET', '/documents')).etag;

    // Offline: change all fields differently.
    const base = snap([{ id: 'a', title: 'T', body: 'B', tags: ['x'] }]);
    const incoming = snap([{ id: 'a', title: 'offline-title', body: 'offline-body', tags: ['offline-tag'] }]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': onlineEtag },
    });
    assert.equal(response.status, 409);
    // Fields sorted: body, tags, title (code point order).
    assert.deepEqual(response.body.conflicts, [{ id: 'a', fields: ['body', 'tags', 'title'] }]);
  } finally {
    await server.stop();
  }
});

// --- Add and delete conflicts ------------------------------------------------

test('reconcile keeps a document only offline added', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    const base = snap([]);
    const incoming = snap([{ id: 'a', title: 'New', body: 'body', tags: [] }]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.documents.map((d) => d.id), ['a']);
    assert.equal(docMap(response.body).get('a').title, 'New');
  } finally {
    await server.stop();
  }
});

test('reconcile accepts identical additions from both sides', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    // Online: add a.
    await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'Same', body: 'body', tags: [] },
      headers: { 'if-match': et },
    });
    const onlineEtag = (await request(server.url, 'GET', '/documents')).etag;

    // Offline: also add a with identical content.
    const base = snap([]);
    const incoming = snap([{ id: 'a', title: 'Same', body: 'body', tags: [] }]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': onlineEtag },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.documents.map((d) => d.id), ['a']);
  } finally {
    await server.stop();
  }
});

test('reconcile reports a document conflict when both sides add the same id differently', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    // Online: add a with title Online.
    await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'Online', body: 'body', tags: [] },
      headers: { 'if-match': et },
    });
    const onlineEtag = (await request(server.url, 'GET', '/documents')).etag;

    // Offline: add a with title Offline.
    const base = snap([]);
    const incoming = snap([{ id: 'a', title: 'Offline', body: 'body', tags: [] }]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': onlineEtag },
    });
    assert.equal(response.status, 409);
    assert.deepEqual(response.body.conflicts, [{ id: 'a', fields: ['document'] }]);
  } finally {
    await server.stop();
  }
});

test('reconcile deletes a document only offline deleted', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'body', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    // Offline: delete a.
    const base = snap([{ id: 'a', title: 'A', body: 'body', tags: [] }]);
    const incoming = snap([]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.documents, []);
  } finally {
    await server.stop();
  }
});

test('reconcile reports a document conflict when offline deletes and online modifies', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'body', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    // Online: modify a.
    await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: 'A', body: 'online body', tags: [] },
      headers: { 'if-match': et },
    });
    const onlineEtag = (await request(server.url, 'GET', '/documents')).etag;

    // Offline: delete a.
    const base = snap([{ id: 'a', title: 'A', body: 'body', tags: [] }]);
    const incoming = snap([]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': onlineEtag },
    });
    assert.equal(response.status, 409);
    assert.deepEqual(response.body.conflicts, [{ id: 'a', fields: ['document'] }]);
  } finally {
    await server.stop();
  }
});

test('reconcile deletes a document only online deleted', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'body', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    // Online: delete a.
    await request(server.url, 'DELETE', '/documents/a', { headers: { 'if-match': et } });
    const onlineEtag = (await request(server.url, 'GET', '/documents')).etag;

    // Offline: unchanged.
    const base = snap([{ id: 'a', title: 'A', body: 'body', tags: [] }]);
    const incoming = snap([{ id: 'a', title: 'A', body: 'body', tags: [] }]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': onlineEtag },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.documents, []);
  } finally {
    await server.stop();
  }
});

test('reconcile reports a document conflict when online deletes and offline modifies', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'body', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    // Online: delete a.
    await request(server.url, 'DELETE', '/documents/a', { headers: { 'if-match': et } });
    const onlineEtag = (await request(server.url, 'GET', '/documents')).etag;

    // Offline: modify a.
    const base = snap([{ id: 'a', title: 'A', body: 'body', tags: [] }]);
    const incoming = snap([{ id: 'a', title: 'A', body: 'offline body', tags: [] }]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': onlineEtag },
    });
    assert.equal(response.status, 409);
    assert.deepEqual(response.body.conflicts, [{ id: 'a', fields: ['document'] }]);
  } finally {
    await server.stop();
  }
});

// --- Title uniqueness --------------------------------------------------------

test('reconcile allows title swaps', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: [] },
    { id: 'b', title: 'Beta', body: 'b', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    // Offline: swap titles.
    const base = snap([
      { id: 'a', title: 'Alpha', body: 'a', tags: [] },
      { id: 'b', title: 'Beta', body: 'b', tags: [] },
    ]);
    const incoming = snap([
      { id: 'a', title: 'Beta', body: 'a', tags: [] },
      { id: 'b', title: 'Alpha', body: 'b', tags: [] },
    ]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.equal(docMap(response.body).get('a').title, 'Beta');
    assert.equal(docMap(response.body).get('b').title, 'Alpha');
  } finally {
    await server.stop();
  }
});

test('reconcile reports title duplicates only when no field conflicts exist', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    // Online: add b with title Beta.
    await request(server.url, 'POST', '/documents', {
      body: { id: 'b', title: 'Beta', body: 'b', tags: [] },
      headers: { 'if-match': et },
    });
    const onlineEtag = (await request(server.url, 'GET', '/documents')).etag;

    // Offline: rename a to Beta (conflicts with online's b).
    const base = snap([{ id: 'a', title: 'Alpha', body: 'a', tags: [] }]);
    const incoming = snap([{ id: 'a', title: 'Beta', body: 'a', tags: [] }]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': onlineEtag },
    });
    assert.equal(response.status, 409);
    assert.equal(response.body.code, 'RECONCILE_CONFLICT');
    assert.deepEqual(response.body.conflicts, [
      { id: 'a', fields: ['title'] },
      { id: 'b', fields: ['title'] },
    ]);
  } finally {
    await server.stop();
  }
});

test('reconcile reports field conflicts before title conflicts', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    // Online: change a's body and add b with title Beta.
    await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: 'Alpha', body: 'online-a', tags: [] },
      headers: { 'if-match': et },
    });
    const et2 = (await request(server.url, 'GET', '/documents')).etag;
    await request(server.url, 'POST', '/documents', {
      body: { id: 'b', title: 'Beta', body: 'b', tags: [] },
      headers: { 'if-match': et2 },
    });
    const onlineEtag = (await request(server.url, 'GET', '/documents')).etag;

    // Offline: rename a to Beta and change its body differently.
    const base = snap([{ id: 'a', title: 'Alpha', body: 'a', tags: [] }]);
    const incoming = snap([{ id: 'a', title: 'Beta', body: 'offline-a', tags: [] }]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': onlineEtag },
    });
    assert.equal(response.status, 409);
    // Only the field conflict is reported, not the title duplicate.
    assert.deepEqual(response.body.conflicts, [{ id: 'a', fields: ['body'] }]);
  } finally {
    await server.stop();
  }
});

// --- dryRun ------------------------------------------------------------------

test('reconcile dryRun returns the projection without changing state', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  writeSnapshot(file, workspaceWith([
    { id: 'a', title: 'Alpha', body: 'original', tags: ['one'] },
  ]));
  const before = fs.readFileSync(file, 'utf8');
  const server = await startServer([file, '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    const base = snap([{ id: 'a', title: 'Alpha', body: 'original', tags: ['one'] }]);
    const incoming = snap([{ id: 'a', title: 'Alpha v2', body: 'original', tags: ['one'] }]);

    const preview = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming, dryRun: true },
      headers: { 'if-match': et },
    });
    assert.equal(preview.status, 200);
    assert.equal(docMap(preview.body).get('a').title, 'Alpha v2');

    // State unchanged.
    const live = await request(server.url, 'GET', '/documents/a');
    assert.equal(live.body.title, 'Alpha');
    assert.equal(live.etag, et);
    assert.equal(fs.readFileSync(file, 'utf8'), before);

    // A real commit with the same precondition then succeeds.
    const commit = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': et },
    });
    assert.equal(commit.status, 200);
    assert.equal(commit.etag, preview.etag);
  } finally {
    await server.stop();
  }
});

test('reconcile dryRun still requires If-Match', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'b', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const base = snap([{ id: 'a', title: 'A', body: 'b', tags: [] }]);
    const incoming = snap([{ id: 'a', title: 'A2', body: 'b', tags: [] }]);

    const missing = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming, dryRun: true },
    });
    assert.equal(missing.status, 428);
    assert.equal(missing.body.code, 'PRECONDITION_REQUIRED');

    const malformed = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming, dryRun: true },
      headers: { 'if-match': 'garbage' },
    });
    assert.equal(malformed.status, 400);
    assert.equal(malformed.body.code, 'INVALID_IF_MATCH');
  } finally {
    await server.stop();
  }
});

// --- No-op -------------------------------------------------------------------

test('reconcile with identical base and incoming is a no-op', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  writeSnapshot(file, workspaceWith([
    { id: 'a', title: 'A', body: 'b', tags: [] },
  ]));
  const before = fs.readFileSync(file, 'utf8');
  const server = await startServer([file, '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    const base = snap([{ id: 'a', title: 'A', body: 'b', tags: [] }]);
    const incoming = snap([{ id: 'a', title: 'A', body: 'b', tags: [] }]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.equal(response.etag, et);
    assert.equal(fs.readFileSync(file, 'utf8'), before);
  } finally {
    await server.stop();
  }
});

// --- Validation ---------------------------------------------------------------

test('reconcile rejects structural envelope errors with INVALID_OPTIONS', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'b', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const send = (payload) => request(server.url, 'POST', '/snapshots/reconcile', {
      body: payload,
      headers: { 'if-match': et },
    });

    const base = snap([{ id: 'a', title: 'A', body: 'b', tags: [] }]);
    const incoming = snap([{ id: 'a', title: 'A2', body: 'b', tags: [] }]);

    for (const [label, payload] of [
      ['not an object', []],
      ['null', null],
      ['missing base', { incoming }],
      ['missing incoming', { base }],
      ['unknown field', { base, incoming, extra: 1 }],
      ['dryRun not boolean', { base, incoming, dryRun: 'yes' }],
    ]) {
      const response = await send(payload);
      assert.equal(response.status, 400, label);
      assert.equal(response.body.code, 'INVALID_OPTIONS', label);
    }

    // null base/incoming are invalid snapshots, not structural errors.
    for (const [label, payload] of [
      ['base is null', { base: null, incoming }],
      ['incoming is null', { base, incoming: null }],
    ]) {
      const response = await send(payload);
      assert.equal(response.status, 400, label);
      assert.equal(response.body.code, 'INVALID_SNAPSHOT', label);
    }
  } finally {
    await server.stop();
  }
});

test('reconcile rejects invalid snapshots with INVALID_SNAPSHOT', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'b', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const valid = snap([{ id: 'a', title: 'A', body: 'b', tags: [] }]);

    for (const [label, bad] of [
      ['base malformed JSON', '{not json'],
      ['base null', null],
      ['base missing checksum', (() => { const s = snap([]); delete s.checksum; return s; })()],
      ['base bad checksum', (() => { const s = snap([]); s.checksum = '0'.repeat(64); return s; })()],
      ['incoming malformed JSON', '{not json'],
      ['incoming null', null],
      ['incoming bad document', (() => { const s = snap([]); s.documents = [{ id: 'Bad Id', title: 'A', body: 'b', tags: [] }]; return s; })()],
    ]) {
      const isBase = label.startsWith('base');
      const payload = isBase ? { base: bad, incoming: valid } : { base: valid, incoming: bad };
      const response = await request(server.url, 'POST', '/snapshots/reconcile', {
        body: payload,
        headers: { 'if-match': et },
      });
      assert.equal(response.status, 400, label);
      assert.equal(response.body.code, 'INVALID_SNAPSHOT', label);
    }
  } finally {
    await server.stop();
  }
});

test('reconcile rejects illegal JSON and oversized bodies with existing codes', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    const illegal = await request(server.url, 'POST', '/snapshots/reconcile', {
      rawBody: '{not json',
      headers: { 'if-match': et },
    });
    assert.equal(illegal.status, 400);
    assert.equal(illegal.body.code, 'INVALID_JSON');

    const oversized = await request(server.url, 'POST', '/snapshots/reconcile', {
      rawBody: JSON.stringify({
        base: snap([]),
        incoming: snap([{ id: 'a', title: 'A', body: 'x'.repeat(1024 * 1024), tags: [] }]),
      }),
      headers: { 'if-match': et },
    });
    assert.equal(oversized.status, 413);
    assert.equal(oversized.body.code, 'PAYLOAD_TOO_LARGE');
  } finally {
    await server.stop();
  }
});

// --- If-Match and concurrency ------------------------------------------------

test('reconcile requires If-Match and honors concurrency', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    const base = snap([]);
    const incoming = snap([{ id: 'a', title: 'A', body: 'b', tags: [] }]);

    const missing = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
    });
    assert.equal(missing.status, 428);

    const malformed = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': 'not-an-etag' },
    });
    assert.equal(malformed.status, 400);

    // Two concurrent reconciles with the same checksum: at most one commits.
    const [first, second] = await Promise.all([
      request(server.url, 'POST', '/snapshots/reconcile', {
        body: { base, incoming: snap([{ id: 'a', title: 'A', body: 'b', tags: [] }]) },
        headers: { 'if-match': et },
      }),
      request(server.url, 'POST', '/snapshots/reconcile', {
        body: { base, incoming: snap([{ id: 'b', title: 'B', body: 'b', tags: [] }]) },
        headers: { 'if-match': et },
      }),
    ]);
    const statuses = [first.status, second.status].sort();
    assert.deepEqual(statuses, [200, 412]);
  } finally {
    await server.stop();
  }
});

// --- History ------------------------------------------------------------------

test('reconcile with history appends create/replace/delete records', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'old', tags: ['one'] },
    { id: 'b', title: 'Beta', body: 'b', tags: [] },
  ]));
  const server = await startServer([
    path.join(cwd, 'snap.json'), '--history', path.join(cwd, 'h.json'), '--port', '0',
  ]);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    // Online: modify a.
    await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: 'Alpha', body: 'online', tags: ['one'] },
      headers: { 'if-match': et },
    });
    const onlineEtag = (await request(server.url, 'GET', '/documents')).etag;

    // Offline: modify a (same field, same value -> no conflict), delete b, add c.
    const base = snap([
      { id: 'a', title: 'Alpha', body: 'old', tags: ['one'] },
      { id: 'b', title: 'Beta', body: 'b', tags: [] },
    ]);
    const incoming = snap([
      { id: 'a', title: 'Alpha', body: 'online', tags: ['one'] },
      { id: 'c', title: 'Gamma', body: 'c', tags: [] },
    ]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': onlineEtag },
    });
    assert.equal(response.status, 200);

    // a: baseline(1), replace(2). b: baseline(1), delete(2). c: create(1).
    const rowsA = (await request(server.url, 'GET', '/documents/a/history')).body;
    assert.deepEqual(rowsA.map((e) => [e.revision, e.action]), [[1, 'baseline'], [2, 'replace']]);
    assert.equal(rowsA[1].document.body, 'online');

    const rowsB = (await request(server.url, 'GET', '/documents/b/history')).body;
    assert.deepEqual(rowsB.map((e) => [e.revision, e.action]), [[1, 'baseline'], [2, 'delete']]);
    assert.equal(rowsB[1].document, null);

    const rowsC = (await request(server.url, 'GET', '/documents/c/history')).body;
    assert.deepEqual(rowsC.map((e) => [e.revision, e.action]), [[1, 'create']]);
  } finally {
    await server.stop();
  }
});

test('reconcile history: a no-op appends no records', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'b', tags: [] },
  ]));
  const server = await startServer([
    path.join(cwd, 'snap.json'), '--history', path.join(cwd, 'h.json'), '--port', '0',
  ]);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    const base = snap([{ id: 'a', title: 'A', body: 'b', tags: [] }]);
    const incoming = snap([{ id: 'a', title: 'A', body: 'b', tags: [] }]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.equal(response.etag, et);

    const rows = (await request(server.url, 'GET', '/documents/a/history')).body;
    assert.deepEqual(rows.map((e) => [e.revision, e.action]), [[1, 'baseline']]);
  } finally {
    await server.stop();
  }
});

test('reconcile history: reappearing a deleted document appends create', async () => {
  const cwd = tempDir();
  const server = await startServer([
    path.join(cwd, 'snap.json'), '--history', path.join(cwd, 'h.json'), '--port', '0',
  ]);
  try {
    let et = (await request(server.url, 'GET', '/documents')).etag;

    // Create a, then delete it.
    await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'v1', tags: [] },
      headers: { 'if-match': et },
    });
    et = (await request(server.url, 'GET', '/documents')).etag;
    await request(server.url, 'DELETE', '/documents/a', { headers: { 'if-match': et } });
    et = (await request(server.url, 'GET', '/documents')).etag;

    // Reconcile: offline re-adds a.
    const base = snap([]);
    const incoming = snap([{ id: 'a', title: 'A', body: 'v2', tags: [] }]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);

    const rows = (await request(server.url, 'GET', '/documents/a/history')).body;
    assert.deepEqual(rows.map((e) => [e.revision, e.action]), [
      [1, 'create'], [2, 'delete'], [3, 'create'],
    ]);
    assert.equal(rows[2].document.body, 'v2');
  } finally {
    await server.stop();
  }
});

// --- Save failure -------------------------------------------------------------

test('reconcile failed save returns 500 IO_ERROR and leaves state and file intact', async () => {
  const cwd = tempDir();
  const blocked = path.join(cwd, 'no-such-dir', 'snap.json');
  const server = await startServer([blocked, '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    const base = snap([]);
    const incoming = snap([{ id: 'a', title: 'A', body: 'b', tags: [] }]);

    const failed = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': et },
    });
    assert.equal(failed.status, 500);
    assert.equal(failed.body.code, 'IO_ERROR');
    assert.ok(!fs.existsSync(blocked));

    // State unchanged.
    const listed = await request(server.url, 'GET', '/documents');
    assert.deepEqual(listed.body, []);
    assert.equal(listed.etag, et);
  } finally {
    await server.stop();
  }
});

// --- Search and links ---------------------------------------------------------

test('reconcile updates search and bidirectional links immediately', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'links [[b]]', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    const base = snap([{ id: 'a', title: 'Alpha', body: 'links [[b]]', tags: [] }]);
    const incoming = snap([
      { id: 'a', title: 'Alpha', body: 'links [[b]] and [[c]]', tags: [] },
      { id: 'b', title: 'Beta', body: 'links [[a]]', tags: [] },
      { id: 'c', title: 'Gamma', body: 'no links', tags: [] },
    ]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);

    // a now links to b and c; b links back to a; c has no links.
    const linksA = await request(server.url, 'GET', '/documents/a/links');
    assert.deepEqual(linksA.body, { outgoing: ['b', 'c'], incoming: ['b'] });
    const linksB = await request(server.url, 'GET', '/documents/b/links');
    assert.deepEqual(linksB.body, { outgoing: ['a'], incoming: ['a'] });

    // Search finds the new content.
    const search = await request(server.url, 'GET', '/search?q=gamma');
    assert.deepEqual(search.body.map((d) => d.id), ['c']);
  } finally {
    await server.stop();
  }
});

// --- Tags as whole set --------------------------------------------------------

test('reconcile compares tags as a normalized whole set', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'b', tags: ['x', 'y'] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    // Online: change body only.
    await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: 'A', body: 'online body', tags: ['x', 'y'] },
      headers: { 'if-match': et },
    });
    const onlineEtag = (await request(server.url, 'GET', '/documents')).etag;

    // Offline: change tags (different set).
    const base = snap([{ id: 'a', title: 'A', body: 'b', tags: ['x', 'y'] }]);
    const incoming = snap([{ id: 'a', title: 'A', body: 'b', tags: ['x', 'z'] }]);

    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': onlineEtag },
    });
    assert.equal(response.status, 200);
    const doc = docMap(response.body).get('a');
    assert.equal(doc.body, 'online body');
    assert.deepEqual(doc.tags, ['x', 'z']);
  } finally {
    await server.stop();
  }
});
