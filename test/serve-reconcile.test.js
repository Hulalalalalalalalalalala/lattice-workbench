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

function snapshotOf(documents) {
  const workspace = new Workspace();
  for (const document of documents) workspace.add(document);
  return workspace.exportJSON();
}

function writeSnapshot(file, documents) {
  fs.writeFileSync(file, `${JSON.stringify(snapshotOf(documents))}\n`);
}

async function startServer(args) {
  const child = spawn(process.execPath, [CLI, 'serve', ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
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

const docMap = (snapshot) => new Map(snapshot.documents.map((document) => [document.id, document]));

const doc = (id, patch = {}) => ({ id, title: id.toUpperCase(), body: `${id} body`, tags: [], ...patch });

// --- happy path --------------------------------------------------------------

test('reconcile keeps non-conflicting online edits while applying offline edits', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  // The server starts at "current": online retitled a and tagged b; the
  // offline fork (base) edited a's body, added c, and deleted untouched d.
  const base = snapshotOf([
    doc('a', { title: 'A', body: 'old body', tags: [] }),
    doc('b', { title: 'B', body: 'b body', tags: [] }),
    doc('d', { title: 'D', body: 'd body', tags: [] }),
  ]);
  writeSnapshot(file, [
    doc('a', { title: 'A Online', body: 'old body', tags: [] }),
    doc('b', { title: 'B', body: 'b body', tags: ['online-tag'] }),
    doc('d', { title: 'D', body: 'd body', tags: [] }),
  ]);
  const incoming = snapshotOf([
    doc('a', { title: 'A', body: 'offline body', tags: [] }),
    doc('b', { title: 'B', body: 'b body', tags: [] }),
    doc('c', { title: 'C', body: 'c body [[a]]', tags: ['new'] }),
  ]);
  const server = await startServer([file, '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.equal(response.etag, `"${response.body.checksum}"`);
    const documents = docMap(response.body);
    assert.deepEqual(documents.get('a'), {
      id: 'a', title: 'A Online', body: 'offline body', tags: [],
    });
    assert.deepEqual(documents.get('b').tags, ['online-tag']);
    assert.equal(documents.get('c').body, 'c body [[a]]');
    assert.ok(!documents.has('d'));

    // Queries and derived data follow the committed state immediately.
    assert.deepEqual((await request(server.url, 'GET', '/documents')).etag, response.etag);
    const search = await request(server.url, 'GET', '/search?q=offline+body');
    assert.deepEqual(search.body.map((d) => d.id), ['a']);
    assert.deepEqual((await request(server.url, 'GET', '/documents/a/links')).status, 200);
    const links = await request(server.url, 'GET', '/documents/a/links');
    assert.deepEqual(links.body.incoming, ['c']);
    const tags = await request(server.url, 'GET', '/tags');
    assert.deepEqual(tags.body, [
      { tag: 'new', count: 1 },
      { tag: 'online-tag', count: 1 },
    ]);

    // The result was persisted.
    const reloaded = JSON.parse(fs.readFileSync(file, 'utf8'));
    assert.equal(reloaded.checksum, response.body.checksum);
  } finally {
    await server.stop();
  }
});

test('reconcile allows title swaps', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  const base = snapshotOf([doc('a', { title: 'A' }), doc('b', { title: 'B' })]);
  // The online side swapped the titles; the offline fork only touched bodies.
  writeSnapshot(file, [doc('a', { title: 'B' }), doc('b', { title: 'A' })]);
  const incoming = snapshotOf([
    doc('a', { title: 'A', body: 'offline a' }),
    doc('b', { title: 'B', body: 'b body' }),
  ]);
  const server = await startServer([file, '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    const documents = docMap(response.body);
    assert.deepEqual(documents.get('a').title, 'B');
    assert.equal(documents.get('a').body, 'offline a');
    assert.deepEqual(documents.get('b').title, 'A');
  } finally {
    await server.stop();
  }
});

// --- conflicts ---------------------------------------------------------------

test('reconcile conflicts return 409 RECONCILE_CONFLICT with a sorted, deduplicated list', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  const base = snapshotOf([
    doc('a_b', { title: 'A_b', body: 'old', tags: ['t'] }),
    doc('a.b', { title: 'A.b', body: 'old', tags: ['t'] }),
    doc('gone', { title: 'Gone', body: 'g', tags: [] }),
  ]);
  writeSnapshot(file, [
    doc('a_b', { title: 'A_b', body: 'online', tags: ['x'] }),
    doc('a.b', { title: 'A.b', body: 'online', tags: ['t'] }),
    doc('gone', { title: 'Gone', body: 'g-modified', tags: [] }),
  ]);
  const incoming = snapshotOf([
    doc('a_b', { title: 'A_b', body: 'offline', tags: ['y'] }),
    doc('a.b', { title: 'A.b', body: 'offline', tags: ['t'] }),
  ]);
  const server = await startServer([file, '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 409);
    assert.equal(response.body.code, 'RECONCILE_CONFLICT');
    assert.deepEqual(response.body.conflicts, [
      { id: 'a.b', fields: ['body'] },
      { id: 'a_b', fields: ['body', 'tags'] },
      { id: 'gone', fields: ['document'] },
    ]);
    // Nothing changed after a rejected reconcile.
    assert.equal((await request(server.url, 'GET', '/documents')).etag, et);
    assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')).documents.length, 3);
  } finally {
    await server.stop();
  }
});

test('duplicate final titles report all involved documents only when no other conflicts exist', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  const base = snapshotOf([doc('a', { title: 'A' }), doc('b', { title: 'B' })]);
  writeSnapshot(file, [doc('a', { title: 'T' }), doc('b', { title: 'B' })]);
  const incoming = snapshotOf([
    doc('a', { title: 'A' }), doc('b', { title: 'B' }), doc('d', { title: 'T' }),
  ]);
  const server = await startServer([file, '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 409);
    assert.equal(response.body.code, 'RECONCILE_CONFLICT');
    assert.deepEqual(response.body.conflicts, [
      { id: 'a', fields: ['title'] },
      { id: 'd', fields: ['title'] },
    ]);
  } finally {
    await server.stop();
  }
});

// --- validation --------------------------------------------------------------

test('structural request errors return 400 INVALID_OPTIONS', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  const base = snapshotOf([]);
  const incoming = snapshotOf([]);
  const server = await startServer([file, '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const send = async (payload) => {
      const response = await request(server.url, 'POST', '/snapshots/reconcile', {
        body: payload,
        headers: { 'if-match': et },
      });
      assert.equal(response.status, 400, `${JSON.stringify(payload)} -> ${response.status}`);
      assert.equal(response.body.code, 'INVALID_OPTIONS');
    };
    await send(null);
    await send({ base });
    await send({ incoming });
    await send({ base, incoming, extra: 1 });
    await send({ base: JSON.stringify(base), incoming });
    await send({ base: [], incoming });
    await send({ base, incoming, dryRun: 'yes' });
    await send({ base, incoming, dryRun: 1 });

    // Malformed JSON keeps the existing INVALID_JSON behavior.
    const badJson = await request(server.url, 'POST', '/snapshots/reconcile', {
      rawBody: '{not json',
      headers: { 'if-match': et },
    });
    assert.equal(badJson.status, 400);
    assert.equal(badJson.body.code, 'INVALID_JSON');
  } finally {
    await server.stop();
  }
});

test('an invalid base or incoming snapshot returns 400 INVALID_SNAPSHOT', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  const good = snapshotOf([]);
  const tampered = structuredClone(good);
  tampered.documents = [{ id: 'a', title: 'A', body: 'tampered', tags: [] }];
  const server = await startServer([file, '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    for (const payload of [{ base: tampered, incoming: good }, { base: good, incoming: tampered }]) {
      const response = await request(server.url, 'POST', '/snapshots/reconcile', {
        body: payload,
        headers: { 'if-match': et },
      });
      assert.equal(response.status, 400);
      assert.equal(response.body.code, 'INVALID_SNAPSHOT');
    }
    assert.equal((await request(server.url, 'GET', '/documents')).etag, et);
  } finally {
    await server.stop();
  }
});

test('an oversized reconcile body is 413', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const good = JSON.stringify(snapshotOf([]));
    const oversized = await request(server.url, 'POST', '/snapshots/reconcile', {
      rawBody: JSON.stringify({
        base: { note: 'x'.repeat(1024 * 1024) },
        incoming: good,
      }),
      headers: { 'if-match': et },
    });
    assert.equal(oversized.status, 413);
    assert.equal(oversized.body.code, 'PAYLOAD_TOO_LARGE');
  } finally {
    await server.stop();
  }
});

// --- preconditions -----------------------------------------------------------

test('reconcile enforces If-Match, including dry-run previews', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  const base = snapshotOf([]);
  const incoming = snapshotOf([doc('a')]);
  const server = await startServer([file, '--port', '0']);
  try {
    const missing = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming, dryRun: true },
    });
    assert.equal(missing.status, 428);
    assert.equal(missing.body.code, 'PRECONDITION_REQUIRED');

    const et = (await request(server.url, 'GET', '/documents')).etag;
    const malformed = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming, dryRun: true },
      headers: { 'if-match': 'garbage' },
    });
    assert.equal(malformed.status, 400);
    assert.equal(malformed.body.code, 'INVALID_IF_MATCH');

    const stale = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': `"${'0'.repeat(64)}"` },
    });
    assert.equal(stale.status, 412);
    assert.equal(stale.body.code, 'PRECONDITION_FAILED');
  } finally {
    await server.stop();
  }
});

test('concurrent reconciles on the same checksum commit at most once', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  const base = snapshotOf([doc('a', { body: 'old' })]);
  writeSnapshot(file, [doc('a', { body: 'old' })]);
  const online = snapshotOf([doc('a', { body: 'online' })]);
  const incomingOne = snapshotOf([doc('a', { body: 'offline one' })]);
  const incomingTwo = snapshotOf([doc('a', { body: 'offline two' })]);
  const server = await startServer([file, '--port', '0']);
  try {
    // Advance the server to the "current" online state first.
    let et = (await request(server.url, 'GET', '/documents')).etag;
    await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming: online },
      headers: { 'if-match': et },
    });
    et = (await request(server.url, 'GET', '/documents')).etag;
    const [first, second] = await Promise.all([
      request(server.url, 'POST', '/snapshots/reconcile', {
        body: { base: online, incoming: incomingOne },
        headers: { 'if-match': et },
      }),
      request(server.url, 'POST', '/snapshots/reconcile', {
        body: { base: online, incoming: incomingTwo },
        headers: { 'if-match': et },
      }),
    ]);
    const statuses = [first.status, second.status].sort();
    assert.deepEqual(statuses, [200, 412]);
  } finally {
    await server.stop();
  }
});

// --- dry run and no-op -------------------------------------------------------

test('dryRun returns the projection without touching queries, history, or files', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  const base = snapshotOf([doc('a', { body: 'old' })]);
  writeSnapshot(file, [doc('a', { body: 'old' })]);
  const incoming = snapshotOf([doc('a', { body: 'offline' }), doc('b')]);
  const before = fs.readFileSync(file, 'utf8');
  const server = await startServer([file, '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const preview = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming, dryRun: true },
      headers: { 'if-match': et },
    });
    assert.equal(preview.status, 200);
    assert.deepEqual([...docMap(preview.body).keys()], ['a', 'b']);
    assert.equal(docMap(preview.body).get('a').body, 'offline');

    const live = await request(server.url, 'GET', '/documents');
    assert.deepEqual(live.body.map((d) => d.id), ['a']);
    assert.equal(live.etag, et);
    assert.equal(fs.readFileSync(file, 'utf8'), before);

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

test('a reconcile whose result equals the current content writes nothing and adds no revision', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  const current = [doc('a', { body: 'same' }), doc('b')];
  writeSnapshot(file, current);
  const server = await startServer([
    file, '--history', path.join(cwd, 'history.json'), '--port', '0',
  ]);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    // Incoming re-applies the online state: no net change.
    const base = snapshotOf([doc('a', { body: 'older' })]);
    const incoming = snapshotOf(current);
    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.equal(response.etag, et);
    const history = await request(server.url, 'GET', '/documents/a/history');
    assert.deepEqual(history.body.map((entry) => entry.action), ['baseline']);
  } finally {
    await server.stop();
  }
});

// --- save failure ------------------------------------------------------------

test('a failed reconcile save returns 500 IO_ERROR and leaves state and file intact', async () => {
  const cwd = tempDir();
  const dataDir = path.join(cwd, 'data');
  fs.mkdirSync(dataDir);
  const file = path.join(dataDir, 'snap.json');
  const base = snapshotOf([doc('a', { body: 'old' })]);
  writeSnapshot(file, [doc('a', { body: 'old' })]);
  const incoming = snapshotOf([doc('a', { body: 'offline' })]);
  const server = await startServer([file, '--port', '0']);
  try {
    let et = (await request(server.url, 'GET', '/documents')).etag;
    fs.rmSync(dataDir, { recursive: true, force: true });
    const failed = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': et },
    });
    assert.equal(failed.status, 500);
    assert.equal(failed.body.code, 'IO_ERROR');

    const live = await request(server.url, 'GET', '/documents/a');
    assert.equal(live.body.body, 'old');
    et = (await request(server.url, 'GET', '/documents')).etag;

    fs.mkdirSync(dataDir);
    const retry = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': et },
    });
    assert.equal(retry.status, 200);
    assert.equal(docMap(retry.body).get('a').body, 'offline');
  } finally {
    await server.stop();
  }
});

// --- history -----------------------------------------------------------------

function startHistory(cwd) {
  return startServer([
    path.join(cwd, 'snap.json'), '--history', path.join(cwd, 'history.json'), '--port', '0',
  ]);
}

test('history appends create/replace/delete records per changed document and continues deleted chains', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  // c was deleted before the offline fork exported its base, so c is absent
  // from both base and the live state but still has a history chain.
  const base = snapshotOf([
    doc('a', { title: 'A', body: 'old a', tags: [] }),
    doc('b', { title: 'B', body: 'old b', tags: [] }),
  ]);
  writeSnapshot(file, [
    doc('a', { title: 'A', body: 'old a', tags: [] }),
    doc('b', { title: 'B', body: 'old b', tags: [] }),
  ]);
  // Prepare a history file in which c was created then deleted.
  const { HistoryStore } = await import('../src/history.js');
  const ledger = HistoryStore.baseline([
    doc('a', { title: 'A', body: 'old a', tags: [] }),
    doc('b', { title: 'B', body: 'old b', tags: [] }),
    doc('c', { title: 'C', body: 'c body', tags: [] }),
  ]);
  const draft = ledger.clone();
  draft.record('c', 'delete', null);
  const { snapshotFromDocuments } = await import('../src/workspace.js');
  const currentSnapshot = snapshotFromDocuments([
    doc('a', { title: 'A', body: 'old a', tags: [] }),
    doc('b', { title: 'B', body: 'old b', tags: [] }),
  ]);
  fs.writeFileSync(
    path.join(cwd, 'history.json'),
    `${JSON.stringify(draft.exportJSON(currentSnapshot.checksum))}\n`,
  );

  // Offline: replaces a, deletes untouched b, re-adds previously-deleted c,
  // and adds brand-new d.
  const incoming = snapshotOf([
    doc('a', { title: 'A', body: 'offline a', tags: [] }),
    doc('c', { title: 'C', body: 'c is back', tags: [] }),
    doc('d', { title: 'D', body: 'd body', tags: [] }),
  ]);
  const server = await startHistory(cwd);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base, incoming },
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    const documents = docMap(response.body);
    assert.equal(documents.get('a').body, 'offline a');
    assert.equal(documents.get('c').body, 'c is back');
    assert.equal(documents.get('d').body, 'd body');
    assert.ok(!documents.has('b'));

    const historyA = await request(server.url, 'GET', '/documents/a/history');
    assert.deepEqual(historyA.body.map((entry) => entry.action), ['baseline', 'replace']);
    const historyB = await request(server.url, 'GET', '/documents/b/history');
    assert.deepEqual(historyB.body.map((entry) => entry.action), ['baseline', 'delete']);
    const historyC = await request(server.url, 'GET', '/documents/c/history');
    assert.deepEqual(historyC.body.map((entry) => entry.action), ['baseline', 'delete', 'create']);
    assert.equal(historyC.body[2].revision, 3);
    assert.equal(historyC.body[2].document.body, 'c is back');
    const historyD = await request(server.url, 'GET', '/documents/d/history');
    assert.deepEqual(historyD.body.map((entry) => entry.action), ['create']);
    assert.equal(historyD.body[0].revision, 1);
  } finally {
    await server.stop();
  }

  // Restart reconstructs content and ledger consistently.
  const restarted = await startHistory(cwd);
  try {
    const documents = await request(restarted.url, 'GET', '/documents');
    assert.deepEqual(documents.body.map((d) => d.id), ['a', 'c', 'd']);
    assert.equal(documents.body.find((d) => d.id === 'a').body, 'offline a');
    const historyC = await request(restarted.url, 'GET', '/documents/c/history');
    assert.deepEqual(historyC.body.map((entry) => [entry.revision, entry.action]), [[1, 'baseline'], [2, 'delete'], [3, 'create']]);
  } finally {
    await restarted.stop();
  }
});
