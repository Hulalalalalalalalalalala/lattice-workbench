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
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-serve-'));
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

test('serve prints one JSON line with the actual address and supports port 0', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    assert.equal(server.address.host, '127.0.0.1');
    assert.ok(server.address.port > 0);
    const lines = server.stdout().split('\n');
    assert.equal(lines.length, 2);
    assert.equal(lines[1], '');
    assert.deepEqual(JSON.parse(lines[0]), server.address);
  } finally {
    await server.stop();
  }
});

test('serve starts empty for a missing snapshot and creates the file on first write', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  const server = await startServer([file, '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    assert.equal(empty.status, 200);
    assert.deepEqual(empty.body, []);
    assert.match(empty.etag, ETAG_PATTERN);
    assert.ok(!fs.existsSync(file));

    const created = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'links [[b]]', tags: ['Intro', 'intro'] },
      headers: { 'if-match': empty.etag },
    });
    assert.equal(created.status, 201);
    assert.equal(created.etag, `"${created.body.checksum}"`);
    assert.equal(created.body.version, 1);
    assert.deepEqual(created.body.documents, [
      { id: 'a', title: 'A', body: 'links [[b]]', tags: ['intro'] },
    ]);
    assert.ok(fs.existsSync(file));

    // The written file is importable through the existing snapshot API.
    const reimported = new Workspace();
    reimported.importJSON(fs.readFileSync(file, 'utf8'), { mode: 'replace' });
    assert.deepEqual(reimported.exportJSON(), created.body);
  } finally {
    await server.stop();
  }

  // A restarted server reads the saved content back.
  const restarted = await startServer([file, '--port', '0']);
  try {
    const listed = await request(restarted.url, 'GET', '/documents');
    assert.deepEqual(listed.body.map((document) => document.id), ['a']);
    const single = await request(restarted.url, 'GET', '/documents/a');
    assert.equal(single.status, 200);
    assert.equal(single.body.body, 'links [[b]]');
    assert.equal(single.etag, `"${createdChecksum(file)}"`);
  } finally {
    await restarted.stop();
  }
});

function createdChecksum(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8')).checksum;
}

test('serve exits 1 with one JSON error line for an unreadable or invalid snapshot', async () => {
  const cwd = tempDir();

  const directory = path.join(cwd, 'a-directory');
  fs.mkdirSync(directory);
  const unreadable = await startServerFailure([directory, '--port', '0']);
  assert.equal(unreadable.status, 1);
  assert.equal(unreadable.stdout, '');
  assert.equal(JSON.parse(unreadable.stderr.trim()).code, 'IO_ERROR');

  const broken = path.join(cwd, 'broken.json');
  fs.writeFileSync(broken, '{broken json');
  const invalid = await startServerFailure([broken, '--port', '0']);
  assert.equal(invalid.status, 1);
  assert.equal(invalid.stdout, '');
  const lines = invalid.stderr.split('\n');
  assert.equal(lines.length, 2);
  assert.equal(JSON.parse(lines[0]).code, 'INVALID_SNAPSHOT');
  assert.equal(fs.readFileSync(broken, 'utf8'), '{broken json');

  const tampered = workspaceWith([{ id: 'a', title: 'A', body: 'original', tags: [] }]).exportJSON();
  tampered.documents[0].body = 'tampered';
  const tamperedFile = path.join(cwd, 'tampered.json');
  fs.writeFileSync(tamperedFile, JSON.stringify(tampered));
  const checksum = await startServerFailure([tamperedFile, '--port', '0']);
  assert.equal(checksum.status, 1);
  assert.equal(JSON.parse(checksum.stderr.trim()).code, 'INVALID_SNAPSHOT');
  assert.equal(fs.readFileSync(tamperedFile, 'utf8'), JSON.stringify(tampered));
});

test('serve rejects invalid arguments with INVALID_OPTIONS', async () => {
  for (const args of [
    [],
    ['one.json', 'two.json'],
    ['one.json', '--port'],
    ['one.json', '--port', 'abc'],
    ['one.json', '--port', '70000'],
    ['one.json', '--unknown'],
  ]) {
    const { status, stdout, stderr } = await startServerFailure(args);
    assert.equal(status, 1, args.join(' '));
    assert.equal(stdout, '', args.join(' '));
    assert.equal(JSON.parse(stderr.trim()).code, 'INVALID_OPTIONS', args.join(' '));
  }
});

test('CRUD, search, and links follow workspace semantics', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'links [[b]] and [[ghost]]', tags: ['One'] },
    { id: 'b', title: 'Beta', body: 'markdown body', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const listed = await request(server.url, 'GET', '/documents');
    assert.deepEqual(listed.body.map((document) => document.id), ['a', 'b']);

    const links = await request(server.url, 'GET', '/documents/a/links');
    assert.equal(links.status, 200);
    assert.deepEqual(links.body, { outgoing: ['b', 'ghost'], incoming: [] });

    const found = await request(server.url, 'GET', '/search?q=markdown');
    assert.deepEqual(found.body.map((document) => document.id), ['b']);

    // Full replace via PUT.
    const replaced = await request(server.url, 'PUT', '/documents/b', {
      body: { id: 'b', title: 'Beta v2', body: 'now links [[a]]', tags: ['Two'] },
      headers: { 'if-match': listed.etag },
    });
    assert.equal(replaced.status, 200);
    assert.equal(replaced.etag, `"${replaced.body.checksum}"`);
    const afterLinks = await request(server.url, 'GET', '/documents/a/links');
    assert.deepEqual(afterLinks.body.incoming, ['b']);

    // Delete keeps dangling references in other bodies and updates links.
    const removed = await request(server.url, 'DELETE', '/documents/b', {
      headers: { 'if-match': replaced.etag },
    });
    assert.equal(removed.status, 200);
    assert.deepEqual(removed.body.documents.map((document) => document.id), ['a']);
    const survivor = await request(server.url, 'GET', '/documents/a');
    assert.equal(survivor.body.body, 'links [[b]] and [[ghost]]');
    const survivorLinks = await request(server.url, 'GET', '/documents/a/links');
    assert.deepEqual(survivorLinks.body, { outgoing: ['b', 'ghost'], incoming: [] });

    const gone = await request(server.url, 'GET', '/documents/b');
    assert.equal(gone.status, 404);
    assert.equal(gone.body.code, 'NOT_FOUND');
  } finally {
    await server.stop();
  }
});

test('write validation maps to 400, 404, and 409 with stable codes', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  const server = await startServer([file, '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const created = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'Taken', body: 'body text', tags: [] },
      headers: { 'if-match': empty.etag },
    });
    assert.equal(created.status, 201);
    const etag = created.etag;

    const duplicateId = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'Other', body: 'body text', tags: [] },
      headers: { 'if-match': etag },
    });
    assert.equal(duplicateId.status, 409);
    assert.equal(duplicateId.body.code, 'CONFLICT');

    const duplicateTitle = await request(server.url, 'POST', '/documents', {
      body: { id: 'b', title: '  Taken  ', body: 'body text', tags: [] },
      headers: { 'if-match': etag },
    });
    assert.equal(duplicateTitle.status, 409);
    assert.equal(duplicateTitle.body.code, 'CONFLICT');

    // Titles remain case-sensitive.
    const differentCase = await request(server.url, 'POST', '/documents', {
      body: { id: 'b', title: 'taken', body: 'body text', tags: [] },
      headers: { 'if-match': etag },
    });
    assert.equal(differentCase.status, 201);

    const idMismatch = await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'c', title: 'C', body: 'body text', tags: [] },
      headers: { 'if-match': differentCase.etag },
    });
    assert.equal(idMismatch.status, 400);
    assert.equal(idMismatch.body.code, 'ID_MISMATCH');

    const missingPut = await request(server.url, 'PUT', '/documents/nope', {
      body: { id: 'nope', title: 'Nope', body: 'body text', tags: [] },
      headers: { 'if-match': differentCase.etag },
    });
    assert.equal(missingPut.status, 404);
    assert.equal(missingPut.body.code, 'NOT_FOUND');

    const missingDelete = await request(server.url, 'DELETE', '/documents/nope', {
      headers: { 'if-match': differentCase.etag },
    });
    assert.equal(missingDelete.status, 404);

    const invalidJson = await request(server.url, 'POST', '/documents', {
      rawBody: '{not json',
      headers: { 'if-match': differentCase.etag },
    });
    assert.equal(invalidJson.status, 400);
    assert.equal(invalidJson.body.code, 'INVALID_JSON');

    const invalidDocument = await request(server.url, 'POST', '/documents', {
      body: { id: 'Bad Id', title: 'X', body: 'body text', tags: [] },
      headers: { 'if-match': differentCase.etag },
    });
    assert.equal(invalidDocument.status, 400);
    assert.equal(invalidDocument.body.code, 'INVALID_DOCUMENT');

    const invalidTags = await request(server.url, 'POST', '/documents', {
      body: { id: 'c', title: 'C', body: 'body text', tags: [1] },
      headers: { 'if-match': differentCase.etag },
    });
    assert.equal(invalidTags.status, 400);
    assert.equal(invalidTags.body.code, 'INVALID_DOCUMENT');

    // Failures never changed the stored content.
    const listed = await request(server.url, 'GET', '/documents');
    assert.deepEqual(listed.body.map((document) => document.id), ['a', 'b']);
  } finally {
    await server.stop();
  }
});

test('If-Match is required, well-formed, and current', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');

    const missing = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'body text', tags: [] },
    });
    assert.equal(missing.status, 428);
    assert.equal(missing.body.code, 'PRECONDITION_REQUIRED');

    const malformed = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'body text', tags: [] },
      headers: { 'if-match': 'not-an-etag' },
    });
    assert.equal(malformed.status, 400);
    assert.equal(malformed.body.code, 'INVALID_IF_MATCH');

    const unquoted = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'body text', tags: [] },
      headers: { 'if-match': empty.etag.slice(1, -1) },
    });
    assert.equal(unquoted.status, 400);

    const created = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'body text', tags: [] },
      headers: { 'if-match': empty.etag },
    });
    assert.equal(created.status, 201);

    const stale = await request(server.url, 'POST', '/documents', {
      body: { id: 'b', title: 'B', body: 'body text', tags: [] },
      headers: { 'if-match': empty.etag },
    });
    assert.equal(stale.status, 412);
    assert.equal(stale.body.code, 'PRECONDITION_FAILED');
  } finally {
    await server.stop();
  }
});

test('two concurrent writes with the same checksum succeed at most once', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const [first, second] = await Promise.all([
      request(server.url, 'POST', '/documents', {
        body: { id: 'a', title: 'A', body: 'body text', tags: [] },
        headers: { 'if-match': empty.etag },
      }),
      request(server.url, 'POST', '/documents', {
        body: { id: 'b', title: 'B', body: 'body text', tags: [] },
        headers: { 'if-match': empty.etag },
      }),
    ]);
    const statuses = [first.status, second.status].sort();
    assert.deepEqual(statuses, [201, 412]);

    const listed = await request(server.url, 'GET', '/documents');
    assert.equal(listed.body.length, 1);
  } finally {
    await server.stop();
  }
});

test('a failed save returns 500 IO_ERROR and leaves memory, queries, and file intact', async () => {
  const cwd = tempDir();
  const blocked = path.join(cwd, 'no-such-dir', 'snap.json');
  const server = await startServer([blocked, '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const failed = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'body text', tags: [] },
      headers: { 'if-match': empty.etag },
    });
    assert.equal(failed.status, 500);
    assert.equal(failed.body.code, 'IO_ERROR');
    assert.ok(!fs.existsSync(blocked));

    // The service keeps accepting requests and the state is unchanged.
    const listed = await request(server.url, 'GET', '/documents');
    assert.equal(listed.status, 200);
    assert.deepEqual(listed.body, []);
    assert.equal(listed.etag, empty.etag);
  } finally {
    await server.stop();
  }
});

test('request bodies over 1 MiB are rejected with 413', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const oversized = await request(server.url, 'POST', '/documents', {
      rawBody: JSON.stringify({ id: 'a', title: 'A', body: 'x'.repeat(1024 * 1024), tags: [] }),
      headers: { 'if-match': empty.etag },
    });
    assert.equal(oversized.status, 413);
    assert.equal(oversized.body.code, 'PAYLOAD_TOO_LARGE');

    const listed = await request(server.url, 'GET', '/documents');
    assert.deepEqual(listed.body, []);
  } finally {
    await server.stop();
  }
});

function historyPaths(cwd) {
  return { snapshot: path.join(cwd, 'snap.json'), history: path.join(cwd, 'history.json') };
}

function startHistory(cwd, extraArgs = []) {
  const { snapshot, history } = historyPaths(cwd);
  return startServer([snapshot, '--history', history, '--port', '0', ...extraArgs]);
}

test('history: existing documents get revision 1 baselines and the file appears on first write', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a body [[b]]', tags: ['One'] },
    { id: 'b', title: 'Beta', body: 'b body', tags: [] },
  ]));
  const { history } = historyPaths(cwd);
  const server = await startHistory(cwd);
  try {
    const rows = await request(server.url, 'GET', '/documents/a/history');
    assert.equal(rows.status, 200);
    assert.deepEqual(rows.body, [
      { revision: 1, action: 'baseline', document: { id: 'a', title: 'Alpha', body: 'a body [[b]]', tags: ['one'] } },
    ]);
    assert.deepEqual((await request(server.url, 'GET', '/documents/b/history')).body[0].action, 'baseline');
    // The history file is created by the first successful write, not at startup.
    assert.ok(!fs.existsSync(history));
    const listed = await request(server.url, 'GET', '/documents');
    const changed = await request(server.url, 'PUT', '/documents/b', {
      body: { id: 'b', title: 'Beta', body: 'b body v2', tags: [] },
      headers: { 'if-match': listed.etag },
    });
    assert.equal(changed.status, 200);
    assert.ok(fs.existsSync(history));
  } finally {
    await server.stop();
  }
});

test('history: revisions are consecutive per document through create, replace, delete, recreate', async () => {
  const cwd = tempDir();
  const server = await startHistory(cwd);
  try {
    let et = (await request(server.url, 'GET', '/documents')).etag;
    const actions = [];
    const write = async (response, label) => { actions.push([label, response.status]); et = response.status < 400 ? response.etag : et; };

    await write(await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'one [[b]]', tags: ['X'] }, headers: { 'if-match': et },
    }), 'create');
    // A failed validation does not consume a revision.
    await write(await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'Dup', body: 'x', tags: [] }, headers: { 'if-match': et },
    }), 'dup');
    await write(await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: 'A', body: 'two', tags: ['x', 'y'] }, headers: { 'if-match': et },
    }), 'replace');
    // A normalized-identical replace succeeds but appends nothing.
    const noop = await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: '  A  ', body: 'two', tags: [' Y ', 'X', 'x'] }, headers: { 'if-match': et },
    });
    assert.equal(noop.status, 200);
    await write(await request(server.url, 'DELETE', '/documents/a', { headers: { 'if-match': et } }), 'delete');
    await write(await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A reborn', body: 'three', tags: [] }, headers: { 'if-match': et },
    }), 'recreate');

    const rows = (await request(server.url, 'GET', '/documents/a/history')).body;
    assert.deepEqual(rows.map((entry) => entry.revision), [1, 2, 3, 4]);
    assert.deepEqual(rows.map((entry) => entry.action), ['create', 'replace', 'delete', 'create']);
    assert.equal(rows[2].document, null);
    assert.deepEqual(rows[0].document, { id: 'a', title: 'A', body: 'one [[b]]', tags: ['x'] });
    assert.deepEqual(rows[1].document.tags, ['x', 'y']);
    assert.deepEqual(rows[3].document.body, 'three');

    // A document that never existed is 404; deleted documents stay readable.
    assert.equal((await request(server.url, 'GET', '/documents/ghost/history')).body.code, 'NOT_FOUND');
  } finally {
    await server.stop();
  }
});

test('history: restore revives revisions, including deleted documents, and appends a restore record', async () => {
  const cwd = tempDir();
  const server = await startHistory(cwd);
  try {
    let et = (await request(server.url, 'GET', '/documents')).etag;
    const send = async (method, route, body) => {
      const response = await request(server.url, method, route, { body, headers: { 'if-match': et } });
      if (response.status < 400) et = response.etag;
      return response;
    };
    await send('POST', '/documents', { id: 'b', title: 'B', body: 'owns title', tags: [] });
    await send('POST', '/documents', { id: 'a', title: 'A', body: 'v1 [[b]]', tags: ['One'] });
    await send('PUT', '/documents/a', { id: 'a', title: 'A2', body: 'v2', tags: ['two'] });
    await send('DELETE', '/documents/a');
    assert.equal((await request(server.url, 'GET', '/documents/a')).status, 404);

    // Restoring a delete revision is 400.
    const rows = (await request(server.url, 'GET', '/documents/a/history')).body;
    const deleteRevision = rows.find((entry) => entry.action === 'delete').revision;
    const badDelete = await send('POST', '/documents/a/restore', { revision: deleteRevision });
    assert.equal(badDelete.status, 400);
    assert.equal(badDelete.body.code, 'INVALID_REVISION');

    // An unknown revision number is 404.
    const unknown = await send('POST', '/documents/a/restore', { revision: 99 });
    assert.equal(unknown.status, 404);
    assert.equal(unknown.body.code, 'NOT_FOUND');

    // Restore revision 1 even though the document is deleted.
    const restored = await send('POST', '/documents/a/restore', { revision: 1 });
    assert.equal(restored.status, 200);
    assert.equal(restored.etag, `"${restored.body.checksum}"`);
    const doc = await request(server.url, 'GET', '/documents/a');
    assert.deepEqual(doc.body, { id: 'a', title: 'A', body: 'v1 [[b]]', tags: ['one'] });

    // Old records are untouched; a restore record was appended.
    const after = (await request(server.url, 'GET', '/documents/a/history')).body;
    assert.deepEqual(after.map((entry) => entry.action), ['create', 'replace', 'delete', 'restore']);
    assert.equal(after[after.length - 1].revision, 4);
    assert.deepEqual(after[after.length - 1].document.body, 'v1 [[b]]');

    // Search and links follow the restored content.
    assert.deepEqual((await request(server.url, 'GET', '/search?q=v2')).body.map((d) => d.id), []);
    const links = await request(server.url, 'GET', '/documents/a/links');
    assert.deepEqual(links.body, { outgoing: ['b'], incoming: [] });

    // Restoring the already-current revision succeeds but appends no record.
    const sameAgain = await send('POST', '/documents/a/restore', { revision: 4 });
    assert.equal(sameAgain.status, 200);
    assert.equal((await request(server.url, 'GET', '/documents/a/history')).body.length, 4);

    // A living document holding the target title makes restore conflict.
    await send('DELETE', '/documents/a');
    const claimant = await send('POST', '/documents', { id: 'c', title: 'A', body: 'holds A', tags: [] });
    assert.equal(claimant.status, 201);
    const conflict = await send('POST', '/documents/a/restore', { revision: 1 });
    assert.equal(conflict.status, 409);
    assert.equal(conflict.body.code, 'CONFLICT');
    // Freeing the title lets the restore revive the deleted document.
    await send('DELETE', '/documents/c');
    const revived = await send('POST', '/documents/a/restore', { revision: 1 });
    assert.equal(revived.status, 200);
    assert.equal((await request(server.url, 'GET', '/documents/a')).body.title, 'A');
  } finally {
    await server.stop();
  }
});

test('history: restore validates the request body and reports title conflicts', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'a body', tags: [] },
    { id: 'b', title: 'Taken', body: 'b body', tags: [] },
  ]));
  const server = await startHistory(cwd);
  try {
    let et = (await request(server.url, 'GET', '/documents')).etag;
    const restore = async (payload, { raw = false } = {}) => {
      const response = await request(server.url, 'POST', '/documents/a/restore', raw
        ? { rawBody: payload, headers: { 'if-match': et } }
        : { body: payload, headers: { 'if-match': et } });
      if (response.status < 400) et = response.etag;
      return response;
    };
    for (const bad of [
      JSON.stringify('{bad'),
      { revision: '1' },
      { revision: 0 },
      { revision: -1 },
      { revision: 1.5 },
      { revision: true },
      { revision: null },
      {},
      { revision: 1, force: true },
      [1],
      1,
    ]) {
      const response = typeof bad === 'string'
        ? await restore(bad, { raw: true })
        : await restore(bad);
      assert.equal(response.status, 400, JSON.stringify(bad));
      assert.equal(response.body.code, 'INVALID_REVISION', JSON.stringify(bad));
    }

    // Restore still honors If-Match.
    const noMatch = await request(server.url, 'POST', '/documents/a/restore', { body: { revision: 1 } });
    assert.equal(noMatch.status, 428);
    const malformed = await request(server.url, 'POST', '/documents/a/restore', {
      body: { revision: 1 }, headers: { 'if-match': 'garbage' },
    });
    assert.equal(malformed.status, 400);
    const stale = await request(server.url, 'POST', '/documents/a/restore', {
      body: { revision: 1 }, headers: { 'if-match': `"${'0'.repeat(64)}"` },
    });
    assert.equal(stale.status, 412);

    // Give a a revision whose title clashes with b, then restore into it.
    const clash = await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: 'Taken', body: 'clash', tags: [] },
      headers: { 'if-match': et },
    });
    assert.equal(clash.status, 409);
    assert.equal(clash.body.code, 'CONFLICT');
  } finally {
    await server.stop();
  }
});

test('history: restore survives a restart and keeps the revision chain', async () => {
  const cwd = tempDir();
  const server = await startHistory(cwd);
  let etag;
  try {
    etag = (await request(server.url, 'GET', '/documents')).etag;
    const send = async (method, route, body) => {
      const response = await request(server.url, method, route, { body, headers: { 'if-match': etag } });
      etag = response.etag;
      return response;
    };
    await send('POST', '/documents', { id: 'a', title: 'A', body: 'v1', tags: [] });
    await send('PUT', '/documents/a', { id: 'a', title: 'A', body: 'v2', tags: [] });
    await send('DELETE', '/documents/a');
    await send('POST', '/documents/a/restore', { revision: 2 });
  } finally {
    await server.stop();
  }

  const restarted = await startHistory(cwd);
  try {
    const doc = await request(restarted.url, 'GET', '/documents/a');
    assert.equal(doc.status, 200);
    assert.equal(doc.body.body, 'v2');
    const rows = (await request(restarted.url, 'GET', '/documents/a/history')).body;
    assert.deepEqual(rows.map((entry) => [entry.revision, entry.action]), [
      [1, 'create'], [2, 'replace'], [3, 'delete'], [4, 'restore'],
    ]);
    assert.equal(rows[3].document.body, 'v2');
  } finally {
    await restarted.stop();
  }
});

test('history: a failed two-file save returns 500 and keeps memory and both files intact', async () => {
  const cwd = tempDir();
  const { snapshot, history } = historyPaths(cwd);
  // The history directory never exists: startup baselines in memory, and the
  // first commit fails while staging the history file.
  const server = await startServer([snapshot, '--history', path.join(cwd, 'no-such-dir', 'history.json'), '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const failed = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'body', tags: [] },
      headers: { 'if-match': empty.etag },
    });
    assert.equal(failed.status, 500);
    assert.equal(failed.body.code, 'IO_ERROR');
    assert.ok(!fs.existsSync(snapshot));
    assert.ok(!fs.existsSync(history));

    const listed = await request(server.url, 'GET', '/documents');
    assert.deepEqual(listed.body, []);
    assert.equal(listed.etag, empty.etag);
    assert.equal((await request(server.url, 'GET', '/documents/a/history')).status, 404);
  } finally {
    await server.stop();
  }
});

test('serve rejects identical snapshot/history paths and bad history files', async () => {
  const cwd = tempDir();

  const same = path.join(cwd, 'both.json');
  const samePath = await startServerFailure([same, '--history', same, '--port', '0']);
  assert.equal(samePath.status, 1);
  assert.equal(samePath.stdout, '');
  assert.equal(JSON.parse(samePath.stderr.trim()).code, 'INVALID_OPTIONS');

  const directory = path.join(cwd, 'history-dir');
  fs.mkdirSync(directory);
  const unreadable = await startServerFailure([
    path.join(cwd, 'snap.json'), '--history', directory, '--port', '0',
  ]);
  assert.equal(unreadable.status, 1);
  assert.equal(JSON.parse(unreadable.stderr.trim()).code, 'IO_ERROR');

  const corrupt = path.join(cwd, 'corrupt-history.json');
  fs.writeFileSync(corrupt, '{broken json');
  const invalid = await startServerFailure([
    path.join(cwd, 'snap.json'), '--history', corrupt, '--port', '0',
  ]);
  assert.equal(invalid.status, 1);
  assert.equal(invalid.stdout, '');
  assert.equal(JSON.parse(invalid.stderr.trim()).code, 'INVALID_HISTORY');
  assert.equal(fs.readFileSync(corrupt, 'utf8'), '{broken json');
});

test('serve without --history keeps the original behavior and exposes no history routes', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'body', tags: [] },
      headers: { 'if-match': et },
    });
    assert.equal((await request(server.url, 'GET', '/documents/a/history')).body.code, 'NOT_FOUND');
    const restore = await request(server.url, 'POST', '/documents/a/restore', {
      body: { revision: 1 }, headers: { 'if-match': (await request(server.url, 'GET', '/documents')).etag },
    });
    assert.equal(restore.status, 404);
  } finally {
    await server.stop();
  }
});

// Builds committed snapshot/history file pairs for a small history so crash
// windows can be simulated by arranging the files before a restart.
function committedPair(documents, mutate) {
  let store = HistoryStore.baseline(documents.map((d) => structuredClone(d)));
  if (mutate) {
    store = store.clone();
    mutate(store);
  }
  const snapshot = snapshotFromDocuments(store.replayedDocuments().values());
  return { snapshot, history: store.exportJSON(snapshot.checksum) };
}

test('history: restart after a kill between the two file installs presents a whole state', async () => {
  const cwd = tempDir();
  const { snapshot: snapshotPath, history: historyPath } = historyPaths(cwd);
  const backupPath = `${historyPath}.bak`;
  const baseDocuments = [{ id: 'a', title: 'A', body: 'OLD', tags: [] }];

  const before = committedPair(baseDocuments);
  const after = committedPair(baseDocuments, (store) => {
    store.record('a', 'replace', { id: 'a', title: 'A', body: 'NEW', tags: [] });
  });

  // Window A: the old history was moved aside and the new one not yet put in
  // place (only the backup exists) — restart must show the pre-commit state.
  fs.writeFileSync(snapshotPath, JSON.stringify(before.snapshot));
  fs.writeFileSync(backupPath, JSON.stringify(before.history));
  let server = await startHistory(cwd);
  try {
    const doc = await request(server.url, 'GET', '/documents/a');
    assert.equal(doc.body.body, 'OLD');
    assert.ok(!fs.existsSync(backupPath));
  } finally {
    await server.stop();
  }

  // Window B: the new history landed but the snapshot rename had not run — the
  // acknowledged (post-commit) state must be reconstructed and presented.
  fs.writeFileSync(snapshotPath, JSON.stringify(before.snapshot));
  fs.writeFileSync(historyPath, JSON.stringify(after.history));
  fs.writeFileSync(backupPath, JSON.stringify(before.history));
  server = await startHistory(cwd);
  try {
    const doc = await request(server.url, 'GET', '/documents/a');
    assert.equal(doc.body.body, 'NEW');
    // The snapshot file is rebuilt and both files agree.
    const onDisk = JSON.parse(fs.readFileSync(snapshotPath, 'utf8'));
    assert.equal(onDisk.checksum, after.snapshot.checksum);
    assert.equal(JSON.parse(fs.readFileSync(historyPath, 'utf8')).snapshot, after.snapshot.checksum);
    assert.ok(!fs.existsSync(backupPath));
    // Further commits continue from the reconstructed state.
    const et = doc.etag;
    const next = await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: 'A', body: 'NEWER', tags: [] },
      headers: { 'if-match': et },
    });
    assert.equal(next.status, 200);
    const rows = (await request(server.url, 'GET', '/documents/a/history')).body;
    assert.deepEqual(rows.map((entry) => [entry.revision, entry.action]), [
      [1, 'baseline'], [2, 'replace'], [3, 'replace'],
    ]);
  } finally {
    await server.stop();
  }
});

test('history: a history that cannot replay to its embedded snapshot is INVALID_HISTORY', async () => {
  const cwd = tempDir();
  const { snapshot: snapshotPath, history: historyPath } = historyPaths(cwd);
  const pair = committedPair([{ id: 'a', title: 'A', body: 'body', tags: [] }]);
  fs.writeFileSync(snapshotPath, JSON.stringify(pair.snapshot));
  // Hand-edit an entry without updating the checksum chain.
  const broken = structuredClone(pair.history);
  broken.history.a[0].document.body = 'tampered';
  fs.writeFileSync(historyPath, JSON.stringify(broken));
  const failed = await startServerFailure([snapshotPath, '--history', historyPath, '--port', '0']);
  assert.equal(failed.status, 1);
  assert.equal(failed.stdout, '');
  assert.equal(JSON.parse(failed.stderr.trim()).code, 'INVALID_HISTORY');
});

test('batch: mixed operations commit atomically and queries reflect the whole batch', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  writeSnapshot(file, workspaceWith([
    { id: 'a', title: 'Alpha', body: 'links [[b]]', tags: ['One'] },
    { id: 'b', title: 'Beta', body: 'markdown body', tags: [] },
  ]));
  const server = await startServer([file, '--port', '0']);
  try {
    const before = await request(server.url, 'GET', '/documents');
    const result = await request(server.url, 'POST', '/batch', {
      body: {
        operations: [
          { type: 'create', document: { id: 'c', title: 'Gamma', body: 'fresh [[a]]', tags: ['New'] } },
          { type: 'replace', document: { id: 'a', title: 'Alpha v2', body: 'now links [[c]]', tags: [] } },
          { type: 'delete', id: 'b' },
        ],
      },
      headers: { 'if-match': before.etag },
    });
    assert.equal(result.status, 200);
    assert.equal(result.etag, `"${result.body.checksum}"`);
    assert.deepEqual(result.body.documents, [
      { id: 'a', title: 'Alpha v2', body: 'now links [[c]]', tags: [] },
      { id: 'c', title: 'Gamma', body: 'fresh [[a]]', tags: ['new'] },
    ]);

    // Search and bidirectional links reflect the whole batch immediately.
    assert.deepEqual((await request(server.url, 'GET', '/search?q=markdown')).body, []);
    const links = await request(server.url, 'GET', '/documents/a/links');
    assert.deepEqual(links.body, { outgoing: ['c'], incoming: ['c'] });
    assert.equal((await request(server.url, 'GET', '/documents/b')).status, 404);

    // The file holds exactly the committed snapshot.
    const onDisk = new Workspace();
    onDisk.importJSON(fs.readFileSync(file, 'utf8'), { mode: 'replace' });
    assert.deepEqual(onDisk.exportJSON(), result.body);
  } finally {
    await server.stop();
  }
});

test('batch: envelope and operation structure errors are 400 INVALID_BATCH', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const { etag } = await request(server.url, 'GET', '/documents');
    const send = (body) => request(server.url, 'POST', '/batch', { body, headers: { 'if-match': etag } });
    const create = { type: 'create', document: { id: 'a', title: 'A', body: 'body', tags: [] } };

    for (const body of [
      null,
      [],
      'text',
      {},
      { operations: create, dryRun: false },
      { operations: [], },
      { operations: [create], extra: true },
      { operations: [create], dryRun: 'yes' },
      { operations: [{}] },
      { operations: [[]] },
      { operations: [{ type: 'frobnicate', id: 'a' }] },
      { operations: [{ type: 'create' }] },
      { operations: [{ ...create, revision: 1 }] },
      { operations: [{ type: 'delete' }] },
      { operations: [{ type: 'delete', id: 'a', document: create.document }] },
      { operations: [{ type: 'delete', id: 7 }] },
      { operations: [{ type: 'restore', id: 'a' }] },
      { operations: [create, { type: 'replace', document: { id: 'a', title: 'A2', body: 'x', tags: [] } }] },
      { operations: [create, { type: 'delete', id: 'a' }] },
      { operations: Array.from({ length: 101 }, (_, i) => (
        { type: 'create', document: { id: `d${i}`, title: `T${i}`, body: 'x', tags: [] } }
      )) },
    ]) {
      const response = await send(body);
      assert.equal(response.status, 400, JSON.stringify(body));
      assert.equal(response.body.code, 'INVALID_BATCH', JSON.stringify(body));
    }

    // Exactly 100 operations is accepted.
    const full = await send({
      operations: Array.from({ length: 100 }, (_, i) => (
        { type: 'create', document: { id: `d${i}`, title: `T${i}`, body: 'x', tags: [] } }
      )),
    });
    assert.equal(full.status, 200);
    assert.equal(full.body.documents.length, 100);

    // Nothing from the failed batches leaked into the state.
    const listed = await request(server.url, 'GET', '/documents');
    assert.equal(listed.body.length, 100);
  } finally {
    await server.stop();
  }
});

test('batch: document and revision errors follow the single-document rules', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a body', tags: [] },
  ]));
  const server = await startHistory(cwd);
  try {
    const { etag } = await request(server.url, 'GET', '/documents');
    const send = (operations) => request(server.url, 'POST', '/batch', {
      body: { operations }, headers: { 'if-match': etag },
    });

    const badDocument = await send([{ type: 'create', document: { id: 'Bad Id', title: 'X', body: 'x', tags: [] } }]);
    assert.equal(badDocument.status, 400);
    assert.equal(badDocument.body.code, 'INVALID_DOCUMENT');

    const badTags = await send([{ type: 'replace', document: { id: 'a', title: 'A', body: 'x', tags: [1] } }]);
    assert.equal(badTags.status, 400);
    assert.equal(badTags.body.code, 'INVALID_DOCUMENT');

    const badRevision = await send([{ type: 'restore', id: 'a', revision: 1.5 }]);
    assert.equal(badRevision.status, 400);
    assert.equal(badRevision.body.code, 'INVALID_REVISION');

    const unknownRevision = await send([{ type: 'restore', id: 'a', revision: 99 }]);
    assert.equal(unknownRevision.status, 404);
    assert.equal(unknownRevision.body.code, 'NOT_FOUND');

    const neverExisted = await send([{ type: 'restore', id: 'ghost', revision: 1 }]);
    assert.equal(neverExisted.status, 404);
    assert.equal(neverExisted.body.code, 'NOT_FOUND');

    const invalidJson = await request(server.url, 'POST', '/batch', {
      rawBody: '{not json', headers: { 'if-match': etag },
    });
    assert.equal(invalidJson.status, 400);
    assert.equal(invalidJson.body.code, 'INVALID_JSON');

    const oversized = await request(server.url, 'POST', '/batch', {
      rawBody: JSON.stringify({ operations: [{ type: 'create', document: { id: 'big', title: 'B', body: 'x'.repeat(1024 * 1024), tags: [] } }] }),
      headers: { 'if-match': etag },
    });
    assert.equal(oversized.status, 413);
    assert.equal(oversized.body.code, 'PAYLOAD_TOO_LARGE');

    // State is untouched by every failure.
    const listed = await request(server.url, 'GET', '/documents');
    assert.deepEqual(listed.body.map((document) => document.id), ['a']);
    assert.equal(listed.etag, etag);
  } finally {
    await server.stop();
  }
});

test('batch: one failing operation rejects the whole batch', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  writeSnapshot(file, workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a body', tags: [] },
  ]));
  const before = fs.readFileSync(file, 'utf8');
  const server = await startServer([file, '--port', '0']);
  try {
    const { etag } = await request(server.url, 'GET', '/documents');

    const createExisting = await request(server.url, 'POST', '/batch', {
      body: { operations: [
        { type: 'create', document: { id: 'b', title: 'Beta', body: 'b body', tags: [] } },
        { type: 'create', document: { id: 'a', title: 'Other', body: 'x', tags: [] } },
      ] },
      headers: { 'if-match': etag },
    });
    assert.equal(createExisting.status, 409);
    assert.equal(createExisting.body.code, 'CONFLICT');

    const replaceMissing = await request(server.url, 'POST', '/batch', {
      body: { operations: [
        { type: 'delete', id: 'a' },
        { type: 'replace', document: { id: 'ghost', title: 'G', body: 'x', tags: [] } },
      ] },
      headers: { 'if-match': etag },
    });
    assert.equal(replaceMissing.status, 404);
    assert.equal(replaceMissing.body.code, 'NOT_FOUND');

    const deleteMissing = await request(server.url, 'POST', '/batch', {
      body: { operations: [{ type: 'delete', id: 'ghost' }] },
      headers: { 'if-match': etag },
    });
    assert.equal(deleteMissing.status, 404);

    // A final-set title collision rejects everything, including valid ops.
    const titleClash = await request(server.url, 'POST', '/batch', {
      body: { operations: [
        { type: 'create', document: { id: 'b', title: 'Beta', body: 'b body', tags: [] } },
        { type: 'replace', document: { id: 'a', title: ' Beta ', body: 'a body', tags: [] } },
      ] },
      headers: { 'if-match': etag },
    });
    assert.equal(titleClash.status, 409);
    assert.equal(titleClash.body.code, 'CONFLICT');

    const listed = await request(server.url, 'GET', '/documents');
    assert.deepEqual(listed.body.map((document) => document.id), ['a']);
    assert.equal(listed.etag, etag);
    assert.equal(fs.readFileSync(file, 'utf8'), before);
  } finally {
    await server.stop();
  }
});

test('batch: titles are only judged on the final set', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a body', tags: [] },
    { id: 'b', title: 'Beta', body: 'b body', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    let et = (await request(server.url, 'GET', '/documents')).etag;

    // Swapping two titles in one batch is fine regardless of operation order.
    const swapped = await request(server.url, 'POST', '/batch', {
      body: { operations: [
        { type: 'replace', document: { id: 'a', title: 'Beta', body: 'a body', tags: [] } },
        { type: 'replace', document: { id: 'b', title: 'Alpha', body: 'b body', tags: [] } },
      ] },
      headers: { 'if-match': et },
    });
    assert.equal(swapped.status, 200);
    et = swapped.etag;

    // A title freed by a delete in the same batch can be reused.
    const reused = await request(server.url, 'POST', '/batch', {
      body: { operations: [
        { type: 'delete', id: 'a' },
        { type: 'create', document: { id: 'c', title: 'Beta', body: 'c body', tags: [] } },
      ] },
      headers: { 'if-match': et },
    });
    assert.equal(reused.status, 200);
    assert.deepEqual(reused.body.documents.map((document) => document.id), ['b', 'c']);

    // Titles stay trimmed and case-sensitive: ' Alpha ' collides after
    // trimming, 'alpha' does not.
    const caseSensitive = await request(server.url, 'POST', '/batch', {
      body: { operations: [
        { type: 'create', document: { id: 'd', title: ' Alpha ', body: 'd body', tags: [] } },
      ] },
      headers: { 'if-match': reused.etag },
    });
    assert.equal(caseSensitive.status, 409);
    const lower = await request(server.url, 'POST', '/batch', {
      body: { operations: [
        { type: 'create', document: { id: 'd', title: 'alpha', body: 'd body', tags: [] } },
      ] },
      headers: { 'if-match': reused.etag },
    });
    assert.equal(lower.status, 200);
  } finally {
    await server.stop();
  }
});

test('batch: dryRun previews the projected snapshot without changing anything', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  const server = await startServer([file, '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const preview = await request(server.url, 'POST', '/batch', {
      body: { dryRun: true, operations: [
        { type: 'create', document: { id: 'a', title: 'A', body: 'a body', tags: [] } },
      ] },
      headers: { 'if-match': empty.etag },
    });
    assert.equal(preview.status, 200);
    assert.equal(preview.body.documents.length, 1);
    assert.equal(preview.etag, `"${preview.body.checksum}"`);

    // The current checksum, queries, and files are unchanged.
    const stillEmpty = await request(server.url, 'GET', '/documents');
    assert.deepEqual(stillEmpty.body, []);
    assert.equal(stillEmpty.etag, empty.etag);
    assert.ok(!fs.existsSync(file));

    // A dry run still validates and still requires If-Match.
    const noMatch = await request(server.url, 'POST', '/batch', {
      body: { dryRun: true, operations: [{ type: 'delete', id: 'a' }] },
    });
    assert.equal(noMatch.status, 428);
    const stale = await request(server.url, 'POST', '/batch', {
      body: { dryRun: true, operations: [{ type: 'delete', id: 'a' }] },
      headers: { 'if-match': `"${'0'.repeat(64)}"` },
    });
    assert.equal(stale.status, 412);
    const invalid = await request(server.url, 'POST', '/batch', {
      body: { dryRun: true, operations: [] },
      headers: { 'if-match': empty.etag },
    });
    assert.equal(invalid.status, 400);

    // Another writer may commit in the meantime; the real commit must match
    // the then-current checksum.
    const created = await request(server.url, 'POST', '/documents', {
      body: { id: 'x', title: 'X', body: 'x body', tags: [] },
      headers: { 'if-match': empty.etag },
    });
    assert.equal(created.status, 201);
    const commit = await request(server.url, 'POST', '/batch', {
      body: { operations: [{ type: 'create', document: { id: 'a', title: 'A', body: 'a body', tags: [] } }] },
      headers: { 'if-match': empty.etag },
    });
    assert.equal(commit.status, 412);
    const committed = await request(server.url, 'POST', '/batch', {
      body: { operations: [{ type: 'create', document: { id: 'a', title: 'A', body: 'a body', tags: [] } }] },
      headers: { 'if-match': created.etag },
    });
    assert.equal(committed.status, 200);
    assert.deepEqual(committed.body.documents.map((document) => document.id), ['a', 'x']);
  } finally {
    await server.stop();
  }
});

test('batch: a batch and a single write on the same checksum succeed at most once', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const [single, batch] = await Promise.all([
      request(server.url, 'POST', '/documents', {
        body: { id: 'a', title: 'A', body: 'a body', tags: [] },
        headers: { 'if-match': empty.etag },
      }),
      request(server.url, 'POST', '/batch', {
        body: { operations: [{ type: 'create', document: { id: 'b', title: 'B', body: 'b body', tags: [] } }] },
        headers: { 'if-match': empty.etag },
      }),
    ]);
    const statuses = [single.status, batch.status];
    assert.ok(statuses.includes(412));
    assert.ok(statuses.includes(200) || statuses.includes(201));
    const listed = await request(server.url, 'GET', '/documents');
    assert.equal(listed.body.length, 1);
  } finally {
    await server.stop();
  }
});

test('batch: a failed save returns 500 IO_ERROR and leaves everything intact', async () => {
  const cwd = tempDir();
  const blocked = path.join(cwd, 'no-such-dir', 'snap.json');
  const server = await startServer([blocked, '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const failed = await request(server.url, 'POST', '/batch', {
      body: { operations: [
        { type: 'create', document: { id: 'a', title: 'A', body: 'a body', tags: [] } },
        { type: 'create', document: { id: 'b', title: 'B', body: 'b body', tags: [] } },
      ] },
      headers: { 'if-match': empty.etag },
    });
    assert.equal(failed.status, 500);
    assert.equal(failed.body.code, 'IO_ERROR');
    assert.ok(!fs.existsSync(blocked));

    const listed = await request(server.url, 'GET', '/documents');
    assert.deepEqual(listed.body, []);
    assert.equal(listed.etag, empty.etag);
  } finally {
    await server.stop();
  }
});

test('batch with history: one record per changed document, no-ops append nothing', async () => {
  const cwd = tempDir();
  const { snapshot, history } = historyPaths(cwd);
  writeSnapshot(snapshot, workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a body', tags: ['One'] },
    { id: 'b', title: 'Beta', body: 'b body', tags: [] },
  ]));
  const server = await startHistory(cwd);
  try {
    let et = (await request(server.url, 'GET', '/documents')).etag;

    // A batch that changes nothing keeps the ETag and writes no files.
    const noop = await request(server.url, 'POST', '/batch', {
      body: { operations: [
        { type: 'replace', document: { id: 'a', title: ' Alpha ', body: 'a body', tags: [' one ', 'ONE'] } },
        { type: 'restore', id: 'b', revision: 1 },
      ] },
      headers: { 'if-match': et },
    });
    assert.equal(noop.status, 200);
    assert.equal(noop.etag, et);
    assert.ok(!fs.existsSync(history));
    assert.equal((await request(server.url, 'GET', '/documents/a/history')).body.length, 1);

    // A mixed batch appends exactly one record per changed document.
    const mixed = await request(server.url, 'POST', '/batch', {
      body: { operations: [
        { type: 'replace', document: { id: 'a', title: 'Alpha', body: 'a body v2', tags: [] } },
        { type: 'delete', id: 'b' },
        { type: 'create', document: { id: 'c', title: 'Gamma', body: 'c body', tags: [] } },
      ] },
      headers: { 'if-match': et },
    });
    assert.equal(mixed.status, 200);
    et = mixed.etag;
    assert.deepEqual(
      (await request(server.url, 'GET', '/documents/a/history')).body.map((entry) => [entry.revision, entry.action]),
      [[1, 'baseline'], [2, 'replace']],
    );
    assert.deepEqual(
      (await request(server.url, 'GET', '/documents/b/history')).body.map((entry) => [entry.revision, entry.action]),
      [[1, 'baseline'], [2, 'delete']],
    );
    assert.deepEqual(
      (await request(server.url, 'GET', '/documents/c/history')).body.map((entry) => [entry.revision, entry.action]),
      [[1, 'create']],
    );

    // Restore inside a batch revives a deleted document and keeps counting.
    const revived = await request(server.url, 'POST', '/batch', {
      body: { operations: [{ type: 'restore', id: 'b', revision: 1 }] },
      headers: { 'if-match': et },
    });
    assert.equal(revived.status, 200);
    et = revived.etag;
    const bRows = (await request(server.url, 'GET', '/documents/b/history')).body;
    assert.deepEqual(bRows.map((entry) => [entry.revision, entry.action]), [[1, 'baseline'], [2, 'delete'], [3, 'restore']]);
    assert.equal((await request(server.url, 'GET', '/documents/b')).body.body, 'b body');

    // Recreating a deleted id inside a batch continues the revision chain.
    await request(server.url, 'DELETE', '/documents/c', { headers: { 'if-match': et } });
    et = (await request(server.url, 'GET', '/documents')).etag;
    const recreated = await request(server.url, 'POST', '/batch', {
      body: { operations: [{ type: 'create', document: { id: 'c', title: 'Gamma reborn', body: 'new', tags: [] } }] },
      headers: { 'if-match': et },
    });
    assert.equal(recreated.status, 200);
    assert.deepEqual(
      (await request(server.url, 'GET', '/documents/c/history')).body.map((entry) => [entry.revision, entry.action]),
      [[1, 'create'], [2, 'delete'], [3, 'create']],
    );

    // A failed batch consumes no revisions.
    const failed = await request(server.url, 'POST', '/batch', {
      body: { operations: [
        { type: 'replace', document: { id: 'a', title: 'Alpha', body: 'changed again', tags: [] } },
        { type: 'delete', id: 'ghost' },
      ] },
      headers: { 'if-match': recreated.etag },
    });
    assert.equal(failed.status, 404);
    assert.equal((await request(server.url, 'GET', '/documents/a/history')).body.length, 2);
  } finally {
    await server.stop();
  }
});

test('batch: restore operations require history and follow single-restore rules', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a body', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const { etag } = await request(server.url, 'GET', '/documents');
    const response = await request(server.url, 'POST', '/batch', {
      body: { operations: [
        { type: 'create', document: { id: 'b', title: 'B', body: 'b body', tags: [] } },
        { type: 'restore', id: 'a', revision: 1 },
      ] },
      headers: { 'if-match': etag },
    });
    assert.equal(response.status, 404);
    assert.equal(response.body.code, 'NOT_FOUND');
    const listed = await request(server.url, 'GET', '/documents');
    assert.deepEqual(listed.body.map((document) => document.id), ['a']);
    assert.equal(listed.etag, etag);
  } finally {
    await server.stop();
  }
});

test('batch: restore of a delete revision is 400 INVALID_REVISION', async () => {
  const cwd = tempDir();
  const server = await startHistory(cwd);
  try {
    let et = (await request(server.url, 'GET', '/documents')).etag;
    const send = async (method, route, body) => {
      const response = await request(server.url, method, route, { body, headers: { 'if-match': et } });
      if (response.status < 400) et = response.etag;
      return response;
    };
    await send('POST', '/documents', { id: 'a', title: 'A', body: 'v1', tags: [] });
    await send('DELETE', '/documents/a');

    const restoreDelete = await send('POST', '/batch', { operations: [{ type: 'restore', id: 'a', revision: 2 }] });
    assert.equal(restoreDelete.status, 400);
    assert.equal(restoreDelete.body.code, 'INVALID_REVISION');

    // Existence and revisions are judged against the pre-batch state: a
    // restore of a deleted id and a create of another id commit together.
    const committed = await send('POST', '/batch', { operations: [
      { type: 'restore', id: 'a', revision: 1 },
      { type: 'create', document: { id: 'b', title: 'B', body: 'b body', tags: [] } },
    ] });
    assert.equal(committed.status, 200);
    assert.deepEqual(committed.body.documents.map((document) => document.id), ['a', 'b']);
    assert.deepEqual(
      (await request(server.url, 'GET', '/documents/a/history')).body.map((entry) => entry.action),
      ['create', 'delete', 'restore'],
    );
  } finally {
    await server.stop();
  }
});
