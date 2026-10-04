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

test('links route only counts prose references, not code samples or escapes', async () => {
  const body = [
    'Prose [[b]] link.',
    'Inline `[[c]]` sample.',
    '```',
    '[[d]] in a fenced block',
    '```',
    'Escaped \\[[e]] reference.',
    'Dangling [[ghost]] target.',
  ].join('\n');
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body, tags: [] },
    { id: 'b', title: 'Beta', body: 'markdown body', tags: [] },
    { id: 'c', title: 'C', body: 'c body', tags: [] },
    { id: 'd', title: 'D', body: 'd body', tags: [] },
    { id: 'e', title: 'E', body: 'e body', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    // Only the plain-prose targets (b and the not-yet-created ghost) count;
    // inline code, the fenced block, and the escaped reference do not.
    const links = await request(server.url, 'GET', '/documents/a/links');
    assert.equal(links.status, 200);
    assert.deepEqual(links.body, { outgoing: ['b', 'ghost'], incoming: [] });

    // a's prose link shows up as b's incoming.
    const bLinks = await request(server.url, 'GET', '/documents/b/links');
    assert.deepEqual(bLinks.body, { outgoing: [], incoming: ['a'] });

    // The code-only targets have no relationship to a either way.
    for (const id of ['c', 'd', 'e']) {
      const other = await request(server.url, 'GET', `/documents/${id}/links`);
      assert.deepEqual(other.body, { outgoing: [], incoming: [] });
    }

    // Querying links leaves the literal code sample in the stored body.
    const single = await request(server.url, 'GET', '/documents/a');
    assert.equal(single.body.body, body);

    // Full-text search still matches text inside the code samples.
    const found = await request(server.url, 'GET', '/search?q=%5B%5Bc%5D%5D');
    assert.deepEqual(found.body.map((document) => document.id), ['a']);

    // The same rules apply to links created by an edit.
    const updated = body.replace('Prose [[b]] link.', 'Prose [[b]] and [[c]] link.');
    const etag = single.etag;
    const put = await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: 'Alpha', body: updated, tags: [] },
      headers: { 'if-match': etag },
    });
    assert.equal(put.status, 200);
    const after = await request(server.url, 'GET', '/documents/a/links');
    assert.deepEqual(after.body, { outgoing: ['b', 'c', 'ghost'], incoming: [] });
    const cLinks = await request(server.url, 'GET', '/documents/c/links');
    assert.deepEqual(cLinks.body.incoming, ['a']);

    // An unknown document still fails the links query the same way.
    const missing = await request(server.url, 'GET', '/documents/nope/links');
    assert.equal(missing.status, 404);
    assert.equal(missing.body.code, 'NOT_FOUND');
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

test('serve rejects a snapshot aliasing the history file or its backup before loading content', async () => {
  const cwd = tempDir();
  const realDir = path.join(cwd, 'real');
  fs.mkdirSync(realDir);
  const history = path.join(realDir, 'history.json');
  const backup = `${history}.bak`;

  // Both inputs are corrupt: the path conflict must still be reported as
  // INVALID_OPTIONS, never INVALID_SNAPSHOT or INVALID_HISTORY.
  fs.writeFileSync(history, '{broken json');
  fs.writeFileSync(backup, 'existing backup');

  const linkDir = path.join(cwd, 'linked');
  fs.symlinkSync(realDir, linkDir, 'dir');
  const snapshotLink = path.join(cwd, 'snap-link.json');
  fs.symlinkSync(history, snapshotLink);

  const conflicting = [
    // The history file itself, spelled different ways.
    history,
    path.join(cwd, 'real', '.', 'history.json'),
    path.join(cwd, 'linked', 'history.json'), // via a symlinked directory
    snapshotLink, // via a file symlink
    path.join('real', '..', 'real', 'history.json'), // relative with ".."
    // The history backup location, spelled different ways.
    backup,
    path.join(cwd, 'linked', 'history.json.bak'),
    path.join('real', 'history.json.bak'), // relative spelling
  ];
  for (const snapshot of conflicting) {
    const { status, stdout, stderr } = await startServerFailure(
      [snapshot, '--history', history, '--port', '0'], { cwd },
    );
    assert.equal(status, 1, snapshot);
    assert.equal(stdout, '', snapshot);
    const lines = stderr.split('\n');
    assert.equal(lines.length, 2, snapshot);
    assert.equal(JSON.parse(lines[0]).code, 'INVALID_OPTIONS', snapshot);
    // Nothing was created, overwritten, moved, or deleted.
    assert.equal(fs.readFileSync(history, 'utf8'), '{broken json');
    assert.equal(fs.readFileSync(backup, 'utf8'), 'existing backup');
  }
});

test('serve rejects snapshot/history aliases whose files do not exist yet', async () => {
  const cwd = tempDir();
  const realDir = path.join(cwd, 'real');
  fs.mkdirSync(realDir);
  const linkDir = path.join(cwd, 'linked');
  fs.symlinkSync(realDir, linkDir, 'dir');

  // Neither file exists: the symlinked parent directory still gives the
  // snapshot the history backup's location.
  const history = path.join(linkDir, 'history.json');
  const snapshot = path.join(realDir, 'history.json.bak');
  const failed = await startServerFailure([snapshot, '--history', history, '--port', '0']);
  assert.equal(failed.status, 1);
  assert.equal(failed.stdout, '');
  assert.equal(JSON.parse(failed.stderr.trim()).code, 'INVALID_OPTIONS');
  assert.ok(!fs.existsSync(snapshot));
  assert.ok(!fs.existsSync(history));

  // Same pair through the non-aliased directory starts normally.
  const server = await startServer([
    path.join(realDir, 'snap.json'), '--history', path.join(realDir, 'history.json'), '--port', '0',
  ]);
  await server.stop();
});

test('serve accepts independent snapshot, history, and backup locations', async () => {
  const cwd = tempDir();
  // The same basename in different real directories is not a conflict, and a
  // snapshot whose name merely ends in ".bak" is not rejected wholesale.
  const dirA = path.join(cwd, 'a');
  const dirB = path.join(cwd, 'b');
  fs.mkdirSync(dirA);
  fs.mkdirSync(dirB);
  const snapshot = path.join(dirA, 'history.json.bak');
  const history = path.join(dirB, 'history.json');
  const server = await startServer([snapshot, '--history', history, '--port', '0']);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    assert.equal(empty.status, 200);
    const created = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'body', tags: [] },
      headers: { 'if-match': empty.etag },
    });
    assert.equal(created.status, 201);
    assert.ok(fs.existsSync(snapshot));
    assert.ok(fs.existsSync(history));
    assert.ok(!fs.existsSync(`${history}.bak`));
    const rows = (await request(server.url, 'GET', '/documents/a/history')).body;
    assert.deepEqual(rows.map((entry) => [entry.revision, entry.action]), [[1, 'create']]);
  } finally {
    await server.stop();
  }
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
