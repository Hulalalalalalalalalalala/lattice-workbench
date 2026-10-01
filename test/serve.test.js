import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import test from 'node:test';
import { Workspace } from '../src/workspace.js';

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
