import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import test from 'node:test';
import { Workspace } from '../src/workspace.js';

const CLI = path.resolve('src/cli.js');

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-serve-'));
}

function startServer(file, extraArgs = []) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, 'serve', file, ...extraArgs], {
      cwd: path.dirname(CLI),
    });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(value);
    };
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      if (stdout.includes('\n')) {
        try {
          const address = JSON.parse(stdout.split('\n')[0]);
          finish(null, { child, address });
        } catch (error) {
          finish(error);
        }
      }
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('error', (error) => finish(error));
    child.on('exit', (code) => {
      if (code !== 0) finish(new Error(`server exited with code ${code}: ${stderr}`));
    });
  });
}

function stopServer(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null) {
      resolve();
      return;
    }
    child.once('exit', () => resolve());
    child.kill();
  });
}

async function stopAll(children) {
  for (const child of children) {
    await stopServer(child);
  }
}

function request(base, method, route, options = {}) {
  return new Promise((resolve, reject) => {
    const payload = options.body === undefined ? null : Buffer.from(options.body);
    const headers = { ...(options.headers ?? {}) };
    if (payload) {
      headers['Content-Type'] = headers['Content-Type'] ?? 'application/json';
      headers['Content-Length'] = payload.length;
    }
    if (options.etag) headers['If-Match'] = options.etag;
    const req = http.request(
      `${base}${route}`,
      { method, headers },
      (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: data ? JSON.parse(data) : null,
          });
        });
      },
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function docBody(overrides = {}) {
  return JSON.stringify({
    id: 'note',
    title: 'Note',
    body: 'body text',
    tags: [],
    ...overrides,
  });
}

test('serve starts on a missing file with an empty workspace and creates the file on first write', async () => {
  const children = [];
  try {
    const cwd = tempDir();
    const file = path.join(cwd, 'workspace.json');
    assert.ok(!fs.existsSync(file));
    const { child, address } = await startServer(file, ['--port', '0']);
    children.push(child);

    assert.match(address.url, /^http:\/\/127\.0\.0\.1:\d+$/u);
    const base = `http://127.0.0.1:${address.port}`;

    const list = await request(base, 'GET', '/documents');
    assert.equal(list.status, 200);
    assert.deepEqual(list.body, { documents: [] });
    assert.match(list.headers.etag, /^"[0-9a-f]{64}"$/u);
    assert.ok(!fs.existsSync(file), 'file is not created before the first write');

    const created = await request(base, 'POST', '/documents', {
      etag: list.headers.etag,
      body: docBody(),
    });
    assert.equal(created.status, 201);
    assert.equal(created.body.version, 1);
    assert.deepEqual(created.body.documents.map((d) => d.id), ['note']);
    assert.equal(created.headers.etag, `"${created.body.checksum}"`);
    assert.ok(fs.existsSync(file), 'file is created on first write');
  } finally {
    await stopAll(children);
  }
});

test('serve loads an existing snapshot and persists writes across restart', async () => {
  const children = [];
  try {
    const cwd = tempDir();
    const file = path.join(cwd, 'workspace.json');
    const seed = new Workspace();
    seed.add({ id: 'welcome', title: 'Welcome', body: 'See [[architecture]].', tags: ['intro'] });
    fs.writeFileSync(file, `${JSON.stringify(seed.exportJSON())}\n`);

    const first = await startServer(file, ['--port', '0']);
    children.push(first.child);
    let base = `http://127.0.0.1:${first.address.port}`;

    const loaded = await request(base, 'GET', '/documents');
    assert.equal(loaded.status, 200);
    assert.deepEqual(loaded.body.documents.map((d) => d.id), ['welcome']);
    assert.equal(loaded.headers.etag, `"${seed.exportJSON().checksum}"`);

    const created = await request(base, 'POST', '/documents', {
      etag: loaded.headers.etag,
      body: docBody({ id: 'architecture', title: 'Architecture', body: 'back to [[welcome]]', tags: ['Markdown'] }),
    });
    assert.equal(created.status, 201);
    await stopServer(first.child);
    children.pop();

    const second = await startServer(file, ['--port', '0']);
    children.push(second.child);
    base = `http://127.0.0.1:${second.address.port}`;

    const afterRestart = await request(base, 'GET', '/documents');
    assert.equal(afterRestart.status, 200);
    assert.deepEqual(afterRestart.body.documents.map((d) => d.id), ['architecture', 'welcome']);
    assert.deepEqual(afterRestart.body.documents[0].tags, ['markdown']);
    assert.equal(afterRestart.body.documents[0].body, 'back to [[welcome]]');

    // The persisted file is a valid snapshot importable by the existing interface.
    const reloaded = new Workspace();
    reloaded.importJSON(fs.readFileSync(file, 'utf8'), { mode: 'replace' });
    assert.deepEqual(reloaded.exportJSON().checksum, afterRestart.headers.etag.slice(1, -1));
  } finally {
    await stopAll(children);
  }
});

test('write preconditions: missing 428, malformed 400, stale 412', async () => {
  const children = [];
  try {
    const cwd = tempDir();
    const file = path.join(cwd, 'workspace.json');
    const { child, address } = await startServer(file, ['--port', '0']);
    children.push(child);
    const base = `http://127.0.0.1:${address.port}`;

    const missing = await request(base, 'POST', '/documents', { body: docBody() });
    assert.equal(missing.status, 428);
    assert.equal(missing.body.code, 'IF_MATCH_REQUIRED');

    const malformed = await request(base, 'POST', '/documents', {
      etag: 'not-a-checksum',
      body: docBody(),
    });
    assert.equal(malformed.status, 400);
    assert.equal(malformed.body.code, 'INVALID_IF_MATCH');

    const stale = await request(base, 'POST', '/documents', {
      etag: `"${'0'.repeat(64)}"`,
      body: docBody(),
    });
    assert.equal(stale.status, 412);
    assert.equal(stale.body.code, 'CHECKSUM_MISMATCH');

    const empty = await request(base, 'GET', '/documents');
    assert.deepEqual(empty.body, { documents: [] });
  } finally {
    await stopAll(children);
  }
});

test('document validation: 400 for invalid JSON and illegal fields, 409 for duplicates', async () => {
  const children = [];
  try {
    const cwd = tempDir();
    const file = path.join(cwd, 'workspace.json');
    const { child, address } = await startServer(file, ['--port', '0']);
    children.push(child);
    const base = `http://127.0.0.1:${address.port}`;
    const list = await request(base, 'GET', '/documents');
    const etag = list.headers.etag;

    const cases = [
      ['{not json', 'INVALID_JSON'],
      [JSON.stringify({ id: 'note', title: 'Note', body: 'x', tags: 'nope' }), 'INVALID_DOCUMENT'],
      [JSON.stringify({ id: 'Bad Id', title: 'Note', body: 'x', tags: [] }), 'INVALID_DOCUMENT'],
      [JSON.stringify({ id: 'note', title: '  ', body: 'x', tags: [] }), 'INVALID_DOCUMENT'],
      [JSON.stringify({ id: 'note', title: 'Note', body: 'x', tags: [], extra: 1 }), 'INVALID_DOCUMENT'],
    ];
    for (const [body, code] of cases) {
      const response = await request(base, 'POST', '/documents', { etag, body });
      assert.equal(response.status, 400, body);
      assert.equal(response.body.code, code, body);
    }

    const created = await request(base, 'POST', '/documents', { etag, body: docBody() });
    assert.equal(created.status, 201);
    const fresh = await request(base, 'GET', '/documents');

    const duplicateId = await request(base, 'POST', '/documents', {
      etag: fresh.headers.etag,
      body: docBody({ id: 'note', title: 'Another' }),
    });
    assert.equal(duplicateId.status, 409);
    assert.equal(duplicateId.body.code, 'DUPLICATE_ID');

    const duplicateTitle = await request(base, 'POST', '/documents', {
      etag: fresh.headers.etag,
      body: docBody({ id: 'other', title: '  Note  ' }),
    });
    assert.equal(duplicateTitle.status, 409);
    assert.equal(duplicateTitle.body.code, 'DUPLICATE_TITLE');

    // Titles are case-sensitive: a different casing is not a collision.
    const differentCase = await request(base, 'POST', '/documents', {
      etag: fresh.headers.etag,
      body: docBody({ id: 'other', title: 'note' }),
    });
    assert.equal(differentCase.status, 201);

    // A document without tags defaults to an empty tag list.
    const noTags = await request(base, 'POST', '/documents', {
      etag: differentCase.headers.etag,
      body: JSON.stringify({ id: 'notags', title: 'No Tags', body: 'body' }),
    });
    assert.equal(noTags.status, 201);
    assert.deepEqual(noTags.body.documents.find((d) => d.id === 'notags').tags, []);
  } finally {
    await stopAll(children);
  }
});

test('PUT replaces fully, DELETE removes, and both return the post-commit snapshot', async () => {
  const children = [];
  try {
    const cwd = tempDir();
    const file = path.join(cwd, 'workspace.json');
    const { child, address } = await startServer(file, ['--port', '0']);
    children.push(child);
    const base = `http://127.0.0.1:${address.port}`;

    let etag = (await request(base, 'GET', '/documents')).headers.etag;
    await request(base, 'POST', '/documents', { etag, body: docBody() });
    etag = (await request(base, 'GET', '/documents')).headers.etag;

    const mismatch = await request(base, 'PUT', '/documents/note', {
      etag,
      body: docBody({ id: 'different', title: 'Note' }),
    });
    assert.equal(mismatch.status, 400);
    assert.equal(mismatch.body.code, 'INVALID_DOCUMENT');

    const missing = await request(base, 'PUT', '/documents/ghost', {
      etag,
      body: docBody({ id: 'ghost', title: 'Ghost' }),
    });
    assert.equal(missing.status, 404);
    assert.equal(missing.body.code, 'NOT_FOUND');

    const replaced = await request(base, 'PUT', '/documents/note', {
      etag,
      body: docBody({ title: 'Renamed', body: 'new body', tags: ['Tag'] }),
    });
    assert.equal(replaced.status, 200);
    assert.equal(replaced.body.documents[0].title, 'Renamed');
    assert.equal(replaced.body.documents[0].body, 'new body');
    assert.deepEqual(replaced.body.documents[0].tags, ['tag']);
    assert.equal(replaced.headers.etag, `"${replaced.body.checksum}"`);

    etag = replaced.headers.etag;
    const deleted = await request(base, 'DELETE', '/documents/note', { etag });
    assert.equal(deleted.status, 200);
    assert.deepEqual(deleted.body.documents, []);
    assert.equal(deleted.headers.etag, `"${deleted.body.checksum}"`);

    const gone = await request(base, 'GET', '/documents/note');
    assert.equal(gone.status, 404);
  } finally {
    await stopAll(children);
  }
});

test('DELETE preserves references in other documents and links/search reflect commits immediately', async () => {
  const children = [];
  try {
    const cwd = tempDir();
    const file = path.join(cwd, 'workspace.json');
    const { child, address } = await startServer(file, ['--port', '0']);
    children.push(child);
    const base = `http://127.0.0.1:${address.port}`;

    let etag = (await request(base, 'GET', '/documents')).headers.etag;
    await request(base, 'POST', '/documents', {
      etag,
      body: docBody({ id: 'a', title: 'A', body: 'links [[b]]', tags: [] }),
    });
    etag = (await request(base, 'GET', '/documents')).headers.etag;
    await request(base, 'POST', '/documents', {
      etag,
      body: docBody({ id: 'b', title: 'B', body: 'links [[a]]', tags: [] }),
    });
    etag = (await request(base, 'GET', '/documents')).headers.etag;

    const linksBefore = await request(base, 'GET', '/documents/a/links');
    assert.deepEqual(linksBefore.body, { outgoing: ['b'], incoming: ['b'] });

    const searchBefore = await request(base, 'GET', '/search?q=links');
    assert.deepEqual(searchBefore.body.documents.map((d) => d.id), ['a', 'b']);

    await request(base, 'DELETE', '/documents/b', { etag });

    const linksAfter = await request(base, 'GET', '/documents/a/links');
    assert.deepEqual(linksAfter.body, { outgoing: ['b'], incoming: [] });

    const searchAfter = await request(base, 'GET', '/search?q=links');
    assert.deepEqual(searchAfter.body.documents.map((d) => d.id), ['a']);

    // The deleted document's own body is gone, but a dangling link target is preserved.
    const snapshot = JSON.parse(fs.readFileSync(file, 'utf8'));
    assert.deepEqual(snapshot.documents.map((d) => d.id), ['a']);
    assert.equal(snapshot.documents[0].body, 'links [[b]]');
  } finally {
    await stopAll(children);
  }
});

test('two concurrent writes sharing a checksum both change content but only one succeeds', async () => {
  const children = [];
  try {
    const cwd = tempDir();
    const file = path.join(cwd, 'workspace.json');
    const { child, address } = await startServer(file, ['--port', '0']);
    children.push(child);
    const base = `http://127.0.0.1:${address.port}`;
    const etag = (await request(base, 'GET', '/documents')).headers.etag;

    const [first, second] = await Promise.all([
      request(base, 'POST', '/documents', { etag, body: docBody({ id: 'one', title: 'One' }) }),
      request(base, 'POST', '/documents', { etag, body: docBody({ id: 'two', title: 'Two' }) }),
    ]);

    const statuses = [first.status, second.status].sort();
    assert.deepEqual(statuses, [201, 412]);
    const winner = first.status === 201 ? first : second;
    assert.equal(winner.headers.etag, `"${winner.body.checksum}"`);

    const list = await request(base, 'GET', '/documents');
    assert.deepEqual(list.body.documents.map((d) => d.id), [winner.body.documents[0].id]);
  } finally {
    await stopAll(children);
  }
});

test('a body over 1 MiB is rejected with 413 and leaves state untouched', async () => {
  const children = [];
  try {
    const cwd = tempDir();
    const file = path.join(cwd, 'workspace.json');
    const { child, address } = await startServer(file, ['--port', '0']);
    children.push(child);
    const base = `http://127.0.0.1:${address.port}`;
    const etag = (await request(base, 'GET', '/documents')).headers.etag;

    const big = docBody({ id: 'big', title: 'Big', body: 'x'.repeat(1024 * 1024 + 1) });
    const response = await request(base, 'POST', '/documents', { etag, body: big });
    assert.equal(response.status, 413);
    assert.equal(response.body.code, 'PAYLOAD_TOO_LARGE');

    const list = await request(base, 'GET', '/documents');
    assert.deepEqual(list.body, { documents: [] });
    assert.ok(!fs.existsSync(file));
  } finally {
    await stopAll(children);
  }
});

test('a failed save returns 500 IO_ERROR, keeps memory and the file intact, and the server keeps serving', async () => {
  const children = [];
  try {
    const cwd = tempDir();
    const file = path.join(cwd, 'workspace.json');
    const { child, address } = await startServer(file, ['--port', '0']);
    children.push(child);
    const base = `http://127.0.0.1:${address.port}`;
    const etag = (await request(base, 'GET', '/documents')).headers.etag;

    await request(base, 'POST', '/documents', { etag, body: docBody() });
    const good = await request(base, 'GET', '/documents');
    assert.equal(good.status, 200);

    // Make the snapshot's directory unwritable so the atomic write fails.
    fs.chmodSync(cwd, 0o555);
    const before = fs.readFileSync(file, 'utf8');
    try {
      const failed = await request(base, 'POST', '/documents', {
        etag: good.headers.etag,
        body: docBody({ id: 'new', title: 'New' }),
      });
      assert.equal(failed.status, 500);
      assert.equal(failed.body.code, 'IO_ERROR');

      const after = await request(base, 'GET', '/documents');
      assert.deepEqual(after.body.documents.map((d) => d.id), ['note']);
      assert.equal(fs.readFileSync(file, 'utf8'), before);

      // The server is still alive and serving requests.
      const ping = await request(base, 'GET', '/documents');
      assert.equal(ping.status, 200);
    } finally {
      fs.chmodSync(cwd, 0o755);
    }
  } finally {
    await stopAll(children);
  }
});

test('serve exits 1 on an unreadable or checksum-invalid file without overwriting it', async () => {
  const cwd = tempDir();

  const tampered = path.join(cwd, 'tampered.json');
  const seed = new Workspace();
  seed.add({ id: 'a', title: 'A', body: 'original', tags: [] });
  const snapshot = seed.exportJSON();
  snapshot.documents[0].body = 'tampered';
  fs.writeFileSync(tampered, JSON.stringify(snapshot));

  await assert.rejects(
    () => startServer(tampered, ['--port', '0']),
    (error) => {
      assert.match(error.message, /INVALID_SNAPSHOT/u);
      return true;
    },
  );
  assert.equal(fs.readFileSync(tampered, 'utf8'), JSON.stringify(snapshot));

  const unreadable = path.join(cwd, 'unreadable.json');
  fs.writeFileSync(unreadable, '{}');
  fs.chmodSync(unreadable, 0o000);
  try {
    await assert.rejects(
      () => startServer(unreadable, ['--port', '0']),
      (error) => {
        assert.match(error.message, /IO_ERROR/u);
        return true;
      },
    );
  } finally {
    fs.chmodSync(unreadable, 0o644);
  }
});

test('serve rejects invalid arguments with INVALID_OPTIONS', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'workspace.json');
  for (const args of [
    ['--port', 'abc'],
    ['--port', '70000'],
    ['--port'],
    ['--unknown'],
  ]) {
    await assert.rejects(
      () => startServer(file, args),
      (error) => {
        assert.match(error.message, /INVALID_OPTIONS/u);
        return true;
      },
      args.join(' '),
    );
  }
});
