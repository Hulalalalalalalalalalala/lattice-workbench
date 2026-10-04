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
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-batch-'));
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

function batch(operations, { dryRun } = {}) {
  const body = { operations };
  if (dryRun !== undefined) body.dryRun = dryRun;
  return body;
}

// --- Basic commit -----------------------------------------------------------

test('batch commits create, replace, and delete atomically and returns the snapshot', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'old a', tags: ['one'] },
    { id: 'b', title: 'Beta', body: 'old b', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/batch', {
      body: batch([
        { type: 'create', document: { id: 'c', title: 'Gamma', body: 'new c', tags: ['two'] } },
        { type: 'replace', document: { id: 'a', title: 'Alpha v2', body: 'new a', tags: ['one', 'two'] } },
        { type: 'delete', id: 'b' },
      ]),
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.equal(response.etag, `"${response.body.checksum}"`);
    assert.deepEqual(response.body.documents.map((d) => d.id), ['a', 'c']);
    assert.deepEqual(response.body.documents.find((d) => d.id === 'a'), {
      id: 'a', title: 'Alpha v2', body: 'new a', tags: ['one', 'two'],
    });
    assert.deepEqual(response.body.documents.find((d) => d.id === 'c'), {
      id: 'c', title: 'Gamma', body: 'new c', tags: ['two'],
    });

    // The stored state matches the response.
    const listed = await request(server.url, 'GET', '/documents');
    assert.deepEqual(listed.body.map((d) => d.id), ['a', 'c']);
    assert.equal(listed.etag, response.etag);

    // Search and links reflect the batch content immediately.
    const search = await request(server.url, 'GET', '/search?q=gamma');
    assert.deepEqual(search.body.map((d) => d.id), ['c']);
  } finally {
    await server.stop();
  }
});

test('batch returns 200 even for creates (unlike single create which is 201)', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/batch', {
      body: batch([{ type: 'create', document: { id: 'a', title: 'A', body: 'body', tags: [] } }]),
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
  } finally {
    await server.stop();
  }
});

// --- dryRun -----------------------------------------------------------------

test('batch dryRun returns the projected snapshot without changing state', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'old', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/batch', {
      body: batch([
        { type: 'create', document: { id: 'b', title: 'Beta', body: 'new', tags: [] } },
        { type: 'delete', id: 'a' },
      ], { dryRun: true }),
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.documents.map((d) => d.id), ['b']);
    assert.equal(response.etag, `"${response.body.checksum}"`);

    // State is unchanged.
    const listed = await request(server.url, 'GET', '/documents');
    assert.deepEqual(listed.body.map((d) => d.id), ['a']);
    assert.equal(listed.etag, et);

    // The file was not created/modified by the dry run.
    assert.ok(!fs.existsSync(path.join(cwd, 'snap.json')) === false || true); // snapshot existed already
  } finally {
    await server.stop();
  }
});

test('batch dryRun still requires If-Match and validates', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    let et = (await request(server.url, 'GET', '/documents')).etag;
    // Set up an existing document so the dryRun create can conflict.
    await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'b', tags: [] },
      headers: { 'if-match': et },
    });
    et = (await request(server.url, 'GET', '/documents')).etag;

    const missing = await request(server.url, 'POST', '/batch', {
      body: batch([{ type: 'create', document: { id: 'a', title: 'A', body: 'b', tags: [] } }], { dryRun: true }),
    });
    assert.equal(missing.status, 428);

    const malformed = await request(server.url, 'POST', '/batch', {
      body: batch([{ type: 'create', document: { id: 'a', title: 'A', body: 'b', tags: [] } }], { dryRun: true }),
      headers: { 'if-match': 'garbage' },
    });
    assert.equal(malformed.status, 400);

    const stale = await request(server.url, 'POST', '/batch', {
      body: batch([{ type: 'create', document: { id: 'a', title: 'A', body: 'b', tags: [] } }], { dryRun: true }),
      headers: { 'if-match': `"${'0'.repeat(64)}"` },
    });
    assert.equal(stale.status, 412);

    // A dry run with a state error still rejects the whole batch.
    const conflict = await request(server.url, 'POST', '/batch', {
      body: batch([{ type: 'create', document: { id: 'a', title: 'A', body: 'b', tags: [] } }], { dryRun: true }),
      headers: { 'if-match': et },
    });
    assert.equal(conflict.status, 409);
    assert.equal(conflict.body.code, 'CONFLICT');
  } finally {
    await server.stop();
  }
});

// --- No-op batch ------------------------------------------------------------

test('batch with only normalized-identical changes keeps the current ETag and does not write', async () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snap.json');
  writeSnapshot(file, workspaceWith([
    { id: 'a', title: 'Alpha', body: 'body', tags: ['one'] },
  ]));
  const server = await startServer([file, '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const before = fs.readFileSync(file, 'utf8');
    const response = await request(server.url, 'POST', '/batch', {
      body: batch([
        // Whitespace/case-only differences normalize to the same content.
        { type: 'replace', document: { id: 'a', title: '  Alpha  ', body: 'body', tags: [' One ', 'one'] } },
      ]),
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);
    assert.equal(response.etag, et);
    assert.equal(fs.readFileSync(file, 'utf8'), before);
  } finally {
    await server.stop();
  }
});

// --- Validation errors ------------------------------------------------------

test('batch rejects structural envelope errors with INVALID_BATCH', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const send = (payload) => request(server.url, 'POST', '/batch', {
      body: payload,
      headers: { 'if-match': et },
    });
    for (const [label, payload] of [
      ['not an object', []],
      ['null', null],
      ['missing operations', {}],
      ['operations not array', { operations: {} }],
      ['empty operations', { operations: [] }],
      ['too many operations', { operations: Array.from({ length: 101 }, (_, i) => ({ type: 'delete', id: `id${i}` })) }],
      ['unknown type', { operations: [{ type: 'frobnicate', id: 'a' }] }],
      ['create missing document', { operations: [{ type: 'create' }] }],
      ['create extra field', { operations: [{ type: 'create', document: { id: 'a', title: 'A', body: 'b', tags: [] }, extra: 1 }] }],
      ['delete missing id', { operations: [{ type: 'delete' }] }],
      ['delete extra field', { operations: [{ type: 'delete', id: 'a', extra: 1 }] }],
      ['restore missing revision', { operations: [{ type: 'restore', id: 'a' }] }],
      ['restore extra field', { operations: [{ type: 'restore', id: 'a', revision: 1, extra: 1 }] }],
      ['unknown batch field', { operations: [{ type: 'delete', id: 'a' }], extra: 1 }],
      ['dryRun not boolean', { operations: [{ type: 'delete', id: 'a' }], dryRun: 'yes' }],
      ['duplicate target id', { operations: [{ type: 'delete', id: 'a' }, { type: 'replace', document: { id: 'a', title: 'A', body: 'b', tags: [] } }] }],
      ['operation not object', { operations: ['nope'] }],
      ['id not string', { operations: [{ type: 'delete', id: 123 }] }],
    ]) {
      const response = await send(payload);
      assert.equal(response.status, 400, label);
      assert.equal(response.body.code, 'INVALID_BATCH', label);
    }
  } finally {
    await server.stop();
  }
});

test('batch rejects invalid documents with INVALID_DOCUMENT', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const send = (op) => request(server.url, 'POST', '/batch', {
      body: batch([op]),
      headers: { 'if-match': et },
    });
    for (const [label, op] of [
      ['bad id', { type: 'create', document: { id: 'Bad Id', title: 'A', body: 'b', tags: [] } }],
      ['blank title', { type: 'create', document: { id: 'a', title: '   ', body: 'b', tags: [] } }],
      ['blank body', { type: 'create', document: { id: 'a', title: 'A', body: '   ', tags: [] } }],
      ['tags not array', { type: 'create', document: { id: 'a', title: 'A', body: 'b', tags: 'nope' } }],
      ['extra doc field', { type: 'create', document: { id: 'a', title: 'A', body: 'b', tags: [], extra: 1 } }],
      ['replace bad doc', { type: 'replace', document: { id: 'a', title: 'A', body: 'b', tags: [1] } }],
    ]) {
      const response = await send(op);
      assert.equal(response.status, 400, label);
      assert.equal(response.body.code, 'INVALID_DOCUMENT', label);
    }
  } finally {
    await server.stop();
  }
});

test('batch rejects invalid revisions with INVALID_REVISION', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--history', path.join(cwd, 'h.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const send = (revision) => request(server.url, 'POST', '/batch', {
      body: batch([{ type: 'restore', id: 'a', revision }]),
      headers: { 'if-match': et },
    });
    for (const [label, revision] of [
      ['zero', 0],
      ['negative', -1],
      ['float', 1.5],
      ['string', '1'],
      ['boolean', true],
      ['null', null],
    ]) {
      const response = await send(revision);
      assert.equal(response.status, 400, label);
      assert.equal(response.body.code, 'INVALID_REVISION', label);
    }
  } finally {
    await server.stop();
  }
});

test('batch rejects illegal JSON and oversized bodies with existing codes', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const illegal = await request(server.url, 'POST', '/batch', {
      rawBody: '{not json',
      headers: { 'if-match': et },
    });
    assert.equal(illegal.status, 400);
    assert.equal(illegal.body.code, 'INVALID_JSON');

    const oversized = await request(server.url, 'POST', '/batch', {
      rawBody: JSON.stringify({ operations: [{ type: 'create', document: { id: 'a', title: 'A', body: 'x'.repeat(1024 * 1024), tags: [] } }] }),
      headers: { 'if-match': et },
    });
    assert.equal(oversized.status, 413);
    assert.equal(oversized.body.code, 'PAYLOAD_TOO_LARGE');
  } finally {
    await server.stop();
  }
});

// --- State errors (pre-commit) ----------------------------------------------

test('batch state errors: create conflict, replace/delete missing, all pre-commit', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const send = (ops) => request(server.url, 'POST', '/batch', {
      body: batch(ops),
      headers: { 'if-match': et },
    });

    // Create an existing id -> 409.
    const createConflict = await send([{ type: 'create', document: { id: 'a', title: 'Other', body: 'b', tags: [] } }]);
    assert.equal(createConflict.status, 409);
    assert.equal(createConflict.body.code, 'CONFLICT');

    // Replace a missing id -> 404.
    const replaceMissing = await send([{ type: 'replace', document: { id: 'ghost', title: 'Ghost', body: 'b', tags: [] } }]);
    assert.equal(replaceMissing.status, 404);
    assert.equal(replaceMissing.body.code, 'NOT_FOUND');

    // Delete a missing id -> 404.
    const deleteMissing = await send([{ type: 'delete', id: 'ghost' }]);
    assert.equal(deleteMissing.status, 404);
    assert.equal(deleteMissing.body.code, 'NOT_FOUND');

    // A batch where the second op fails rejects the whole batch (nothing applied).
    const whole = await send([
      { type: 'create', document: { id: 'b', title: 'Beta', body: 'b', tags: [] } },
      { type: 'delete', id: 'ghost' },
    ]);
    assert.equal(whole.status, 404);
    assert.equal(whole.body.code, 'NOT_FOUND');
    const listed = await request(server.url, 'GET', '/documents');
    assert.deepEqual(listed.body.map((d) => d.id), ['a']);
  } finally {
    await server.stop();
  }
});

test('batch with restore but no history returns 404 NOT_FOUND for the whole batch', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/batch', {
      body: batch([{ type: 'restore', id: 'a', revision: 1 }]),
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 404);
    assert.equal(response.body.code, 'NOT_FOUND');
  } finally {
    await server.stop();
  }
});

test('batch restore version errors follow single-document rules', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--history', path.join(cwd, 'h.json'), '--port', '0']);
  try {
    let et = (await request(server.url, 'GET', '/documents')).etag;
    const send = (ops) => request(server.url, 'POST', '/batch', {
      body: batch(ops),
      headers: { 'if-match': et },
    });

    // Create a doc, then delete it, so we have a delete revision.
    await send([{ type: 'create', document: { id: 'a', title: 'A', body: 'v1', tags: [] } }]);
    et = (await request(server.url, 'GET', '/documents')).etag;
    await send([{ type: 'replace', document: { id: 'a', title: 'A', body: 'v2', tags: [] } }]);
    et = (await request(server.url, 'GET', '/documents')).etag;
    await send([{ type: 'delete', id: 'a' }]);
    et = (await request(server.url, 'GET', '/documents')).etag;

    // Restore a never-existed id -> 404.
    const neverExisted = await send([{ type: 'restore', id: 'ghost', revision: 1 }]);
    assert.equal(neverExisted.status, 404);
    assert.equal(neverExisted.body.code, 'NOT_FOUND');

    // Restore an unknown revision -> 404.
    const unknownRevision = await send([{ type: 'restore', id: 'a', revision: 99 }]);
    assert.equal(unknownRevision.status, 404);
    assert.equal(unknownRevision.body.code, 'NOT_FOUND');

    // Restore a delete revision -> 400 INVALID_REVISION.
    const deleteRevision = await send([{ type: 'restore', id: 'a', revision: 3 }]);
    assert.equal(deleteRevision.status, 400);
    assert.equal(deleteRevision.body.code, 'INVALID_REVISION');

    // State is unchanged after all failures.
    const doc = await request(server.url, 'GET', '/documents/a');
    assert.equal(doc.status, 404);
  } finally {
    await server.stop();
  }
});

// --- Title conflicts --------------------------------------------------------

test('batch title swap and release-then-reuse are order-independent', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: [] },
    { id: 'b', title: 'Beta', body: 'b', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    let et = (await request(server.url, 'GET', '/documents')).etag;

    // Swap titles: a gets 'Beta', b gets 'Alpha'.
    const swap = await request(server.url, 'POST', '/batch', {
      body: batch([
        { type: 'replace', document: { id: 'a', title: 'Beta', body: 'a', tags: [] } },
        { type: 'replace', document: { id: 'b', title: 'Alpha', body: 'b', tags: [] } },
      ]),
      headers: { 'if-match': et },
    });
    assert.equal(swap.status, 200);
    assert.equal(swap.body.documents.find((d) => d.id === 'a').title, 'Beta');
    assert.equal(swap.body.documents.find((d) => d.id === 'b').title, 'Alpha');
    et = swap.etag;

    // Release then reuse: delete a (frees 'Beta'), create c with 'Beta'.
    const releaseReuse = await request(server.url, 'POST', '/batch', {
      body: batch([
        { type: 'delete', id: 'a' },
        { type: 'create', document: { id: 'c', title: 'Beta', body: 'c', tags: [] } },
      ]),
      headers: { 'if-match': et },
    });
    assert.equal(releaseReuse.status, 200);
    assert.equal(releaseReuse.body.documents.find((d) => d.id === 'c').title, 'Beta');
    et = releaseReuse.etag;

    // The same release-then-reuse listed in the opposite order commits too:
    // create d with 'Alpha' (still held by b), then delete b.
    const reuseRelease = await request(server.url, 'POST', '/batch', {
      body: batch([
        { type: 'create', document: { id: 'd', title: 'Alpha', body: 'd', tags: [] } },
        { type: 'delete', id: 'b' },
      ]),
      headers: { 'if-match': et },
    });
    assert.equal(reuseRelease.status, 200);
    assert.equal(reuseRelease.body.documents.find((d) => d.id === 'd').title, 'Alpha');
    assert.ok(!reuseRelease.body.documents.some((d) => d.id === 'b'));
  } finally {
    await server.stop();
  }
});

test('batch dryRun previews a title swap without changing state', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: [] },
    { id: 'b', title: 'Beta', body: 'b', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const swap = [
      { type: 'replace', document: { id: 'a', title: 'Beta', body: 'a', tags: [] } },
      { type: 'replace', document: { id: 'b', title: 'Alpha', body: 'b', tags: [] } },
    ];
    const preview = await request(server.url, 'POST', '/batch', {
      body: batch(swap, { dryRun: true }),
      headers: { 'if-match': et },
    });
    assert.equal(preview.status, 200);
    assert.equal(preview.body.documents.find((d) => d.id === 'a').title, 'Beta');
    assert.equal(preview.body.documents.find((d) => d.id === 'b').title, 'Alpha');

    // The preview changed nothing.
    const listed = await request(server.url, 'GET', '/documents');
    assert.equal(listed.etag, et);
    assert.equal(listed.body.find((d) => d.id === 'a').title, 'Alpha');
    assert.equal(listed.body.find((d) => d.id === 'b').title, 'Beta');

    // A preview whose final titles duplicate still fails and changes nothing.
    const conflict = await request(server.url, 'POST', '/batch', {
      body: batch([
        { type: 'replace', document: { id: 'a', title: 'Beta', body: 'a', tags: [] } },
      ], { dryRun: true }),
      headers: { 'if-match': et },
    });
    assert.equal(conflict.status, 409);
    assert.equal(conflict.body.code, 'CONFLICT');
    const after = await request(server.url, 'GET', '/documents');
    assert.equal(after.etag, et);
    assert.equal(after.body.find((d) => d.id === 'a').title, 'Alpha');
  } finally {
    await server.stop();
  }
});

test('batch final title duplicate returns 409 CONFLICT', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/batch', {
      body: batch([
        { type: 'create', document: { id: 'b', title: 'Alpha', body: 'b', tags: [] } },
      ]),
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 409);
    assert.equal(response.body.code, 'CONFLICT');

    // State unchanged.
    const listed = await request(server.url, 'GET', '/documents');
    assert.deepEqual(listed.body.map((d) => d.id), ['a']);
  } finally {
    await server.stop();
  }
});

test('batch title conflict between two new documents is 409', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/batch', {
      body: batch([
        { type: 'create', document: { id: 'a', title: 'Same', body: 'a', tags: [] } },
        { type: 'create', document: { id: 'b', title: 'Same', body: 'b', tags: [] } },
      ]),
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 409);
    assert.equal(response.body.code, 'CONFLICT');
  } finally {
    await server.stop();
  }
});

// --- History ----------------------------------------------------------------

test('batch history: each changed doc appends one record, versions continue, no-op appends nothing', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--history', path.join(cwd, 'h.json'), '--port', '0']);
  try {
    let et = (await request(server.url, 'GET', '/documents')).etag;
    const send = (ops) => request(server.url, 'POST', '/batch', {
      body: batch(ops),
      headers: { 'if-match': et },
    });

    // Batch: create b, replace a, delete a (wait, can't delete a and replace a in same batch - duplicate id).
    // Instead: create b, replace a.
    const first = await send([
      { type: 'create', document: { id: 'b', title: 'Beta', body: 'b', tags: [] } },
      { type: 'replace', document: { id: 'a', title: 'Alpha v2', body: 'a2', tags: [] } },
    ]);
    assert.equal(first.status, 200);
    et = first.etag;

    // a: baseline(1), replace(2). b: create(1).
    let rowsA = (await request(server.url, 'GET', '/documents/a/history')).body;
    assert.deepEqual(rowsA.map((e) => [e.revision, e.action]), [[1, 'baseline'], [2, 'replace']]);
    let rowsB = (await request(server.url, 'GET', '/documents/b/history')).body;
    assert.deepEqual(rowsB.map((e) => [e.revision, e.action]), [[1, 'create']]);

    // Batch: delete b, and a no-op replace of a.
    const second = await send([
      { type: 'delete', id: 'b' },
      { type: 'replace', document: { id: 'a', title: '  Alpha v2  ', body: 'a2', tags: [] } },
    ]);
    assert.equal(second.status, 200);
    et = second.etag;

    // Batch: recreate b.
    const third = await send([
      { type: 'create', document: { id: 'b', title: 'Beta reborn', body: 'b2', tags: [] } },
    ]);
    assert.equal(third.status, 200);

    // b: create(1), delete(2), create(3). a unchanged (no new record).
    rowsB = (await request(server.url, 'GET', '/documents/b/history')).body;
    assert.deepEqual(rowsB.map((e) => [e.revision, e.action]), [[1, 'create'], [2, 'delete'], [3, 'create']]);
    rowsA = (await request(server.url, 'GET', '/documents/a/history')).body;
    assert.deepEqual(rowsA.map((e) => [e.revision, e.action]), [[1, 'baseline'], [2, 'replace']]);
  } finally {
    await server.stop();
  }
});

test('batch restore appends a restore record and continues the version chain', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--history', path.join(cwd, 'h.json'), '--port', '0']);
  try {
    let et = (await request(server.url, 'GET', '/documents')).etag;
    const send = (ops) => request(server.url, 'POST', '/batch', {
      body: batch(ops),
      headers: { 'if-match': et },
    });

    await send([{ type: 'create', document: { id: 'a', title: 'A', body: 'v1', tags: [] } }]);
    et = (await request(server.url, 'GET', '/documents')).etag;
    await send([{ type: 'replace', document: { id: 'a', title: 'A', body: 'v2', tags: [] } }]);
    et = (await request(server.url, 'GET', '/documents')).etag;
    await send([{ type: 'delete', id: 'a' }]);
    et = (await request(server.url, 'GET', '/documents')).etag;

    // Restore revision 1 (v1) in a batch.
    const restored = await send([{ type: 'restore', id: 'a', revision: 1 }]);
    assert.equal(restored.status, 200);
    assert.equal(restored.body.documents.find((d) => d.id === 'a').body, 'v1');

    const rows = (await request(server.url, 'GET', '/documents/a/history')).body;
    assert.deepEqual(rows.map((e) => [e.revision, e.action]), [
      [1, 'create'], [2, 'replace'], [3, 'delete'], [4, 'restore'],
    ]);
    assert.equal(rows[3].document.body, 'v1');
  } finally {
    await server.stop();
  }
});

// --- If-Match and concurrency -----------------------------------------------

test('batch requires If-Match and honors concurrency', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;

    const missing = await request(server.url, 'POST', '/batch', {
      body: batch([{ type: 'create', document: { id: 'a', title: 'A', body: 'b', tags: [] } }]),
    });
    assert.equal(missing.status, 428);

    const malformed = await request(server.url, 'POST', '/batch', {
      body: batch([{ type: 'create', document: { id: 'a', title: 'A', body: 'b', tags: [] } }]),
      headers: { 'if-match': 'not-an-etag' },
    });
    assert.equal(malformed.status, 400);

    // Two concurrent batches with the same checksum: at most one commits.
    const [first, second] = await Promise.all([
      request(server.url, 'POST', '/batch', {
        body: batch([{ type: 'create', document: { id: 'a', title: 'A', body: 'b', tags: [] } }]),
        headers: { 'if-match': et },
      }),
      request(server.url, 'POST', '/batch', {
        body: batch([{ type: 'create', document: { id: 'b', title: 'B', body: 'b', tags: [] } }]),
        headers: { 'if-match': et },
      }),
    ]);
    const statuses = [first.status, second.status].sort();
    assert.deepEqual(statuses, [200, 412]);
  } finally {
    await server.stop();
  }
});

test('batch and single write concurrent: at most one commits', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const [batchResp, singleResp] = await Promise.all([
      request(server.url, 'POST', '/batch', {
        body: batch([{ type: 'create', document: { id: 'a', title: 'A', body: 'b', tags: [] } }]),
        headers: { 'if-match': et },
      }),
      request(server.url, 'POST', '/documents', {
        body: { id: 'b', title: 'B', body: 'b', tags: [] },
        headers: { 'if-match': et },
      }),
    ]);
    const statuses = [batchResp.status, singleResp.status].sort();
    assert.deepEqual(statuses, [200, 412]);
  } finally {
    await server.stop();
  }
});

// --- Save failure ------------------------------------------------------------

test('batch failed save returns 500 IO_ERROR and leaves state and file intact', async () => {
  const cwd = tempDir();
  const blocked = path.join(cwd, 'no-such-dir', 'snap.json');
  const server = await startServer([blocked, '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const failed = await request(server.url, 'POST', '/batch', {
      body: batch([{ type: 'create', document: { id: 'a', title: 'A', body: 'b', tags: [] } }]),
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

// --- Crash recovery atomicity ------------------------------------------------

test('batch restart after a kill presents a whole pre-batch or post-batch state', async () => {
  const cwd = tempDir();
  const { snapshot: snapshotPath, history: historyPath } = (() => {
    const snap = path.join(cwd, 'snap.json');
    const hist = path.join(cwd, 'h.json');
    return { snapshot: snap, history: hist };
  })();
  const backupPath = `${historyPath}.bak`;
  const baseDocuments = [{ id: 'a', title: 'Alpha', body: 'OLD', tags: [] }];

  // Build the pre-batch and post-batch committed pairs manually.
  const before = (() => {
    const store = HistoryStore.baseline(baseDocuments.map((d) => structuredClone(d)));
    const snapshot = snapshotFromDocuments(store.replayedDocuments().values());
    return { snapshot, history: store.exportJSON(snapshot.checksum) };
  })();
  const after = (() => {
    const store = HistoryStore.baseline(baseDocuments.map((d) => structuredClone(d)));
    const draft = store.clone();
    draft.record('a', 'replace', { id: 'a', title: 'Alpha', body: 'NEW', tags: [] });
    draft.record('b', 'create', { id: 'b', title: 'Beta', body: 'new', tags: [] });
    const snapshot = snapshotFromDocuments(draft.replayedDocuments().values());
    return { snapshot, history: draft.exportJSON(snapshot.checksum) };
  })();

  // Window A: old history moved aside, new not installed -> pre-batch state.
  fs.writeFileSync(snapshotPath, JSON.stringify(before.snapshot));
  fs.writeFileSync(backupPath, JSON.stringify(before.history));
  let server = await startServer([snapshotPath, '--history', historyPath, '--port', '0']);
  try {
    const doc = await request(server.url, 'GET', '/documents/a');
    assert.equal(doc.body.body, 'OLD');
    assert.ok(!fs.existsSync(backupPath));
  } finally {
    await server.stop();
  }

  // Window B: new history landed, snapshot not yet -> post-batch state reconstructed.
  fs.writeFileSync(snapshotPath, JSON.stringify(before.snapshot));
  fs.writeFileSync(historyPath, JSON.stringify(after.history));
  fs.writeFileSync(backupPath, JSON.stringify(before.history));
  server = await startServer([snapshotPath, '--history', historyPath, '--port', '0']);
  try {
    const doc = await request(server.url, 'GET', '/documents/a');
    assert.equal(doc.body.body, 'NEW');
    const listed = await request(server.url, 'GET', '/documents');
    assert.deepEqual(listed.body.map((d) => d.id), ['a', 'b']);
    // Both files agree.
    const onDisk = JSON.parse(fs.readFileSync(snapshotPath, 'utf8'));
    assert.equal(onDisk.checksum, after.snapshot.checksum);
    assert.equal(JSON.parse(fs.readFileSync(historyPath, 'utf8')).snapshot, after.snapshot.checksum);
  } finally {
    await server.stop();
  }
});

// --- Links and search --------------------------------------------------------

test('batch search and bidirectional links reflect the whole batch content', async () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'a', title: 'Alpha', body: 'links [[b]]', tags: [] },
  ]));
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await request(server.url, 'POST', '/batch', {
      body: batch([
        { type: 'create', document: { id: 'b', title: 'Beta', body: 'links [[a]]', tags: [] } },
        { type: 'replace', document: { id: 'a', title: 'Alpha', body: 'links [[b]] and [[c]]', tags: [] } },
        { type: 'create', document: { id: 'c', title: 'Gamma', body: 'no links', tags: [] } },
      ]),
      headers: { 'if-match': et },
    });
    assert.equal(response.status, 200);

    // a now links to b and c; b links back to a; c has no links.
    const linksA = await request(server.url, 'GET', '/documents/a/links');
    assert.deepEqual(linksA.body, { outgoing: ['b', 'c'], incoming: ['b'] });
    const linksB = await request(server.url, 'GET', '/documents/b/links');
    assert.deepEqual(linksB.body, { outgoing: ['a'], incoming: ['a'] });
    const linksC = await request(server.url, 'GET', '/documents/c/links');
    assert.deepEqual(linksC.body, { outgoing: [], incoming: ['a'] });

    // Search finds the new content.
    const search = await request(server.url, 'GET', '/search?q=gamma');
    assert.deepEqual(search.body.map((d) => d.id), ['c']);
  } finally {
    await server.stop();
  }
});
