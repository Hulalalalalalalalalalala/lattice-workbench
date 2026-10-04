import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import test from 'node:test';
import { Workspace } from '../src/workspace.js';

const CLI = path.resolve('src/cli.js');

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-paths-'));
}

function workspaceWith(documents) {
  const workspace = new Workspace();
  for (const document of documents) workspace.add(document);
  return workspace;
}

function writeSnapshot(file, workspace) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(workspace.exportJSON())}\n`);
}

async function serve(args, { cwd } = {}) {
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
    address,
    url: `http://${address.host}:${address.port}`,
    stop: () => new Promise((resolve) => {
      child.once('exit', resolve);
      child.kill('SIGKILL');
    }),
  };
}

async function serveFails(args, { cwd } = {}) {
  const child = spawn(process.execPath, [CLI, 'serve', ...args], { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const status = await new Promise((resolve) => child.on('exit', resolve));
  return { status, stdout, stderr };
}

async function request(base, method, route, { body, headers = {} } = {}) {
  const response = await fetch(`${base}${route}`, {
    method,
    headers: {
      ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
      ...headers,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  return { status: response.status, etag: response.headers.get('etag'), body: text ? JSON.parse(text) : null };
}

// Asserts the process exits 1 having printed nothing on stdout and exactly one
// INVALID_OPTIONS JSON line on stderr.
function assertPathConflict(result, label) {
  assert.equal(result.status, 1, label);
  assert.equal(result.stdout, '', label);
  const lines = result.stderr.split('\n');
  assert.equal(lines.length, 2, `${label}: ${result.stderr}`);
  assert.equal(lines[1], '', label);
  const payload = JSON.parse(lines[0]);
  assert.equal(payload.code, 'INVALID_OPTIONS', label);
  return payload;
}

test('snapshot at the history file location is rejected through lexical path aliases', async () => {
  const cases = [];

  let cwd = tempDir();
  cases.push(['identical relative paths', [path.join(cwd, 'history.json'), '--history', path.join(cwd, 'history.json'), '--port', '0'], {}]);

  cwd = tempDir();
  cases.push(['relative versus absolute', ['history.json', '--history', path.join(cwd, 'history.json'), '--port', '0'], { cwd }]);

  cwd = tempDir();
  fs.mkdirSync(path.join(cwd, 'dir'));
  cases.push(['dot segments versus plain', ['./dir/../history.json', '--history', 'history.json', '--port', '0'], { cwd }]);

  cwd = tempDir();
  fs.mkdirSync(path.join(cwd, 'sub'));
  cases.push([
    'dot-dot through a subdirectory cwd',
    ['../history.json', '--history', path.join(cwd, 'history.json'), '--port', '0'],
    { cwd: path.join(cwd, 'sub') },
  ]);

  cwd = tempDir();
  fs.mkdirSync(path.join(cwd, 'a'));
  cases.push([
    'absolute dot segments',
    [path.join(cwd, 'a', '..', 'history.json'), '--history', path.join(cwd, 'history.json'), '--port', '0'],
    { cwd },
  ]);

  for (const [label, args, options] of cases) {
    const result = await serveFails(args, options);
    assertPathConflict(result, label);
    assert.match(JSON.parse(result.stderr).message, /history file/u, label);
  }
});

test('snapshot at the history backup (<history>.bak) location is rejected', async () => {
  const cwd = tempDir();
  const history = path.join(cwd, 'history.json');
  const cases = [
    ['plain backup name', [`${history}.bak`, '--history', history, '--port', '0']],
    ['lexical backup alias', [path.join(cwd, '.', 'history.json.bak'), '--history', path.join(cwd, 'history.json'), '--port', '0']],
    ['relative backup', ['history.json.bak', '--history', path.join(cwd, 'history.json'), '--port', '0']],
  ];
  for (const [label, args] of cases) {
    const result = await serveFails(args, { cwd });
    assertPathConflict(result, label);
    assert.match(JSON.parse(result.stderr).message, /backup/u, label);
  }
  // Neither the history, its backup, nor staging files come into existence.
  assert.deepEqual(fs.readdirSync(cwd), []);
});

test('snapshot/history aliases through a symlinked directory are rejected before the files exist', async () => {
  const cwd = tempDir();
  fs.mkdirSync(path.join(cwd, 'real'));
  fs.symlinkSync('real', path.join(cwd, 'alias'));

  const viaAlias = await serveFails([
    path.join(cwd, 'alias', 'state.json'),
    '--history', path.join(cwd, 'real', 'state.json'), '--port', '0',
  ]);
  assertPathConflict(viaAlias, 'snapshot via alias');

  const viaAliasHistory = await serveFails([
    path.join(cwd, 'real', 'state.json'),
    '--history', path.join(cwd, 'alias', 'state.json'), '--port', '0',
  ]);
  assertPathConflict(viaAliasHistory, 'history via alias');

  const backupViaAlias = await serveFails([
    path.join(cwd, 'alias', 'history.json.bak'),
    '--history', path.join(cwd, 'real', 'history.json'), '--port', '0',
  ]);
  assertPathConflict(backupViaAlias, 'backup via alias');

  // The not-yet-created files were never created.
  assert.deepEqual(fs.readdirSync(path.join(cwd, 'real')), []);
});

test('an existing snapshot reached through a symlinked directory alias is left untouched', async () => {
  const cwd = tempDir();
  const workspace = workspaceWith([{ id: 'a', title: 'A', body: 'a body [[b]]', tags: ['one'] }]);
  writeSnapshot(path.join(cwd, 'real', 'state.json'), workspace);
  fs.symlinkSync('real', path.join(cwd, 'alias'));
  const original = fs.readFileSync(path.join(cwd, 'real', 'state.json'), 'utf8');

  const result = await serveFails([
    path.join(cwd, 'alias', 'state.json'),
    '--history', path.join(cwd, 'real', 'state.json'), '--port', '0',
  ]);
  assertPathConflict(result, 'existing aliased snapshot');

  // The snapshot is neither moved, deleted, nor replaced; no backup or staging
  // file appears.
  assert.equal(fs.readFileSync(path.join(cwd, 'real', 'state.json'), 'utf8'), original);
  assert.ok(!fs.existsSync(path.join(cwd, 'real', 'state.json.bak')));
  assert.deepEqual(fs.readdirSync(path.join(cwd, 'real')), ['state.json']);
});

test('a snapshot that is a symlink to the history file (or its backup) is rejected', async () => {
  const cwd = tempDir();
  fs.mkdirSync(path.join(cwd, 'data'));

  // Dangling link: neither file exists yet, but the link already aliases the
  // history location.
  fs.symlinkSync(path.join('data', 'history.json'), path.join(cwd, 'snap.json'));
  const dangling = await serveFails([
    path.join(cwd, 'snap.json'),
    '--history', path.join(cwd, 'data', 'history.json'), '--port', '0',
  ]);
  assertPathConflict(dangling, 'dangling symlink to history');
  assert.ok(!fs.existsSync(path.join(cwd, 'data', 'history.json')));

  // Existing link target: a corrupt history reached through the snapshot link
  // still reports the path conflict, never INVALID_HISTORY, and is not moved.
  fs.writeFileSync(path.join(cwd, 'data', 'history.json'), '{broken json');
  const linked = await serveFails([
    path.join(cwd, 'snap.json'),
    '--history', path.join(cwd, 'data', 'history.json'), '--port', '0',
  ]);
  assertPathConflict(linked, 'symlink to existing history');
  assert.equal(fs.readFileSync(path.join(cwd, 'data', 'history.json'), 'utf8'), '{broken json');

  // Link aliasing the backup location.
  fs.symlinkSync(path.join('data', 'history.json.bak'), path.join(cwd, 'backup-link'));
  const backupLink = await serveFails([
    path.join(cwd, 'backup-link'),
    '--history', path.join(cwd, 'data', 'history.json'), '--port', '0',
  ]);
  assertPathConflict(backupLink, 'symlink to backup location');
});

test('a path conflict takes precedence over corrupt snapshot or history content', async () => {
  const cwd = tempDir();

  // Same file used as both snapshot and history, containing garbage.
  const both = path.join(cwd, 'both.json');
  fs.writeFileSync(both, '{broken json');
  const sameBroken = await serveFails([both, '--history', both, '--port', '0']);
  assertPathConflict(sameBroken, 'broken shared file');
  assert.equal(fs.readFileSync(both, 'utf8'), '{broken json');

  // Broken snapshot sitting at the backup location.
  const atBackup = path.join(cwd, 'history.json.bak');
  fs.writeFileSync(atBackup, '{not json either');
  const brokenBackup = await serveFails([
    atBackup, '--history', path.join(cwd, 'history.json'), '--port', '0',
  ]);
  assertPathConflict(brokenBackup, 'broken snapshot at backup');
  assert.equal(fs.readFileSync(atBackup, 'utf8'), '{not json either');
  assert.ok(!fs.existsSync(path.join(cwd, 'history.json')));
});

test('independent locations keep working: same basename elsewhere, merely-.bak names', async () => {
  // Same file name in different real directories is fine.
  let cwd = tempDir();
  let server = await serve([
    path.join(cwd, 'a', 'state.json'),
    '--history', path.join(cwd, 'b', 'state.json'), '--port', '0',
  ]);
  try {
    const listed = await request(server.url, 'GET', '/documents');
    assert.equal(listed.status, 200);
    assert.deepEqual(listed.body, []);
  } finally {
    await server.stop();
  }

  // A snapshot whose name merely ends in .bak is allowed, as is a history file
  // whose name ends in .bak (its backup gets a second .bak suffix).
  cwd = tempDir();
  server = await serve([
    path.join(cwd, 'snapshot.bak'),
    '--history', path.join(cwd, 'ledger.bak'), '--port', '0',
  ]);
  try {
    const empty = await request(server.url, 'GET', '/documents');
    const created = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'one', tags: [] },
      headers: { 'if-match': empty.etag },
    });
    assert.equal(created.status, 201);

    // A second write exercises the history backup/rename flow; it must leave no
    // backup behind and keep both files valid.
    const updated = await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: 'A', body: 'two', tags: ['x'] },
      headers: { 'if-match': created.etag },
    });
    assert.equal(updated.status, 200);
    assert.ok(fs.existsSync(path.join(cwd, 'snapshot.bak')));
    assert.ok(fs.existsSync(path.join(cwd, 'ledger.bak')));
    assert.ok(!fs.existsSync(path.join(cwd, 'ledger.bak.bak')));
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(cwd, 'snapshot.bak'), 'utf8')).documents.length, 1);

    const rows = (await request(server.url, 'GET', '/documents/a/history')).body;
    assert.deepEqual(rows.map((entry) => entry.action), ['create', 'replace']);
  } finally {
    await server.stop();
  }
});

test('a history.json.bak-style name unrelated to the actual history is allowed', async () => {
  const cwd = tempDir();
  // History is named ledger.json, so its backup is ledger.json.bak; a snapshot
  // called history.json.bak has nothing to do with either.
  const server = await serve([
    path.join(cwd, 'history.json.bak'),
    '--history', path.join(cwd, 'ledger.json'), '--port', '0',
  ]);
  try {
    const listed = await request(server.url, 'GET', '/documents');
    assert.equal(listed.status, 200);
  } finally {
    await server.stop();
  }
});

test('serve without --history performs no history-location checks', async () => {
  const cwd = tempDir();
  // Would be the backup location of a history named history.json, but history
  // is disabled entirely.
  const server = await serve([path.join(cwd, 'history.json.bak'), '--port', '0']);
  try {
    const empty = await fetch(`${server.url}/documents`);
    assert.equal(empty.status, 200);
  } finally {
    await server.stop();
  }
});

test('a valid history pair still restarts and preserves history after the change', async () => {
  const cwd = tempDir();
  const snapshot = path.join(cwd, 'snap.json');
  const history = path.join(cwd, 'history.json');
  const workspace = workspaceWith([{ id: 'a', title: 'Alpha', body: 'a body', tags: ['one'] }]);
  writeSnapshot(snapshot, workspace);

  let server = await serve([snapshot, '--history', history, '--port', '0']);
  try {
    const listed = await request(server.url, 'GET', '/documents');
    const changed = await request(server.url, 'PUT', '/documents/a', {
      body: { id: 'a', title: 'Alpha', body: 'a body v2', tags: ['one'] },
      headers: { 'if-match': listed.etag },
    });
    assert.equal(changed.status, 200);
  } finally {
    await server.stop();
  }

  server = await serve([snapshot, '--history', history, '--port', '0']);
  try {
    const doc = await request(server.url, 'GET', '/documents/a');
    assert.equal(doc.body.body, 'a body v2');
    const rows = await request(server.url, 'GET', '/documents/a/history');
    assert.deepEqual(rows.body.map((entry) => [entry.revision, entry.action]), [[1, 'baseline'], [2, 'replace']]);
  } finally {
    await server.stop();
  }
  assert.ok(!fs.existsSync(`${history}.bak`));
});
