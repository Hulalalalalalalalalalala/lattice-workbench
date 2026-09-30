import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, writeFile, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Workspace } from '../src/workspace.js';

const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));

function runCli(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd: fileURLToPath(new URL('..', import.meta.url)) });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

async function makeSnapshot(folder, name, documents) {
  const workspace = new Workspace();
  for (const document of documents) workspace.add(document);
  const path = join(folder, name);
  await writeFile(path, JSON.stringify(workspace.exportJSON()));
  return path;
}

let folder;
test.beforeEach(async () => {
  folder = await mkdtemp(join(tmpdir(), 'lattice-cli-'));
});
test.afterEach(async () => {
  await rm(folder, { recursive: true, force: true });
});

test('migrate writes the merged snapshot and prints one JSON line', async () => {
  const base = await makeSnapshot(folder, 'base.json', [{ id: 'a', title: 'Alpha', body: 'base', tags: ['x'] }]);
  const incoming = await makeSnapshot(folder, 'incoming.json', [{ id: 'b', title: 'Beta', body: '[[a]]', tags: ['y'] }]);
  const output = join(folder, 'out.json');

  const { status, stdout, stderr } = await runCli(['migrate', base, incoming, output, 'merge']);
  assert.equal(status, 0);
  assert.equal(stderr, '');
  const result = JSON.parse(stdout);
  assert.deepEqual(result.documents.map((document) => document.id), ['a', 'b']);
  const written = JSON.parse(await readFile(output, 'utf8'));
  assert.deepEqual(written, result);
});

test('migrate replace drops documents absent from incoming', async () => {
  const base = await makeSnapshot(folder, 'base.json', [{ id: 'a', title: 'Alpha', body: 'x', tags: [] }, { id: 'b', title: 'Beta', body: 'y', tags: [] }]);
  const incoming = await makeSnapshot(folder, 'incoming.json', [{ id: 'a', title: 'Alpha', body: 'x', tags: [] }]);
  const output = join(folder, 'out.json');

  const { status, stdout } = await runCli(['migrate', base, incoming, output, 'replace']);
  assert.equal(status, 0);
  const result = JSON.parse(stdout);
  assert.deepEqual(result.documents.map((document) => document.id), ['a']);
});

test('migrate --dry-run prints the result without creating the output', async () => {
  const base = await makeSnapshot(folder, 'base.json', [{ id: 'a', title: 'Alpha', body: 'x', tags: [] }]);
  const incoming = await makeSnapshot(folder, 'incoming.json', [{ id: 'b', title: 'Beta', body: 'y', tags: [] }]);
  const output = join(folder, 'out.json');

  const { status, stdout } = await runCli(['migrate', base, incoming, output, 'merge', '--dry-run']);
  assert.equal(status, 0);
  const result = JSON.parse(stdout);
  assert.deepEqual(result.documents.map((document) => document.id), ['a', 'b']);
  await assert.rejects(() => readFile(output, 'utf8'), /ENOENT/u);
});

test('migrate --dry-run leaves an existing output untouched', async () => {
  const base = await makeSnapshot(folder, 'base.json', [{ id: 'a', title: 'Alpha', body: 'x', tags: [] }]);
  const incoming = await makeSnapshot(folder, 'incoming.json', [{ id: 'b', title: 'Beta', body: 'y', tags: [] }]);
  const output = join(folder, 'out.json');
  await writeFile(output, '{"keep":true}');

  const { status } = await runCli(['migrate', base, incoming, output, 'merge', '--dry-run']);
  assert.equal(status, 0);
  assert.equal(await readFile(output, 'utf8'), '{"keep":true}');
});

test('migrate accepts output equal to base', async () => {
  const base = await makeSnapshot(folder, 'base.json', [{ id: 'a', title: 'Alpha', body: 'x', tags: [] }]);
  const incoming = await makeSnapshot(folder, 'incoming.json', [{ id: 'b', title: 'Beta', body: 'y', tags: [] }]);

  const { status, stdout } = await runCli(['migrate', base, incoming, base, 'merge']);
  assert.equal(status, 0);
  const result = JSON.parse(stdout);
  assert.deepEqual(result.documents.map((document) => document.id), ['a', 'b']);
  const written = JSON.parse(await readFile(base, 'utf8'));
  assert.deepEqual(written, result);
});

test('migrate reports INVALID_SNAPSHOT for unparseable input', async () => {
  const base = join(folder, 'base.json');
  await writeFile(base, '{ not json');
  const incoming = await makeSnapshot(folder, 'incoming.json', [{ id: 'a', title: 'Alpha', body: 'x', tags: [] }]);
  const output = join(folder, 'out.json');

  const { status, stdout, stderr } = await runCli(['migrate', base, incoming, output, 'merge']);
  assert.equal(status, 1);
  assert.equal(stdout, '');
  assert.deepEqual(JSON.parse(stderr), { code: 'INVALID_SNAPSHOT' });
  await assert.rejects(() => readFile(output, 'utf8'), /ENOENT/u);
});

test('migrate reports INVALID_SNAPSHOT for a semantically invalid snapshot', async () => {
  const base = join(folder, 'base.json');
  await writeFile(base, JSON.stringify({ version: 2, documents: [], checksum: '0'.repeat(64) }));
  const incoming = await makeSnapshot(folder, 'incoming.json', [{ id: 'a', title: 'Alpha', body: 'x', tags: [] }]);
  const output = join(folder, 'out.json');

  const { status, stdout, stderr } = await runCli(['migrate', base, incoming, output, 'merge']);
  assert.equal(status, 1);
  assert.equal(stdout, '');
  assert.deepEqual(JSON.parse(stderr), { code: 'INVALID_SNAPSHOT' });
});

test('migrate reports IO_ERROR for a missing input file', async () => {
  const incoming = await makeSnapshot(folder, 'incoming.json', [{ id: 'a', title: 'Alpha', body: 'x', tags: [] }]);
  const output = join(folder, 'out.json');

  const { status, stdout, stderr } = await runCli(['migrate', join(folder, 'missing.json'), incoming, output, 'merge']);
  assert.equal(status, 1);
  assert.equal(stdout, '');
  assert.deepEqual(JSON.parse(stderr), { code: 'IO_ERROR' });
});

test('migrate reports IO_ERROR when the output cannot be written', async () => {
  const base = await makeSnapshot(folder, 'base.json', [{ id: 'a', title: 'Alpha', body: 'x', tags: [] }]);
  const incoming = await makeSnapshot(folder, 'incoming.json', [{ id: 'b', title: 'Beta', body: 'y', tags: [] }]);
  const output = join(folder, 'a-directory');
  await mkdir(output);

  const { status, stdout, stderr } = await runCli(['migrate', base, incoming, output, 'merge']);
  assert.equal(status, 1);
  assert.equal(stdout, '');
  assert.deepEqual(JSON.parse(stderr), { code: 'IO_ERROR' });
});

test('migrate reports IMPORT_CONFLICT with ids and leaves inputs untouched', async () => {
  const base = await makeSnapshot(folder, 'base.json', [{ id: 'a', title: 'Alpha', body: 'orig', tags: [] }]);
  const incoming = await makeSnapshot(folder, 'incoming.json', [{ id: 'a', title: 'Alpha', body: 'changed', tags: [] }]);
  const output = join(folder, 'out.json');

  const beforeBase = await readFile(base, 'utf8');
  const beforeIncoming = await readFile(incoming, 'utf8');
  const { status, stdout, stderr } = await runCli(['migrate', base, incoming, output, 'merge']);
  assert.equal(status, 1);
  assert.equal(stdout, '');
  assert.deepEqual(JSON.parse(stderr), { code: 'IMPORT_CONFLICT', ids: ['a'] });
  assert.equal(await readFile(base, 'utf8'), beforeBase);
  assert.equal(await readFile(incoming, 'utf8'), beforeIncoming);
  await assert.rejects(() => readFile(output, 'utf8'), /ENOENT/u);
});

test('migrate reports INVALID_OPTIONS for an unknown mode', async () => {
  const base = await makeSnapshot(folder, 'base.json', [{ id: 'a', title: 'Alpha', body: 'x', tags: [] }]);
  const incoming = await makeSnapshot(folder, 'incoming.json', [{ id: 'a', title: 'Alpha', body: 'x', tags: [] }]);
  const output = join(folder, 'out.json');

  const { status, stdout, stderr } = await runCli(['migrate', base, incoming, output, 'bogus']);
  assert.equal(status, 1);
  assert.equal(stdout, '');
  assert.deepEqual(JSON.parse(stderr), { code: 'INVALID_OPTIONS' });
});

test('migrate reports INVALID_OPTIONS for bad usage', async () => {
  const { status, stdout, stderr } = await runCli(['migrate', 'only-one-arg']);
  assert.equal(status, 1);
  assert.equal(stdout, '');
  assert.deepEqual(JSON.parse(stderr), { code: 'INVALID_OPTIONS' });
});

test('demo still prints the workspace summary', async () => {
  const { status, stdout, stderr } = await runCli(['demo']);
  assert.equal(status, 0);
  assert.equal(stderr, '');
  const result = JSON.parse(stdout);
  assert.equal(result.product, 'Lattice Workbench');
  assert.equal(result.documents.length, 2);
});
