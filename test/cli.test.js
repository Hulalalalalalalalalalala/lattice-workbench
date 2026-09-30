import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import test from 'node:test';
import { Workspace } from '../src/workspace.js';

const CLI = path.resolve('src/cli.js');

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-migrate-'));
}

function writeSnapshot(file, workspace) {
  fs.writeFileSync(file, `${JSON.stringify(workspace.exportJSON())}\n`);
}

function workspaceWith(documents) {
  const workspace = new Workspace();
  for (const document of documents) workspace.add(document);
  return workspace;
}

function runMigrate(args, cwd) {
  try {
    const stdout = execFileSync(process.execPath, [CLI, 'migrate', ...args], { cwd, encoding: 'utf8' });
    return { status: 0, stdout, stderr: '' };
  } catch (error) {
    return { status: error.status ?? 1, stdout: error.stdout?.toString() ?? '', stderr: error.stderr?.toString() ?? '' };
  }
}

test('migrate merge builds from base, imports incoming, writes and prints one snapshot line', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'base.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'links [[b]]', tags: ['base'] },
  ]));
  writeSnapshot(path.join(cwd, 'incoming.json'), workspaceWith([
    { id: 'b', title: 'B', body: 'new doc [[ghost]]', tags: ['Incoming'] },
  ]));
  const output = path.join(cwd, 'out.json');

  const { status, stdout, stderr } = runMigrate(['base.json', 'incoming.json', 'out.json', 'merge'], cwd);
  assert.equal(status, 0);
  assert.equal(stderr, '');
  const lines = stdout.split('\n');
  assert.equal(lines.length, 2);
  assert.equal(lines[1], '');

  const printed = JSON.parse(lines[0]);
  const written = JSON.parse(fs.readFileSync(output, 'utf8'));
  assert.deepEqual(printed, written);
  assert.deepEqual(printed.documents.map((document) => document.id), ['a', 'b']);
  assert.equal(printed.documents[0].body, 'links [[b]]');
  assert.equal(printed.version, 1);
  assert.equal(typeof printed.checksum, 'string');

  const expected = workspaceWith([
    { id: 'a', title: 'A', body: 'links [[b]]', tags: ['base'] },
    { id: 'b', title: 'B', body: 'new doc [[ghost]]', tags: ['incoming'] },
  ]).exportJSON();
  assert.deepEqual(printed, expected);
});

test('migrate replace swaps the full document set', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'base.json'), workspaceWith([
    { id: 'old', title: 'Old', body: 'body text', tags: [] },
  ]));
  writeSnapshot(path.join(cwd, 'incoming.json'), workspaceWith([
    { id: 'new', title: 'New', body: 'body text', tags: [] },
  ]));

  const { status, stdout } = runMigrate(['base.json', 'incoming.json', 'out.json', 'replace'], cwd);
  assert.equal(status, 0);
  const snapshot = JSON.parse(stdout.trim());
  assert.deepEqual(snapshot.documents.map((document) => document.id), ['new']);
});

test('migrate --dry-run prints the projection without touching or creating the output', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'base.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'body text', tags: [] },
  ]));
  writeSnapshot(path.join(cwd, 'incoming.json'), workspaceWith([
    { id: 'b', title: 'B', body: 'body text', tags: [] },
  ]));
  const output = path.join(cwd, 'missing.json');

  const { status, stdout, stderr } = runMigrate(
    ['base.json', 'incoming.json', 'missing.json', 'merge', '--dry-run'],
    cwd,
  );
  assert.equal(status, 0);
  assert.equal(stderr, '');
  assert.deepEqual(JSON.parse(stdout.trim()).documents.map((document) => document.id), ['a', 'b']);
  assert.ok(!fs.existsSync(output));

  // Dry-run also leaves a pre-existing output file byte-for-byte unchanged.
  const existing = path.join(cwd, 'existing.json');
  fs.writeFileSync(existing, 'do not touch\n');
  runMigrate(['base.json', 'incoming.json', 'existing.json', 'merge', '--dry-run'], cwd);
  assert.equal(fs.readFileSync(existing, 'utf8'), 'do not touch\n');
});

test('migrate allows output and base to be the same path', () => {
  const cwd = tempDir();
  const file = path.join(cwd, 'snapshot.json');
  writeSnapshot(file, workspaceWith([{ id: 'a', title: 'A', body: 'body text', tags: [] }]));
  writeSnapshot(path.join(cwd, 'incoming.json'), workspaceWith([
    { id: 'b', title: 'B', body: 'body text', tags: [] },
  ]));

  const { status, stdout } = runMigrate(['snapshot.json', 'incoming.json', 'snapshot.json', 'merge'], cwd);
  assert.equal(status, 0);
  const merged = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(merged.documents.map((document) => document.id), ['a', 'b']);
  assert.equal(JSON.parse(stdout.trim()).checksum, merged.checksum);
});

test('migrate reports parse failures as INVALID_SNAPSHOT on one stderr JSON line', () => {
  const cwd = tempDir();
  const base = path.join(cwd, 'base.json');
  const incoming = path.join(cwd, 'incoming.json');
  const output = path.join(cwd, 'out.json');
  fs.writeFileSync(base, '{broken json');
  writeSnapshot(incoming, new Workspace());

  const { status, stdout, stderr } = runMigrate(['base.json', 'incoming.json', 'out.json', 'merge'], cwd);
  assert.equal(status, 1);
  assert.equal(stdout, '');
  const lines = stderr.split('\n');
  assert.equal(lines.length, 2);
  assert.equal(lines[1], '');
  assert.equal(JSON.parse(lines[0]).code, 'INVALID_SNAPSHOT');
  assert.ok(!fs.existsSync(output));
});

test('migrate reports checksum failures as INVALID_SNAPSHOT and leaves files untouched', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'base.json'), new Workspace());
  const tampered = workspaceWith([{ id: 'a', title: 'A', body: 'original', tags: [] }]).exportJSON();
  tampered.documents[0].body = 'tampered';
  fs.writeFileSync(path.join(cwd, 'incoming.json'), JSON.stringify(tampered));
  const output = path.join(cwd, 'out.json');

  const { status, stdout, stderr } = runMigrate(['base.json', 'incoming.json', 'out.json', 'merge'], cwd);
  assert.equal(status, 1);
  assert.equal(stdout, '');
  assert.equal(JSON.parse(stderr.trim()).code, 'INVALID_SNAPSHOT');
  assert.ok(!fs.existsSync(output));
});

test('migrate reports merge conflicts with sorted ids and preserves the output', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'base.json'), workspaceWith([
    { id: 'a', title: 'A', body: 'one', tags: [] },
  ]));
  writeSnapshot(path.join(cwd, 'incoming.json'), workspaceWith([
    { id: 'b', title: 'B', body: 'body text', tags: [] },
    { id: 'a', title: 'A', body: 'two', tags: [] },
  ]));
  const output = path.join(cwd, 'out.json');
  fs.writeFileSync(output, 'previous content\n');

  const { status, stdout, stderr } = runMigrate(['base.json', 'incoming.json', 'out.json', 'merge'], cwd);
  assert.equal(status, 1);
  assert.equal(stdout, '');
  const payload = JSON.parse(stderr.trim());
  assert.equal(payload.code, 'IMPORT_CONFLICT');
  assert.deepEqual(payload.ids, ['a']);
  assert.equal(fs.readFileSync(output, 'utf8'), 'previous content\n');
});

test('migrate reports unreadable inputs as IO_ERROR', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'base.json'), new Workspace());
  const output = path.join(cwd, 'out.json');

  const missingIncoming = runMigrate(['base.json', 'missing.json', 'out.json', 'merge'], cwd);
  assert.equal(missingIncoming.status, 1);
  assert.equal(missingIncoming.stdout, '');
  assert.equal(JSON.parse(missingIncoming.stderr.trim()).code, 'IO_ERROR');
  assert.ok(!fs.existsSync(output));

  const missingBase = runMigrate(['nope.json', 'base.json', 'out.json', 'merge'], cwd);
  assert.equal(missingBase.status, 1);
  assert.equal(JSON.parse(missingBase.stderr.trim()).code, 'IO_ERROR');
});

test('migrate reports unwritable output as IO_ERROR with inputs intact', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'base.json'), new Workspace());
  writeSnapshot(path.join(cwd, 'incoming.json'), new Workspace());
  const blockedDirectory = path.join(cwd, 'no-such-dir');

  const { status, stdout, stderr } = runMigrate(
    ['base.json', 'incoming.json', path.join(blockedDirectory, 'out.json'), 'merge'],
    cwd,
  );
  assert.equal(status, 1);
  assert.equal(stdout, '');
  assert.equal(JSON.parse(stderr.trim()).code, 'IO_ERROR');
  assert.ok(!fs.existsSync(blockedDirectory));
});

test('migrate rejects invalid arguments with INVALID_OPTIONS', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'base.json'), new Workspace());
  writeSnapshot(path.join(cwd, 'incoming.json'), new Workspace());

  for (const args of [
    ['base.json', 'incoming.json', 'out.json', 'upsert'],
    ['base.json', 'incoming.json', 'out.json'],
    ['base.json', 'incoming.json', 'out.json', 'merge', '--unknown'],
    ['base.json', 'incoming.json', 'out.json', 'merge', 'extra'],
  ]) {
    const { status, stdout, stderr } = runMigrate(args, cwd);
    assert.equal(status, 1, args.join(' '));
    assert.equal(stdout, '', args.join(' '));
    assert.equal(JSON.parse(stderr.trim()).code, 'INVALID_OPTIONS', args.join(' '));
  }
});

test('demo command still runs through the CLI', () => {
  let stdout;
  try {
    stdout = execFileSync(process.execPath, [CLI, 'demo'], { encoding: 'utf8' });
  } catch (error) {
    assert.fail(error.stderr?.toString() ?? error.message);
  }
  assert.match(stdout, /Lattice Workbench/u);
});
