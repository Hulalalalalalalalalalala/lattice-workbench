import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import test from 'node:test';
import { Workspace, snapshotFromDocuments } from '../src/workspace.js';

const CLI = path.resolve('src/cli.js');

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-md-'));
}

function writeSnapshot(file, workspace) {
  fs.writeFileSync(file, `${JSON.stringify(workspace.exportJSON())}\n`);
}

function workspaceWith(documents) {
  const workspace = new Workspace();
  for (const document of documents) workspace.add(document);
  return workspace;
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function runCli(args, cwd) {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8' });
    return { status: 0, stdout, stderr: '' };
  } catch (error) {
    return { status: error.status ?? 1, stdout: error.stdout?.toString() ?? '', stderr: error.stderr?.toString() ?? '' };
  }
}

function runExportMd(args, cwd) {
  return runCli(['export-md', ...args], cwd);
}

function runImportMd(args, cwd) {
  return runCli(['import-md', ...args], cwd);
}

// Builds a package independently of the export-md command, normalizing the
// same way the workspace does, so import tests do not share export's blind
// spots. Returns the normalized snapshot the package should rebuild.
function buildPackage(dir, documents) {
  fs.mkdirSync(dir, { recursive: true });
  const normalized = documents.map((document) => ({
    id: document.id,
    title: document.title.trim(),
    body: document.body,
    tags: [...new Set(document.tags.map((tag) => tag.trim().toLowerCase()).filter(Boolean))].sort(),
  }));
  const entries = normalized.map((document) => {
    const file = `${document.id}.md`;
    const bytes = Buffer.from(document.body, 'utf8');
    fs.writeFileSync(path.join(dir, file), bytes);
    return { id: document.id, title: document.title, tags: document.tags, file, sha256: sha256(bytes) };
  });
  const snapshot = snapshotFromDocuments(normalized);
  const manifest = { version: 1, documents: entries, checksum: snapshot.checksum };
  fs.writeFileSync(path.join(dir, 'manifest.json'), `${JSON.stringify(manifest)}\n`, 'utf8');
  return { snapshot, manifest };
}

function readPackage(dir) {
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const files = {};
  for (const name of fs.readdirSync(dir)) {
    if (name === 'manifest.json') continue;
    files[name] = fs.readFileSync(path.join(dir, name));
  }
  return { manifest, files };
}

test('export-md writes manifest.json and <id>.md files with the exact manifest shape', () => {
  const cwd = tempDir();
  const snap = path.join(cwd, 'snap.json');
  writeSnapshot(snap, workspaceWith([
    { id: 'welcome', title: '欢迎', body: 'See [[ghost]] and [[architecture]].\n\nLine three.', tags: ['Intro', 'intro'] },
    { id: 'architecture', title: '架构', body: 'Back to [[welcome]].', tags: ['arch'] },
  ]));
  const out = path.join(cwd, 'out');

  const { status, stdout, stderr } = runExportMd([snap, out], cwd);
  assert.equal(status, 0);
  assert.equal(stderr, '');
  const lines = stdout.split('\n');
  assert.equal(lines.length, 2);
  assert.equal(lines[1], '');
  const printed = JSON.parse(lines[0]);

  const { manifest, files } = readPackage(out);
  assert.deepEqual(printed, manifest);
  assert.deepEqual(Object.keys(manifest), ['version', 'documents', 'checksum']);
  assert.equal(manifest.version, 1);
  assert.equal(manifest.checksum, JSON.parse(fs.readFileSync(snap, 'utf8')).checksum);
  assert.deepEqual(manifest.documents.map((entry) => entry.id), ['architecture', 'welcome']);
  for (const entry of manifest.documents) {
    assert.deepEqual(Object.keys(entry), ['id', 'title', 'tags', 'file', 'sha256']);
    assert.equal(entry.file, `${entry.id}.md`);
    assert.match(entry.sha256, /^[0-9a-f]{64}$/u);
    assert.equal(entry.sha256, sha256(files[entry.file]));
  }
  assert.deepEqual(Object.keys(files).sort(), ['architecture.md', 'welcome.md']);
  // Bodies are byte-for-byte the original UTF-8 content: no added newline.
  assert.equal(files['welcome.md'].toString('utf8'), 'See [[ghost]] and [[architecture]].\n\nLine three.');
});

test('export-md on an empty workspace produces a round-trippable empty package', () => {
  const cwd = tempDir();
  const snap = path.join(cwd, 'snap.json');
  writeSnapshot(snap, new Workspace());
  const out = path.join(cwd, 'out');

  const { status, stdout } = runExportMd([snap, out], cwd);
  assert.equal(status, 0);
  const printed = JSON.parse(stdout.trim());
  assert.deepEqual(printed.documents, []);
  assert.equal(printed.checksum, JSON.parse(fs.readFileSync(snap, 'utf8')).checksum);
  assert.deepEqual(fs.readdirSync(out), ['manifest.json']);

  const back = path.join(cwd, 'back.json');
  const result = runImportMd([snap, out, back, 'replace'], cwd);
  assert.equal(result.status, 0);
  assert.deepEqual(JSON.parse(result.stdout.trim()), JSON.parse(fs.readFileSync(snap, 'utf8')));
});

test('export-md writes byte-identical packages for the same snapshot', () => {
  const cwd = tempDir();
  const snap = path.join(cwd, 'snap.json');
  writeSnapshot(snap, workspaceWith([
    { id: 'a', title: 'A', body: 'body [[b]]', tags: ['x'] },
    { id: 'b', title: 'B', body: 'body [[a]]', tags: ['y'] },
  ]));

  const first = path.join(cwd, 'out1');
  const second = path.join(cwd, 'out2');
  assert.equal(runExportMd([snap, first], cwd).status, 0);
  assert.equal(runExportMd([snap, second], cwd).status, 0);

  const all = (dir) => fs.readdirSync(dir).sort().map((name) => ({
    name,
    bytes: fs.readFileSync(path.join(dir, name)),
  }));
  assert.deepEqual(all(first), all(second));
});

test('export-md replaces an existing target wholesale, leaving no old files', () => {
  const cwd = tempDir();
  const snapA = path.join(cwd, 'a.json');
  const snapB = path.join(cwd, 'b.json');
  writeSnapshot(snapA, workspaceWith([{ id: 'alpha', title: 'Alpha', body: 'body', tags: [] }]));
  writeSnapshot(snapB, workspaceWith([{ id: 'beta', title: 'Beta', body: 'body', tags: [] }]));
  const out = path.join(cwd, 'out');

  assert.equal(runExportMd([snapA, out], cwd).status, 0);
  assert.deepEqual(fs.readdirSync(out).sort(), ['alpha.md', 'manifest.json']);
  assert.equal(runExportMd([snapB, out], cwd).status, 0);
  assert.deepEqual(fs.readdirSync(out).sort(), ['beta.md', 'manifest.json']);
});

test('export-md rejects a target that is a symbolic link with INVALID_OPTIONS', () => {
  const cwd = tempDir();
  const snap = path.join(cwd, 'snap.json');
  writeSnapshot(snap, workspaceWith([{ id: 'a', title: 'A', body: 'body', tags: [] }]));
  const real = path.join(cwd, 'real');
  fs.mkdirSync(real);
  const link = path.join(cwd, 'link');
  fs.symlinkSync(real, link);

  const result = runExportMd([snap, link], cwd);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(JSON.parse(result.stderr.trim()).code, 'INVALID_OPTIONS');
  // The real directory behind the link is untouched.
  assert.deepEqual(fs.readdirSync(real), []);
});

test('export-md rejects a target that contains the source snapshot, including through aliases', () => {
  const cwd = tempDir();
  const inside = path.join(cwd, 'out');
  fs.mkdirSync(inside);
  const snapInside = path.join(inside, 'snap.json');
  writeSnapshot(snapInside, workspaceWith([{ id: 'a', title: 'A', body: 'body', tags: [] }]));

  const direct = runExportMd([snapInside, inside], cwd);
  assert.equal(direct.status, 1);
  assert.equal(direct.stdout, '');
  assert.equal(JSON.parse(direct.stderr.trim()).code, 'INVALID_OPTIONS');
  // No package was written into the target.
  assert.deepEqual(fs.readdirSync(inside), ['snap.json']);

  // Alias: the source is reached through a symlink whose real location is
  // inside the real target directory.
  const realOut = path.join(cwd, 'real-out');
  fs.mkdirSync(realOut);
  const snapInReal = path.join(realOut, 'snap.json');
  writeSnapshot(snapInReal, workspaceWith([{ id: 'a', title: 'A', body: 'body', tags: [] }]));
  const alias = path.join(cwd, 'snap-alias.json');
  fs.symlinkSync(snapInReal, alias);
  const aliased = runExportMd([alias, realOut], cwd);
  assert.equal(aliased.status, 1);
  assert.equal(aliased.stdout, '');
  assert.equal(JSON.parse(aliased.stderr.trim()).code, 'INVALID_OPTIONS');
  assert.deepEqual(fs.readdirSync(realOut), ['snap.json']);
});

test('export-md reports a lone-surrogate body as INVALID_MARKDOWN and leaves the target absent', () => {
  const cwd = tempDir();
  const snap = path.join(cwd, 'snap.json');
  const workspace = new Workspace();
  workspace.add({ id: 'a', title: 'A', body: 'lone surrogate \uD800 here', tags: [] });
  writeSnapshot(snap, workspace);
  const out = path.join(cwd, 'out');

  const result = runExportMd([snap, out], cwd);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(JSON.parse(result.stderr.trim()).code, 'INVALID_MARKDOWN');
  assert.ok(!fs.existsSync(out));
});

test('export-md reports a missing snapshot as IO_ERROR', () => {
  const cwd = tempDir();
  const result = runExportMd([path.join(cwd, 'nope.json'), path.join(cwd, 'out')], cwd);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(JSON.parse(result.stderr.trim()).code, 'IO_ERROR');
});

test('export-md recovers from a stale staging directory and produces a complete package', () => {
  const cwd = tempDir();
  const snap = path.join(cwd, 'snap.json');
  writeSnapshot(snap, workspaceWith([
    { id: 'a', title: 'A', body: 'body [[b]]', tags: [] },
    { id: 'b', title: 'B', body: 'body [[a]]', tags: [] },
  ]));
  const out = path.join(cwd, 'out');
  // Leftover staging directory from a killed earlier attempt.
  const stale = path.join(cwd, `.out.${process.pid}.deadbeef.tmp`);
  fs.mkdirSync(stale);
  fs.writeFileSync(path.join(stale, 'garbage'), 'half-written');

  const result = runExportMd([snap, out], cwd);
  assert.equal(result.status, 0);
  assert.deepEqual(fs.readdirSync(out).sort(), ['a.md', 'b.md', 'manifest.json']);
  assert.equal(JSON.parse(result.stdout.trim()).checksum, JSON.parse(fs.readFileSync(snap, 'utf8')).checksum);
});

test('import-md round-trips content, search results, and bidirectional links', () => {
  const cwd = tempDir();
  const base = path.join(cwd, 'base.json');
  writeSnapshot(base, workspaceWith([
    { id: 'welcome', title: '欢迎', body: 'See [[ghost]] and [[architecture]].', tags: ['Intro'] },
    { id: 'architecture', title: '架构', body: 'Back to [[welcome]].', tags: ['arch'] },
  ]));
  const pkg = path.join(cwd, 'pkg');
  assert.equal(runExportMd([base, pkg], cwd).status, 0);
  const back = path.join(cwd, 'back.json');

  const result = runImportMd([base, pkg, back, 'replace'], cwd);
  assert.equal(result.status, 0);
  assert.equal(result.stderr, '');
  const printed = JSON.parse(result.stdout.trim());
  const written = JSON.parse(fs.readFileSync(back, 'utf8'));
  assert.deepEqual(printed, written);

  const expected = JSON.parse(fs.readFileSync(base, 'utf8'));
  assert.deepEqual(printed, expected);

  const reloaded = new Workspace();
  reloaded.importJSON(printed, { mode: 'replace' });
  // Search matches titles, bodies, and tags: welcome's body links to
  // architecture, so the architecture term surfaces welcome as well.
  assert.deepEqual(reloaded.search('架构').map((d) => d.id), ['architecture']);
  assert.deepEqual(reloaded.search('欢迎').map((d) => d.id), ['welcome']);
  assert.deepEqual(reloaded.search('ghost').map((d) => d.id), ['welcome']);
  assert.deepEqual(reloaded.search('back').map((d) => d.id), ['architecture']);
  assert.deepEqual(reloaded.links('welcome'), { outgoing: ['architecture', 'ghost'], incoming: ['architecture'] });
  assert.deepEqual(reloaded.links('architecture'), { outgoing: ['welcome'], incoming: ['welcome'] });
  assert.deepEqual(reloaded.links('ghost'), null);
});

test('import-md merge keeps existing documents and adds package documents', () => {
  const cwd = tempDir();
  const base = path.join(cwd, 'base.json');
  writeSnapshot(base, workspaceWith([{ id: 'a', title: 'A', body: 'base [[c]]', tags: ['keep'] }]));
  const pkg = path.join(cwd, 'pkg');
  buildPackage(pkg, [
    { id: 'b', title: 'B', body: 'new [[a]]', tags: ['incoming'] },
    { id: 'c', title: 'C', body: 'dangling [[nowhere]]', tags: [] },
  ]);
  const out = path.join(cwd, 'out.json');

  const result = runImportMd([base, pkg, out, 'merge'], cwd);
  assert.equal(result.status, 0);
  assert.deepEqual(JSON.parse(result.stdout.trim()).documents.map((d) => d.id), ['a', 'b', 'c']);
  const reloaded = new Workspace();
  reloaded.importJSON(JSON.parse(fs.readFileSync(out, 'utf8')), { mode: 'replace' });
  assert.equal(reloaded.get('a').body, 'base [[c]]');
  assert.deepEqual(reloaded.links('a'), { outgoing: ['c'], incoming: ['b'] });
});

test('import-md merge reports conflicts with sorted ids and leaves the output untouched', () => {
  const cwd = tempDir();
  const base = path.join(cwd, 'base.json');
  writeSnapshot(base, workspaceWith([
    { id: 'a', title: 'A', body: 'one', tags: [] },
    { id: 'b', title: 'B', body: 'body', tags: [] },
  ]));
  const pkg = path.join(cwd, 'pkg');
  buildPackage(pkg, [
    { id: 'b', title: 'B', body: 'changed', tags: [] },
    { id: 'a', title: 'A', body: 'two', tags: [] },
  ]);
  const out = path.join(cwd, 'out.json');
  fs.writeFileSync(out, 'previous\n');

  const result = runImportMd([base, pkg, out, 'merge'], cwd);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  const payload = JSON.parse(result.stderr.trim());
  assert.equal(payload.code, 'IMPORT_CONFLICT');
  assert.deepEqual(payload.ids, ['a', 'b']);
  assert.equal(fs.readFileSync(out, 'utf8'), 'previous\n');
});

test('import-md replace swaps the full document set', () => {
  const cwd = tempDir();
  const base = path.join(cwd, 'base.json');
  writeSnapshot(base, workspaceWith([{ id: 'old', title: 'Old', body: 'gone', tags: [] }]));
  const pkg = path.join(cwd, 'pkg');
  buildPackage(pkg, [{ id: 'new', title: 'New', body: 'here', tags: [] }]);
  const out = path.join(cwd, 'out.json');

  const result = runImportMd([base, pkg, out, 'replace'], cwd);
  assert.equal(result.status, 0);
  assert.deepEqual(JSON.parse(result.stdout.trim()).documents.map((d) => d.id), ['new']);
});

test('import-md --dry-run prints the projection without creating or touching the output', () => {
  const cwd = tempDir();
  const base = path.join(cwd, 'base.json');
  writeSnapshot(base, workspaceWith([{ id: 'a', title: 'A', body: 'body', tags: [] }]));
  const pkg = path.join(cwd, 'pkg');
  buildPackage(pkg, [{ id: 'b', title: 'B', body: 'body', tags: [] }]);
  const missing = path.join(cwd, 'missing.json');

  const dry = runImportMd([base, pkg, missing, 'merge', '--dry-run'], cwd);
  assert.equal(dry.status, 0);
  assert.deepEqual(JSON.parse(dry.stdout.trim()).documents.map((d) => d.id), ['a', 'b']);
  assert.ok(!fs.existsSync(missing));

  const existing = path.join(cwd, 'existing.json');
  fs.writeFileSync(existing, 'do not touch\n');
  runImportMd([base, pkg, existing, 'merge', '--dry-run'], cwd);
  assert.equal(fs.readFileSync(existing, 'utf8'), 'do not touch\n');
});

test('import-md output may overwrite the base snapshot', () => {
  const cwd = tempDir();
  const base = path.join(cwd, 'base.json');
  writeSnapshot(base, workspaceWith([{ id: 'a', title: 'A', body: 'body', tags: [] }]));
  const pkg = path.join(cwd, 'pkg');
  buildPackage(pkg, [{ id: 'b', title: 'B', body: 'body', tags: [] }]);

  const result = runImportMd([base, pkg, base, 'replace'], cwd);
  assert.equal(result.status, 0);
  assert.deepEqual(JSON.parse(fs.readFileSync(base, 'utf8')).documents.map((d) => d.id), ['b']);
});

test('import-md rejects an input directory that is a symbolic link', () => {
  const cwd = tempDir();
  const base = path.join(cwd, 'base.json');
  writeSnapshot(base, new Workspace());
  const real = path.join(cwd, 'real');
  const pkg = path.join(cwd, 'pkg');
  buildPackage(real, [{ id: 'a', title: 'A', body: 'body', tags: [] }]);
  fs.symlinkSync(real, pkg);

  const result = runImportMd([base, pkg, path.join(cwd, 'out.json'), 'replace'], cwd);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(JSON.parse(result.stderr.trim()).code, 'INVALID_MARKDOWN');
});

test('import-md rejects packages containing symlinks, subdirectories, or illegal filenames', () => {
  const cwd = tempDir();
  const base = path.join(cwd, 'base.json');
  writeSnapshot(base, new Workspace());
  const out = path.join(cwd, 'out.json');

  // Symlink inside the package.
  const withLink = path.join(cwd, 'link-pkg');
  buildPackage(withLink, [{ id: 'a', title: 'A', body: 'body', tags: [] }]);
  fs.symlinkSync(path.join(withLink, 'a.md'), path.join(withLink, 'alias.md'));
  let result = runImportMd([base, withLink, out, 'replace'], cwd);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr.trim()).code, 'INVALID_MARKDOWN');

  // Subdirectory inside the package.
  const withDir = path.join(cwd, 'dir-pkg');
  buildPackage(withDir, [{ id: 'a', title: 'A', body: 'body', tags: [] }]);
  fs.mkdirSync(path.join(withDir, 'subdir'));
  result = runImportMd([base, withDir, out, 'replace'], cwd);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr.trim()).code, 'INVALID_MARKDOWN');

  // Illegal filename.
  const withIllegal = path.join(cwd, 'illegal-pkg');
  buildPackage(withIllegal, [{ id: 'a', title: 'A', body: 'body', tags: [] }]);
  fs.writeFileSync(path.join(withIllegal, 'UPPER.md'), 'body');
  result = runImportMd([base, withIllegal, out, 'replace'], cwd);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr.trim()).code, 'INVALID_MARKDOWN');
});

test('import-md rejects missing or extra package files', () => {
  const cwd = tempDir();
  const base = path.join(cwd, 'base.json');
  writeSnapshot(base, new Workspace());
  const out = path.join(cwd, 'out.json');

  const missing = path.join(cwd, 'missing-pkg');
  buildPackage(missing, [{ id: 'a', title: 'A', body: 'body', tags: [] }]);
  fs.rmSync(path.join(missing, 'a.md'));
  let result = runImportMd([base, missing, out, 'replace'], cwd);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr.trim()).code, 'INVALID_MARKDOWN');

  const extra = path.join(cwd, 'extra-pkg');
  buildPackage(extra, [{ id: 'a', title: 'A', body: 'body', tags: [] }]);
  fs.writeFileSync(path.join(extra, 'b.md'), 'body');
  result = runImportMd([base, extra, out, 'replace'], cwd);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr.trim()).code, 'INVALID_MARKDOWN');
});

test('import-md rejects malformed manifests and manifest field/type errors', () => {
  const cwd = tempDir();
  const base = path.join(cwd, 'base.json');
  writeSnapshot(base, new Workspace());
  const out = path.join(cwd, 'out.json');

  const cases = [];
  // Not JSON.
  const notJson = path.join(cwd, 'not-json');
  fs.mkdirSync(notJson);
  fs.writeFileSync(path.join(notJson, 'manifest.json'), '{broken');
  cases.push(notJson);
  // Not an object.
  const notObject = path.join(cwd, 'not-object');
  fs.mkdirSync(notObject);
  fs.writeFileSync(path.join(notObject, 'manifest.json'), '[]');
  cases.push(notObject);
  // Missing checksum.
  const missingKey = path.join(cwd, 'missing-key');
  buildPackage(missingKey, [{ id: 'a', title: 'A', body: 'body', tags: [] }]);
  let manifest = JSON.parse(fs.readFileSync(path.join(missingKey, 'manifest.json'), 'utf8'));
  delete manifest.checksum;
  fs.writeFileSync(path.join(missingKey, 'manifest.json'), JSON.stringify(manifest));
  cases.push(missingKey);
  // Extra top-level field.
  const extraKey = path.join(cwd, 'extra-key');
  buildPackage(extraKey, [{ id: 'a', title: 'A', body: 'body', tags: [] }]);
  manifest = JSON.parse(fs.readFileSync(path.join(extraKey, 'manifest.json'), 'utf8'));
  manifest.extra = 1;
  fs.writeFileSync(path.join(extraKey, 'manifest.json'), JSON.stringify(manifest));
  cases.push(extraKey);
  // Wrong version.
  const wrongVersion = path.join(cwd, 'wrong-version');
  buildPackage(wrongVersion, [{ id: 'a', title: 'A', body: 'body', tags: [] }]);
  manifest = JSON.parse(fs.readFileSync(path.join(wrongVersion, 'manifest.json'), 'utf8'));
  manifest.version = 2;
  fs.writeFileSync(path.join(wrongVersion, 'manifest.json'), JSON.stringify(manifest));
  cases.push(wrongVersion);
  // Documents not an array.
  const docsNotArray = path.join(cwd, 'docs-not-array');
  buildPackage(docsNotArray, [{ id: 'a', title: 'A', body: 'body', tags: [] }]);
  manifest = JSON.parse(fs.readFileSync(path.join(docsNotArray, 'manifest.json'), 'utf8'));
  manifest.documents = {};
  fs.writeFileSync(path.join(docsNotArray, 'manifest.json'), JSON.stringify(manifest));
  cases.push(docsNotArray);
  // Entry with a missing field.
  const entryMissing = path.join(cwd, 'entry-missing');
  buildPackage(entryMissing, [{ id: 'a', title: 'A', body: 'body', tags: [] }]);
  manifest = JSON.parse(fs.readFileSync(path.join(entryMissing, 'manifest.json'), 'utf8'));
  delete manifest.documents[0].sha256;
  fs.writeFileSync(path.join(entryMissing, 'manifest.json'), JSON.stringify(manifest));
  cases.push(entryMissing);
  // Entry with a wrong type.
  const entryWrongType = path.join(cwd, 'entry-wrong-type');
  buildPackage(entryWrongType, [{ id: 'a', title: 'A', body: 'body', tags: [] }]);
  manifest = JSON.parse(fs.readFileSync(path.join(entryWrongType, 'manifest.json'), 'utf8'));
  manifest.documents[0].tags = 'x';
  fs.writeFileSync(path.join(entryWrongType, 'manifest.json'), JSON.stringify(manifest));
  cases.push(entryWrongType);
  // file does not match <id>.md.
  const fileMismatch = path.join(cwd, 'file-mismatch');
  buildPackage(fileMismatch, [{ id: 'a', title: 'A', body: 'body', tags: [] }]);
  manifest = JSON.parse(fs.readFileSync(path.join(fileMismatch, 'manifest.json'), 'utf8'));
  manifest.documents[0].file = 'b.md';
  fs.writeFileSync(path.join(fileMismatch, 'manifest.json'), JSON.stringify(manifest));
  cases.push(fileMismatch);

  for (const pkg of cases) {
    const result = runImportMd([base, pkg, out, 'replace'], cwd);
    assert.equal(result.status, 1, pkg);
    assert.equal(result.stdout, '', pkg);
    assert.equal(JSON.parse(result.stderr.trim()).code, 'INVALID_MARKDOWN', pkg);
    assert.ok(!fs.existsSync(out), pkg);
  }
});

test('import-md rejects duplicate ids and duplicate normalized titles', () => {
  const cwd = tempDir();
  const base = path.join(cwd, 'base.json');
  writeSnapshot(base, new Workspace());
  const out = path.join(cwd, 'out.json');

  const dupId = path.join(cwd, 'dup-id');
  buildPackage(dupId, [{ id: 'a', title: 'A', body: 'body', tags: [] }]);
  let manifest = JSON.parse(fs.readFileSync(path.join(dupId, 'manifest.json'), 'utf8'));
  const entry = { ...manifest.documents[0] };
  fs.copyFileSync(path.join(dupId, 'a.md'), path.join(dupId, 'b.md'));
  entry.file = 'b.md';
  manifest.documents.push(entry);
  fs.writeFileSync(path.join(dupId, 'manifest.json'), JSON.stringify(manifest));
  let result = runImportMd([base, dupId, out, 'replace'], cwd);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr.trim()).code, 'INVALID_MARKDOWN');

  const dupTitle = path.join(cwd, 'dup-title');
  buildPackage(dupTitle, [
    { id: 'a', title: 'Same', body: 'body', tags: [] },
    { id: 'b', title: 'Other', body: 'body', tags: [] },
  ]);
  // Inject an untrimmed title that normalizes to the first title.
  manifest = JSON.parse(fs.readFileSync(path.join(dupTitle, 'manifest.json'), 'utf8'));
  manifest.documents[1].title = ' Same ';
  fs.writeFileSync(path.join(dupTitle, 'manifest.json'), JSON.stringify(manifest));
  result = runImportMd([base, dupTitle, out, 'replace'], cwd);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr.trim()).code, 'INVALID_MARKDOWN');
});

test('import-md rejects illegal UTF-8 bodies, sha256 mismatches, and checksum mismatches', () => {
  const cwd = tempDir();
  const base = path.join(cwd, 'base.json');
  writeSnapshot(base, new Workspace());
  const out = path.join(cwd, 'out.json');

  const illegalUtf8 = path.join(cwd, 'illegal-utf8');
  buildPackage(illegalUtf8, [{ id: 'a', title: 'A', body: 'body', tags: [] }]);
  fs.writeFileSync(path.join(illegalUtf8, 'a.md'), Buffer.from([0xff, 0xfe, 0x62]));
  let result = runImportMd([base, illegalUtf8, out, 'replace'], cwd);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr.trim()).code, 'INVALID_MARKDOWN');

  const badSha = path.join(cwd, 'bad-sha');
  buildPackage(badSha, [{ id: 'a', title: 'A', body: 'body', tags: [] }]);
  fs.appendFileSync(path.join(badSha, 'a.md'), 'x');
  result = runImportMd([base, badSha, out, 'replace'], cwd);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr.trim()).code, 'INVALID_MARKDOWN');

  const badChecksum = path.join(cwd, 'bad-checksum');
  buildPackage(badChecksum, [{ id: 'a', title: 'A', body: 'body', tags: [] }]);
  const manifest = JSON.parse(fs.readFileSync(path.join(badChecksum, 'manifest.json'), 'utf8'));
  manifest.checksum = '0'.repeat(64);
  fs.writeFileSync(path.join(badChecksum, 'manifest.json'), JSON.stringify(manifest));
  result = runImportMd([base, badChecksum, out, 'replace'], cwd);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr.trim()).code, 'INVALID_MARKDOWN');
});

test('import-md rejects an output inside the input directory, including through aliases', () => {
  const cwd = tempDir();
  const base = path.join(cwd, 'base.json');
  writeSnapshot(base, new Workspace());
  const pkg = path.join(cwd, 'pkg');
  buildPackage(pkg, [{ id: 'a', title: 'A', body: 'body', tags: [] }]);

  const inside = path.join(pkg, 'out.json');
  let result = runImportMd([base, pkg, inside, 'replace'], cwd);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(JSON.parse(result.stderr.trim()).code, 'INVALID_OPTIONS');
  assert.ok(!fs.existsSync(inside));

  // Alias: the output is reached through a symlink inside the package.
  const alias = path.join(pkg, 'alias.json');
  fs.symlinkSync(path.join(cwd, 'real-out.json'), alias);
  result = runImportMd([base, pkg, alias, 'replace'], cwd);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr.trim()).code, 'INVALID_OPTIONS');
});

test('import-md reports a missing base snapshot as IO_ERROR', () => {
  const cwd = tempDir();
  const pkg = path.join(cwd, 'pkg');
  buildPackage(pkg, [{ id: 'a', title: 'A', body: 'body', tags: [] }]);
  const result = runImportMd([path.join(cwd, 'nope.json'), pkg, path.join(cwd, 'out.json'), 'replace'], cwd);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(JSON.parse(result.stderr.trim()).code, 'IO_ERROR');
});

test('import-md rejects invalid arguments with INVALID_OPTIONS', () => {
  const cwd = tempDir();
  const base = path.join(cwd, 'base.json');
  writeSnapshot(base, new Workspace());
  const pkg = path.join(cwd, 'pkg');
  buildPackage(pkg, [{ id: 'a', title: 'A', body: 'body', tags: [] }]);

  for (const args of [
    [base, pkg, path.join(cwd, 'out.json'), 'upsert'],
    [base, pkg, path.join(cwd, 'out.json')],
    [base, pkg, path.join(cwd, 'out.json'), 'merge', '--unknown'],
    [base, pkg, path.join(cwd, 'out.json'), 'merge', 'extra'],
  ]) {
    const result = runImportMd(args, cwd);
    assert.equal(result.status, 1, args.join(' '));
    assert.equal(result.stdout, '', args.join(' '));
    assert.equal(JSON.parse(result.stderr.trim()).code, 'INVALID_OPTIONS', args.join(' '));
  }
});

test('export-md and import-md leave stdout empty and stderr as one JSON line on every failure', () => {
  const cwd = tempDir();
  const snap = path.join(cwd, 'snap.json');
  writeSnapshot(snap, workspaceWith([{ id: 'a', title: 'A', body: 'body', tags: [] }]));
  const out = path.join(cwd, 'out');

  const failed = runExportMd([snap, path.join(cwd, 'no-such-parent', 'out')], cwd);
  assert.equal(failed.status, 1);
  assert.equal(failed.stdout, '');
  const lines = failed.stderr.split('\n');
  assert.equal(lines.length, 2);
  assert.equal(lines[1], '');
  assert.deepEqual(Object.keys(JSON.parse(lines[0])), ['code', 'message']);
});
