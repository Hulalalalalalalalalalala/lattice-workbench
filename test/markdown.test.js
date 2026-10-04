import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import test from 'node:test';
import { Workspace, snapshotFromDocuments } from '../src/workspace.js';
import { buildPackage, parsePackage, exportMarkdown, importMarkdown } from '../src/markdown-pkg.js';

const CLI = path.resolve('src/cli.js');

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-markdown-'));
}

function workspaceWith(documents) {
  const workspace = new Workspace();
  for (const document of documents) workspace.add(document);
  return workspace;
}

function writeSnapshot(file, workspace) {
  fs.writeFileSync(file, `${JSON.stringify(workspace.exportJSON())}\n`);
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function runCli(args, cwd) {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8' });
    return { status: 0, stdout, stderr: '' };
  } catch (error) {
    return { status: error.status ?? 1, stdout: error.stdout?.toString() ?? '', stderr: error.stderr?.toString() ?? '' };
  }
}

const sampleDocuments = [
  { id: 'welcome', title: '欢迎使用', body: '从 [[architecture]] 和 [[ghost]] 开始。\n第二行\n', tags: ['Intro', 'intro'] },
  { id: 'architecture', title: '架构', body: '本地优先，返回 [[welcome]]。\t保留制表符', tags: ['架构', 'MARKDOWN'] },
  { id: 'a.b', title: 'Dot', body: '[[]] dangling [[missing.one]]', tags: [] },
];

// ---- Pure build/parse ------------------------------------------------------

test('buildPackage emits manifest.json plus one <id>.md per document with raw bytes', () => {
  const snapshot = workspaceWith(sampleDocuments).exportJSON();
  const { manifest, files } = buildPackage(snapshot);
  assert.deepEqual(Object.keys(manifest), ['version', 'documents', 'checksum']);
  assert.equal(manifest.version, 1);
  assert.equal(manifest.checksum, snapshot.checksum);
  assert.deepEqual(manifest.documents.map((entry) => entry.id), ['a.b', 'architecture', 'welcome']);
  for (const entry of manifest.documents) {
    assert.deepEqual(Object.keys(entry), ['id', 'title', 'tags', 'file', 'sha256']);
    assert.equal(entry.file, `${entry.id}.md`);
    const document = snapshot.documents.find((candidate) => candidate.id === entry.id);
    assert.deepEqual(entry.tags, document.tags);
    assert.deepEqual(files.get(entry.file), Buffer.from(document.body, 'utf8'));
    assert.equal(entry.sha256, sha256(files.get(entry.file)));
    assert.equal(entry.sha256, entry.sha256.toLowerCase());
  }
  assert.ok(files.has('manifest.json'));
});

test('repeat builds are byte-identical, including the empty workspace', () => {
  const snapshot = workspaceWith(sampleDocuments).exportJSON();
  const first = buildPackage(snapshot);
  const second = buildPackage(snapshot);
  assert.deepEqual([...first.files], [...second.files]);
  const emptyA = buildPackage(new Workspace().exportJSON());
  const emptyB = buildPackage(new Workspace().exportJSON());
  assert.deepEqual([...emptyA.files], [...emptyB.files]);
  assert.deepEqual(emptyA.manifest.documents, []);
});

test('a body that cannot be encoded as UTF-8 fails with INVALID_MARKDOWN', () => {
  // A lone surrogate survives JSON.stringify but has no standalone UTF-8 form.
  const snapshot = snapshotFromDocuments([{ id: 'a', title: 'A', body: 'bad \uD800 surrogate', tags: [] }]);
  assert.throws(() => buildPackage(snapshot), (error) => error.code === 'INVALID_MARKDOWN');
});

test('parsePackage accepts a roundtrip and rejects illegal UTF-8 even with a matching hash', () => {
  const snapshot = workspaceWith([{ id: 'a', title: 'A', body: 'body text', tags: ['x'] }]).exportJSON();
  const { manifest, files } = buildPackage(snapshot);
  const parsed = parsePackage(manifest, files);
  assert.equal(parsed.checksum, snapshot.checksum);
  assert.equal(parsed.entries[0].body, 'body text');

  const bytes = Buffer.from([0xff, 0xfe]);
  const tampered = new Map(files);
  tampered.set('a.md', bytes);
  const forged = structuredClone(manifest);
  forged.documents[0].sha256 = sha256(bytes);
  assert.throws(() => parsePackage(forged, tampered), (error) => error.code === 'INVALID_MARKDOWN');
});

test('parsePackage verifies every file digest and flags missing or extra files', () => {
  const snapshot = workspaceWith([
    { id: 'a', title: 'A', body: 'alpha', tags: [] },
    { id: 'b', title: 'B', body: 'beta', tags: [] },
  ]).exportJSON();
  const { manifest, files } = buildPackage(snapshot);

  const changed = new Map(files);
  changed.set('a.md', Buffer.from('alpha!', 'utf8'));
  assert.throws(() => parsePackage(manifest, changed), (e) => e.code === 'INVALID_MARKDOWN' && /sha256/u.test(e.message));

  const missing = new Map(files);
  missing.delete('b.md');
  assert.throws(() => parsePackage(manifest, missing), (e) => e.code === 'INVALID_MARKDOWN' && /missing/u.test(e.message));

  const extra = new Map(files);
  extra.set('stray.md', Buffer.from('x', 'utf8'));
  assert.throws(() => parsePackage(manifest, extra), (e) => e.code === 'INVALID_MARKDOWN' && /unexpected/u.test(e.message));
});

const INVALID_MANIFESTS = [
  ['not an object', null],
  ['an array', []],
  ['extra top-level field', (() => { const m = buildPackage(new Workspace().exportJSON()).manifest; m.extra = 1; return m; })()],
  ['missing version', (() => { const m = buildPackage(new Workspace().exportJSON()).manifest; delete m.version; return m; })()],
  ['wrong version', (() => { const m = buildPackage(new Workspace().exportJSON()).manifest; m.version = 2; return m; })()],
  ['string version', (() => { const m = buildPackage(new Workspace().exportJSON()).manifest; m.version = '1'; return m; })()],
  ['bad checksum shape', (() => { const m = buildPackage(new Workspace().exportJSON()).manifest; m.checksum = 'ABC'; return m; })()],
  ['documents not array', (() => { const m = buildPackage(new Workspace().exportJSON()).manifest; m.documents = {}; return m; })()],
  ['entry extra field', (() => {
    const p = buildPackage(workspaceWith([{ id: 'a', title: 'A', body: 'b', tags: [] }]).exportJSON());
    p.manifest.documents[0].extra = 1; return p.manifest;
  })()],
  ['entry missing field', (() => {
    const p = buildPackage(workspaceWith([{ id: 'a', title: 'A', body: 'b', tags: [] }]).exportJSON());
    delete p.manifest.documents[0].sha256; return p.manifest;
  })()],
  ['non-string id', (() => {
    const p = buildPackage(workspaceWith([{ id: 'a', title: 'A', body: 'b', tags: [] }]).exportJSON());
    p.manifest.documents[0].id = 1; return p.manifest;
  })()],
  ['tags not strings', (() => {
    const p = buildPackage(workspaceWith([{ id: 'a', title: 'A', body: 'b', tags: [] }]).exportJSON());
    p.manifest.documents[0].tags = [1]; return p.manifest;
  })()],
  ['bad file value', (() => {
    const p = buildPackage(workspaceWith([{ id: 'a', title: 'A', body: 'b', tags: [] }]).exportJSON());
    p.manifest.documents[0].file = 'other.md'; return p.manifest;
  })()],
  ['bad sha256 shape', (() => {
    const p = buildPackage(workspaceWith([{ id: 'a', title: 'A', body: 'b', tags: [] }]).exportJSON());
    p.manifest.documents[0].sha256 = 'z'.repeat(64); return p.manifest;
  })()],
];

for (const [label, manifest] of INVALID_MANIFESTS) {
  test(`parsePackage rejects ${label}`, () => {
    const files = new Map([['manifest.json', Buffer.from('{}')]]);
    assert.throws(() => parsePackage(manifest, files), (error) => error.code === 'INVALID_MARKDOWN');
  });
}

test('parsePackage rejects duplicate ids and duplicate normalized titles', () => {
  const snapshot = workspaceWith([
    { id: 'a', title: 'A', body: 'a', tags: [] },
    { id: 'b', title: 'B', body: 'b', tags: [] },
  ]).exportJSON();
  const { manifest, files } = buildPackage(snapshot);
  const dupId = structuredClone(manifest);
  dupId.documents.push(structuredClone(dupId.documents[0]));
  assert.throws(() => parsePackage(dupId, files), (e) => /duplicate document id/u.test(e.message));

  const dupTitle = structuredClone(manifest);
  // Give the second entry its own file/hash but a colliding trimmed title.
  const b = dupTitle.documents.find((entry) => entry.id === 'b');
  b.title = ' A ';
  const a = dupTitle.documents.find((entry) => entry.id === 'a');
  files.set('b.md', files.get('a.md'));
  b.sha256 = a.sha256;
  b.file = 'b.md';
  assert.throws(() => parsePackage(dupTitle, files), (e) => /duplicate normalized title/u.test(e.message));
});

// ---- Module-level round trip on disk ---------------------------------------

test('exportMarkdown then importMarkdown reproduces bodies, search, and bidirectional links', () => {
  const cwd = tempDir();
  const original = workspaceWith(sampleDocuments);
  writeSnapshot(path.join(cwd, 'snap.json'), original);
  writeSnapshot(path.join(cwd, 'empty.json'), new Workspace());

  const { manifestText } = exportMarkdown(path.join(cwd, 'snap.json'), path.join(cwd, 'pkg'));
  const result = importMarkdown(
    path.join(cwd, 'empty.json'), path.join(cwd, 'pkg'), path.join(cwd, 'out.json'), 'replace',
  );

  const rebuilt = new Workspace();
  rebuilt.importJSON(result.snapshot, { mode: 'replace' });
  assert.deepEqual(rebuilt.exportJSON(), original.exportJSON());
  // Content bytes survive verbatim (newline/tab/dangling links), search and links agree.
  assert.equal(rebuilt.get('welcome').body, sampleDocuments[0].body);
  assert.deepEqual(rebuilt.search('markdown').map((d) => d.id), ['architecture']);
  assert.deepEqual(rebuilt.search('架构').map((d) => d.id), ['architecture']);
  assert.deepEqual(rebuilt.links('welcome'), { outgoing: ['architecture', 'ghost'], incoming: ['architecture'] });
  assert.deepEqual(rebuilt.links('architecture'), { outgoing: ['welcome'], incoming: ['welcome'] });
  // Saved bytes match the returned snapshot exactly and the printed manifest.
  assert.equal(fs.readFileSync(path.join(cwd, 'out.json'), 'utf8'), result.rendered);
  assert.equal(fs.readFileSync(path.join(cwd, 'pkg', 'manifest.json'), 'utf8'), manifestText);
});

test('importMarkdown normalizes titles and tags under existing rules', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'empty.json'), new Workspace());
  const normalized = workspaceWith([{ id: 'a', title: 'A', body: 'body text', tags: ['x'] }]).exportJSON();
  const pkg = buildPackage(normalized);
  fs.mkdirSync(path.join(cwd, 'pkg'));
  // Manifest carries untrimmed casing and equivalent duplicate tags; the
  // rebuilt snapshot must normalize them and still match the bound checksum.
  const raw = structuredClone(pkg.manifest);
  raw.documents[0].title = '  A   ';
  raw.documents[0].tags = [' X ', 'x', 'X'];
  fs.writeFileSync(path.join(cwd, 'pkg', 'manifest.json'), `${JSON.stringify(raw)}\n`);
  fs.writeFileSync(path.join(cwd, 'pkg', 'a.md'), pkg.files.get('a.md'));

  const { snapshot } = importMarkdown(
    path.join(cwd, 'empty.json'), path.join(cwd, 'pkg'), path.join(cwd, 'out.json'), 'replace',
  );
  assert.equal(snapshot.checksum, normalized.checksum);
  assert.equal(snapshot.documents[0].title, 'A');
  assert.deepEqual(snapshot.documents[0].tags, ['x']);
});

test('importMarkdown dry run validates fully but creates or changes nothing', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith(sampleDocuments));
  writeSnapshot(path.join(cwd, 'empty.json'), new Workspace());
  exportMarkdown(path.join(cwd, 'snap.json'), path.join(cwd, 'pkg'));
  const output = path.join(cwd, 'missing.json');

  const { snapshot } = importMarkdown(
    path.join(cwd, 'empty.json'), path.join(cwd, 'pkg'), output, 'replace', true,
  );
  assert.equal(snapshot.checksum, workspaceWith(sampleDocuments).exportJSON().checksum);
  assert.ok(!fs.existsSync(output));

  fs.writeFileSync(output, 'keep\n');
  importMarkdown(path.join(cwd, 'empty.json'), path.join(cwd, 'pkg'), output, 'replace', true);
  assert.equal(fs.readFileSync(output, 'utf8'), 'keep\n');
});

test('export replaces the target directory wholesale, leaving no stale files', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([{ id: 'a', title: 'A', body: 'b', tags: [] }]));
  const target = path.join(cwd, 'pkg');
  fs.mkdirSync(target);
  fs.writeFileSync(path.join(target, 'stale.txt'), 'old');
  fs.mkdirSync(path.join(target, 'olddir'));

  exportMarkdown(path.join(cwd, 'snap.json'), target);
  assert.deepEqual(fs.readdirSync(target).sort(), ['a.md', 'manifest.json']);
});

test('retrying after a killed export finishes a complete fresh package', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith(sampleDocuments));
  const target = path.join(cwd, 'pkg');
  fs.mkdirSync(`${target}.export.tmp`);
  fs.writeFileSync(`${target}.export.tmp/partial.md`, 'partial');
  fs.mkdirSync(`${target}.old.tmp`);

  const { manifestText } = exportMarkdown(path.join(cwd, 'snap.json'), target);
  assert.ok(!fs.existsSync(`${target}.export.tmp`));
  assert.ok(!fs.existsSync(`${target}.old.tmp`));
  assert.equal(fs.readFileSync(path.join(target, 'manifest.json'), 'utf8'), manifestText);
  for (const document of sampleDocuments) {
    assert.ok(fs.existsSync(path.join(target, `${document.id}.md`)));
  }
});

test('export rejects an un-encodable snapshot without touching an existing target', () => {
  const cwd = tempDir();
  const snapshot = snapshotFromDocuments([{ id: 'a', title: 'A', body: 'x \uD800', tags: [] }]);
  fs.writeFileSync(path.join(cwd, 'snap.json'), `${JSON.stringify(snapshot)}\n`);
  const target = path.join(cwd, 'pkg');
  fs.mkdirSync(target);
  fs.writeFileSync(path.join(target, 'untouched'), 'yes');
  assert.throws(
    () => exportMarkdown(path.join(cwd, 'snap.json'), target),
    (error) => error.code === 'INVALID_MARKDOWN',
  );
  assert.equal(fs.readFileSync(path.join(target, 'untouched'), 'utf8'), 'yes');
});

test('export refuses a source inside the staging or backup location and changes nothing', () => {
  const snapshotTree = (root) => {
    const walk = (directory) => {
      const entries = {};
      for (const name of fs.readdirSync(directory).sort()) {
        const full = path.join(directory, name);
        const stats = fs.lstatSync(full);
        if (stats.isSymbolicLink()) entries[name] = `<symlink:${fs.readlinkSync(full)}>`;
        else if (stats.isDirectory()) entries[name] = walk(full);
        else entries[name] = fs.readFileSync(full);
      }
      return entries;
    };
    return walk(root);
  };

  const variants = [
    (dir) => {
      // Leftover staging directory from a killed previous export.
      const stage = path.join(dir, 'pkg.export.tmp');
      fs.mkdirSync(stage);
      fs.writeFileSync(path.join(stage, 'partial.md'), 'partial');
      fs.writeFileSync(path.join(stage, 'snap.json'), fs.readFileSync(path.join(dir, 'snap.json')));
      return { source: path.join(stage, 'snap.json'), output: path.join(dir, 'pkg') };
    },
    (dir) => {
      // Leftover backup directory holding the source snapshot.
      const backup = path.join(dir, 'pkg.old.tmp');
      fs.mkdirSync(backup);
      fs.writeFileSync(path.join(backup, 'snap.json'), fs.readFileSync(path.join(dir, 'snap.json')));
      return { source: path.join(backup, 'snap.json'), output: path.join(dir, 'pkg') };
    },
    (dir) => {
      // The scratch location itself is the snapshot file (exact equality).
      const stage = path.join(dir, 'pkg.export.tmp');
      fs.writeFileSync(stage, fs.readFileSync(path.join(dir, 'snap.json')));
      return { source: stage, output: path.join(dir, 'pkg') };
    },
  ];
  for (let index = 0; index < variants.length; index += 1) {
    const cwd = tempDir();
    writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([{ id: 'a', title: 'A', body: 'b', tags: [] }]));
    // A pre-existing target with content the rejection must leave in place.
    fs.mkdirSync(path.join(cwd, 'pkg'));
    fs.writeFileSync(path.join(cwd, 'pkg', 'untouched'), 'yes');

    const { source, output } = variants[index](cwd);
    const before = snapshotTree(cwd);
    assert.throws(
      () => exportMarkdown(source, output),
      (error) => error.code === 'INVALID_OPTIONS',
      `variant ${index}`,
    );
    // No path under cwd was deleted, moved, created, or rewritten.
    assert.deepEqual(snapshotTree(cwd), before, `variant ${index}`);
  }
});

test('export refuses a source equal to the output path even when the target already exists', () => {
  const cwd = tempDir();
  const workspace = workspaceWith([{ id: 'a', title: 'A', body: 'b', tags: [] }]);
  // The output path is itself a regular file holding the source snapshot.
  const samePath = path.join(cwd, 'snapshot-and-target.json');
  fs.writeFileSync(samePath, `${JSON.stringify(workspace.exportJSON())}\n`);
  const before = fs.readFileSync(samePath);

  assert.throws(
    () => exportMarkdown(samePath, samePath),
    (error) => error.code === 'INVALID_OPTIONS',
  );
  assert.deepEqual(fs.readFileSync(samePath), before);
  assert.ok(!fs.existsSync(`${samePath}.export.tmp`));
  assert.ok(!fs.existsSync(`${samePath}.old.tmp`));
});

test('staging/backup overlap is detected through symlinked parents before the output exists', () => {
  const cwd = tempDir();
  const workspace = workspaceWith([{ id: 'a', title: 'A', body: 'b', tags: [] }]);
  const scratches = path.join(cwd, 'scratches');
  fs.mkdirSync(scratches);
  fs.mkdirSync(path.join(scratches, 'pkg.export.tmp'));
  writeSnapshot(path.join(scratches, 'pkg.export.tmp', 's.json'), workspace);
  fs.symlinkSync('scratches', path.join(cwd, 'alias'));

  // Textually different path, same real scratch location; pkg/ does not exist yet.
  assert.throws(
    () => exportMarkdown(
      path.join(cwd, 'alias', 'pkg.export.tmp', 's.json'),
      path.join(cwd, 'scratches', 'pkg'),
    ),
    (error) => error.code === 'INVALID_OPTIONS',
  );
  assert.deepEqual(
    fs.readFileSync(path.join(scratches, 'pkg.export.tmp', 's.json'), 'utf8'),
    `${JSON.stringify(workspace.exportJSON())}\n`,
  );
  assert.ok(!fs.existsSync(path.join(scratches, 'pkg')));
  assert.ok(!fs.existsSync(path.join(scratches, 'pkg.old.tmp')));
});

test('snapshots merely named like scratch locations export normally', () => {
  const cwd = tempDir();
  const workspace = workspaceWith([{ id: 'a', title: 'A', body: 'b', tags: [] }]);

  // A sibling directory whose name shares the staging suffix.
  fs.mkdirSync(path.join(cwd, 'my-pkg.export.tmp'));
  writeSnapshot(path.join(cwd, 'my-pkg.export.tmp', 's.json'), workspace);
  // A sibling file whose name contains the backup wording.
  writeSnapshot(path.join(cwd, 'pkg.old.tmp.maybe.json'), workspace);

  exportMarkdown(path.join(cwd, 'my-pkg.export.tmp', 's.json'), path.join(cwd, 'pkg'));
  assert.deepEqual(fs.readdirSync(path.join(cwd, 'pkg')).sort(), ['a.md', 'manifest.json']);
  assert.deepEqual(
    fs.readFileSync(path.join(cwd, 'my-pkg.export.tmp', 's.json'), 'utf8'),
    `${JSON.stringify(workspace.exportJSON())}\n`,
  );

  const second = path.join(cwd, 'pkg2');
  exportMarkdown(path.join(cwd, 'pkg.old.tmp.maybe.json'), second);
  assert.deepEqual(fs.readdirSync(second).sort(), ['a.md', 'manifest.json']);
  assert.ok(fs.existsSync(path.join(cwd, 'pkg.old.tmp.maybe.json')));
});

test('export refuses a source nested under a dot-dot name inside the output or scratch locations', () => {
  const snapshotTree = (root) => {
    const walk = (directory) => {
      const entries = {};
      for (const name of fs.readdirSync(directory).sort()) {
        const full = path.join(directory, name);
        const stats = fs.lstatSync(full);
        if (stats.isSymbolicLink()) entries[name] = `<symlink:${fs.readlinkSync(full)}>`;
        else if (stats.isDirectory()) entries[name] = walk(full);
        else entries[name] = fs.readFileSync(full);
      }
      return entries;
    };
    return walk(root);
  };

  const variants = [
    // Valid snapshot placed in <output>/..notes, then the output is the target.
    (dir) => {
      fs.mkdirSync(path.join(dir, 'pkg', '..notes'), { recursive: true });
      return { source: path.join(dir, 'pkg', '..notes', 'snap.json'), output: path.join(dir, 'pkg') };
    },
    // Nested deeper than the dot-dot-named component.
    (dir) => {
      fs.mkdirSync(path.join(dir, 'pkg', '..notes', 'a', 'b'), { recursive: true });
      return { source: path.join(dir, 'pkg', '..notes', 'a', 'b', 's.json'), output: path.join(dir, 'pkg') };
    },
    // Leftover staging directory holding the source under a dot-dot name.
    (dir) => {
      const stage = path.join(dir, 'pkg.export.tmp');
      fs.mkdirSync(path.join(stage, '..notes'), { recursive: true });
      return { source: path.join(stage, '..notes', 'snap.json'), output: path.join(dir, 'pkg') };
    },
    // Leftover backup directory holding the source under a dot-dot name.
    (dir) => {
      const backup = path.join(dir, 'pkg.old.tmp');
      fs.mkdirSync(path.join(backup, '..notes', 'nested'), { recursive: true });
      return { source: path.join(backup, '..notes', 'nested', 'snap.json'), output: path.join(dir, 'pkg') };
    },
  ];
  for (let index = 0; index < variants.length; index += 1) {
    const cwd = tempDir();
    writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([{ id: 'a', title: 'A', body: 'b', tags: [] }]));
    // A pre-existing target with content the rejection must leave in place.
    fs.mkdirSync(path.join(cwd, 'pkg'), { recursive: true });
    fs.writeFileSync(path.join(cwd, 'pkg', 'untouched'), 'yes');

    const { source, output } = variants[index](cwd);
    fs.writeFileSync(source, fs.readFileSync(path.join(cwd, 'snap.json')));
    const before = snapshotTree(cwd);
    assert.throws(
      () => exportMarkdown(source, output),
      (error) => error.code === 'INVALID_OPTIONS',
      `variant ${index}`,
    );
    // No path under cwd was deleted, moved, created, or rewritten.
    assert.deepEqual(snapshotTree(cwd), before, `variant ${index}`);
    assert.ok(fs.existsSync(source), `variant ${index}`);
  }
});

test('a dot-dot named directory overlapping the output is detected through a symlinked parent', () => {
  const cwd = tempDir();
  const workspace = workspaceWith([{ id: 'a', title: 'A', body: 'b', tags: [] }]);
  const realOut = path.join(cwd, 'realout');
  fs.mkdirSync(path.join(realOut, '..notes', 'deep'), { recursive: true });
  writeSnapshot(path.join(realOut, '..notes', 'deep', 's.json'), workspace);
  fs.symlinkSync('realout', path.join(cwd, 'alias'));

  // Source reached through the aliased parent, output given by its real path.
  assert.throws(
    () => exportMarkdown(path.join(cwd, 'alias', '..notes', 'deep', 's.json'), realOut),
    (error) => error.code === 'INVALID_OPTIONS',
  );
  // Output reached through the alias, source given by its real path.
  assert.throws(
    () => exportMarkdown(path.join(realOut, '..notes', 'deep', 's.json'), path.join(cwd, 'alias')),
    (error) => error.code === 'INVALID_OPTIONS',
  );
  assert.deepEqual(
    fs.readFileSync(path.join(realOut, '..notes', 'deep', 's.json'), 'utf8'),
    `${JSON.stringify(workspace.exportJSON())}\n`,
  );
  assert.ok(!fs.existsSync(path.join(realOut, 'a.md')));
});

test('path conflict inside a dot-dot name is reported before an unreadable or invalid source', () => {
  const cwd = tempDir();
  const target = path.join(cwd, 'pkg');

  // Invalid snapshot content: the path conflict still wins.
  fs.mkdirSync(path.join(target, '..notes'), { recursive: true });
  fs.writeFileSync(path.join(target, '..notes', 'bad.json'), '{ not valid json');
  assert.throws(
    () => exportMarkdown(path.join(target, '..notes', 'bad.json'), target),
    (error) => error.code === 'INVALID_OPTIONS',
  );

  // A source that does not even exist: the path conflict still wins and the
  // missing output location is never created.
  assert.throws(
    () => exportMarkdown(path.join(target, '..notes', 'missing.json'), target),
    (error) => error.code === 'INVALID_OPTIONS',
  );
  assert.deepEqual(fs.readdirSync(target), ['..notes']);
  assert.ok(!fs.existsSync(path.join(cwd, 'pkg.export.tmp')));
  assert.ok(!fs.existsSync(path.join(cwd, 'pkg.old.tmp')));
});

test('a source in an adjacent dot-dot named directory exports normally and is retained', () => {
  const cwd = tempDir();
  const workspace = workspaceWith([{ id: 'a', title: 'A', body: 'b', tags: [] }]);

  // Sibling ..notes directory next to the output: no overlap, exports fine.
  fs.mkdirSync(path.join(cwd, '..notes'), { recursive: true });
  const adjacent = path.join(cwd, '..notes', 'snap.json');
  writeSnapshot(adjacent, workspace);
  exportMarkdown(adjacent, path.join(cwd, 'pkg'));
  assert.deepEqual(fs.readdirSync(path.join(cwd, 'pkg')).sort(), ['a.md', 'manifest.json']);
  assert.deepEqual(
    fs.readFileSync(adjacent, 'utf8'),
    `${JSON.stringify(workspace.exportJSON())}\n`,
  );

  // A dot-dot name nested inside a merely similarly named sibling directory.
  const second = path.join(cwd, 'scratch');
  fs.mkdirSync(path.join(second, '..notes'), { recursive: true });
  const other = path.join(second, '..notes', 'snap.json');
  writeSnapshot(other, workspace);
  exportMarkdown(other, path.join(cwd, 'pkg2'));
  assert.deepEqual(fs.readdirSync(path.join(cwd, 'pkg2')).sort(), ['a.md', 'manifest.json']);
  assert.ok(fs.existsSync(other));
});

test('CLI export-md fails with status 1 when the source sits in the staging directory', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([{ id: 'a', title: 'A', body: 'b', tags: [] }]));
  fs.mkdirSync(path.join(cwd, 'pkg.export.tmp'));
  const source = path.join(cwd, 'pkg.export.tmp', 's.json');
  fs.writeFileSync(source, fs.readFileSync(path.join(cwd, 'snap.json')));

  const { status, stdout, stderr } = runCli(
    ['export-md', path.join('pkg.export.tmp', 's.json'), 'pkg'],
    cwd,
  );
  assert.equal(status, 1);
  assert.equal(stdout, '');
  const lines = stderr.split('\n');
  assert.equal(lines.length, 2);
  assert.equal(lines[1], '');
  assert.equal(JSON.parse(lines[0]).code, 'INVALID_OPTIONS');
  assert.deepEqual(fs.readFileSync(source), fs.readFileSync(path.join(cwd, 'snap.json')));
  assert.ok(!fs.existsSync(path.join(cwd, 'pkg')));
});

test('CLI export-md rejects a source in <output>/..notes with one INVALID_OPTIONS line', () => {
  const cwd = tempDir();
  const workspace = workspaceWith([{ id: 'a', title: 'A', body: 'b', tags: [] }]);
  fs.mkdirSync(path.join(cwd, 'pkg', '..notes'), { recursive: true });
  const source = path.join(cwd, 'pkg', '..notes', 's.json');
  writeSnapshot(source, workspace);

  const { status, stdout, stderr } = runCli(
    ['export-md', path.join('pkg', '..notes', 's.json'), 'pkg'],
    cwd,
  );
  assert.equal(status, 1);
  assert.equal(stdout, '');
  const lines = stderr.split('\n');
  assert.equal(lines.length, 2);
  assert.equal(lines[1], '');
  assert.equal(JSON.parse(lines[0]).code, 'INVALID_OPTIONS');
  assert.deepEqual(
    fs.readFileSync(source, 'utf8'),
    `${JSON.stringify(workspace.exportJSON())}\n`,
  );
  assert.deepEqual(fs.readdirSync(path.join(cwd, 'pkg')), ['..notes']);
  assert.ok(!fs.existsSync(path.join(cwd, 'pkg.export.tmp')));
  assert.ok(!fs.existsSync(path.join(cwd, 'pkg.old.tmp')));
});

test('path options are compared by real location', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([{ id: 'a', title: 'A', body: 'b', tags: [] }]));
  writeSnapshot(path.join(cwd, 'empty.json'), new Workspace());

  // Output directory containing the source snapshot (through a symlinked alias).
  const dataDir = path.join(cwd, 'data');
  fs.mkdirSync(dataDir);
  fs.writeFileSync(path.join(dataDir, 's.json'), fs.readFileSync(path.join(cwd, 'snap.json')));
  fs.symlinkSync('data', path.join(cwd, 'link'));
  assert.throws(
    () => exportMarkdown(path.join(cwd, 'link', 's.json'), dataDir),
    (error) => error.code === 'INVALID_OPTIONS',
  );

  // Import output inside the package directory through an aliased path.
  exportMarkdown(path.join(cwd, 'snap.json'), path.join(cwd, 'pkg'));
  assert.throws(
    () => importMarkdown(
      path.join(cwd, 'empty.json'), path.join(cwd, 'pkg'), path.join(cwd, 'pkg', 'out.json'), 'replace',
    ),
    (error) => error.code === 'INVALID_OPTIONS',
  );

  // A symlinked ancestor of a nonexistent target leaf is allowed; only the
  // leaf directory itself being a symlink is rejected.
  fs.mkdirSync(path.join(cwd, 'deep', 'real'), { recursive: true });
  fs.symlinkSync('real', path.join(cwd, 'deep', 'r'));
  exportMarkdown(path.join(cwd, 'snap.json'), path.join(cwd, 'deep', 'r', 'pkg'));
  assert.ok(fs.existsSync(path.join(cwd, 'deep', 'real', 'pkg', 'manifest.json')));
});

test('symlink targets and symlink/structural package entries are refused', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([{ id: 'a', title: 'A', body: 'b', tags: [] }]));
  writeSnapshot(path.join(cwd, 'empty.json'), new Workspace());
  exportMarkdown(path.join(cwd, 'snap.json'), path.join(cwd, 'pkg'));

  fs.mkdirSync(path.join(cwd, 'real'));
  fs.symlinkSync('real', path.join(cwd, 'dlink'));
  assert.throws(
    () => exportMarkdown(path.join(cwd, 'snap.json'), path.join(cwd, 'dlink')),
    (error) => error.code === 'INVALID_OPTIONS',
  );

  fs.symlinkSync('pkg', path.join(cwd, 'plink'));
  assert.throws(
    () => importMarkdown(
      path.join(cwd, 'empty.json'), path.join(cwd, 'plink'), path.join(cwd, 'x.json'), 'replace',
    ),
    (error) => error.code === 'INVALID_MARKDOWN',
  );

  const withSymlink = path.join(cwd, 'pkg-sym');
  fs.cpSync(path.join(cwd, 'pkg'), withSymlink, { recursive: true });
  fs.symlinkSync('a.md', path.join(withSymlink, 'evil.md'));
  assert.throws(
    () => importMarkdown(
      path.join(cwd, 'empty.json'), withSymlink, path.join(cwd, 'x.json'), 'replace',
    ),
    (error) => error.code === 'INVALID_MARKDOWN',
  );

  const withDir = path.join(cwd, 'pkg-dir');
  fs.cpSync(path.join(cwd, 'pkg'), withDir, { recursive: true });
  fs.mkdirSync(path.join(withDir, 'sub'));
  assert.throws(
    () => importMarkdown(
      path.join(cwd, 'empty.json'), withDir, path.join(cwd, 'x.json'), 'replace',
    ),
    (error) => error.code === 'INVALID_MARKDOWN',
  );
});

test('read failures surface as IO_ERROR without changing inputs or outputs', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'empty.json'), new Workspace());
  assert.throws(
    () => exportMarkdown(path.join(cwd, 'missing.json'), path.join(cwd, 'pkg')),
    (error) => error.code === 'IO_ERROR',
  );
  assert.throws(
    () => importMarkdown(
      path.join(cwd, 'empty.json'), path.join(cwd, 'no-pkg'), path.join(cwd, 'x.json'), 'replace',
    ),
    (error) => error.code === 'IO_ERROR',
  );
});

// ---- CLI contract ----------------------------------------------------------

test('export-md prints exactly one manifest line and writes the package', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith(sampleDocuments));
  const { status, stdout, stderr } = runCli(['export-md', 'snap.json', 'pkg'], cwd);
  assert.equal(status, 0);
  assert.equal(stderr, '');
  const lines = stdout.split('\n');
  assert.equal(lines.length, 2);
  assert.equal(lines[1], '');
  const printed = JSON.parse(lines[0]);
  assert.deepEqual(printed, JSON.parse(fs.readFileSync(path.join(cwd, 'pkg', 'manifest.json'), 'utf8')));
  assert.equal(printed.checksum, workspaceWith(sampleDocuments).exportJSON().checksum);
});

test('import-md replace roundtrips byte-for-byte and merge keeps base semantics', () => {
  const cwd = tempDir();
  const original = workspaceWith(sampleDocuments);
  writeSnapshot(path.join(cwd, 'snap.json'), original);
  writeSnapshot(path.join(cwd, 'empty.json'), new Workspace());
  runCli(['export-md', 'snap.json', 'pkg'], cwd);

  const replaced = runCli(['import-md', 'empty.json', 'pkg', 'out.json', 'replace'], cwd);
  assert.equal(replaced.status, 0);
  const printed = JSON.parse(replaced.stdout.trim());
  assert.deepEqual(printed, original.exportJSON());
  assert.equal(fs.readFileSync(path.join(cwd, 'out.json'), 'utf8'), replaced.stdout);

  const base = workspaceWith([{ id: 'base-doc', title: 'Base', body: 'see [[welcome]]', tags: ['b'] }]);
  writeSnapshot(path.join(cwd, 'base.json'), base);
  const merged = runCli(['import-md', 'base.json', 'pkg', 'merged.json', 'merge'], cwd);
  assert.equal(merged.status, 0);
  assert.deepEqual(
    JSON.parse(merged.stdout.trim()).documents.map((d) => d.id),
    ['a.b', 'architecture', 'base-doc', 'welcome'],
  );
});

test('import-md --dry-run prints the projection without creating the output', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith(sampleDocuments));
  writeSnapshot(path.join(cwd, 'empty.json'), new Workspace());
  runCli(['export-md', 'snap.json', 'pkg'], cwd);

  const { status, stderr } = runCli(['import-md', 'empty.json', 'pkg', 'preview.json', 'replace', '--dry-run'], cwd);
  assert.equal(status, 0);
  assert.equal(stderr, '');
  assert.ok(!fs.existsSync(path.join(cwd, 'preview.json')));
});

test('import-md can overwrite the base snapshot', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith(sampleDocuments));
  writeSnapshot(path.join(cwd, 'empty.json'), new Workspace());
  runCli(['export-md', 'snap.json', 'pkg'], cwd);
  const { status } = runCli(['import-md', 'empty.json', 'pkg', 'empty.json', 'replace'], cwd);
  assert.equal(status, 0);
  assert.deepEqual(
    JSON.parse(fs.readFileSync(path.join(cwd, 'empty.json'), 'utf8')).documents.map((d) => d.id),
    sampleDocuments.map((d) => d.id).sort(),
  );
});

test('merge conflicts return IMPORT_CONFLICT with sorted ids and preserve the output', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith([
    { id: 'welcome', title: '欢迎使用', body: 'changed body', tags: ['intro'] },
  ]));
  writeSnapshot(path.join(cwd, 'source.json'), workspaceWith(sampleDocuments));
  runCli(['export-md', 'source.json', 'pkg'], cwd);
  fs.writeFileSync(path.join(cwd, 'out.json'), 'previous\n');

  const { status, stdout, stderr } = runCli(['import-md', 'snap.json', 'pkg', 'out.json', 'merge'], cwd);
  assert.equal(status, 1);
  assert.equal(stdout, '');
  const payload = JSON.parse(stderr.trim());
  assert.equal(payload.code, 'IMPORT_CONFLICT');
  assert.deepEqual(payload.ids, ['welcome']);
  assert.equal(fs.readFileSync(path.join(cwd, 'out.json'), 'utf8'), 'previous\n');
});

const CLI_FAILURES = [
  ['bad mode', ['import-md', 'empty.json', 'pkg', 'o.json', 'upsert'], 'INVALID_OPTIONS'],
  ['unknown flag', ['export-md', 'snap.json', 'pkg', '--nope'], 'INVALID_OPTIONS'],
  ['export dry-run flag', ['export-md', 'snap.json', 'pkg', '--dry-run'], 'INVALID_OPTIONS'],
  ['missing positional', ['import-md', 'empty.json', 'pkg', 'merge'], 'INVALID_OPTIONS'],
  ['unreadable snapshot', ['export-md', 'nope.json', 'pkg2'], 'IO_ERROR'],
  ['unreadable package', ['import-md', 'empty.json', 'nope-pkg', 'o.json', 'replace'], 'IO_ERROR'],
  ['output inside package', ['import-md', 'empty.json', 'pkg', 'pkg/o.json', 'replace'], 'INVALID_OPTIONS'],
];

test('CLI failures emit one stderr JSON line, empty stdout, exit 1', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith(sampleDocuments));
  writeSnapshot(path.join(cwd, 'empty.json'), new Workspace());
  runCli(['export-md', 'snap.json', 'pkg'], cwd);
  for (const [label, args, code] of CLI_FAILURES) {
    const result = runCli(args, cwd);
    assert.equal(result.status, 1, label);
    assert.equal(result.stdout, '', label);
    const lines = result.stderr.split('\n');
    assert.equal(lines.length, 2, label);
    assert.equal(lines[1], '', label);
    assert.equal(JSON.parse(lines[0]).code, code, label);
  }
});

test('corrupt packages fail with INVALID_MARKDOWN and leave the output untouched', () => {
  const cwd = tempDir();
  writeSnapshot(path.join(cwd, 'snap.json'), workspaceWith(sampleDocuments));
  writeSnapshot(path.join(cwd, 'empty.json'), new Workspace());
  runCli(['export-md', 'snap.json', 'pkg'], cwd);

  const variants = [
    (dir) => fs.appendFileSync(path.join(dir, 'welcome.md'), 'tampered'),
    (dir) => fs.writeFileSync(path.join(dir, 'stray.md'), 'x'),
    (dir) => fs.rmSync(path.join(dir, 'architecture.md')),
    (dir) => fs.mkdirSync(path.join(dir, 'sub')),
    (dir) => fs.symlinkSync('welcome.md', path.join(dir, 'link.md')),
    (dir) => fs.writeFileSync(path.join(dir, 'manifest.json'), '{broken'),
  ];
  let index = 0;
  for (const mutate of variants) {
    const dir = path.join(cwd, `bad-${index}`);
    fs.cpSync(path.join(cwd, 'pkg'), dir, { recursive: true });
    mutate(dir);
    const output = path.join(cwd, `out-${index}.json`);
    fs.writeFileSync(output, 'sentinel\n');
    const result = runCli(['import-md', 'empty.json', dir, output, 'replace'], cwd);
    assert.equal(result.status, 1, `variant ${index}`);
    assert.equal(result.stdout, '', `variant ${index}`);
    assert.equal(JSON.parse(result.stderr.trim()).code, 'INVALID_MARKDOWN', `variant ${index}`);
    assert.equal(fs.readFileSync(output, 'utf8'), 'sentinel\n', `variant ${index}`);
    index += 1;
  }
});
