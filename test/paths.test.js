import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { realLocation } from '../src/paths.js';

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-realloc-'));
}

test('realLocation normalizes lexical aliases', () => {
  const cwd = tempDir();
  fs.mkdirSync(path.join(cwd, 'dir'));
  assert.equal(
    realLocation(path.join(cwd, 'dir', '..', 'history.json')),
    path.join(cwd, 'history.json'),
  );
  assert.equal(realLocation(path.join(cwd, '.', 'a', 'b')), path.join(cwd, 'a', 'b'));
});

test('realLocation resolves symlinked parents with nonexistent leaves', () => {
  const cwd = tempDir();
  fs.mkdirSync(path.join(cwd, 'real'));
  fs.symlinkSync('real', path.join(cwd, 'alias'));
  assert.equal(
    realLocation(path.join(cwd, 'alias', 'history.json')),
    path.join(fs.realpathSync(path.join(cwd, 'real')), 'history.json'),
  );
  assert.equal(
    realLocation(path.join(cwd, 'alias', 'history.json.bak')),
    path.join(fs.realpathSync(path.join(cwd, 'real')), 'history.json.bak'),
  );
});

test('realLocation follows dangling symlink files to their target location', () => {
  const cwd = tempDir();
  fs.symlinkSync('history.json', path.join(cwd, 'link.json'));
  assert.equal(
    realLocation(path.join(cwd, 'link.json')),
    path.join(cwd, 'history.json'),
  );
  // An absolute dangling link resolves the same way.
  fs.symlinkSync(path.join(cwd, 'real', 'state.json'), path.join(cwd, 'abs-link.json'));
  assert.equal(
    realLocation(path.join(cwd, 'abs-link.json')),
    path.join(cwd, 'real', 'state.json'),
  );
});

test('realLocation reports IO_ERROR for a cyclic symbolic link', () => {
  const cwd = tempDir();
  fs.symlinkSync('b', path.join(cwd, 'a'));
  fs.symlinkSync('a', path.join(cwd, 'b'));
  assert.throws(
    () => realLocation(path.join(cwd, 'a')),
    (error) => error.code === 'IO_ERROR',
  );
});

test('realLocation leaves a lexical tail beyond the last existing directory', () => {
  const cwd = tempDir();
  // No 'deep' directory at all: resolution falls back to the resolved root.
  assert.equal(
    realLocation(path.join(cwd, 'deep', 'nested', 'snap.json')),
    path.join(fs.realpathSync(cwd), 'deep', 'nested', 'snap.json'),
  );
});
