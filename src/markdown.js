import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { SnapshotError, snapshotFromDocuments } from './workspace.js';

const MANIFEST_NAME = 'manifest.json';
const MANIFEST_KEYS = ['version', 'documents', 'checksum'];
const ENTRY_KEYS = ['id', 'title', 'tags', 'file', 'sha256'];
const CHECKSUM_PATTERN = /^[0-9a-f]{64}$/u;
const ID_PATTERN = /^[a-z0-9][a-z0-9._-]*$/u;
const PACKAGE_VERSION = 1;

function compareCodePoints(a, b) {
  const left = Array.from(a, (char) => char.codePointAt(0));
  const right = Array.from(b, (char) => char.codePointAt(0));
  for (let i = 0; i < Math.min(left.length, right.length); i += 1) {
    if (left[i] !== right[i]) return left[i] - right[i];
  }
  return left.length - right.length;
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function sameKeys(object, expected) {
  const keys = Object.keys(object);
  return keys.length === expected.length && expected.every((key) => keys.includes(key));
}

function normalizeTags(tags) {
  return [...new Set(tags.map((tag) => tag.trim().toLowerCase()).filter(Boolean))].sort();
}

// A JS string can carry unpaired surrogates that Node's UTF-8 encoder silently
// replaces with U+FFFD, so a body would not survive a round trip byte-for-byte.
// Reject those bodies instead of writing a lossy file.
function assertEncodable(body, id) {
  const encoded = Buffer.from(body, 'utf8');
  if (encoded.toString('utf8') !== body) {
    throw new SnapshotError('INVALID_MARKDOWN', `document ${id} body cannot be losslessly encoded as UTF-8`);
  }
}

function decodeUtf8(bytes, name) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new SnapshotError('INVALID_MARKDOWN', `${name} is not valid UTF-8`);
  }
}

function readBytes(file) {
  try {
    return fs.readFileSync(file);
  } catch (error) {
    throw new SnapshotError('IO_ERROR', `cannot read file ${file}: ${error.message}`);
  }
}

// Reads a file that is part of the package. A file that is simply absent is a
// package integrity problem (INVALID_MARKDOWN); any other read failure is an
// I/O error.
function readPackageFile(dir, name) {
  const file = path.join(dir, name);
  try {
    return fs.readFileSync(file);
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw new SnapshotError('INVALID_MARKDOWN', `missing package file: ${name}`);
    }
    throw new SnapshotError('IO_ERROR', `cannot read package file ${name}: ${error.message}`);
  }
}

// Exports a version-1 markdown package for an already validated snapshot.
//
// The package is assembled in a sibling staging directory and only installed
// once every byte has been written: the existing target is then removed whole
// and the staging directory renamed into place, so a kill at any point leaves
// either the previous package or a complete new one, never a partial mix.
// Returns the manifest object that was written to manifest.json.
export function exportMarkdownPackage(snapshot, outputDir) {
  for (const document of snapshot.documents) {
    assertEncodable(document.body, document.id);
  }

  const parent = path.dirname(path.resolve(outputDir));
  const staging = path.join(
    parent,
    `.${path.basename(outputDir)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`,
  );

  try {
    fs.mkdirSync(staging);
    const entries = snapshot.documents.map((document) => {
      const file = `${document.id}.md`;
      const bytes = Buffer.from(document.body, 'utf8');
      fs.writeFileSync(path.join(staging, file), bytes);
      return {
        id: document.id,
        title: document.title,
        tags: [...document.tags],
        file,
        sha256: sha256(bytes),
      };
    });
    const manifest = { version: PACKAGE_VERSION, documents: entries, checksum: snapshot.checksum };
    fs.writeFileSync(path.join(staging, MANIFEST_NAME), `${JSON.stringify(manifest)}\n`, 'utf8');

    fs.rmSync(outputDir, { recursive: true, force: true });
    fs.renameSync(staging, outputDir);
    return manifest;
  } catch (error) {
    try {
      fs.rmSync(staging, { recursive: true, force: true });
    } catch {
      // best-effort cleanup of the staging directory
    }
    if (error instanceof SnapshotError) throw error;
    throw new SnapshotError('IO_ERROR', `cannot write markdown package to ${outputDir}: ${error.message}`);
  }
}

// Validates and reads a markdown package, returning a normalized snapshot
// object (version 1, documents sorted by id, checksum) ready for
// Workspace#importJSON. Every package rule is enforced here:
//
// - the input path is a directory and not a symbolic link;
// - the package contains only manifest.json and <id>.md regular files;
// - the manifest has exactly version, documents, checksum with the right types;
// - every document entry has exactly id, title, tags, file, sha256;
// - ids are unique, titles unique after normalization, files match <id>.md;
// - every body file is valid UTF-8 and its SHA-256 matches;
// - no files are missing or extra, and the rebuilt snapshot checksum matches.
//
// Only files inside the package directory are ever read.
export function importMarkdownPackage(inputDir) {
  let stat;
  try {
    stat = fs.lstatSync(inputDir);
  } catch (error) {
    throw new SnapshotError('IO_ERROR', `cannot read markdown package ${inputDir}: ${error.message}`);
  }
  if (stat.isSymbolicLink()) {
    throw new SnapshotError('INVALID_MARKDOWN', 'input directory must not be a symbolic link');
  }
  if (!stat.isDirectory()) {
    throw new SnapshotError('INVALID_MARKDOWN', 'input path is not a directory');
  }

  let names;
  try {
    names = fs.readdirSync(inputDir);
  } catch (error) {
    throw new SnapshotError('IO_ERROR', `cannot read markdown package ${inputDir}: ${error.message}`);
  }

  for (const name of names) {
    let entry;
    try {
      entry = fs.lstatSync(path.join(inputDir, name));
    } catch (error) {
      throw new SnapshotError('IO_ERROR', `cannot read package entry ${name}: ${error.message}`);
    }
    if (entry.isSymbolicLink()) {
      throw new SnapshotError('INVALID_MARKDOWN', `package entry must not be a symbolic link: ${name}`);
    }
    if (!entry.isFile()) {
      throw new SnapshotError('INVALID_MARKDOWN', `package entry must be a regular file: ${name}`);
    }
  }

  const manifestBytes = readPackageFile(inputDir, MANIFEST_NAME);
  const manifestText = decodeUtf8(manifestBytes, MANIFEST_NAME);
  let manifest;
  try {
    manifest = JSON.parse(manifestText);
  } catch {
    throw new SnapshotError('INVALID_MARKDOWN', 'manifest is not valid JSON');
  }
  if (!isPlainObject(manifest)) {
    throw new SnapshotError('INVALID_MARKDOWN', 'manifest must be an object');
  }
  if (!sameKeys(manifest, MANIFEST_KEYS)) {
    throw new SnapshotError('INVALID_MARKDOWN', 'manifest must contain exactly version, documents, and checksum');
  }
  if (manifest.version !== PACKAGE_VERSION) {
    throw new SnapshotError('INVALID_MARKDOWN', `unsupported manifest version: ${String(manifest.version)}`);
  }
  if (typeof manifest.checksum !== 'string') {
    throw new SnapshotError('INVALID_MARKDOWN', 'manifest checksum must be a string');
  }
  if (!Array.isArray(manifest.documents)) {
    throw new SnapshotError('INVALID_MARKDOWN', 'manifest documents must be an array');
  }

  const documents = [];
  const ids = new Set();
  const titles = new Set();
  manifest.documents.forEach((entry, index) => {
    const location = `manifest.documents[${index}]`;
    if (!isPlainObject(entry)) {
      throw new SnapshotError('INVALID_MARKDOWN', `${location} must be an object`);
    }
    if (!sameKeys(entry, ENTRY_KEYS)) {
      throw new SnapshotError('INVALID_MARKDOWN', `${location} must contain exactly id, title, tags, file, and sha256`);
    }
    if (typeof entry.id !== 'string' || !ID_PATTERN.test(entry.id)) {
      throw new SnapshotError('INVALID_MARKDOWN', `${location}.id must be a URL-safe lowercase identifier`);
    }
    if (typeof entry.title !== 'string' || !entry.title.trim()) {
      throw new SnapshotError('INVALID_MARKDOWN', `${location}.title must be a non-empty string`);
    }
    if (!Array.isArray(entry.tags) || entry.tags.some((tag) => typeof tag !== 'string')) {
      throw new SnapshotError('INVALID_MARKDOWN', `${location}.tags must be an array of strings`);
    }
    if (typeof entry.file !== 'string' || entry.file !== `${entry.id}.md`) {
      throw new SnapshotError('INVALID_MARKDOWN', `${location}.file must equal ${entry.id}.md`);
    }
    if (typeof entry.sha256 !== 'string' || !CHECKSUM_PATTERN.test(entry.sha256)) {
      throw new SnapshotError('INVALID_MARKDOWN', `${location}.sha256 must be a lowercase SHA-256 checksum`);
    }
    if (ids.has(entry.id)) {
      throw new SnapshotError('INVALID_MARKDOWN', `duplicate document id: ${entry.id}`);
    }
    ids.add(entry.id);

    const bytes = readPackageFile(inputDir, entry.file);
    if (sha256(bytes) !== entry.sha256) {
      throw new SnapshotError('INVALID_MARKDOWN', `sha256 mismatch for ${entry.file}`);
    }
    const body = decodeUtf8(bytes, entry.file);
    if (!body.trim()) {
      throw new SnapshotError('INVALID_MARKDOWN', `${entry.file} body must be a non-empty string`);
    }

    const document = {
      id: entry.id,
      title: entry.title.trim(),
      body,
      tags: normalizeTags(entry.tags),
    };
    if (titles.has(document.title)) {
      throw new SnapshotError('INVALID_MARKDOWN', `duplicate normalized title: ${document.title}`);
    }
    titles.add(document.title);
    documents.push(document);
  });

  const expectedFiles = new Set(documents.map((document) => `${document.id}.md`));
  expectedFiles.add(MANIFEST_NAME);
  for (const name of names) {
    if (!expectedFiles.has(name)) {
      throw new SnapshotError('INVALID_MARKDOWN', `unexpected file in package: ${name}`);
    }
  }
  if (names.length !== expectedFiles.size) {
    for (const file of expectedFiles) {
      if (!names.includes(file)) {
        throw new SnapshotError('INVALID_MARKDOWN', `missing package file: ${file}`);
      }
    }
  }

  const snapshot = snapshotFromDocuments(documents.sort(compareCodePoints));
  if (snapshot.checksum !== manifest.checksum) {
    throw new SnapshotError('INVALID_MARKDOWN', 'manifest checksum does not match the rebuilt snapshot');
  }
  return snapshot;
}
