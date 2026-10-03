import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { SnapshotError, Workspace, assertDocument, normalizeTags } from './workspace.js';

const PACKAGE_VERSION = 1;
const MANIFEST_FILE = 'manifest.json';
const MANIFEST_KEYS = ['version', 'documents', 'checksum'];
const ENTRY_KEYS = ['id', 'title', 'tags', 'file', 'sha256'];
const HEX_SHA256 = /^[0-9a-f]{64}$/u;

const fatalDecoder = new TextDecoder('utf-8', { fatal: true });

function sha256Bytes(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function invalidMarkdown(message) {
  return new SnapshotError('INVALID_MARKDOWN', message);
}

function ioError(message) {
  return new SnapshotError('IO_ERROR', message);
}

function sameKeys(object, expected) {
  const keys = Object.keys(object);
  return keys.length === expected.length && expected.every((key) => keys.includes(key));
}

function compareCodePoints(a, b) {
  const left = Array.from(a, (char) => char.codePointAt(0));
  const right = Array.from(b, (char) => char.codePointAt(0));
  for (let i = 0; i < Math.min(left.length, right.length); i += 1) {
    if (left[i] !== right[i]) return left[i] - right[i];
  }
  return left.length - right.length;
}

// Encodes a document body as raw UTF-8 bytes and proves the round trip is
// lossless. A body carrying unpaired surrogates (which JSON text can express
// via "\uD800" escapes) cannot be represented as standalone UTF-8, so it is
// rejected instead of silently turning into U+FFFD.
function encodeBody(body) {
  const bytes = Buffer.from(body, 'utf8');
  let decoded;
  try {
    decoded = fatalDecoder.decode(bytes);
  } catch {
    throw invalidMarkdown('document body cannot be encoded as UTF-8');
  }
  if (decoded !== body) throw invalidMarkdown('document body cannot be encoded as UTF-8 losslessly');
  return bytes;
}

// ---- Pure package build/parse ---------------------------------------------

// Builds the on-disk package for a validated version-1 snapshot (documents
// already normalized and code-point sorted, checksum matching).
export function buildPackage(snapshot) {
  const files = new Map();
  const entries = snapshot.documents.map((document) => {
    const name = `${document.id}.md`;
    files.set(name, encodeBody(document.body));
    return {
      id: document.id,
      title: document.title,
      tags: structuredClone(document.tags),
      file: name,
      sha256: sha256Bytes(files.get(name)),
    };
  });
  const manifest = { version: PACKAGE_VERSION, documents: entries, checksum: snapshot.checksum };
  const manifestText = `${JSON.stringify(manifest)}\n`;
  const manifestBytes = Buffer.from(manifestText, 'utf8');
  files.set(MANIFEST_FILE, manifestBytes);
  return { manifest, files, manifestText };
}

// Parses a raw manifest object and verifies every declared document file's
// bytes. Returns normalized, code-point-sorted entries carrying verified
// bodies, plus the manifest's bound snapshot checksum. Pure: never touches
// the file system.
export function parsePackage(manifestRaw, fileBytes) {
  if (!manifestRaw || typeof manifestRaw !== 'object' || Array.isArray(manifestRaw)) {
    throw invalidMarkdown('manifest must be a JSON object');
  }
  if (!sameKeys(manifestRaw, MANIFEST_KEYS)) {
    throw invalidMarkdown('manifest must contain exactly version, documents, and checksum');
  }
  const { version, documents, checksum } = manifestRaw;
  if (typeof version !== 'number' || version !== PACKAGE_VERSION) {
    throw invalidMarkdown(`unsupported manifest version: ${String(version)}`);
  }
  if (!Array.isArray(documents)) throw invalidMarkdown('manifest documents must be an array');
  if (typeof checksum !== 'string' || !HEX_SHA256.test(checksum)) {
    throw invalidMarkdown('manifest checksum must be a lowercase hex SHA-256');
  }

  const seenIds = new Set();
  const entries = [];
  documents.forEach((raw, index) => {
    const location = `documents[${index}]`;
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      throw invalidMarkdown(`${location} must be an object`);
    }
    if (!sameKeys(raw, ENTRY_KEYS)) {
      throw invalidMarkdown(`${location} must contain exactly id, title, tags, file, and sha256`);
    }
    const { id, title, tags, file, sha256 } = raw;
    if (typeof id !== 'string') throw invalidMarkdown(`${location}.id must be a string`);
    if (typeof title !== 'string') throw invalidMarkdown(`${location}.title must be a string`);
    if (typeof file !== 'string') throw invalidMarkdown(`${location}.file must be a string`);
    if (typeof sha256 !== 'string' || !HEX_SHA256.test(sha256)) {
      throw invalidMarkdown(`${location}.sha256 must be a lowercase hex SHA-256`);
    }
    if (!Array.isArray(tags) || tags.some((tag) => typeof tag !== 'string')) {
      throw invalidMarkdown(`${location}.tags must be an array of strings`);
    }
    if (seenIds.has(id)) throw invalidMarkdown(`duplicate document id: ${id}`);
    seenIds.add(id);
    if (file !== `${id}.md`) throw invalidMarkdown(`${location}.file must equal ${id}.md`);

    const bytes = fileBytes.get(file);
    if (bytes === undefined) throw invalidMarkdown(`missing package file: ${file}`);
    if (sha256Bytes(bytes) !== sha256) {
      throw invalidMarkdown(`sha256 mismatch for ${file}`);
    }
    let body;
    try {
      body = fatalDecoder.decode(bytes);
    } catch {
      throw invalidMarkdown(`illegal UTF-8 in package file: ${file}`);
    }
    try {
      assertDocument({ id, title, body, tags });
    } catch (error) {
      throw invalidMarkdown(`${location}: ${error.message}`);
    }
    entries.push({ id, title: title.trim(), body, tags: normalizeTags(tags), file, sha256 });
  });

  entries.sort((a, b) => compareCodePoints(a.id, b.id));
  const titles = new Set();
  for (const entry of entries) {
    if (titles.has(entry.title)) throw invalidMarkdown(`duplicate normalized title: ${entry.title}`);
    titles.add(entry.title);
  }

  const expectedFiles = new Set([MANIFEST_FILE, ...entries.map((entry) => entry.file)]);
  for (const name of fileBytes.keys()) {
    if (!expectedFiles.has(name)) throw invalidMarkdown(`unexpected package file: ${name}`);
  }
  return { entries, checksum };
}

// ---- Path helpers ----------------------------------------------------------

// Resolves symlinks of every existing path component, appending a nonexistent
// tail lexically, so aliased paths compare by their real on-disk location.
function realLocation(target) {
  let current = path.resolve(target);
  const tail = [];
  for (;;) {
    try {
      const real = fs.realpathSync(current);
      return tail.length === 0 ? real : path.join(real, ...tail.reverse());
    } catch (error) {
      if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') {
        throw ioError(`cannot resolve ${target}: ${error.message}`);
      }
      tail.push(path.basename(current));
      const parent = path.dirname(current);
      if (parent === current) return current;
      current = parent;
    }
  }
}

function isInside(candidate, directory) {
  const relative = path.relative(directory, candidate);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

// ---- File-system orchestration --------------------------------------------

function readSnapshotText(file) {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch (error) {
    throw ioError(`cannot read snapshot file ${file}: ${error.message}`);
  }
}

function stagingFile(file) {
  const directory = path.dirname(path.resolve(file));
  return path.join(directory, `.${path.basename(file)}.${process.pid}.tmp`);
}

function atomicWrite(file, content) {
  const temp = stagingFile(file);
  try {
    fs.writeFileSync(temp, content, 'utf8');
    fs.renameSync(temp, file);
  } catch (error) {
    try {
      fs.rmSync(temp, { force: true });
    } catch {
      // best-effort staging cleanup
    }
    throw ioError(`cannot write snapshot file ${file}: ${error.message}`);
  }
}

// Enforces the package directory's structural rules and returns its parsed
// contents. The directory itself must be a real directory (not a symlink);
// it may contain only regular files with legal names — no symlinks,
// subdirectories, devices, or other special entries.
function readPackageDirectory(directory) {
  let rootStats;
  try {
    rootStats = fs.lstatSync(directory);
  } catch (error) {
    throw ioError(`cannot read package directory ${directory}: ${error.message}`);
  }
  if (rootStats.isSymbolicLink()) throw invalidMarkdown('package directory must not be a symlink');
  if (!rootStats.isDirectory()) throw ioError(`package input is not a directory: ${directory}`);

  let names;
  try {
    names = fs.readdirSync(directory);
  } catch (error) {
    throw ioError(`cannot read package directory ${directory}: ${error.message}`);
  }
  if (!names.includes(MANIFEST_FILE)) throw invalidMarkdown(`missing package file: ${MANIFEST_FILE}`);

  const fileBytes = new Map();
  for (const name of names) {
    if (name === '' || name === '.' || name === '..' || name.includes('/') || name.includes('\\')) {
      throw invalidMarkdown(`illegal package file name: ${name}`);
    }
    const full = path.join(directory, name);
    let stats;
    try {
      stats = fs.lstatSync(full);
    } catch (error) {
      throw ioError(`cannot read package file ${name}: ${error.message}`);
    }
    if (stats.isSymbolicLink()) throw invalidMarkdown(`symlinks are not allowed in a package: ${name}`);
    if (stats.isDirectory()) throw invalidMarkdown(`subdirectories are not allowed in a package: ${name}`);
    if (!stats.isFile()) throw invalidMarkdown(`illegal package entry: ${name}`);
    try {
      fileBytes.set(name, fs.readFileSync(full));
    } catch (error) {
      throw ioError(`cannot read package file ${name}: ${error.message}`);
    }
  }

  let manifestRaw;
  try {
    manifestRaw = JSON.parse(fileBytes.get(MANIFEST_FILE).toString('utf8'));
  } catch {
    throw invalidMarkdown('manifest is not valid JSON');
  }
  return parsePackage(manifestRaw, fileBytes);
}

function removeQuiet(target) {
  try {
    fs.rmSync(target, { recursive: true, force: true });
  } catch {
    // best-effort cleanup
  }
}

// Exports a version-1 JSON snapshot file into a Markdown package directory.
// The package is materialized in a sibling staging directory and swapped into
// place with a single rename; fixed staging/backup names let a retry after a
// killed export finish a complete package with no stale files left behind.
export function exportMarkdown(snapshotFile, outputDirectory) {
  const output = path.resolve(outputDirectory);
  const parent = path.dirname(output);
  let parentStats;
  try {
    // Follow symlinked ancestors: only the target leaf itself being a symlink
    // is rejected below.
    parentStats = fs.statSync(parent);
  } catch (error) {
    throw ioError(`cannot access output parent ${parent}: ${error.message}`);
  }
  if (!parentStats.isDirectory()) throw ioError(`output parent is not a directory: ${parent}`);

  let outputStats;
  try {
    outputStats = fs.lstatSync(output);
  } catch (error) {
    if (error.code !== 'ENOENT') throw ioError(`cannot access output directory ${outputDirectory}: ${error.message}`);
  }
  if (outputStats?.isSymbolicLink()) {
    throw new SnapshotError('INVALID_OPTIONS', 'output directory must not be a symlink');
  }

  // Fixed staging/backup names used below. They are computed before any check
  // so the source can be protected against all three locations the export
  // replaces or removes — not just the final output directory.
  const stage = `${output}.export.tmp`;
  const backup = `${output}.old.tmp`;

  // Path-option checks precede reading so an invalid layout is reported even
  // when the source itself would be unreadable. The source snapshot is user
  // input: it must never be deleted, moved, or rewritten merely because it
  // sits at (or inside) the output directory or either scratch location this
  // export is about to clear or swap. All comparisons use real locations so
  // paths reached through symlinked parents alias correctly even when the
  // output leaf does not exist yet.
  const sourceReal = realLocation(snapshotFile);
  const protectedLocations = [realLocation(output), realLocation(stage), realLocation(backup)];
  if (protectedLocations.some((location) => isInside(sourceReal, location))) {
    throw new SnapshotError(
      'INVALID_OPTIONS',
      'source snapshot must not be the output directory or an export staging or backup location',
    );
  }

  const snapshotText = readSnapshotText(snapshotFile);

  // All content validation happens before anything on disk changes.
  const workspace = new Workspace();
  workspace.importJSON(snapshotText, { mode: 'replace' });
  const snapshot = workspace.exportJSON();
  const { files, manifestText } = buildPackage(snapshot);

  // Clear leftovers from a previously killed attempt first.
  removeQuiet(stage);
  removeQuiet(backup);
  let stageReady = false;
  try {
    fs.mkdirSync(stage);
    for (const [name, bytes] of files) fs.writeFileSync(path.join(stage, name), bytes);
    stageReady = true;

    const hadTarget = outputStats !== undefined;
    if (hadTarget) fs.renameSync(output, backup);
    try {
      fs.renameSync(stage, output);
    } catch (error) {
      if (hadTarget) {
        try {
          fs.renameSync(backup, output);
        } catch {
          // surface the original failure with whatever can be restored
        }
      }
      throw error;
    }
    if (hadTarget) removeQuiet(backup);
  } catch (error) {
    if (stageReady) removeQuiet(stage);
    if (error instanceof SnapshotError) throw error;
    throw ioError(`cannot write package directory ${outputDirectory}: ${error.message}`);
  }

  return { manifest: JSON.parse(manifestText), manifestText };
}

// Imports a Markdown package over a base snapshot and writes the projected
// version-1 snapshot. Every validation step runs before the output is
// touched, so failure leaves the base snapshot and any existing output
// untouched. Returns the result snapshot plus the exact bytes saved.
export function importMarkdown(baseFile, inputDirectory, outputFile, mode, dryRun = false) {
  const input = path.resolve(inputDirectory);
  let inputStats;
  try {
    inputStats = fs.lstatSync(input);
  } catch (error) {
    throw ioError(`cannot read package directory ${inputDirectory}: ${error.message}`);
  }
  if (inputStats.isSymbolicLink()) throw invalidMarkdown('package directory must not be a symlink');

  // Layout options are validated before any file content is read.
  const inputReal = realLocation(input);
  const outputReal = realLocation(outputFile);
  if (isInside(outputReal, inputReal)) {
    throw new SnapshotError('INVALID_OPTIONS', 'output snapshot must not be inside the input package');
  }

  const baseText = readSnapshotText(baseFile);
  const { entries, checksum } = readPackageDirectory(input);

  const baseWorkspace = new Workspace();
  baseWorkspace.importJSON(baseText, { mode: 'replace' });

  // Rebuild the incoming snapshot from normalized entries and verify the
  // manifest's bound checksum exactly as a version-1 snapshot would compute.
  const incomingDocuments = entries.map(({ file: _file, sha256: _sha256, ...document }) => structuredClone(document));
  const incomingWorkspace = new Workspace();
  try {
    incomingWorkspace.importJSON(
      { version: 1, documents: incomingDocuments, checksum },
      { mode: 'replace' },
    );
  } catch (error) {
    if (error instanceof SnapshotError && error.code === 'INVALID_SNAPSHOT') {
      throw invalidMarkdown(`package does not rebuild a matching snapshot: ${error.message}`);
    }
    throw error;
  }
  const incomingSnapshot = incomingWorkspace.exportJSON();
  if (incomingSnapshot.checksum !== checksum) {
    throw invalidMarkdown('manifest checksum does not match the rebuilt snapshot');
  }

  // Existing merge conflict / ids rules apply unchanged; replace installs
  // the package wholesale.
  const result = baseWorkspace.importJSON(incomingSnapshot, { mode });

  const rendered = `${JSON.stringify(result)}\n`;
  if (!dryRun) atomicWrite(path.resolve(outputFile), rendered);
  return { snapshot: result, rendered: dryRun ? null : rendered };
}
