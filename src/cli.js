#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { createDocumentServer } from './server.js';
import { SnapshotError, Workspace } from './workspace.js';
import { appendRecord, assertHistoryConsistent, loadHistory, newHistory } from './history.js';

function demo() {
  const workspace = new Workspace();
  workspace.add({ id: 'welcome', title: '欢迎使用', body: '从 [[architecture]] 开始了解工作台。', tags: ['入门', 'Markdown'] });
  workspace.add({ id: 'architecture', title: '架构备忘', body: '本地优先的文档与双向链接基线。返回 [[welcome]]。', tags: ['架构', 'markdown'] });
  const result = {
    product: 'Lattice Workbench',
    documents: workspace.list(),
    search: workspace.search('markdown').map(({ id, title }) => ({ id, title })),
    relationships: Object.fromEntries(workspace.list().map(({ id }) => [id, workspace.links(id)])),
  };
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

function readSnapshotFile(file) {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch (error) {
    throw new SnapshotError('IO_ERROR', `cannot read snapshot file ${file}: ${error.message}`);
  }
}

function atomicWrite(file, content) {
  const directory = path.dirname(path.resolve(file));
  const temp = path.join(directory, `.${path.basename(file)}.${process.pid}.tmp`);
  try {
    fs.writeFileSync(temp, content, 'utf8');
    fs.renameSync(temp, file);
  } catch (error) {
    try {
      fs.rmSync(temp, { force: true });
    } catch {
      // best-effort cleanup of the staging file
    }
    throw new SnapshotError('IO_ERROR', `cannot write snapshot file ${file}: ${error.message}`);
  }
}

// --- history transactions -------------------------------------------------
// A commit must move the snapshot and its history from one consistent pair to
// the next. A journal written before the rename pair lets a process killed
// mid-commit recover: on restart the journal is replayed, so the presented
// state is always either the pre-commit or the post-commit pair.

function journalPath(snapshotFile) {
  return path.join(path.dirname(path.resolve(snapshotFile)), `.${path.basename(snapshotFile)}.txn`);
}

function writeTemp(file, content) {
  const temp = `${file}.tmp`;
  fs.writeFileSync(temp, content, 'utf8');
  const handle = fs.openSync(temp, 'r+');
  try {
    fs.fsyncSync(handle);
  } finally {
    fs.closeSync(handle);
  }
}

// Atomically replaces `file` with `${file}.tmp`, keeping a `${file}.bak` copy
// of the original. On failure the original is restored.
function installFile(file) {
  const temp = `${file}.tmp`;
  const backup = `${file}.bak`;
  let movedOriginal = false;
  try {
    if (fs.existsSync(file)) {
      fs.renameSync(file, backup);
      movedOriginal = true;
    }
    fs.renameSync(temp, file);
  } catch (error) {
    if (movedOriginal) {
      try {
        fs.renameSync(backup, file);
      } catch {
        // best-effort restore; the journal will complete the transaction
      }
    }
    throw error;
  }
}

// Restores `file` from its `.bak` copy, undoing an installFile.
function restoreFile(file) {
  const backup = `${file}.bak`;
  if (!fs.existsSync(backup)) return;
  if (fs.existsSync(file)) {
    fs.renameSync(file, `${file}.tmp`);
  }
  fs.renameSync(backup, file);
  fs.rmSync(`${file}.tmp`, { force: true });
}

function removeIfExists(file) {
  try {
    fs.rmSync(file, { force: true });
  } catch {
    // best-effort cleanup
  }
}

// Persists the next snapshot and history as one transaction. If either file
// cannot be written, both are left untouched and IO_ERROR is thrown.
function commitFiles(snapshotFile, historyFile, snapshotContent, historyContent) {
  const journal = journalPath(snapshotFile);
  const temps = [snapshotFile, historyFile, journal].map((file) => `${file}.tmp`);
  const backups = [snapshotFile, historyFile].map((file) => `${file}.bak`);
  let failed = false;
  try {
    writeTemp(snapshotFile, snapshotContent);
    writeTemp(historyFile, historyContent);
    writeTemp(journal, JSON.stringify({ version: 1, snapshot: snapshotContent, history: historyContent }));
    installFile(snapshotFile);
    installFile(historyFile);
  } catch (error) {
    failed = true;
    try {
      restoreFile(historyFile);
      restoreFile(snapshotFile);
    } catch {
      // Rollback failed: leave the journal in place so a restart can complete
      // the transaction.
      throw new SnapshotError('IO_ERROR', `cannot write snapshot/history: ${error.message}`);
    }
    throw new SnapshotError('IO_ERROR', `cannot write snapshot/history: ${error.message}`);
  } finally {
    for (const temp of temps) removeIfExists(temp);
    for (const backup of backups) removeIfExists(backup);
    if (!failed) removeIfExists(journal);
  }
}

// Replays a leftover journal, completing an interrupted transaction. Returns
// true when a journal was replayed.
function recoverJournal(snapshotFile, historyFile) {
  const journal = journalPath(snapshotFile);
  if (!fs.existsSync(journal)) return false;
  let payload;
  try {
    payload = JSON.parse(fs.readFileSync(journal, 'utf8'));
  } catch (error) {
    throw new SnapshotError('INVALID_HISTORY', `cannot read transaction journal: ${error.message}`);
  }
  if (!payload || payload.version !== 1
    || typeof payload.snapshot !== 'string' || typeof payload.history !== 'string') {
    throw new SnapshotError('INVALID_HISTORY', 'invalid transaction journal');
  }
  let ok = false;
  try {
    writeTemp(snapshotFile, payload.snapshot);
    writeTemp(historyFile, payload.history);
    installFile(snapshotFile);
    installFile(historyFile);
    ok = true;
  } catch (error) {
    throw new SnapshotError('IO_ERROR', `cannot complete transaction: ${error.message}`);
  } finally {
    for (const file of [snapshotFile, historyFile]) {
      removeIfExists(`${file}.tmp`);
      removeIfExists(`${file}.bak`);
    }
    // Only consume the journal when the transaction completed; a failure
    // leaves it for the next restart to retry.
    if (ok) removeIfExists(journal);
  }
  return true;
}

function parseMigrateArgs(args) {
  const positionals = [];
  let dryRun = false;
  for (const arg of args) {
    if (arg === '--dry-run') {
      dryRun = true;
    } else if (arg.startsWith('--')) {
      throw new SnapshotError('INVALID_OPTIONS', `unknown option: ${arg}`);
    } else {
      positionals.push(arg);
    }
  }
  if (positionals.length !== 4) {
    throw new SnapshotError('INVALID_OPTIONS', 'usage: migrate <base> <incoming> <output> <mode> [--dry-run]');
  }
  const [base, incoming, output, mode] = positionals;
  if (mode !== 'merge' && mode !== 'replace') {
    throw new SnapshotError('INVALID_OPTIONS', "mode must be 'merge' or 'replace'");
  }
  return { base, incoming, output, mode, dryRun };
}

function migrate(args) {
  const { base, incoming, output, mode, dryRun } = parseMigrateArgs(args);

  const workspace = new Workspace();
  workspace.importJSON(readSnapshotFile(base), { mode: 'replace' });
  const snapshot = workspace.importJSON(readSnapshotFile(incoming), { mode, dryRun });

  const rendered = `${JSON.stringify(snapshot)}\n`;
  if (!dryRun) atomicWrite(output, rendered);
  process.stdout.write(rendered);
}

function parsePort(value) {
  if (!/^\d+$/u.test(value)) {
    throw new SnapshotError('INVALID_OPTIONS', `invalid port: ${value}`);
  }
  const port = Number(value);
  if (port > 65535) {
    throw new SnapshotError('INVALID_OPTIONS', `invalid port: ${value}`);
  }
  return port;
}

function parseServeArgs(args) {
  const positionals = [];
  let port = 3000;
  let historyFile = null;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--port') {
      index += 1;
      if (index >= args.length) throw new SnapshotError('INVALID_OPTIONS', '--port requires a value');
      port = parsePort(args[index]);
    } else if (arg.startsWith('--port=')) {
      port = parsePort(arg.slice('--port='.length));
    } else if (arg === '--history') {
      index += 1;
      if (index >= args.length) throw new SnapshotError('INVALID_OPTIONS', '--history requires a value');
      historyFile = args[index];
    } else if (arg.startsWith('--history=')) {
      historyFile = arg.slice('--history='.length);
    } else if (arg.startsWith('--')) {
      throw new SnapshotError('INVALID_OPTIONS', `unknown option: ${arg}`);
    } else {
      positionals.push(arg);
    }
  }
  if (positionals.length !== 1) {
    throw new SnapshotError('INVALID_OPTIONS', 'usage: serve <snapshot> [--port <port>] [--history <file>]');
  }
  return { file: positionals[0], port, historyFile };
}

function serve(args) {
  const { file, port, historyFile } = parseServeArgs(args);
  if (historyFile && path.resolve(file) === path.resolve(historyFile)) {
    throw new SnapshotError('INVALID_OPTIONS', 'snapshot and history files must be different paths');
  }

  let workspace = new Workspace();
  if (fs.existsSync(file)) {
    // An unreadable or invalid snapshot is fatal; the file is left untouched.
    workspace.importJSON(readSnapshotFile(file), { mode: 'replace' });
  }

  let history = null;
  if (historyFile) {
    // A leftover journal from an interrupted commit is replayed before either
    // file is read, so the pair is always presented in a consistent state.
    if (recoverJournal(file, historyFile)) {
      workspace = new Workspace();
      workspace.importJSON(readSnapshotFile(file), { mode: 'replace' });
    }
    if (fs.existsSync(historyFile)) {
      let text;
      try {
        text = fs.readFileSync(historyFile, 'utf8');
      } catch (error) {
        throw new SnapshotError('IO_ERROR', `cannot read history file ${historyFile}: ${error.message}`);
      }
      history = loadHistory(text);
      assertHistoryConsistent(workspace, history);
    } else {
      // No history file yet: every existing document gets a revision-1
      // baseline; new documents will start at revision 1 with a create.
      history = newHistory();
      for (const document of workspace.list()) {
        history = appendRecord(history, document.id, 'baseline', document);
      }
    }
  }

  const commit = historyFile
    ? (snapshot, nextHistory) => commitFiles(
        file,
        historyFile,
        `${JSON.stringify(snapshot)}\n`,
        `${JSON.stringify(nextHistory)}\n`,
      )
    : (snapshot) => atomicWrite(file, `${JSON.stringify(snapshot)}\n`);

  const server = createDocumentServer({
    workspace,
    history,
    commit,
  });
  server.on('error', (error) => {
    reportError(new SnapshotError('IO_ERROR', `cannot serve ${file}: ${error.message}`));
  });
  server.listen(port, '127.0.0.1', () => {
    const address = server.address();
    process.stdout.write(`${JSON.stringify({ host: address.address, port: address.port })}\n`);
  });
}

function reportError(error) {
  const payload = { code: error instanceof SnapshotError ? error.code : 'IO_ERROR' };
  if (typeof error.message === 'string') payload.message = error.message;
  if (Array.isArray(error.ids)) payload.ids = error.ids;
  process.stderr.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = 1;
}

const command = process.argv[2];
if (command === 'demo') {
  demo();
} else if (command === 'migrate') {
  try {
    migrate(process.argv.slice(3));
  } catch (error) {
    reportError(error);
  }
} else if (command === 'serve') {
  try {
    serve(process.argv.slice(3));
  } catch (error) {
    reportError(error);
  }
} else {
  process.stderr.write('Usage: node src/cli.js demo | node src/cli.js migrate <base> <incoming> <output> <mode> [--dry-run] | node src/cli.js serve <snapshot> [--port <port>] [--history <file>]\n');
  process.exitCode = 1;
}
