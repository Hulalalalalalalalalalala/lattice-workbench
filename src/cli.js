#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { createDocumentServer } from './server.js';
import { HistoryStore, loadHistoryFile } from './history.js';
import { exportMarkdown, importMarkdown } from './markdown-pkg.js';
import { SnapshotError, Workspace, snapshotFromDocuments } from './workspace.js';
import { realLocation } from './paths.js';

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
  const temp = stagingPath(file);
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

function stagingPath(file) {
  const directory = path.dirname(path.resolve(file));
  return path.join(directory, `.${path.basename(file)}.${process.pid}.tmp`);
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

function parseMarkdownArgs(args) {
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
  return { positionals, dryRun };
}

function exportMd(args) {
  const { positionals, dryRun } = parseMarkdownArgs(args);
  if (dryRun || positionals.length !== 2) {
    throw new SnapshotError('INVALID_OPTIONS', 'usage: export-md <snapshot> <output-directory>');
  }
  const [snapshot, outputDirectory] = positionals;
  const { manifestText } = exportMarkdown(snapshot, outputDirectory);
  process.stdout.write(manifestText);
}

function importMd(args) {
  const { positionals, dryRun } = parseMarkdownArgs(args);
  if (positionals.length !== 4) {
    throw new SnapshotError(
      'INVALID_OPTIONS',
      'usage: import-md <base> <input-directory> <output> <mode> [--dry-run]',
    );
  }
  const [base, inputDirectory, output, mode] = positionals;
  if (mode !== 'merge' && mode !== 'replace') {
    throw new SnapshotError('INVALID_OPTIONS', "mode must be 'merge' or 'replace'");
  }
  const { snapshot } = importMarkdown(base, inputDirectory, output, mode, dryRun);
  process.stdout.write(`${JSON.stringify(snapshot)}\n`);
}

function parsePort(value) {  if (!/^\d+$/u.test(value)) {
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
      if (index >= args.length || args[index] === '') throw new SnapshotError('INVALID_OPTIONS', '--history requires a value');
      historyFile = args[index];
    } else if (arg.startsWith('--history=')) {
      historyFile = arg.slice('--history='.length);
      if (historyFile === '') throw new SnapshotError('INVALID_OPTIONS', '--history requires a value');
    } else if (arg.startsWith('--')) {
      throw new SnapshotError('INVALID_OPTIONS', `unknown option: ${arg}`);
    } else {
      positionals.push(arg);
    }
  }
  if (positionals.length !== 1) {
    throw new SnapshotError('INVALID_OPTIONS', 'usage: serve <snapshot> [--port <port>] [--history <file>]');
  }
  if (historyFile !== null) {
    // The history commit moves the old history aside to <history>.bak and
    // deletes that backup afterwards, so the content snapshot must occupy
    // neither location: a snapshot placed there would be moved or deleted on
    // startup or on the first save. Compare real locations so relative
    // paths, '.'/'..' spellings, and symlinked aliases are caught even before
    // any of the files exist. This runs before the snapshot is read, so a
    // conflicting layout is reported ahead of any INVALID_SNAPSHOT/
    // INVALID_HISTORY.
    const snapshotReal = realLocation(positionals[0]);
    const historyReal = realLocation(historyFile);
    if (snapshotReal === historyReal) {
      throw new SnapshotError('INVALID_OPTIONS', 'snapshot must not share a location with the history file');
    }
    const backupReal = realLocation(`${historyFile}.bak`);
    if (snapshotReal === backupReal) {
      throw new SnapshotError('INVALID_OPTIONS', 'snapshot must not occupy the history backup location (<history>.bak)');
    }
  }
  return { file: positionals[0], port, historyFile };
}

function readText(file) {
  return fs.readFileSync(file, 'utf8');
}

function writeStaging(file, content) {
  const temp = stagingPath(file);
  try {
    fs.writeFileSync(temp, content, 'utf8');
  } catch (error) {
    try {
      fs.rmSync(temp, { force: true });
    } catch {
      // best-effort cleanup
    }
    throw new SnapshotError('IO_ERROR', `cannot write file ${file}: ${error.message}`);
  }
  return temp;
}

function removeQuiet(file) {
  try {
    fs.rmSync(file, { force: true });
  } catch {
    // best-effort cleanup
  }
}

// Commits snapshot and history together. The history file is the commit
// marker: it is installed first and embeds the new snapshot checksum, so a
// kill between the two renames leaves a history the next startup replays to
// reconstruct the snapshot. A failed I/O step rolls the files back to the
// pre-commit state; the caller only swaps in-memory state after this returns.
function commitWithHistory(snapshotFile, historyFile, backupFile, snapshot, historySnapshot) {
  const snapshotText = `${JSON.stringify(snapshot)}\n`;
  const historyText = `${JSON.stringify(historySnapshot)}\n`;
  const snapshotTemp = writeStaging(snapshotFile, snapshotText);
  let historyTemp;
  try {
    historyTemp = writeStaging(historyFile, historyText);
  } catch (error) {
    removeQuiet(snapshotTemp);
    throw error;
  }
  const hadHistory = fs.existsSync(historyFile);
  try {
    if (hadHistory) fs.renameSync(historyFile, backupFile);
    fs.renameSync(historyTemp, historyFile);
  } catch (error) {
    if (hadHistory) {
      try {
        fs.renameSync(backupFile, historyFile);
      } catch {
        // startup recovery reconciles whatever remains
      }
    }
    removeQuiet(snapshotTemp);
    removeQuiet(historyTemp);
    throw new SnapshotError('IO_ERROR', `cannot write history file ${historyFile}: ${error.message}`);
  }
  try {
    fs.renameSync(snapshotTemp, snapshotFile);
  } catch (error) {
    try {
      if (hadHistory) {
        fs.renameSync(backupFile, historyFile);
      } else {
        fs.rmSync(historyFile, { force: true });
      }
    } catch {
      // startup recovery reconciles whatever remains
    }
    removeQuiet(historyTemp);
    throw new SnapshotError('IO_ERROR', `cannot write snapshot file ${snapshotFile}: ${error.message}`);
  }
  removeQuiet(backupFile);
}

// Loads the snapshot/history pair and brings both to a single consistent
// state. Returns { workspace, ledger }. Throws a SnapshotError (IO_ERROR,
// INVALID_SNAPSHOT, or INVALID_HISTORY) on any unrecoverable problem; files
// are left untouched in that case.
function loadState(file, historyFile) {
  const workspace = new Workspace();
  let snapshot = null;
  if (fs.existsSync(file)) {
    const text = readSnapshotFile(file);
    workspace.importJSON(text, { mode: 'replace' });
    snapshot = workspace.exportJSON();
  } else {
    snapshot = workspace.exportJSON();
  }

  if (historyFile === null) return { workspace, ledger: null };

  const backupFile = `${historyFile}.bak`;
  // A kill between moving the old history aside and installing the new one
  // leaves only the backup; restore the pre-commit history before proceeding.
  if (!fs.existsSync(historyFile) && fs.existsSync(backupFile)) {
    try {
      fs.renameSync(backupFile, historyFile);
    } catch (error) {
      throw new SnapshotError('IO_ERROR', `cannot recover history file ${historyFile}: ${error.message}`);
    }
  }

  if (!fs.existsSync(historyFile)) {
    // First run with a history file: revision 1 baselines the current content.
    // The file itself appears with the first successful write.
    return { workspace, ledger: HistoryStore.baseline(workspace.list()) };
  }

  const ledger = loadHistoryFile(historyFile, readText);
  removeQuiet(backupFile);
  if (ledger.snapshotChecksum === snapshot.checksum) {
    return { workspace, ledger };
  }

  // The files disagree: the history ledger is authoritative (it records every
  // acknowledged commit). Reconstruct the snapshot from its replay and install
  // it atomically.
  const recovered = snapshotFromDocuments(ledger.replayedDocuments().values());
  if (recovered.checksum !== ledger.snapshotChecksum) {
    throw new SnapshotError('INVALID_HISTORY', 'history cannot be reconciled to a consistent snapshot');
  }
  const recoveredWorkspace = new Workspace();
  recoveredWorkspace.importJSON(recovered, { mode: 'replace' });
  atomicWrite(file, `${JSON.stringify(recovered)}\n`);
  return { workspace: recoveredWorkspace, ledger };
}

function serve(args) {
  const { file, port, historyFile } = parseServeArgs(args);
  const { workspace, ledger } = loadState(file, historyFile);

  const backupFile = historyFile === null ? null : `${historyFile}.bak`;
  const server = createDocumentServer({
    workspace,
    history: ledger,
    save: (snapshot, historySnapshot) => {
      if (historyFile === null) {
        atomicWrite(file, `${JSON.stringify(snapshot)}\n`);
      } else {
        commitWithHistory(file, historyFile, backupFile, snapshot, historySnapshot);
      }
    },
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
} else if (command === 'export-md') {
  try {
    exportMd(process.argv.slice(3));
  } catch (error) {
    reportError(error);
  }
} else if (command === 'import-md') {
  try {
    importMd(process.argv.slice(3));
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
  process.stderr.write('Usage: node src/cli.js demo | migrate <base> <incoming> <output> <mode> [--dry-run] | export-md <snapshot> <output-directory> | import-md <base> <input-directory> <output> <mode> [--dry-run] | serve <snapshot> [--port <port>] [--history <file>]\n');
  process.exitCode = 1;
}
