#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { createDocumentServer } from './server.js';
import { SnapshotError, Workspace } from './workspace.js';

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
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--port') {
      index += 1;
      if (index >= args.length) throw new SnapshotError('INVALID_OPTIONS', '--port requires a value');
      port = parsePort(args[index]);
    } else if (arg.startsWith('--port=')) {
      port = parsePort(arg.slice('--port='.length));
    } else if (arg.startsWith('--')) {
      throw new SnapshotError('INVALID_OPTIONS', `unknown option: ${arg}`);
    } else {
      positionals.push(arg);
    }
  }
  if (positionals.length !== 1) {
    throw new SnapshotError('INVALID_OPTIONS', 'usage: serve <snapshot> [--port <port>]');
  }
  return { file: positionals[0], port };
}

function serve(args) {
  const { file, port } = parseServeArgs(args);

  const workspace = new Workspace();
  if (fs.existsSync(file)) {
    // An unreadable or invalid snapshot is fatal; the file is left untouched.
    workspace.importJSON(readSnapshotFile(file), { mode: 'replace' });
  }

  const server = createDocumentServer({
    workspace,
    save: (snapshot) => atomicWrite(file, `${JSON.stringify(snapshot)}\n`),
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
  process.stderr.write('Usage: node src/cli.js demo | node src/cli.js migrate <base> <incoming> <output> <mode> [--dry-run] | node src/cli.js serve <snapshot> [--port <port>]\n');
  process.exitCode = 1;
}
