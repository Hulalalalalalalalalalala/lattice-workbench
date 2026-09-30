#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import { Workspace } from './workspace.js';

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

function cliError(code, message, extra) {
  const error = new Error(message);
  error.code = code;
  if (extra) Object.assign(error, extra);
  return error;
}

async function readSnapshotFile(path) {
  let text;
  try {
    text = await readFile(path, 'utf8');
  } catch {
    throw cliError('IO_ERROR', `cannot read snapshot file: ${path}`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw cliError('INVALID_SNAPSHOT', `invalid snapshot JSON: ${path}`);
  }
}

async function migrate(basePath, incomingPath, outputPath, mode, dryRun) {
  const [baseData, incomingData] = await Promise.all([
    readSnapshotFile(basePath),
    readSnapshotFile(incomingPath),
  ]);

  const workspace = new Workspace();
  workspace.importJSON(baseData, { mode: 'replace' });
  const result = workspace.importJSON(incomingData, { mode, dryRun });

  if (!dryRun) {
    try {
      await writeFile(outputPath, `${JSON.stringify(result)}\n`, 'utf8');
    } catch {
      throw cliError('IO_ERROR', `cannot write snapshot file: ${outputPath}`);
    }
  }
  return result;
}

async function main() {
  const args = process.argv.slice(2);

  if (args[0] === 'demo') {
    demo();
    return;
  }

  if (args[0] !== 'migrate'
    || args.length < 5
    || args.length > 6
    || (args.length === 6 && args[5] !== '--dry-run')) {
    throw cliError('INVALID_OPTIONS', 'usage: node src/cli.js migrate <base> <incoming> <output> <mode> [--dry-run]');
  }

  const [, basePath, incomingPath, outputPath, mode] = args;
  const dryRun = args.length === 6;
  const result = await migrate(basePath, incomingPath, outputPath, mode, dryRun);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

main().catch((error) => {
  const payload = { code: error.code || 'IO_ERROR' };
  if (Array.isArray(error.ids)) payload.ids = error.ids;
  process.stderr.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = 1;
});
