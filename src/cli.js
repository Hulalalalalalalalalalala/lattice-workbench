#!/usr/bin/env node
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

if (process.argv[2] === 'demo') demo();
else {
  process.stderr.write('Usage: node src/cli.js demo\n');
  process.exitCode = 1;
}
