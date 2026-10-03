import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import test from 'node:test';
import { Workspace } from '../src/workspace.js';

const CLI = path.resolve('src/cli.js');

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-utf8-'));
}

function writeSnapshot(file, workspace) {
  fs.writeFileSync(file, `${JSON.stringify(workspace.exportJSON())}\n`);
}

function workspaceWith(documents) {
  const workspace = new Workspace();
  for (const document of documents) workspace.add(document);
  return workspace;
}

function snapshotOf(documents) {
  return workspaceWith(documents).exportJSON();
}

async function startServer(args) {
  const child = spawn(process.execPath, [CLI, 'serve', ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const address = await new Promise((resolve, reject) => {
    child.stdout.on('data', () => {
      const index = stdout.indexOf('\n');
      if (index === -1) return;
      try {
        resolve(JSON.parse(stdout.slice(0, index)));
      } catch (error) {
        reject(error);
      }
    });
    child.on('exit', (code) => reject(new Error(`server exited with status ${code}: ${stderr.trim()}`)));
  });
  return {
    child,
    address,
    url: `http://${address.host}:${address.port}`,
    stop: () => new Promise((resolve) => {
      child.once('exit', resolve);
      child.kill('SIGKILL');
    }),
  };
}

// rawBody may be a Buffer (arbitrary bytes); fetch forwards it untouched.
async function request(base, method, route, { body, rawBody, headers = {} } = {}) {
  const response = await fetch(`${base}${route}`, {
    method,
    headers: {
      ...(body !== undefined || rawBody !== undefined ? { 'content-type': 'application/json' } : {}),
      ...headers,
    },
    body: rawBody ?? (body !== undefined ? JSON.stringify(body) : undefined),
  });
  const text = await response.text();
  return {
    status: response.status,
    etag: response.headers.get('etag'),
    body: text ? JSON.parse(text) : null,
  };
}

// --- raw TCP helpers --------------------------------------------------------

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function chunkFrame(sock, bytes) {
  sock.write(`${bytes.length.toString(16)}\r\n`);
  sock.write(bytes);
  sock.write('\r\n');
}

function dechunk(bytes) {
  let output = Buffer.alloc(0);
  let offset = 0;
  for (;;) {
    const lineEnd = bytes.indexOf('\r\n', offset);
    if (lineEnd === -1) break; // connection ended mid-trailer
    const length = parseInt(bytes.subarray(offset, lineEnd).toString('utf8'), 16);
    if (Number.isNaN(length)) break;
    offset = lineEnd + 2;
    if (length === 0) break;
    output = Buffer.concat([output, bytes.subarray(offset, offset + length)]);
    offset += length + 2; // skip data and its trailing CRLF
  }
  return output;
}

function parseRawResponse(raw) {
  const sep = raw.indexOf('\r\n\r\n');
  assert.notEqual(sep, -1, () => `no response headers in ${raw.toString('utf8')}`);
  const lines = raw.subarray(0, sep).toString('utf8').split('\r\n');
  const status = Number(lines[0].split(' ')[1]);
  const headers = {};
  for (const line of lines.slice(1)) {
    const i = line.indexOf(':');
    headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  let bytes = raw.subarray(sep + 4);
  if ((headers['transfer-encoding'] ?? '').includes('chunked')) {
    bytes = dechunk(bytes);
  } else {
    const length = Number(headers['content-length']);
    if (Number.isFinite(length) && length >= 0) bytes = bytes.subarray(0, length);
  }
  const text = bytes.toString('utf8');
  return { status, headers, etag: headers.etag ?? null, body: text ? JSON.parse(text) : null };
}

// Opens a raw POST where the caller controls every byte and write timing. The
// client sends Connection: close, so the reply body runs to socket close.
async function rawExchange(base, route, requestHeaders, write) {
  const url = new URL(base);
  const sock = new net.Socket();
  const connected = new Promise((resolve, reject) => {
    sock.once('connect', resolve);
    sock.once('error', reject);
  });
  sock.connect({ host: url.hostname, port: Number(url.port) });
  await connected;

  let received = Buffer.alloc(0);
  const closed = new Promise((resolve) => {
    sock.on('data', (chunk) => { received = Buffer.concat([received, chunk]); });
    sock.on('close', () => resolve(received));
    // A server that rejects an oversized stream mid-upload resets the socket;
    // whatever it already sent is the complete reply.
    sock.on('error', () => resolve(received));
  });

  const head = [
    `POST ${route} HTTP/1.1`,
    `Host: ${url.host}`,
    'Connection: close',
    ...Object.entries(requestHeaders).map(([key, value]) => `${key}: ${value}`),
    '',
    '',
  ].join('\r\n');
  sock.write(head);
  try {
    await write(sock, () => received);
  } catch {
    // Writing after the reply/close is expected for oversized uploads.
  }
  const raw = await closed;
  sock.destroy();
  return parseRawResponse(raw);
}

// --- byte fixtures ----------------------------------------------------------

const BAD_SEQUENCES = {
  'lone continuation byte': Buffer.from([0x80]),
  'truncated three-byte character': Buffer.from([0xe4, 0xb8]),
  'truncated four-byte character': Buffer.from([0xf0, 0x9f, 0x98]),
  'overlong two-byte encoding': Buffer.from([0xc0, 0xaf]),
  'overlong three-byte encoding': Buffer.from([0xe0, 0x80, 0x80]),
  'surrogate-range bytes ED A0 80': Buffer.from([0xed, 0xa0, 0x80]),
  'surrogate-range bytes ED BF BF': Buffer.from([0xed, 0xbf, 0xbf]),
  'bytes beyond Unicode F4 90 80 80': Buffer.from([0xf4, 0x90, 0x80, 0x80]),
  'leading F5 byte': Buffer.from([0xf5, 0x80, 0x80, 0x80]),
};

// Replaces the first occurrence of `token` in the JSON template with the raw
// byte sequence, so the invalid bytes land inside a JSON string.
function inject(template, token, bad) {
  const at = template.indexOf(token);
  assert.notEqual(at, -1);
  return Buffer.concat([
    Buffer.from(template.slice(0, at), 'utf8'),
    bad,
    Buffer.from(template.slice(at + token.length), 'utf8'),
  ]);
}

const createJson = (field) => `{"id":"x","title":"__TITLE__","body":"__BODY__","tags":[__TAG__]}`
  .replace('__TITLE__', field === 'title' ? 'XX' : 'T')
  .replace('__BODY__', field === 'body' ? 'XX' : 'b')
  .replace('__TAG__', field === 'tags' ? '"XX"' : '"t"');

// --- invalid byte sequences -------------------------------------------------

test('every malformed UTF-8 sequence in a document body is 400 INVALID_JSON', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    for (const [label, bad] of Object.entries(BAD_SEQUENCES)) {
      const response = await request(server.url, 'POST', '/documents', {
        rawBody: inject(createJson('body'), 'XX', bad),
        headers: { 'if-match': et },
      });
      assert.equal(response.status, 400, label);
      assert.equal(response.body.code, 'INVALID_JSON', label);
      // Nothing was stored and the current ETag never moved.
      assert.deepEqual((await request(server.url, 'GET', '/documents')).body, []);
      assert.equal((await request(server.url, 'GET', '/documents')).etag, et, label);
    }
    assert.ok(!fs.existsSync(path.join(cwd, 'snap.json')));
  } finally {
    await server.stop();
  }
});

test('invalid bytes in a title, body, or tag string are all rejected', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    for (const field of ['title', 'body', 'tags']) {
      const response = await request(server.url, 'POST', '/documents', {
        rawBody: inject(createJson(field), 'XX', Buffer.from([0x80])),
        headers: { 'if-match': et },
      });
      assert.equal(response.status, 400, field);
      assert.equal(response.body.code, 'INVALID_JSON', field);
    }
    assert.deepEqual((await request(server.url, 'GET', '/documents')).body, []);
  } finally {
    await server.stop();
  }
});

test('a rejected write leaves content, ETag, files, and history exactly as they were', async () => {
  const cwd = tempDir();
  const snapshotFile = path.join(cwd, 'snap.json');
  const historyFile = path.join(cwd, 'h.json');
  const server = await startServer([snapshotFile, '--history', historyFile, '--port', '0']);
  try {
    let et = (await request(server.url, 'GET', '/documents')).etag;
    const created = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'Alpha', body: 'original', tags: ['one'] },
      headers: { 'if-match': et },
    });
    assert.equal(created.status, 201);
    et = created.etag;

    const snapshotBytes = fs.readFileSync(snapshotFile);
    const historyBytes = fs.readFileSync(historyFile);

    const bad = await request(server.url, 'PUT', '/documents/a', {
      rawBody: inject(
        '{"id":"a","title":"__T__","body":"__B__","tags":[]}',
        '__B__',
        Buffer.from([0xed, 0xa0, 0x80]),
      ),
      headers: { 'if-match': et },
    });
    assert.equal(bad.status, 400);
    assert.equal(bad.body.code, 'INVALID_JSON');

    const doc = await request(server.url, 'GET', '/documents/a');
    assert.deepEqual(doc.body, { id: 'a', title: 'Alpha', body: 'original', tags: ['one'] });
    assert.equal(doc.etag, et);
    assert.equal((await request(server.url, 'GET', '/documents')).etag, et);
    assert.ok(!(await request(server.url, 'GET', '/search?q=replacement')).body.length);
    assert.deepEqual(fs.readFileSync(snapshotFile), snapshotBytes);
    assert.deepEqual(fs.readFileSync(historyFile), historyBytes);
    // Only the original create record exists; no replace was appended.
    const rows = (await request(server.url, 'GET', '/documents/a/history')).body;
    assert.deepEqual(rows.map((row) => row.action), ['create']);
  } finally {
    await server.stop();
  }
});

// --- valid encoding is untouched --------------------------------------------

test('Chinese, emoji, and a legitimately encoded U+FFFD are stored verbatim', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    let et = (await request(server.url, 'GET', '/documents')).etag;

    const cjk = { id: 'cjk', title: '中文标题 😀', body: '正文内容：你好，世界 🌏', tags: ['标签', 'Emoji😀', 'mixed'] };
    const cjkResponse = await request(server.url, 'POST', '/documents', {
      body: cjk,
      headers: { 'if-match': et },
    });
    assert.equal(cjkResponse.status, 201);
    et = cjkResponse.etag;
    const stored = (await request(server.url, 'GET', '/documents/cjk')).body;
    assert.equal(stored.title, cjk.title);
    assert.equal(stored.body, cjk.body);
    assert.deepEqual(stored.tags, ['emoji😀', 'mixed', '标签']);
    // The body bytes on the saved snapshot are the original UTF-8, untouched.
    assert.ok(fs.readFileSync(path.join(cwd, 'snap.json')).includes(Buffer.from(cjk.body, 'utf8')));

    // U+FFFD supplied as a real character (valid EF BF BD bytes) is preserved.
    const replacement = { id: 'rep', title: 'Replacement', body: 'before � after', tags: [] };
    const repResponse = await request(server.url, 'POST', '/documents', {
      body: replacement,
      headers: { 'if-match': et },
    });
    assert.equal(repResponse.status, 201);
    et = repResponse.etag;
    const repDoc = (await request(server.url, 'GET', '/documents/rep')).body;
    assert.equal(repDoc.body, 'before � after');
    assert.ok(repDoc.body.includes('�'));
    assert.deepEqual([...repDoc.body].filter((char) => char === '�'), ['�']);

    // The same character arrived as a "�" JSON escape: identical string.
    const escaped = await request(server.url, 'POST', '/documents', {
      rawBody: '{"id":"esc","title":"Esc","body":"before \\uFFFD after","tags":[]}',
      headers: { 'if-match': et },
    });
    assert.equal(escaped.status, 201);
    assert.equal((await request(server.url, 'GET', '/documents/esc')).body.body, repDoc.body);

    // A surrogate escape that JSON.parse currently accepts keeps working (it is
    // an escape, not a byte sequence, so it is not evidence of invalid UTF-8).
    const loneSurrogate = await request(server.url, 'POST', '/documents', {
      rawBody: '{"id":"sur","title":"Sur","body":"x\\uD800y","tags":[]}',
      headers: { 'if-match': escaped.etag },
    });
    assert.equal(loneSurrogate.status, 201);
    const surBody = (await request(server.url, 'GET', '/documents/sur')).body.body;
    assert.equal(surBody.codePointAt(1), 0xd800);

    // Paired surrogate escapes still decode to the intended emoji.
    const paired = await request(server.url, 'POST', '/documents', {
      rawBody: '{"id":"pair","title":"Pair","body":"\\uD83D\\uDE00","tags":[]}',
      headers: { 'if-match': loneSurrogate.etag },
    });
    assert.equal(paired.status, 201);
    assert.equal((await request(server.url, 'GET', '/documents/pair')).body.body, '😀');
  } finally {
    await server.stop();
  }
});

test('a multibyte character split across network chunks is accepted identically to one send', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const doc = { id: 'split', title: 'T', body: '你好', tags: [] };
    const whole = Buffer.from(JSON.stringify(doc), 'utf8');

    // Cut between the first and second byte of "你" (E4 BD A0).
    const cut = whole.indexOf(0xe4) + 1;
    const part1 = whole.subarray(0, cut);
    const part2 = whole.subarray(cut);
    const chunked = await rawExchange(server.url, '/documents', {
      'Transfer-Encoding': 'chunked',
      'Content-Type': 'application/json',
      'If-Match': et,
    }, async (sock) => {
      chunkFrame(sock, part1);
      await sleep(20);
      chunkFrame(sock, part2);
      await sleep(20);
      sock.end('0\r\n\r\n');
    });
    assert.equal(chunked.status, 201);

    // The same bytes delivered in one request give the same stored body.
    const oneShotEtag = chunked.etag;
    const oneShot = await request(server.url, 'POST', '/documents', {
      rawBody: Buffer.from(JSON.stringify({ ...doc, id: 'whole', title: 'W' }), 'utf8'),
      headers: { 'if-match': oneShotEtag },
    });
    assert.equal(oneShot.status, 201);
    const splitDoc = (await request(server.url, 'GET', '/documents/split')).body;
    const wholeDoc = (await request(server.url, 'GET', '/documents/whole')).body;
    // The body is what traversed the chunk boundary; it matches a one-shot send.
    assert.equal(splitDoc.body, wholeDoc.body);
    assert.deepEqual(splitDoc.tags, wholeDoc.tags);
  } finally {
    await server.stop();
  }
});

test('an invalid sequence split across chunks is still rejected', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const body = inject('{"id":"x","title":"T","body":"XX","tags":[]}', 'XX', Buffer.from([0xe4, 0xb8]));
    const cut = body.length - 3; // separate E4 from B8 across two writes
    const response = await rawExchange(server.url, '/documents', {
      'Transfer-Encoding': 'chunked',
      'Content-Type': 'application/json',
      'If-Match': et,
    }, async (sock) => {
      chunkFrame(sock, body.subarray(0, cut));
      await sleep(15);
      chunkFrame(sock, body.subarray(cut));
      await sleep(15);
      sock.end('0\r\n\r\n');
    });
    assert.equal(response.status, 400);
    assert.equal(response.body.code, 'INVALID_JSON');
    assert.deepEqual((await request(server.url, 'GET', '/documents')).body, []);
    assert.equal((await request(server.url, 'GET', '/documents')).etag, et);
  } finally {
    await server.stop();
  }
});

// --- batch edits ------------------------------------------------------------

test('batch rejects the whole request when a single string carries invalid bytes', async () => {
  const cwd = tempDir();
  const snapshotFile = path.join(cwd, 'snap.json');
  const historyFile = path.join(cwd, 'h.json');
  writeSnapshot(snapshotFile, workspaceWith([
    { id: 'a', title: 'Alpha', body: 'a body', tags: [] },
  ]));
  const server = await startServer([snapshotFile, '--history', historyFile, '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    for (const dryRun of [false, true]) {
      const envelope = JSON.stringify(
        dryRun
          ? { operations: [
            { type: 'create', document: { id: 'b', title: 'Beta', body: 'fine', tags: [] } },
            { type: 'replace', document: { id: 'a', title: 'Alpha', body: 'XX', tags: [] } },
          ], dryRun: true }
          : { operations: [
            { type: 'create', document: { id: 'b', title: 'Beta', body: 'fine', tags: [] } },
            { type: 'replace', document: { id: 'a', title: 'Alpha', body: 'XX', tags: [] } },
          ] },
      );
      const raw = inject(envelope, 'XX', Buffer.from([0x80]));
      const response = await request(server.url, 'POST', '/batch', {
        rawBody: raw,
        headers: { 'if-match': et },
      });
      assert.equal(response.status, 400, `dryRun=${dryRun}`);
      assert.equal(response.body.code, 'INVALID_JSON');
      assert.deepEqual((await request(server.url, 'GET', '/documents')).body.map((d) => d.id), ['a']);
      assert.equal((await request(server.url, 'GET', '/documents')).etag, et);
    }

    // Neither the valid create nor the bad replace was recorded.
    const rows = (await request(server.url, 'GET', '/documents/a/history')).body;
    assert.deepEqual(rows.map((row) => row.action), ['baseline']);
  } finally {
    await server.stop();
  }
});

// --- offline reconcile ------------------------------------------------------

test('reconcile rejects the whole request when a snapshot string has invalid bytes', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const empty = snapshotOf([]);
    const incoming = snapshotOf([
      { id: 'a', title: 'A', body: 'offline body', tags: [] },
    ]);

    for (const dryRun of [false, true]) {
      const envelope = JSON.stringify(
        dryRun ? { base: empty, incoming, dryRun: true } : { base: empty, incoming },
      );
      const raw = inject(envelope, 'offline body', Buffer.from([0xf4, 0x90, 0x80, 0x80]));
      const response = await request(server.url, 'POST', '/snapshots/reconcile', {
        rawBody: raw,
        headers: { 'if-match': et },
      });
      assert.equal(response.status, 400, `dryRun=${dryRun}`);
      assert.equal(response.body.code, 'INVALID_JSON');
      assert.deepEqual((await request(server.url, 'GET', '/documents')).body, []);
      assert.equal((await request(server.url, 'GET', '/documents')).etag, et);
      assert.ok(!fs.existsSync(path.join(cwd, 'snap.json')));
    }

    // A well-formed reconcile carrying Chinese still lands verbatim.
    const cjkIncoming = snapshotOf([
      { id: 'note', title: '笔记', body: '离线编辑的正文 [[note]]', tags: ['中文'] },
    ]);
    const ok = await request(server.url, 'POST', '/snapshots/reconcile', {
      body: { base: empty, incoming: cjkIncoming },
      headers: { 'if-match': et },
    });
    assert.equal(ok.status, 200);
    const note = (await request(server.url, 'GET', '/documents/note')).body;
    assert.equal(note.title, '笔记');
    assert.equal(note.body, '离线编辑的正文 [[note]]');
    assert.deepEqual(note.tags, ['中文']);
  } finally {
    await server.stop();
  }
});

// --- tag rewrite and restore ------------------------------------------------

test('tag rewrite previews and commits reject invalid UTF-8 as INVALID_JSON', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    let et = (await request(server.url, 'GET', '/documents')).etag;
    await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'a', tags: ['old'] },
      headers: { 'if-match': et },
    });
    et = (await request(server.url, 'GET', '/documents')).etag;

    for (const dryRun of [false, true]) {
      const envelope = JSON.stringify({
        rules: [{ from: 'old', to: 'XX' }],
        ...(dryRun ? { dryRun: true } : {}),
      });
      const response = await request(server.url, 'POST', '/tags/rewrite', {
        rawBody: inject(envelope, 'XX', Buffer.from([0xc0, 0xaf])),
        headers: { 'if-match': et },
      });
      assert.equal(response.status, 400, String(dryRun));
      assert.equal(response.body.code, 'INVALID_JSON');
      assert.deepEqual((await request(server.url, 'GET', '/tags')).body, [{ tag: 'old', count: 1 }]);
      assert.equal((await request(server.url, 'GET', '/tags')).etag, et);
    }
  } finally {
    await server.stop();
  }
});

test('restore reports INVALID_JSON (not INVALID_REVISION) for bad UTF-8 and appends nothing', async () => {
  const cwd = tempDir();
  const server = await startServer([
    path.join(cwd, 'snap.json'), '--history', path.join(cwd, 'h.json'), '--port', '0',
  ]);
  try {
    let et = (await request(server.url, 'GET', '/documents')).etag;
    const created = await request(server.url, 'POST', '/documents', {
      body: { id: 'a', title: 'A', body: 'v1', tags: [] },
      headers: { 'if-match': et },
    });
    et = created.etag;

    const raw = Buffer.concat([Buffer.from('{"revision":1,"note":"', 'utf8'), Buffer.from([0xed, 0xa0, 0x80]), Buffer.from('"}', 'utf8')]);
    const bad = await request(server.url, 'POST', '/documents/a/restore', {
      rawBody: raw,
      headers: { 'if-match': et },
    });
    assert.equal(bad.status, 400);
    assert.equal(bad.body.code, 'INVALID_JSON');

    assert.equal((await request(server.url, 'GET', '/documents')).etag, et);
    const rows = (await request(server.url, 'GET', '/documents/a/history')).body;
    assert.deepEqual(rows.map((row) => row.revision), [1]);
    assert.deepEqual(rows.map((row) => row.action), ['create']);

    // Valid UTF-8 that is merely not-JSON keeps its route-specific code.
    const syntaxError = await request(server.url, 'POST', '/documents/a/restore', {
      rawBody: '{not json',
      headers: { 'if-match': et },
    });
    assert.equal(syntaxError.status, 400);
    assert.equal(syntaxError.body.code, 'INVALID_REVISION');
  } finally {
    await server.stop();
  }
});

// --- 413 precedence ---------------------------------------------------------

test('an oversized body that also contains invalid bytes is 413 (declared Content-Length)', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await rawExchange(server.url, '/documents', {
      'Content-Length': String(1024 * 1024 + 1),
      'Content-Type': 'application/json',
      'If-Match': et,
    }, (sock) => {
      // The declared length trips the limit before any byte is read; the body
      // itself starts with an invalid continuation byte.
      sock.end(Buffer.from([0x80]));
    });
    assert.equal(response.status, 413);
    assert.equal(response.body.code, 'PAYLOAD_TOO_LARGE');
    assert.deepEqual((await request(server.url, 'GET', '/documents')).body, []);
  } finally {
    await server.stop();
  }
});

test('an oversized stream that accumulates past 1 MiB with invalid bytes is 413', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const et = (await request(server.url, 'GET', '/documents')).etag;
    const response = await rawExchange(server.url, '/documents', {
      'Transfer-Encoding': 'chunked',
      'Content-Type': 'application/json',
      'If-Match': et,
    }, async (sock, peek) => {
      // Invalid byte right at the start; the byte-count limit must still win
      // while the stream is being accumulated.
      chunkFrame(sock, Buffer.from([0x7b, 0x80]));
      const pad = Buffer.alloc(64 * 1024, 0x78);
      let total = 2;
      while (total <= 1024 * 1024 && peek().indexOf('\r\n\r\n') === -1) {
        await sleep(5);
        chunkFrame(sock, pad);
        total += pad.length;
      }
      try { sock.end('0\r\n\r\n'); } catch { /* server already replied */ }
    });
    assert.equal(response.status, 413);
    assert.equal(response.body.code, 'PAYLOAD_TOO_LARGE');
    assert.deepEqual((await request(server.url, 'GET', '/documents')).body, []);
    assert.equal((await request(server.url, 'GET', '/documents')).etag, et);
  } finally {
    await server.stop();
  }
});
