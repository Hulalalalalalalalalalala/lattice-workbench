import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { spawn } from 'node:child_process';
import test from 'node:test';

const CLI = path.resolve('src/cli.js');

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-utf8-'));
}

async function startServer(args, { cwd } = {}) {
  const child = spawn(process.execPath, [CLI, 'serve', ...args], { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
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
    stderr: () => stderr,
    stop: () => new Promise((resolve) => {
      child.once('exit', resolve);
      child.kill('SIGKILL');
    }),
  };
}

// Sends a raw Buffer. Without content-length, fetch uses chunked transfer
// encoding; `splitAt` cuts the buffer so a multibyte character can straddle
// two transport frames.
async function sendRaw(base, method, route, raw, { etag, splitAt, extraHeaders } = {}) {
  const headers = { 'content-type': 'application/json', ...extraHeaders };
  if (etag !== undefined) headers['if-match'] = etag;
  let body;
  let duplex;
  if (splitAt === undefined) {
    body = raw;
  } else {
    delete headers['content-length'];
    body = Readable.from([raw.subarray(0, splitAt), raw.subarray(splitAt)]);
    duplex = 'half';
  }
  const response = await fetch(`${base}${route}`, { method, headers, body, duplex });
  const text = await response.text();
  return {
    status: response.status,
    etag: response.headers.get('etag'),
    body: text ? JSON.parse(text) : null,
  };
}

// Every kind of byte sequence the fix must refuse, placed inside a JSON
// string value. The surrounding JSON is otherwise well-formed.
const ILLEGAL_SEQUENCES = {
  'lone continuation byte': Buffer.from([0x80]),
  'truncated three-byte character': Buffer.from([0xe4, 0xb8]),
  'truncated two-byte character': Buffer.from([0xc3]),
  'overlong encoding': Buffer.from([0xc0, 0xaf]),
  'surrogate code point': Buffer.from([0xed, 0xa0, 0x80]),
  'code point beyond Unicode': Buffer.from([0xf4, 0x90, 0x80, 0x80]),
  'five-byte sequence': Buffer.from([0xf8, 0x80, 0x80, 0x80, 0x80]),
};

function documentWithValue(valueBytes) {
  return Buffer.concat([
    Buffer.from('{"id":"a","title":"', 'utf8'),
    valueBytes,
    Buffer.from('","body":"body","tags":[]}', 'utf8'),
  ]);
}

test('illegal UTF-8 in document fields is 400 INVALID_JSON and leaves everything untouched', async () => {
  const cwd = tempDir();
  const history = path.join(cwd, 'history.json');
  const server = await startServer([path.join(cwd, 'snap.json'), '--history', history, '--port', '0']);
  try {
    const etag = (await fetch(`${server.url}/documents`)).headers.get('etag');

    for (const [label, bytes] of Object.entries(ILLEGAL_SEQUENCES)) {
      for (const [field, raw] of Object.entries({
        title: documentWithValue(bytes),
        body: Buffer.concat([
          Buffer.from('{"id":"a","title":"A","body":"', 'utf8'),
          bytes,
          Buffer.from('","tags":[]}', 'utf8'),
        ]),
        tags: Buffer.concat([
          Buffer.from('{"id":"a","title":"A","body":"body","tags":["', 'utf8'),
          bytes,
          Buffer.from('"]}', 'utf8'),
        ]),
      })) {
        const response = await sendRaw(server.url, 'POST', '/documents', raw, { etag });
        assert.equal(response.status, 400, `${label} in ${field}`);
        assert.equal(response.body.code, 'INVALID_JSON', `${label} in ${field}`);
      }
    }

    // Nothing was written: no documents, the original ETag, no files, and no
    // history ledger.
    const after = await fetch(`${server.url}/documents`);
    assert.deepEqual(await after.json(), []);
    assert.equal(after.headers.get('etag'), etag);
    assert.ok(!fs.existsSync(path.join(cwd, 'snap.json')));
    assert.ok(!fs.existsSync(history));
  } finally {
    await server.stop();
  }
});

test('illegal UTF-8 after a successful write does not change content, ETag, or history', async () => {
  const cwd = tempDir();
  const history = path.join(cwd, 'history.json');
  const server = await startServer([path.join(cwd, 'snap.json'), '--history', history, '--port', '0']);
  try {
    const firstEtag = (await fetch(`${server.url}/documents`)).headers.get('etag');
    const created = await sendRaw(
      server.url, 'POST', '/documents',
      Buffer.from(JSON.stringify({ id: 'a', title: 'Alpha', body: 'original', tags: [] }), 'utf8'),
      { etag: firstEtag },
    );
    assert.equal(created.status, 201);
    const etag = created.etag;

    // A PUT carrying an illegal byte is rejected wholesale.
    const bad = await sendRaw(
      server.url, 'PUT', '/documents/a',
      Buffer.concat([
        Buffer.from('{"id":"a","title":"Alpha","body":"new ', 'utf8'),
        Buffer.from([0xe4, 0xb8]),
        Buffer.from('","tags":[]}', 'utf8'),
      ]),
      { etag },
    );
    assert.equal(bad.status, 400);
    assert.equal(bad.body.code, 'INVALID_JSON');

    // The stored body, ETag, and history chain are all unchanged.
    const fetched = await (await fetch(`${server.url}/documents/a`)).json();
    assert.equal(fetched.body, 'original');
    assert.equal((await fetch(`${server.url}/documents`)).headers.get('etag'), etag);
    const records = await (await fetch(`${server.url}/documents/a/history`)).json();
    assert.deepEqual(records.map((entry) => entry.action), ['create']);
  } finally {
    await server.stop();
  }
});

test('valid Chinese, emoji, and an encoded U+FFFD are stored verbatim', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const etag = (await fetch(`${server.url}/documents`)).headers.get('etag');
    const title = '中文笔记';
    const body = '你好世界 😀 �';
    const tags = ['标签', '😀'];
    const raw = Buffer.from(JSON.stringify({ id: 'a', title, body, tags }), 'utf8');
    const created = await sendRaw(server.url, 'POST', '/documents', raw, { etag });
    assert.equal(created.status, 201);

    const fetched = await (await fetch(`${server.url}/documents/a`)).json();
    assert.equal(fetched.title, title);
    assert.equal(fetched.body, body);
    assert.deepEqual(fetched.tags, tags);
    // The legitimately encoded replacement character survives as itself; it
    // is not treated as evidence of a decode error.
    assert.ok(fetched.body.includes('�'));
  } finally {
    await server.stop();
  }
});

test('a multibyte character split across chunked frames gives the same result as one send', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const etag = (await fetch(`${server.url}/documents`)).headers.get('etag');
    const raw = Buffer.from(JSON.stringify({
      id: 'a',
      title: 'A',
      body: 'x'.repeat(100) + '中文😀' + 'y'.repeat(100),
      tags: [],
    }), 'utf8');

    // Split at every byte boundary around the multibyte run; the character
    // straddles the two frames whenever the cut lands inside it.
    const multibyteStart = Buffer.from('x'.repeat(100), 'utf8').length;
    for (const splitAt of [multibyteStart, multibyteStart + 1, multibyteStart + 2, multibyteStart + 3]) {
      const response = await sendRaw(server.url, 'POST', '/documents', raw, { etag, splitAt });
      assert.equal(response.status, 201, `split at ${splitAt}`);
      const fetched = await (await fetch(`${server.url}/documents/a`)).json();
      assert.equal(fetched.body, 'x'.repeat(100) + '中文😀' + 'y'.repeat(100));
      // Remove it again for the next split attempt.
      const nextEtag = response.etag;
      const removed = await fetch(`${server.url}/documents/a`, { method: 'DELETE', headers: { 'if-match': nextEtag } });
      assert.equal(removed.status, 200);
    }
  } finally {
    await server.stop();
  }
});

test('JSON escapes keep their string semantics, including surrogate escapes', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const etag = (await fetch(`${server.url}/documents`)).headers.get('etag');
    // A paired surrogate escape decodes to an emoji; a lone surrogate escape
    // keeps being accepted as before (it is valid JSON text, not bad UTF-8).
    const raw = Buffer.from('{"id":"a","title":"emoji \\uD83D\\uDE00 lone \\uD800","body":"\\u4e2d\\u6587","tags":[]}', 'utf8');
    const created = await sendRaw(server.url, 'POST', '/documents', raw, { etag });
    assert.equal(created.status, 201);
    const fetched = await (await fetch(`${server.url}/documents/a`)).json();
    assert.equal(fetched.title, 'emoji 😀 lone \uD800');
    assert.equal(fetched.body, '中文');
  } finally {
    await server.stop();
  }
});

test('batch rejects the whole request when one string carries illegal bytes', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const etag = (await fetch(`${server.url}/documents`)).headers.get('etag');
    // The second operation is valid; the illegal bytes in the first must
    // still reject the entire batch atomically.
    const raw = Buffer.concat([
      Buffer.from('{"operations":[{"type":"create","document":{"id":"a","title":"', 'utf8'),
      Buffer.from([0xed, 0xa0, 0x80]),
      Buffer.from('","body":"a","tags":[]}},', 'utf8'),
      Buffer.from(JSON.stringify({ type: 'create', document: { id: 'b', title: 'B', body: 'b', tags: [] } }), 'utf8').subarray(1),
      Buffer.from(']}', 'utf8'),
    ]);
    const response = await sendRaw(server.url, 'POST', '/batch', raw, { etag });
    assert.equal(response.status, 400);
    assert.equal(response.body.code, 'INVALID_JSON');
    assert.deepEqual(await (await fetch(`${server.url}/documents`)).json(), []);
    assert.equal((await fetch(`${server.url}/documents`)).headers.get('etag'), etag);

    // A dry-run preview is refused identically.
    const preview = await sendRaw(server.url, 'POST', '/batch', raw, {
      etag,
      splitAt: 20,
    });
    assert.equal(preview.status, 400);
    assert.equal(preview.body.code, 'INVALID_JSON');
  } finally {
    await server.stop();
  }
});

test('reconcile rejects illegal bytes in either snapshot', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const etag = (await fetch(`${server.url}/documents`)).headers.get('etag');
    // A syntactically valid envelope whose incoming document string holds a
    // lone continuation byte.
    const raw = Buffer.concat([
      Buffer.from('{"base":{"version":1,"documents":[],"checksum":"0000000000000000000000000000000000000000000000000000000000000000"},"incoming":{"version":1,"documents":[{"id":"a","title":"A","body":"', 'utf8'),
      Buffer.from([0x80]),
      Buffer.from('","tags":[]}]}}', 'utf8'),
    ]);
    const response = await sendRaw(server.url, 'POST', '/snapshots/reconcile', raw, { etag });
    assert.equal(response.status, 400);
    assert.equal(response.body.code, 'INVALID_JSON');
    assert.equal((await fetch(`${server.url}/documents`)).headers.get('etag'), etag);

    // dryRun previews follow the same rule.
    const preview = await sendRaw(server.url, 'POST', '/snapshots/reconcile', raw, {
      etag,
      splitAt: 30,
    });
    assert.equal(preview.status, 400);
    assert.equal(preview.body.code, 'INVALID_JSON');
  } finally {
    await server.stop();
  }
});

test('tag rewrite rejects illegal bytes in rule strings', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const etag = (await fetch(`${server.url}/documents`)).headers.get('etag');
    const raw = Buffer.concat([
      Buffer.from('{"rules":[{"from":"', 'utf8'),
      Buffer.from([0xf4, 0x90, 0x80, 0x80]),
      Buffer.from('","to":"b"}],"dryRun":true}', 'utf8'),
    ]);
    const response = await sendRaw(server.url, 'POST', '/tags/rewrite', raw, { etag });
    assert.equal(response.status, 400);
    assert.equal(response.body.code, 'INVALID_JSON');
  } finally {
    await server.stop();
  }
});

test('restore rejects illegal UTF-8 before touching the revision ledger', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--history', path.join(cwd, 'h.json'), '--port', '0']);
  try {
    const etag = (await fetch(`${server.url}/documents`)).headers.get('etag');
    const created = await sendRaw(
      server.url, 'POST', '/documents',
      Buffer.from(JSON.stringify({ id: 'a', title: 'A', body: 'a', tags: [] }), 'utf8'),
      { etag },
    );
    assert.equal(created.status, 201);

    // A truncated multibyte sequence inside the otherwise-valid restore body.
    const raw = Buffer.concat([
      Buffer.from('{"revision"', 'utf8'),
      Buffer.from([0xc3]),
      Buffer.from(':1}', 'utf8'),
    ]);
    const response = await sendRaw(server.url, 'POST', '/documents/a/restore', raw, { etag: created.etag });
    assert.equal(response.status, 400);
    assert.equal(response.body.code, 'INVALID_JSON');
    const records = await (await fetch(`${server.url}/documents/a/history`)).json();
    assert.deepEqual(records.map((entry) => entry.action), ['create']);
  } finally {
    await server.stop();
  }
});

test('oversize bodies stay 413 even when they also contain illegal bytes', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const etag = (await fetch(`${server.url}/documents`)).headers.get('etag');

    // Declared over length via Content-Length: size wins before any decode.
    const oversized = Buffer.from(JSON.stringify({
      id: 'a', title: 'A', body: 'x'.repeat(1024 * 1024), tags: [],
    }), 'utf8');
    oversized[oversized.length - 10] = 0xff;
    const byLength = await sendRaw(server.url, 'POST', '/documents', oversized, { etag });
    assert.equal(byLength.status, 413);
    assert.equal(byLength.body.code, 'PAYLOAD_TOO_LARGE');

    // Chunked with no Content-Length: accumulated size trips 413 mid-stream.
    const streamed = await sendRaw(server.url, 'POST', '/documents', oversized, { etag, splitAt: 4096 });
    assert.equal(streamed.status, 413);
    assert.equal(streamed.body.code, 'PAYLOAD_TOO_LARGE');
  } finally {
    await server.stop();
  }
});

test('valid UTF-8 with JSON syntax errors still reports INVALID_JSON only once parsed', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const etag = (await fetch(`${server.url}/documents`)).headers.get('etag');
    const response = await sendRaw(
      server.url, 'POST', '/documents',
      Buffer.from('{"id":"a","title":"中文",', 'utf8'),
      { etag },
    );
    assert.equal(response.status, 400);
    assert.equal(response.body.code, 'INVALID_JSON');
  } finally {
    await server.stop();
  }
});

test('If-Match and feature-availability gates take precedence over UTF-8 decoding', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const etag = (await fetch(`${server.url}/documents`)).headers.get('etag');
    const bad = Buffer.concat([
      Buffer.from('{"id":"a","title":"A","body":"', 'utf8'),
      Buffer.from([0x80]),
      Buffer.from('","tags":[]}', 'utf8'),
    ]);

    const missing = await sendRaw(server.url, 'POST', '/documents', bad);
    assert.equal(missing.status, 428);
    assert.equal(missing.body.code, 'PRECONDITION_REQUIRED');

    const malformed = await sendRaw(server.url, 'POST', '/documents', bad, { extraHeaders: { 'if-match': 'garbage' } });
    assert.equal(malformed.status, 400);
    assert.equal(malformed.body.code, 'INVALID_IF_MATCH');

    const stale = await sendRaw(server.url, 'POST', '/documents', bad, {
      extraHeaders: { 'if-match': `"${'0'.repeat(64)}"` },
    });
    assert.equal(stale.status, 412);
    assert.equal(stale.body.code, 'PRECONDITION_FAILED');

    // The body only reaches the decoder once If-Match passes, at which point
    // the invalid bytes surface as INVALID_JSON.
    const decoded = await sendRaw(server.url, 'POST', '/documents', bad, { etag });
    assert.equal(decoded.status, 400);
    assert.equal(decoded.body.code, 'INVALID_JSON');
    assert.equal((await fetch(`${server.url}/documents`)).headers.get('etag'), etag);
  } finally {
    await server.stop();
  }
});

test('restore without history answers 404 even when the body carries illegal bytes', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const etag = (await fetch(`${server.url}/documents`)).headers.get('etag');
    const bad = Buffer.concat([Buffer.from('{"revision"', 'utf8'), Buffer.from([0x80]), Buffer.from(':1}', 'utf8')]);
    const response = await sendRaw(server.url, 'POST', '/documents/a/restore', bad, { etag });
    assert.equal(response.status, 404);
    assert.equal(response.body.code, 'NOT_FOUND');
  } finally {
    await server.stop();
  }
});

test('illegal bytes split across chunked frames are still rejected', async () => {
  const cwd = tempDir();
  const server = await startServer([path.join(cwd, 'snap.json'), '--port', '0']);
  try {
    const etag = (await fetch(`${server.url}/documents`)).headers.get('etag');
    const raw = Buffer.concat([
      Buffer.from('{"id":"a","title":"A","body":"x', 'utf8'),
      Buffer.from([0xed, 0xa0, 0x80]), // encodes U+D800: invalid even when complete
      Buffer.from('y","tags":[]}', 'utf8'),
    ]);
    // Cut between the lead byte and its first continuation, and again after
    // one continuation: the character straddles the frames but the server
    // concatenates before decoding, so it still fails.
    const lead = raw.indexOf(0xed);
    for (const splitAt of [lead + 1, lead + 2]) {
      const response = await sendRaw(server.url, 'POST', '/documents', raw, { etag, splitAt });
      assert.equal(response.status, 400, `split at ${splitAt}`);
      assert.equal(response.body.code, 'INVALID_JSON', `split at ${splitAt}`);
      assert.equal((await fetch(`${server.url}/documents`)).headers.get('etag'), etag);
    }
  } finally {
    await server.stop();
  }
});
