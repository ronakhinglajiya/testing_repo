const test = require('node:test');
const assert = require('node:assert/strict');
const { createServer } = require('../server.js');

let app, base;
test.before(async () => {
  app = createServer();
  await new Promise((r) => app.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${app.address().port}`;
});
test.after(() => app.close());

test('serves the app with a strict security policy', async () => {
  const r = await fetch(`${base}/`);
  assert.equal(r.status, 200);
  const csp = r.headers.get('content-security-policy');
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /connect-src 'self'/, 'the page may only talk to this server');
  assert.match(await r.text(), /Ruko Call Guard/);
});

test('serves the Vosk speech engine from node_modules', async () => {
  const r = await fetch(`${base}/vendor/vosk.js`, { method: 'HEAD' });
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-type'), /javascript/);
});

test('lists installed speech models; a missing model file is a 404', async () => {
  const list = await (await fetch(`${base}/models/index.json`)).json();
  assert.ok(Array.isArray(list));
  assert.ok(list.every((m) => ['hi', 'en-in'].includes(m)));
  assert.equal((await fetch(`${base}/models/does-not-exist.tar.gz`, { method: 'HEAD' })).status, 404);
});

test('there is no API: nothing accepts uploads', async () => {
  for (const p of ['/api/stt', '/api/analyze', '/']) {
    const r = await fetch(`${base}${p}`, { method: 'POST', body: 'x' });
    assert.equal(r.status, 405, p);
  }
});

test('path traversal is blocked', async () => {
  const r = await fetch(`${base}/..%2fserver.js`);
  assert.notEqual(r.status, 200);
});
