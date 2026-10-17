const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

// Fake Sarvam + OpenAI so the real request shapes can be checked without keys.
const seen = {};
const upstream = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    if (req.url === '/speech-to-text') {
      seen.stt = { headers: req.headers, body: body.toString('latin1') };
      res.setHeader('Content-Type', 'application/json');
      return res.end(JSON.stringify({ request_id: 'r1', transcript: 'Sir OTP bata dijiye 4 8 2 1', language_code: 'hi-IN' }));
    }
    if (req.url === '/v1/chat/completions') {
      seen.ai = { headers: req.headers, body: JSON.parse(body.toString('utf8')) };
      const verdict = { risk_score: 93, verdict: 'scam', scam_type: 'Bank OTP fraud', red_flags: [{ label: 'Asks for OTP', quote: 'OTP bata dijiye' }], advice_en: 'Hang up now.', advice_hi: 'फोन काट दें।', say_this: 'I will call my bank myself.' };
      res.setHeader('Content-Type', 'application/json');
      return res.end(JSON.stringify({ choices: [{ message: { content: JSON.stringify(verdict) } }] }));
    }
    res.statusCode = 404; res.end('{}');
  });
});

let app, base;

function wav(bytes = 3200) {
  const b = Buffer.alloc(44 + bytes);
  b.write('RIFF', 0, 'ascii'); b.write('WAVE', 8, 'ascii');
  return b;
}

test.before(async () => {
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const up = `http://127.0.0.1:${upstream.address().port}`;
  Object.assign(process.env, {
    SARVAM_API_KEY: 'test-sarvam', SARVAM_BASE_URL: up, SARVAM_MODEL: 'saaras:v3', SARVAM_MODE: 'transcribe', SARVAM_LANGUAGE: 'unknown',
    OPENAI_API_KEY: 'test-openai', OPENAI_BASE_URL: `${up}/v1`, OPENAI_MODEL: 'test-model'
  });
  const { createServer } = require('../server.js');
  app = createServer();
  await new Promise((r) => app.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${app.address().port}`;
});

test.after(() => { app.close(); upstream.close(); });

test('status reports both services', async () => {
  const j = await (await fetch(`${base}/api/status`)).json();
  assert.deepEqual(j, { stt: true, sttModel: 'saaras:v3', ai: true, aiModel: 'test-model' });
});

test('/api/stt forwards the WAV to Sarvam with key, model, mode and language', async () => {
  const r = await fetch(`${base}/api/stt`, { method: 'POST', headers: { 'Content-Type': 'audio/wav' }, body: wav() });
  assert.equal(r.status, 200);
  assert.deepEqual(await r.json(), { text: 'Sir OTP bata dijiye 4 8 2 1', language: 'hi-IN' });
  assert.equal(seen.stt.headers['api-subscription-key'], 'test-sarvam');
  assert.match(seen.stt.headers['content-type'], /^multipart\/form-data; boundary=/);
  for (const [name, value] of [['model', 'saaras:v3'], ['mode', 'transcribe'], ['language_code', 'unknown']]) {
    assert.match(seen.stt.body, new RegExp(`name="${name}"\\r\\n\\r\\n${value}\\r\\n`));
  }
  assert.match(seen.stt.body, /name="file"; filename="chunk.wav"\r\nContent-Type: audio\/wav/);
});

test('/api/stt rejects non-WAV bodies', async () => {
  const r = await fetch(`${base}/api/stt`, { method: 'POST', body: 'hello' });
  assert.equal(r.status, 400);
});

test('/api/analyze masks digits before calling OpenAI and returns the verdict', async () => {
  const r = await fetch(`${base}/api/analyze`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ transcript: 'Sir OTP bata dijiye. Card 4111 1111 1111 1111' })
  });
  const j = await r.json();
  assert.equal(r.status, 200);
  assert.equal(j.ai, true);
  assert.equal(j.verdict, 'scam');
  assert.equal(j.score, 93);
  assert.equal(j.sayThis, 'I will call my bank myself.');
  assert.equal(j.rules.level, 'scam');
  const sent = JSON.stringify(seen.ai.body);
  assert.ok(!sent.includes('4111'), 'card number must not reach OpenAI');
  assert.equal(seen.ai.headers.authorization, 'Bearer test-openai');
  assert.equal(seen.ai.body.model, 'test-model');
  assert.deepEqual(seen.ai.body.response_format, { type: 'json_object' });
});

test('without keys: stt says how to fix it, analyze falls back to keywords', async () => {
  const saved = { s: process.env.SARVAM_API_KEY, o: process.env.OPENAI_API_KEY };
  delete process.env.SARVAM_API_KEY; delete process.env.OPENAI_API_KEY;
  try {
    const r1 = await fetch(`${base}/api/stt`, { method: 'POST', body: wav() });
    assert.equal(r1.status, 503);
    assert.match((await r1.json()).error, /SARVAM_API_KEY/);
    const r2 = await fetch(`${base}/api/analyze`, { method: 'POST', body: JSON.stringify({ transcript: 'You are under digital arrest' }) });
    const j = await r2.json();
    assert.equal(j.ai, false);
    assert.equal(j.rules.level, 'scam');
  } finally {
    process.env.SARVAM_API_KEY = saved.s; process.env.OPENAI_API_KEY = saved.o;
  }
});

test('static files are served and path traversal is blocked', async () => {
  const r = await fetch(`${base}/`);
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-security-policy'), /default-src 'self'/);
  assert.match(await r.text(), /Ruko Call Guard/);
  const bad = await fetch(`${base}/..%2fserver.js`);
  assert.notEqual(bad.status, 200);
});
