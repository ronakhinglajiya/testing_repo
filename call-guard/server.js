'use strict';

/*
 * Ruko Call Guard server.
 * - Serves the web app from ./public
 * - POST /api/stt      audio/wav chunk  -> Sarvam speech-to-text -> { text, language }
 * - POST /api/analyze  { transcript }   -> OpenAI scam verdict     -> { ai, ... }
 * - GET  /api/status   which services are configured
 * API keys stay on the server. Nothing is written to disk or logged.
 */

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

try { process.loadEnvFile(path.join(__dirname, '.env')); } catch { /* .env is optional */ }

const { transcribeWithSarvam } = require('./lib/sarvam');
const { analyzeWithOpenAI } = require('./lib/openai');
const ScamRules = require('./public/scamRules.js');

const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_AUDIO_BYTES = 2 * 1024 * 1024; // ~60 s of 16 kHz mono WAV; chunks are ~5 s
const MAX_JSON_BYTES = 64 * 1024;
const MAX_TRANSCRIPT_CHARS = 6000;

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.json': 'application/json'
};

const SECURITY_HEADERS = {
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "connect-src 'self'",
    "media-src 'self' blob:",
    "img-src 'self' data:",
    "worker-src 'self'"
  ].join('; '),
  'Permissions-Policy': 'microphone=(self), display-capture=(self), screen-wake-lock=(self)',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff'
};

function config() {
  const env = process.env;
  return {
    sarvam: {
      apiKey: env.SARVAM_API_KEY || '',
      baseUrl: (env.SARVAM_BASE_URL || 'https://api.sarvam.ai').replace(/\/$/, ''),
      model: env.SARVAM_MODEL || 'saaras:v3',
      mode: env.SARVAM_MODE || 'transcribe',
      language: env.SARVAM_LANGUAGE || 'unknown'
    },
    openai: {
      apiKey: env.OPENAI_API_KEY || '',
      baseUrl: (env.OPENAI_BASE_URL || 'https://api.openai.com/v1').replace(/\/$/, ''),
      model: env.OPENAI_MODEL || 'gpt-4.1-mini'
    }
  };
}

function send(res, status, body, headers = {}) {
  const isJson = typeof body !== 'string' && !Buffer.isBuffer(body);
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    'Cache-Control': 'no-store',
    ...(isJson ? { 'Content-Type': 'application/json; charset=utf-8' } : {}),
    ...headers
  });
  res.end(isJson ? JSON.stringify(body) : body);
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(Object.assign(new Error('Request body is too large.'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function handleStt(req, res) {
  const cfg = config().sarvam;
  if (!cfg.apiKey) return send(res, 503, { error: 'Speech-to-text is not set up. Add SARVAM_API_KEY to call-guard/.env and restart the server.' });
  const audio = await readBody(req, MAX_AUDIO_BYTES);
  if (audio.length < 44 || audio.toString('ascii', 0, 4) !== 'RIFF') return send(res, 400, { error: 'Expected a WAV audio chunk.' });
  const result = await transcribeWithSarvam(audio, cfg);
  send(res, 200, result);
}

async function handleAnalyze(req, res) {
  const raw = await readBody(req, MAX_JSON_BYTES);
  let body;
  try { body = JSON.parse(raw.toString('utf8') || '{}'); } catch { return send(res, 400, { error: 'Body must be JSON.' }); }

  // Mask digits again on the server so OTPs or card numbers never reach the AI.
  const transcript = ScamRules.maskNumbers(String(body.transcript || '')).text.slice(-MAX_TRANSCRIPT_CHARS).trim();
  if (!transcript) return send(res, 400, { error: 'Transcript is empty.' });

  const rules = ScamRules.analyze(transcript);
  const cfg = config().openai;
  if (!cfg.apiKey) return send(res, 200, { ai: false, rules });

  const ruleIds = rules.flags.map((f) => f.id);
  const verdict = await analyzeWithOpenAI(transcript, ruleIds, cfg);
  send(res, 200, { ai: true, model: cfg.model, ...verdict, rules });
}

function serveStatic(req, res) {
  let urlPath;
  try { urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname); } catch { return send(res, 400, 'Bad request', { 'Content-Type': 'text/plain' }); }
  if (urlPath === '/') urlPath = '/index.html';
  const file = path.normalize(path.join(PUBLIC_DIR, urlPath));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) return send(res, 403, 'Forbidden', { 'Content-Type': 'text/plain' });
  fs.readFile(file, (err, data) => {
    if (err) return send(res, 404, 'Not found', { 'Content-Type': 'text/plain' });
    send(res, 200, data, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
  });
}

function createServer() {
  return http.createServer(async (req, res) => {
    try {
      const { pathname } = new URL(req.url, 'http://x');
      if (pathname === '/api/status' && req.method === 'GET') {
        const c = config();
        return send(res, 200, {
          stt: Boolean(c.sarvam.apiKey), sttModel: c.sarvam.model,
          ai: Boolean(c.openai.apiKey), aiModel: c.openai.model
        });
      }
      if (pathname === '/api/stt' && req.method === 'POST') return await handleStt(req, res);
      if (pathname === '/api/analyze' && req.method === 'POST') return await handleAnalyze(req, res);
      if (pathname.startsWith('/api/')) return send(res, 404, { error: 'Unknown API route.' });
      if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { error: 'Method not allowed.' });
      return serveStatic(req, res);
    } catch (err) {
      if (!res.headersSent) send(res, err.status || 500, { error: err.message || 'Server error.' });
    }
  });
}

if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  const host = process.env.HOST || '127.0.0.1';
  createServer().listen(port, host, () => {
    const c = config();
    console.log(`Ruko Call Guard running at http://${host === '0.0.0.0' ? 'localhost' : host}:${port}`);
    console.log(`  Speech-to-text (Sarvam ${c.sarvam.model}): ${c.sarvam.apiKey ? 'ON' : 'OFF - add SARVAM_API_KEY to .env'}`);
    console.log(`  AI analysis (OpenAI ${c.openai.model}):    ${c.openai.apiKey ? 'ON' : 'OFF - add OPENAI_API_KEY to .env (keyword detector still works)'}`);
  });
}

module.exports = { createServer, config };
