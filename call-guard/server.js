'use strict';

/*
 * Ruko Call Guard server: serves the app files and nothing else.
 * There is no API, no key and no cloud call. Speech recognition (Vosk) and
 * fraud detection both run inside the browser, so call audio never leaves
 * the device. The server only exists because browsers block the microphone,
 * Web Workers and model downloads on file:// pages.
 */

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const PUBLIC_DIR = path.join(__dirname, 'public');
const VOSK_JS = path.join(__dirname, 'node_modules', 'vosk-browser', 'dist', 'vosk.js');

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.gz': 'application/gzip'
};

const SECURITY_HEADERS = {
  'Content-Security-Policy': [
    "default-src 'self'",
    // Vosk runs WebAssembly inside a Web Worker it creates from a blob: URL, and
    // its Emscripten glue code uses eval. Scripts still only load from this
    // server and connect-src keeps everything on this server.
    "script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval'",
    "worker-src 'self' blob:",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    'font-src https://fonts.gstatic.com',
    "connect-src 'self'",
    "media-src 'self' blob:",
    "img-src 'self' data:"
  ].join('; '),
  'Permissions-Policy': 'microphone=(self), display-capture=(self), screen-wake-lock=(self)',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff'
};

function send(res, status, body, headers = {}) {
  res.writeHead(status, { ...SECURITY_HEADERS, ...headers });
  res.end(body);
}

function sendFile(req, res, file) {
  fs.stat(file, (err, stat) => {
    if (err || !stat.isFile()) return send(res, 404, 'Not found', { 'Content-Type': 'text/plain; charset=utf-8' });
    // Models are large and never change for a given file name: let the browser keep them.
    const cache = /\.tar\.gz$/.test(file) || file === VOSK_JS ? 'public, max-age=604800' : 'no-cache';
    res.writeHead(200, {
      ...SECURITY_HEADERS,
      'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream',
      'Content-Length': stat.size,
      'Cache-Control': cache
    });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  });
}

// Which offline speech models are installed (see scripts/get-models.js).
function installedModels() {
  return ['hi', 'en-in'].filter((m) => fs.existsSync(path.join(PUBLIC_DIR, 'models', `${m}.tar.gz`)));
}

function createServer() {
  return http.createServer((req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return send(res, 405, 'Method not allowed', { 'Content-Type': 'text/plain; charset=utf-8', Allow: 'GET, HEAD' });
    }
    let urlPath;
    try { urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname); } catch {
      return send(res, 400, 'Bad request', { 'Content-Type': 'text/plain; charset=utf-8' });
    }
    if (urlPath === '/vendor/vosk.js') return sendFile(req, res, VOSK_JS);
    if (urlPath === '/models/index.json') {
      return send(res, 200, JSON.stringify(installedModels()), { 'Content-Type': TYPES['.json'], 'Cache-Control': 'no-store' });
    }
    if (urlPath === '/') urlPath = '/index.html';
    const file = path.normalize(path.join(PUBLIC_DIR, urlPath));
    if (!file.startsWith(PUBLIC_DIR + path.sep)) {
      return send(res, 403, 'Forbidden', { 'Content-Type': 'text/plain; charset=utf-8' });
    }
    return sendFile(req, res, file);
  });
}

if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  const host = process.env.HOST || '127.0.0.1';
  createServer().listen(port, host, () => {
    const models = installedModels();
    console.log(`Ruko Call Guard running at http://${host === '0.0.0.0' ? 'localhost' : host}:${port}`);
    console.log(`  Speech engine (Vosk, on-device): ${fs.existsSync(VOSK_JS) ? 'installed' : 'MISSING - run npm install'}`);
    console.log(`  Speech models: ${models.length ? models.join(', ') : 'none - run npm run models (demo and typing still work)'}`);
    console.log('  Fraud detection: on-device rules. No API keys, nothing leaves this device.');
  });
}

module.exports = { createServer };
