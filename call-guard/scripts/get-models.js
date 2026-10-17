#!/usr/bin/env node
'use strict';

/*
 * Downloads the free Vosk speech models (Hindi and Indian English, about 40 MB
 * each) and converts them to the .tar.gz format vosk-browser loads.
 * One-time setup; after this everything runs offline.
 *
 *   npm run models              download both
 *   npm run models -- hi        only Hindi
 *   npm run models -- --from vosk-model-small-hi-0.22.zip --as hi
 *                               convert a zip you downloaded yourself
 *
 * No dependencies: the zip reader and tar writer below use only Node built-ins.
 */

const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

const MODELS = {
  hi: { name: 'Hindi', url: 'https://alphacephei.com/vosk/models/vosk-model-small-hi-0.22.zip' },
  'en-in': { name: 'English (India)', url: 'https://alphacephei.com/vosk/models/vosk-model-small-en-in-0.4.zip' }
};
const OUT_DIR = path.join(__dirname, '..', 'public', 'models');

// ---------- zip reading ----------
function readZip(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd === -1) throw new Error('Not a zip file (end of central directory not found).');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  const entries = [];
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('Corrupt zip central directory.');
    const method = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOffset = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    p += 46 + nameLen + extraLen + commentLen;

    const lNameLen = buf.readUInt16LE(localOffset + 26);
    const lExtraLen = buf.readUInt16LE(localOffset + 28);
    const start = localOffset + 30 + lNameLen + lExtraLen;
    const raw = buf.subarray(start, start + compSize);
    const isDir = name.endsWith('/');
    let data = Buffer.alloc(0);
    if (!isDir) {
      if (method === 0) data = Buffer.from(raw);
      else if (method === 8) data = zlib.inflateRawSync(raw);
      else throw new Error(`Unsupported zip compression method ${method} for ${name}.`);
    }
    entries.push({ name, isDir, data });
  }
  return entries;
}

// ---------- tar writing (ustar) ----------
function octal(n, width) {
  return n.toString(8).padStart(width - 1, '0') + '\0';
}

function tarHeader(name, size, isDir) {
  const h = Buffer.alloc(512);
  let prefix = '';
  if (Buffer.byteLength(name) > 100) {
    const cut = name.lastIndexOf('/', name.length - 2);
    prefix = name.slice(0, cut);
    name = name.slice(cut + 1);
    if (Buffer.byteLength(name) > 100 || Buffer.byteLength(prefix) > 155) throw new Error(`Path too long for tar: ${prefix}/${name}`);
  }
  h.write(name, 0, 100, 'utf8');
  h.write(octal(isDir ? 0o755 : 0o644, 8), 100, 'ascii');
  h.write(octal(0, 8), 108, 'ascii');
  h.write(octal(0, 8), 116, 'ascii');
  h.write(octal(size, 12), 124, 'ascii');
  h.write(octal(Math.floor(Date.now() / 1000), 12), 136, 'ascii');
  h.write('        ', 148, 'ascii');
  h.write(isDir ? '5' : '0', 156, 'ascii');
  h.write('ustar\0', 257, 'ascii');
  h.write('00', 263, 'ascii');
  h.write(prefix, 345, 155, 'utf8');
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += h[i];
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 'ascii');
  return h;
}

// vosk-browser always strips the first path component when it unpacks the
// archive, so every file must sit under exactly one top-level folder, and each
// folder gets its own entry so it exists before its files are written.
function normalizeEntries(entries) {
  const files = entries.filter((e) => !e.isDir && e.name && !e.name.startsWith('__MACOSX/'));
  const tops = new Set(files.map((e) => e.name.split('/')[0]));
  const nested = tops.size === 1 && files.every((e) => e.name.includes('/'));
  const rel = files.map((e) => ({ ...e, name: nested ? e.name : `model/${e.name}` }));
  const dirs = new Set();
  for (const e of rel) {
    const segs = e.name.split('/');
    for (let i = 1; i < segs.length; i++) dirs.add(segs.slice(0, i).join('/') + '/');
  }
  const dirEntries = [...dirs].sort().map((name) => ({ name, isDir: true, data: Buffer.alloc(0) }));
  return dirEntries.concat(rel);
}

function toTarGz(rawEntries) {
  const entries = normalizeEntries(rawEntries);
  const parts = [];
  for (const e of entries) {
    parts.push(tarHeader(e.name, e.isDir ? 0 : e.data.length, e.isDir));
    if (!e.isDir) {
      parts.push(e.data);
      const pad = (512 - (e.data.length % 512)) % 512;
      if (pad) parts.push(Buffer.alloc(pad));
    }
  }
  parts.push(Buffer.alloc(1024));
  return zlib.gzipSync(Buffer.concat(parts), { level: 6 });
}

function convert(zipBuf, id) {
  const entries = readZip(zipBuf);
  if (!entries.some((e) => /(^|\/)am\/final\.mdl$/.test(e.name))) {
    throw new Error('This zip does not look like a Vosk model (am/final.mdl is missing).');
  }
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const out = path.join(OUT_DIR, `${id}.tar.gz`);
  fs.writeFileSync(out, toTarGz(entries));
  return out;
}

async function download(url) {
  process.stdout.write(`  downloading ${url}\n`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Download failed (${res.status}) for ${url}`);
  const total = Number(res.headers.get('content-length')) || 0;
  const chunks = [];
  let got = 0, lastPct = -1;
  for await (const chunk of res.body) {
    chunks.push(chunk);
    got += chunk.length;
    const pct = total ? Math.floor((got / total) * 100) : -1;
    if (pct !== lastPct && pct % 10 === 0) { process.stdout.write(`  ${pct}%\n`); lastPct = pct; }
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c)));
}

async function main(argv) {
  const fromIdx = argv.indexOf('--from');
  if (fromIdx !== -1) {
    const zip = argv[fromIdx + 1];
    const asIdx = argv.indexOf('--as');
    const id = asIdx !== -1 ? argv[asIdx + 1] : 'hi';
    if (!zip) throw new Error('Usage: npm run models -- --from <model.zip> --as hi|en-in');
    const out = convert(fs.readFileSync(zip), id);
    console.log(`Saved ${path.relative(process.cwd(), out)}`);
    return;
  }
  const wanted = argv.filter((a) => MODELS[a]);
  const ids = wanted.length ? wanted : Object.keys(MODELS);
  for (const id of ids) {
    console.log(`${MODELS[id].name} model:`);
    const out = convert(await download(MODELS[id].url), id);
    console.log(`  saved ${path.relative(process.cwd(), out)}`);
  }
  console.log('Done. Restart the server; live listening now works offline.');
}

if (require.main === module) {
  main(process.argv.slice(2)).catch((err) => {
    console.error(`\nCould not get the models: ${err.message}`);
    console.error('You can download the zip in a browser from https://alphacephei.com/vosk/models and run:');
    console.error('  npm run models -- --from vosk-model-small-hi-0.22.zip --as hi');
    process.exit(1);
  });
}

module.exports = { readZip, toTarGz, normalizeEntries, convert, MODELS };
