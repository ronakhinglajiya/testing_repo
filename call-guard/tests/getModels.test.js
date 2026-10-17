const test = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('node:zlib');
const { readZip, toTarGz, normalizeEntries } = require('../scripts/get-models.js');

// Build a small zip in memory (one stored file, one deflated file).
function makeZip(files) {
  const locals = [], centrals = [];
  let offset = 0;
  for (const [name, content, deflate] of files) {
    const data = Buffer.from(content);
    const comp = deflate ? zlib.deflateRawSync(data) : data;
    const nameBuf = Buffer.from(name);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(deflate ? 8 : 0, 8);
    lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(nameBuf.length, 26);
    locals.push(lh, nameBuf, comp);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(deflate ? 8 : 0, 10);
    ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(nameBuf.length, 28); ch.writeUInt32LE(offset, 42);
    centrals.push(ch, nameBuf);
    offset += 30 + nameBuf.length + comp.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(files.length, 8); eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

function tarNames(gz) {
  const tar = zlib.gunzipSync(gz);
  const names = [];
  for (let p = 0; p + 512 <= tar.length; ) {
    const name = tar.toString('utf8', p, p + 100).replace(/\0.*$/, '');
    if (!name) break;
    const size = parseInt(tar.toString('ascii', p + 124, p + 136), 8) || 0;
    names.push({ name, data: tar.subarray(p + 512, p + 512 + size).toString() });
    p += 512 + Math.ceil(size / 512) * 512;
  }
  return names;
}

test('reads stored and deflated zip entries', () => {
  const entries = readZip(makeZip([['am/final.mdl', 'acoustic', false], ['conf/model.conf', 'x'.repeat(2000), true]]));
  assert.deepEqual(entries.map((e) => e.name), ['am/final.mdl', 'conf/model.conf']);
  assert.equal(entries[1].data.toString(), 'x'.repeat(2000));
});

test('model without a top folder gets one (vosk-browser strips the first folder)', () => {
  const gz = toTarGz(readZip(makeZip([['am/final.mdl', 'acoustic', true], ['conf/model.conf', 'beam', false]])));
  const files = tarNames(gz);
  assert.deepEqual(files.map((f) => f.name), ['model/', 'model/am/', 'model/conf/', 'model/am/final.mdl', 'model/conf/model.conf']);
  assert.equal(files.find((f) => f.name === 'model/am/final.mdl').data, 'acoustic');
});

test('official model zips keep their own top folder', () => {
  const names = normalizeEntries(readZip(makeZip([['vosk-model-small-hi-0.22/am/final.mdl', 'a', true]]))).map((e) => e.name);
  assert.deepEqual(names, ['vosk-model-small-hi-0.22/', 'vosk-model-small-hi-0.22/am/', 'vosk-model-small-hi-0.22/am/final.mdl']);
});
