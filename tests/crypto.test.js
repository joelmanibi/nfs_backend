'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Writable } = require('node:stream');
const { pipeline } = require('node:stream');
const { promisify } = require('node:util');

const { generateIv, encryptFileStream, createDecipherStream } = require('../helpers/crypto');

const pipelineAsync = promisify(pipeline);
const TEST_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

test('generateIv returns a 32-char hex string (16 random bytes)', () => {
  const iv = generateIv();

  assert.equal(iv.length, 32);
  assert.match(iv, /^[0-9a-f]{32}$/);
  assert.notEqual(iv, generateIv());
});

test('encryptFileStream + createDecipherStream round-trip a file without buffering it fully', async (t) => {
  const previousKey = process.env.FILE_ENCRYPTION_KEY;
  process.env.FILE_ENCRYPTION_KEY = TEST_KEY;
  t.after(() => {
    if (previousKey === undefined) delete process.env.FILE_ENCRYPTION_KEY;
    else process.env.FILE_ENCRYPTION_KEY = previousKey;
  });

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nfs-crypto-test-'));
  t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  const srcPath  = path.join(tmpDir, 'plain.txt');
  const destPath = path.join(tmpDir, 'encrypted.bin');
  const original = 'contenu en clair pour le test de round-trip AES-256-CBC';
  fs.writeFileSync(srcPath, original);

  const iv = generateIv();
  await encryptFileStream(srcPath, destPath, iv);

  // Le fichier chiffré sur disque ne doit jamais contenir le texte en clair.
  const encryptedBuffer = fs.readFileSync(destPath);
  assert.equal(encryptedBuffer.toString('latin1').includes(original), false);

  const chunks = [];
  const collector = new Writable({
    write(chunk, _enc, cb) { chunks.push(chunk); cb(); },
  });

  await pipelineAsync(fs.createReadStream(destPath), createDecipherStream(iv), collector);

  assert.equal(Buffer.concat(chunks).toString('utf8'), original);
});
