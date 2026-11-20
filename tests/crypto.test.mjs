// Crypto tests — use the REAL WebCrypto (Node's globalThis.crypto).
// The app's crypto module is dependency-free and importable in Node.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  PBKDF2_ITERATIONS,
  bytesToBase64url,
  base64urlToBytes,
  sha256Hex,
  generateFileKey,
  deriveKeyFromPassphrase,
  exportKeyRaw,
  importKey,
  encryptBytes,
  decryptBytes,
  encryptFilename,
  decryptFilename,
  encryptFile,
  decryptFile,
  buildShareLink,
  parseShareLink,
  randomBytes,
} from '../app/src/crypto/crypto.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

describe('base64url helpers', () => {
  it('round-trips arbitrary bytes', () => {
    const bytes = randomBytes(64);
    assert.deepEqual(base64urlToBytes(bytesToBase64url(bytes)), bytes);
  });

  it('is URL-safe (no +, / or =)', () => {
    for (let i = 0; i < 20; i += 1) {
      const s = bytesToBase64url(randomBytes(32));
      assert.match(s, /^[A-Za-z0-9_-]+$/);
    }
  });

  it('rejects invalid input', () => {
    assert.throws(() => base64urlToBytes('not base64!'), /Invalid base64url/);
  });
});

describe('sha256Hex', () => {
  it('matches the known SHA-256 test vector for "abc"', async () => {
    const hash = await sha256Hex(enc.encode('abc'));
    assert.equal(hash, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
});

describe('PBKDF2 key derivation', () => {
  it('uses 600,000 iterations', () => {
    assert.equal(PBKDF2_ITERATIONS, 600000);
  });

  it('is deterministic for the same passphrase + salt', async () => {
    const salt = randomBytes(16);
    const k1 = await deriveKeyFromPassphrase('correct horse battery staple', salt);
    const k2 = await deriveKeyFromPassphrase('correct horse battery staple', salt);
    assert.deepEqual(await exportKeyRaw(k1), await exportKeyRaw(k2));
  });

  it('produces a different key for a different salt', async () => {
    const k1 = await deriveKeyFromPassphrase('same passphrase', randomBytes(16));
    const k2 = await deriveKeyFromPassphrase('same passphrase', randomBytes(16));
    assert.notDeepEqual(await exportKeyRaw(k1), await exportKeyRaw(k2));
  });

  it('produces a different key for a different passphrase', async () => {
    const salt = randomBytes(16);
    const k1 = await deriveKeyFromPassphrase('passphrase-one', salt);
    const k2 = await deriveKeyFromPassphrase('passphrase-two', salt);
    assert.notDeepEqual(await exportKeyRaw(k1), await exportKeyRaw(k2));
  });

  it('rejects an empty passphrase', async () => {
    await assert.rejects(() => deriveKeyFromPassphrase('', randomBytes(16)), /must not be empty/);
  });
});

describe('AES-256-GCM round-trip', () => {
  it('encrypt -> decrypt returns the original bytes (random key)', async () => {
    const { key } = await generateFileKey();
    const iv = randomBytes(12);
    const plain = enc.encode('The quick brown fox jumps over the lazy dog'.repeat(50));
    const cipher = await encryptBytes(plain, key, iv);
    assert.notDeepEqual(cipher, plain);
    // GCM appends a 16-byte auth tag
    assert.equal(cipher.length, plain.length + 16);
    const out = await decryptBytes(cipher, key, iv);
    assert.deepEqual(out, plain);
  });

  it('encryptFile -> decryptFile round-trips file bytes + filename (no passphrase)', async () => {
    const data = enc.encode('Top-secret quarterly report contents…');
    const result = await encryptFile(data, 'Q3 report (confidential).pdf');
    assert.ok(result.keyB64url, 'random-key mode must return the key for the share link');
    assert.equal(result.salt, null);
    assert.match(result.sha256, /^[0-9a-f]{64}$/);
    const meta = {
      iv: result.iv,
      filenameIv: result.filenameIv,
      salt: result.salt,
      sha256: result.sha256,
      filenameEnc: result.filenameEnc,
    };
    const out = await decryptFile(result.ciphertext, meta, { keyB64url: result.keyB64url });
    assert.deepEqual(out.data, data);
    assert.equal(out.filename, 'Q3 report (confidential).pdf');
  });

  it('encryptFile -> decryptFile round-trips with a passphrase', async () => {
    const data = randomBytes(4096);
    const result = await encryptFile(data, 'notes.txt', { passphrase: 'hunter2!' });
    assert.equal(result.keyB64url, null, 'passphrase mode must NOT return a key');
    assert.ok(result.salt, 'passphrase mode must store a salt');
    const meta = {
      iv: result.iv,
      filenameIv: result.filenameIv,
      salt: result.salt,
      sha256: result.sha256,
      filenameEnc: result.filenameEnc,
    };
    const out = await decryptFile(result.ciphertext, meta, { passphrase: 'hunter2!' });
    assert.deepEqual(out.data, data);
    assert.equal(out.filename, 'notes.txt');
  });

  it('handles an empty file', async () => {
    const result = await encryptFile(new Uint8Array(0), 'empty.txt');
    const meta = {
      iv: result.iv,
      filenameIv: result.filenameIv,
      salt: result.salt,
      sha256: result.sha256,
      filenameEnc: result.filenameEnc,
    };
    const out = await decryptFile(result.ciphertext, meta, { keyB64url: result.keyB64url });
    assert.equal(out.data.length, 0);
    assert.equal(out.filename, 'empty.txt');
  });
});

describe('tamper detection', () => {
  it('a flipped ciphertext byte fails the SHA-256 integrity check', async () => {
    const result = await encryptFile(enc.encode('do not tamper with this'), 'a.txt');
    const tampered = new Uint8Array(result.ciphertext);
    tampered[0] ^= 0xff;
    const meta = {
      iv: result.iv,
      filenameIv: result.filenameIv,
      salt: result.salt,
      sha256: result.sha256,
      filenameEnc: result.filenameEnc,
    };
    await assert.rejects(
      () => decryptFile(tampered, meta, { keyB64url: result.keyB64url }),
      /Integrity check failed/,
    );
  });

  it('a flipped ciphertext byte fails GCM authentication even if the hash is recomputed', async () => {
    // Defence in depth: even an attacker who can rewrite the stored hash
    // cannot forge the GCM auth tag.
    const { key } = await generateFileKey();
    const iv = randomBytes(12);
    const cipher = await encryptBytes(enc.encode('authenticated'), key, iv);
    const tampered = new Uint8Array(cipher);
    tampered[tampered.length - 1] ^= 0x01;
    await assert.rejects(() => decryptBytes(tampered, key, iv));
  });

  it('a flipped auth-tag byte fails decryption', async () => {
    const { key } = await generateFileKey();
    const iv = randomBytes(12);
    const cipher = await encryptBytes(enc.encode('tag me'), key, iv);
    const tampered = new Uint8Array(cipher);
    tampered[tampered.length - 5] ^= 0x80;
    await assert.rejects(() => decryptBytes(tampered, key, iv));
  });
});

describe('wrong key / wrong passphrase', () => {
  it('decryption with the wrong random key fails', async () => {
    const result = await encryptFile(enc.encode('secret'), 's.txt');
    const { raw } = await generateFileKey();
    const meta = {
      iv: result.iv,
      filenameIv: result.filenameIv,
      salt: result.salt,
      sha256: result.sha256,
      filenameEnc: result.filenameEnc,
    };
    await assert.rejects(
      () => decryptFile(result.ciphertext, meta, { keyB64url: bytesToBase64url(raw) }),
      /Decryption failed/,
    );
  });

  it('decryption with the wrong passphrase fails', async () => {
    const result = await encryptFile(enc.encode('secret'), 's.txt', { passphrase: 'right one' });
    const meta = {
      iv: result.iv,
      filenameIv: result.filenameIv,
      salt: result.salt,
      sha256: result.sha256,
      filenameEnc: result.filenameEnc,
    };
    await assert.rejects(
      () => decryptFile(result.ciphertext, meta, { passphrase: 'wrong one' }),
      /Decryption failed/,
    );
  });

  it('importKey rejects a short key', async () => {
    await assert.rejects(() => importKey(new Uint8Array(16)), /32 bytes/);
  });
});

describe('filename encryption', () => {
  it('encrypts the filename (server never sees plaintext)', async () => {
    const { key } = await generateFileKey();
    const filenameIv = randomBytes(12);
    const encrypted = await encryptFilename('my-salary-2026.xlsx', key, filenameIv);
    assert.ok(!encrypted.includes('salary'), 'encrypted filename must not contain the plaintext');
    assert.equal(await decryptFilename(encrypted, key, filenameIv), 'my-salary-2026.xlsx');
  });

  it('uses a different IV for filename and file body', async () => {
    const result = await encryptFile(enc.encode('x'), 'x.txt');
    assert.notEqual(result.iv, result.filenameIv, 'GCM IVs must never be reused with the same key');
  });
});

describe('share links', () => {
  it('builds a keyed link and parses it back', async () => {
    const { raw } = await generateFileKey();
    const keyB64url = bytesToBase64url(raw);
    const id = '123e4567-e89b-12d3-a456-426614174000';
    const link = buildShareLink('http://localhost:3001', id, keyB64url);
    assert.equal(link, `http://localhost:3001/d/${id}#key=${keyB64url}`);
    assert.deepEqual(parseShareLink(link), { id, keyB64url });
  });

  it('builds a keyless link for passphrase-protected files', () => {
    const id = '123e4567-e89b-12d3-a456-426614174000';
    const link = buildShareLink('http://localhost:3001/', id, null);
    assert.equal(link, `http://localhost:3001/d/${id}`);
    assert.deepEqual(parseShareLink(link), { id, keyB64url: null });
  });

  it('parses the app-side URL form (?id=...#key=...)', () => {
    const parsed = parseShareLink('http://localhost:8081/?id=abc-def-123#key=QUJD');
    assert.deepEqual(parsed, { id: 'abc-def-123', keyB64url: 'QUJD' });
  });

  it('rejects a link with no id', () => {
    assert.throws(() => parseShareLink('https://example.com/nothing-here'), /Could not find a file id/);
  });
});
