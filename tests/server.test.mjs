// API tests — start a real Express server on an ephemeral port with a
// temp storage directory, and exercise it over HTTP with global fetch.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { createApp } = require('../server/index.js');

import { encryptFile, decryptFile } from '../app/src/crypto/crypto.js';

const enc = new TextEncoder();

/** Encrypt a test file and upload it; returns the upload response JSON. */
async function uploadEncrypted(base, { filename = 'hello.txt', content = 'hello, secure world', passphrase, expiresInHours = 24, burnAfterReading = false } = {}) {
  const data = typeof content === 'string' ? enc.encode(content) : content;
  const result = await encryptFile(data, filename, passphrase ? { passphrase } : {});
  const form = new FormData();
  form.append('file', new Blob([result.ciphertext], { type: 'application/octet-stream' }), 'blob.bin');
  form.append('meta', JSON.stringify({
    iv: result.iv,
    filenameIv: result.filenameIv,
    salt: result.salt,
    sha256: result.sha256,
    filenameEnc: result.filenameEnc,
    originalSize: data.length,
    expiresInHours,
    burnAfterReading,
  }));
  const res = await fetch(`${base}/api/upload`, { method: 'POST', body: form });
  return { res, result, data };
}

describe('SecureShare API', () => {
  let tmpDir;
  let server;
  let base;
  let sweep;

  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureshare-test-'));
    const created = createApp({ storageDir: tmpDir, appUrl: 'http://localhost:8081' });
    sweep = created.sweep;
    server = await new Promise((resolve) => {
      const s = created.app.listen(0, () => resolve(s));
    });
    base = `http://127.0.0.1:${server.address().port}`;
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('health endpoint responds', async () => {
    const res = await fetch(`${base}/api/health`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true });
  });

  it('API responses carry security headers', async () => {
    const res = await fetch(`${base}/api/health`);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.match(res.headers.get('content-security-policy') || '', /default-src 'none'/);
  });

  it('upload -> meta -> download -> decrypt round-trips end to end', async () => {
    const { res, result, data } = await uploadEncrypted(base, { filename: 'report.txt', content: 'quarterly secrets' });
    assert.equal(res.status, 201);
    const body = await res.json();
    assert.match(body.id, /^[0-9a-f-]{36}$/);
    assert.ok(body.downloadUrl.includes(`/d/${body.id}`));
    assert.ok(body.expiresAt > Date.now());

    // Meta: no key material, no plaintext filename anywhere.
    const metaRes = await fetch(`${base}/api/files/${body.id}/meta`);
    assert.equal(metaRes.status, 200);
    const meta = await metaRes.json();
    assert.equal(meta.originalSize, data.length);
    assert.equal(meta.encryptedSize, result.ciphertext.length);
    assert.equal(meta.sha256, result.sha256);
    assert.equal(meta.salt, null);
    assert.ok(!('key' in meta) && !('passphrase' in meta));
    assert.ok(!JSON.stringify(meta).includes('report.txt'), 'plaintext filename must not leak in metadata');

    // Download: bytes must match the uploaded ciphertext exactly.
    const dlRes = await fetch(`${base}/api/files/${body.id}/download`);
    assert.equal(dlRes.status, 200);
    assert.equal(dlRes.headers.get('content-type'), 'application/octet-stream');
    const downloaded = new Uint8Array(await dlRes.arrayBuffer());
    assert.deepEqual(downloaded, result.ciphertext);

    // And the client can decrypt it back to the original file.
    const out = await decryptFile(downloaded, meta, { keyB64url: result.keyB64url });
    assert.deepEqual(out.data, data);
    assert.equal(out.filename, 'report.txt');
  });

  it('passphrase-protected upload round-trips (keyless link)', async () => {
    const { res, result, data } = await uploadEncrypted(base, {
      filename: 'vault.txt', content: 'locked', passphrase: 's3cret-pass',
    });
    assert.equal(res.status, 201);
    const { id } = await res.json();
    const meta = await (await fetch(`${base}/api/files/${id}/meta`)).json();
    assert.ok(meta.salt, 'salt must be stored for passphrase files');
    const downloaded = new Uint8Array(await (await fetch(`${base}/api/files/${id}/download`)).arrayBuffer());
    const out = await decryptFile(downloaded, meta, { passphrase: 's3cret-pass' });
    assert.deepEqual(out.data, data);
    assert.equal(out.filename, 'vault.txt');
    await assert.rejects(() => decryptFile(downloaded, meta, { passphrase: 'nope' }), /Decryption failed/);
  });

  it('DELETE removes the file; subsequent reads 404', async () => {
    const { res } = await uploadEncrypted(base, { filename: 'gone.txt', content: 'bye' });
    const { id } = await res.json();
    const del = await fetch(`${base}/api/files/${id}`, { method: 'DELETE' });
    assert.equal(del.status, 200);
    assert.deepEqual(await del.json(), { deleted: true, id });
    assert.equal((await fetch(`${base}/api/files/${id}/meta`)).status, 404);
    assert.equal((await fetch(`${base}/api/files/${id}/download`)).status, 404);
    assert.equal((await fetch(`${base}/api/files/${id}`, { method: 'DELETE' })).status, 404);
  });

  it('expired download returns 410 Gone and the file is deleted', async () => {
    const { res } = await uploadEncrypted(base, { filename: 'old.txt', content: 'stale' });
    const { id } = await res.json();
    // Backdate the stored metadata to simulate expiry.
    const metaPath = path.join(tmpDir, `${id}.json`);
    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
    meta.expiresAt = Date.now() - 1000;
    fs.writeFileSync(metaPath, JSON.stringify(meta));
    const dl = await fetch(`${base}/api/files/${id}/download`);
    assert.equal(dl.status, 410);
    assert.equal((await dl.json()).error, 'expired');
    assert.equal(fs.existsSync(metaPath), false, 'expired file must be deleted on access');
    assert.equal(fs.existsSync(path.join(tmpDir, `${id}.bin`)), false);
  });

  it('the sweeper deletes expired files', async () => {
    const { res } = await uploadEncrypted(base, { filename: 'sweep-me.txt', content: 'dust' });
    const { id } = await res.json();
    const metaPath = path.join(tmpDir, `${id}.json`);
    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
    meta.expiresAt = Date.now() - 1000;
    fs.writeFileSync(metaPath, JSON.stringify(meta));
    const removed = sweep();
    assert.equal(removed, 1);
    assert.equal(fs.existsSync(metaPath), false);
    assert.equal(fs.existsSync(path.join(tmpDir, `${id}.bin`)), false);
  });

  it('burn-after-reading: first download succeeds, second 404s', async () => {
    const { res, result } = await uploadEncrypted(base, {
      filename: 'burn.txt', content: 'read once', burnAfterReading: true,
    });
    const { id } = await res.json();
    const first = await fetch(`${base}/api/files/${id}/download`);
    assert.equal(first.status, 200);
    assert.deepEqual(new Uint8Array(await first.arrayBuffer()), result.ciphertext);
    // The delete happens on response finish; give the server a tick.
    await new Promise((r) => setTimeout(r, 50));
    assert.equal((await fetch(`${base}/api/files/${id}/meta`)).status, 404);
    assert.equal((await fetch(`${base}/api/files/${id}/download`)).status, 404);
  });

  it('upload with a mismatched SHA-256 is rejected', async () => {
    const result = await encryptFile(enc.encode('x'), 'x.txt');
    const form = new FormData();
    form.append('file', new Blob([result.ciphertext]), 'blob.bin');
    form.append('meta', JSON.stringify({
      iv: result.iv,
      filenameIv: result.filenameIv,
      salt: null,
      sha256: '0'.repeat(64), // lie about the hash
      filenameEnc: result.filenameEnc,
      originalSize: 1,
      expiresInHours: 24,
      burnAfterReading: false,
    }));
    const res = await fetch(`${base}/api/upload`, { method: 'POST', body: form });
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error, 'sha256_mismatch');
  });

  it('upload without a file is rejected', async () => {
    const form = new FormData();
    form.append('meta', JSON.stringify({}));
    const res = await fetch(`${base}/api/upload`, { method: 'POST', body: form });
    assert.equal(res.status, 400);
  });

  it('unknown ids 404; malformed ids 400 (no path traversal)', async () => {
    const missing = '123e4567-e89b-12d3-a456-426614174000';
    assert.equal((await fetch(`${base}/api/files/${missing}/meta`)).status, 404);
    assert.equal((await fetch(`${base}/api/files/${missing}/download`)).status, 404);
    for (const bad of ['..', '../etc/passwd', '%2e%2e%2fsecret', 'a/b', 'a b']) {
      const res = await fetch(`${base}/api/files/${encodeURIComponent(bad)}/meta`);
      assert.ok(res.status === 400 || res.status === 404, `id ${bad} -> ${res.status}`);
    }
  });

  it('the /d share page returns an HTML redirect preserving the fragment client-side', async () => {
    const { res } = await uploadEncrypted(base, { filename: 'shared.txt', content: 'link me' });
    const { id } = await res.json();
    const page = await fetch(`${base}/d/${id}`);
    assert.equal(page.status, 200);
    assert.match(page.headers.get('content-type'), /text\/html/);
    const html = await page.text();
    assert.ok(html.includes('http://localhost:8081'), 'redirect target must be the app URL');
    assert.ok(html.includes('window.location.hash'), 'fragment must be read client-side');
    assert.ok(html.includes(id));
  });
});

describe('upload size limit', () => {
  it('oversize uploads are rejected with 413', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureshare-limit-'));
    const { app } = createApp({ storageDir: tmpDir, maxFileMb: 0.001 }); // ~1 KB limit
    const server = await new Promise((resolve) => {
      const s = app.listen(0, () => resolve(s));
    });
    try {
      const base = `http://127.0.0.1:${server.address().port}`;
      const form = new FormData();
      form.append('file', new Blob([new Uint8Array(2048)]), 'big.bin');
      form.append('meta', JSON.stringify({}));
      const res = await fetch(`${base}/api/upload`, { method: 'POST', body: form });
      assert.equal(res.status, 413);
      assert.equal((await res.json()).error, 'file_too_large');
    } finally {
      await new Promise((resolve) => server.close(resolve));
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
