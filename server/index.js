'use strict';
/**
 * SecureShare server — Express API.
 *
 * The server is intentionally "dumb": it stores ONLY ciphertext blobs and
 * non-secret metadata (IV, salt, SHA-256, encrypted filename). It never
 * receives decryption keys, passphrases, or plaintext filenames.
 *
 * Endpoints:
 *   POST   /api/upload            multipart: file (ciphertext) + meta (JSON)
 *   GET    /api/files/:id/meta    public metadata (no key material)
 *   GET    /api/files/:id/download  streams ciphertext (410 if expired)
 *   DELETE /api/files/:id         manual delete
 *   GET    /d/:id                 share-link landing page (JS redirect to the
 *                                 app, preserving the #key= fragment — the
 *                                 fragment is never sent to this server)
 *
 * Storage: <STORAGE_DIR>/<id>.bin + <id>.json (one meta file per upload).
 * Expired files are deleted by a sweeper (every 5 min + on startup).
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const multer = require('multer');

const DEFAULT_PORT = 3001;
const DEFAULT_MAX_FILE_MB = 25;
const MIN_EXPIRY_HOURS = 1 / 60; // 1 minute (lets tests use short lifetimes)
const MAX_EXPIRY_HOURS = 24 * 7; // 7 days
const DEFAULT_SWEEP_MS = 5 * 60 * 1000;
const ID_RE = /^[A-Za-z0-9-]{8,64}$/; // UUIDs / hex ids only — no path chars

function configFromEnv(env = process.env) {
  return {
    port: Number(env.PORT || DEFAULT_PORT),
    storageDir: env.STORAGE_DIR
      ? path.resolve(env.STORAGE_DIR)
      : path.join(__dirname, 'storage'),
    maxFileMb: Number(env.MAX_FILE_MB || DEFAULT_MAX_FILE_MB),
    appUrl: (env.APP_URL || 'http://localhost:8081').replace(/\/$/, ''),
    sweepMs: Number(env.SWEEP_INTERVAL_MS || DEFAULT_SWEEP_MS),
    corsOrigins: (env.CORS_ORIGINS || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  };
}

function createApp(options = {}) {
  const cfg = { ...configFromEnv(), ...options };
  fs.mkdirSync(cfg.storageDir, { recursive: true });

  const app = express();
  app.disable('x-powered-by');

  // Security headers. CSP is set per-route below (the /d page needs an
  // inline script, the API needs none), so helmet's CSP is disabled here.
  app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

  // CORS: allow localhost / 127.0.0.1 origins (Expo web dev server, local
  // testing) plus any explicitly configured origins.
  const allowedOrigins = new Set(cfg.corsOrigins);
  try {
    allowedOrigins.add(new URL(cfg.appUrl).origin);
  } catch { /* ignore invalid APP_URL */ }
  app.use(cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true); // curl / same-origin / non-browser
      try {
        const u = new URL(origin);
        if (u.hostname === 'localhost' || u.hostname === '127.0.0.1' || allowedOrigins.has(u.origin)) {
          return cb(null, true);
        }
      } catch { /* fall through */ }
      return cb(null, false);
    },
  }));
  app.use(express.json({ limit: '1mb' }));

  // Strict CSP + no-store on all API responses.
  app.use('/api', (req, res, next) => {
    res.set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    res.set('Cache-Control', 'no-store');
    next();
  });

  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: Math.floor(cfg.maxFileMb * 1024 * 1024), files: 1 },
  });

  const blobPath = (id) => path.join(cfg.storageDir, `${id}.bin`);
  const metaPath = (id) => path.join(cfg.storageDir, `${id}.json`);

  function readMeta(id) {
    try {
      return JSON.parse(fs.readFileSync(metaPath(id), 'utf8'));
    } catch {
      return null;
    }
  }

  function deleteFile(id) {
    for (const p of [blobPath(id), metaPath(id)]) {
      try { fs.unlinkSync(p); } catch { /* already gone */ }
    }
  }

  function isExpired(meta) {
    return Date.now() >= meta.expiresAt;
  }

  /** Delete every expired upload. Runs on startup and on an interval. */
  function sweep() {
    let removed = 0;
    let files;
    try {
      files = fs.readdirSync(cfg.storageDir);
    } catch {
      return 0;
    }
    for (const f of files) {
      if (!f.endsWith('.json')) continue;
      const id = f.slice(0, -'.json'.length);
      const meta = readMeta(id);
      if (meta && isExpired(meta)) {
        deleteFile(id);
        removed += 1;
      }
    }
    return removed;
  }

  function validId(req, res, next) {
    if (!ID_RE.test(req.params.id)) {
      return res.status(400).json({ error: 'invalid_id' });
    }
    next();
  }

  function loadMetaOrError(req, res) {
    const meta = readMeta(req.params.id);
    if (!meta || !fs.existsSync(blobPath(req.params.id))) {
      res.status(404).json({ error: 'not_found' });
      return null;
    }
    if (isExpired(meta)) {
      deleteFile(req.params.id);
      res.status(410).json({ error: 'expired' });
      return null;
    }
    return meta;
  }

  /** Public metadata — never contains key material. */
  function publicMeta(meta) {
    return {
      id: meta.id,
      originalSize: meta.originalSize,
      encryptedSize: meta.encryptedSize,
      iv: meta.iv,
      filenameIv: meta.filenameIv,
      salt: meta.salt,
      sha256: meta.sha256,
      filenameEnc: meta.filenameEnc,
      expiresAt: meta.expiresAt,
      burnAfterReading: meta.burnAfterReading,
      downloads: meta.downloads,
      downloadsRemaining: meta.burnAfterReading ? 1 - meta.downloads : null,
      createdAt: meta.createdAt,
    };
  }

  app.get('/api/health', (req, res) => res.json({ ok: true }));

  app.post('/api/upload', (req, res) => {
    upload.single('file')(req, res, (err) => {
      if (err) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(413).json({ error: 'file_too_large', maxMb: cfg.maxFileMb });
        }
        return res.status(400).json({ error: 'upload_error', detail: err.message });
      }
      try {
        if (!req.file) return res.status(400).json({ error: 'missing_file' });
        let meta;
        try {
          meta = JSON.parse(req.body.meta || '{}');
        } catch {
          return res.status(400).json({ error: 'invalid_meta' });
        }
        const { iv, filenameIv, salt, sha256, filenameEnc, originalSize, expiresInHours, burnAfterReading } = meta;
        if (typeof iv !== 'string' || !iv
          || typeof filenameIv !== 'string' || !filenameIv
          || typeof sha256 !== 'string' || !/^[0-9a-f]{64}$/i.test(sha256)
          || typeof filenameEnc !== 'string' || !filenameEnc
          || !Number.isInteger(originalSize) || originalSize < 0) {
          return res.status(400).json({ error: 'invalid_meta_fields' });
        }
        if (salt !== null && salt !== undefined && typeof salt !== 'string') {
          return res.status(400).json({ error: 'invalid_meta_fields' });
        }
        // Server-side integrity check: the stored blob must match the
        // client-declared SHA-256 of the ciphertext.
        const actual = crypto.createHash('sha256').update(req.file.buffer).digest('hex');
        if (actual !== sha256.toLowerCase()) {
          return res.status(400).json({ error: 'sha256_mismatch' });
        }
        const hours = Math.min(
          MAX_EXPIRY_HOURS,
          Math.max(MIN_EXPIRY_HOURS, Number(expiresInHours) || 24),
        );
        const id = crypto.randomUUID();
        const record = {
          id,
          iv,
          filenameIv,
          salt: salt || null,
          sha256: sha256.toLowerCase(),
          filenameEnc,
          originalSize,
          encryptedSize: req.file.buffer.length,
          expiresAt: Date.now() + hours * 3600 * 1000,
          burnAfterReading: burnAfterReading === true || burnAfterReading === 'true',
          downloads: 0,
          createdAt: Date.now(),
        };
        fs.writeFileSync(blobPath(id), req.file.buffer);
        fs.writeFileSync(metaPath(id), JSON.stringify(record, null, 2));
        const base = `${req.protocol}://${req.get('host')}`;
        return res.status(201).json({
          id,
          downloadUrl: `${base}/d/${id}`,
          expiresAt: record.expiresAt,
          burnAfterReading: record.burnAfterReading,
        });
      } catch (e) {
        return res.status(500).json({ error: 'internal_error' });
      }
    });
  });

  app.get('/api/files/:id/meta', validId, (req, res) => {
    const meta = loadMetaOrError(req, res);
    if (!meta) return;
    res.json(publicMeta(meta));
  });

  app.get('/api/files/:id/download', validId, (req, res) => {
    const meta = loadMetaOrError(req, res);
    if (!meta) return;
    res.set('Content-Type', 'application/octet-stream');
    res.set('Content-Disposition', `attachment; filename="secureshare-${meta.id}.bin"`);
    res.set('Content-Length', String(meta.encryptedSize));
    res.set('X-Content-Type-Options', 'nosniff');
    const stream = fs.createReadStream(blobPath(meta.id));
    stream.on('error', () => {
      if (!res.headersSent) res.status(404).json({ error: 'not_found' });
      else res.destroy();
    });
    stream.pipe(res);
    // Burn-after-reading: delete once the response has been fully sent.
    res.on('finish', () => {
      if (meta.burnAfterReading) {
        deleteFile(meta.id);
      } else {
        const fresh = readMeta(meta.id);
        if (fresh) {
          fresh.downloads = (fresh.downloads || 0) + 1;
          try { fs.writeFileSync(metaPath(meta.id), JSON.stringify(fresh, null, 2)); } catch { /* ignore */ }
        }
      }
    });
  });

  app.delete('/api/files/:id', validId, (req, res) => {
    const meta = readMeta(req.params.id);
    if (!meta) return res.status(404).json({ error: 'not_found' });
    deleteFile(req.params.id);
    res.json({ deleted: true, id: req.params.id });
  });

  // Share-link landing page. The #key= fragment is never sent to the server;
  // this page's inline script reads it in the browser and forwards the user
  // to the app with the fragment intact.
  app.get('/d/:id', validId, (req, res) => {
    const meta = readMeta(req.params.id);
    if (!meta) return res.status(404).send('File not found or already deleted.');
    if (isExpired(meta)) {
      deleteFile(req.params.id);
      return res.status(410).send('This file has expired and been deleted.');
    }
    res.set('Content-Type', 'text/html; charset=utf-8');
    res.set('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'");
    res.send(`<!doctype html>
<html><head><meta charset="utf-8"><title>SecureShare</title>
<style>body{background:#f7f7f4;color:#22262b;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center}h1{font-size:20px}</style>
</head><body><div><h1>🔒 SecureShare</h1><p>Opening your secure file…</p></div>
<script>
(function () {
  var target = ${JSON.stringify(cfg.appUrl)} + '/?id=' + encodeURIComponent(${JSON.stringify(req.params.id)}) + window.location.hash;
  window.location.replace(target);
})();
</script></body></html>`);
  });

  // Fallthrough + error handler.
  app.use((req, res) => res.status(404).json({ error: 'not_found' }));
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => res.status(500).json({ error: 'internal_error' }));

  return { app, cfg, sweep, deleteFile, readMeta };
}

if (require.main === module) {
  const { app, cfg, sweep } = createApp();
  const removed = sweep();
  if (removed) console.log(`[secureshare] startup sweep removed ${removed} expired file(s)`);
  setInterval(() => {
    const n = sweep();
    if (n) console.log(`[secureshare] sweep removed ${n} expired file(s)`);
  }, cfg.sweepMs).unref();
  app.listen(cfg.port, () => {
    console.log(`[secureshare] server listening on http://localhost:${cfg.port}`);
    console.log(`[secureshare] storage: ${cfg.storageDir} (max file ${cfg.maxFileMb} MB)`);
    console.log(`[secureshare] app URL for share links: ${cfg.appUrl}`);
  });
}

module.exports = { createApp, configFromEnv };
