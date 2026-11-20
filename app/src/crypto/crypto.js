/**
 * SecureShare crypto — dependency-free, WebCrypto-only.
 *
 * This module uses ONLY `globalThis.crypto` (WebCrypto) and standard
 * built-ins, so it runs unchanged in browsers (Expo web), in Node 19+
 * (tests / tooling), and anywhere else WebCrypto exists. It imports
 * nothing from React Native — see polyfill-note.js for the native story.
 *
 * Design:
 *  - AES-256-GCM, random 256-bit key per file, random 12-byte IV per file.
 *  - Optional passphrase: PBKDF2-SHA-256, 600,000 iterations, random
 *    16-byte salt. With a passphrase the key is DERIVED, never stored or
 *    put in the share link — the recipient must know the passphrase.
 *  - Without a passphrase the random key travels in the URL FRAGMENT
 *    (#key=...) of the share link. Fragments are never sent to the server.
 *  - Filenames are encrypted with the same key but a SEPARATE random IV
 *    (never reuse a GCM IV with the same key). The server only ever sees
 *    the encrypted filename and the ciphertext.
 *  - SHA-256 of the ciphertext is stored and verified before decrypting;
 *    GCM's auth tag also fails decryption on any tampering.
 *  - Keys are NEVER logged and NEVER persisted to storage by this module.
 */

export const PBKDF2_ITERATIONS = 600000;
export const KEY_LENGTH_BITS = 256;
export const IV_LENGTH_BYTES = 12;
export const SALT_LENGTH_BYTES = 16;
export const GCM_TAG_LENGTH_BITS = 128;

function getSubtle() {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error(
      'WebCrypto is not available in this environment. On the web, serve the app over HTTPS or localhost. On React Native, see polyfill-note.js.',
    );
  }
  return subtle;
}

function getRandomValues() {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error('Secure random numbers are not available in this environment.');
  }
  return globalThis.crypto.getRandomValues.bind(globalThis.crypto);
}

/** Cryptographically random bytes. */
export function randomBytes(length) {
  return getRandomValues()(new Uint8Array(length));
}

/** URL-safe base64 (RFC 4648 §5) without padding. Browser- and Node-safe. */
export function bytesToBase64url(bytes) {
  const bin = [];
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin.push(String.fromCharCode(...bytes.subarray(i, i + CHUNK)));
  }
  return btoa(bin.join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64urlToBytes(str) {
  if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str)) {
    throw new Error('Invalid base64url string');
  }
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** SHA-256 digest as a lowercase hex string. */
export async function sha256Hex(data) {
  const digest = await getSubtle().digest('SHA-256', data);
  return bytesToHex(new Uint8Array(digest));
}

/** Generate a fresh random AES-256-GCM key. Returns { key, raw }. */
export async function generateFileKey() {
  const key = await getSubtle().generateKey(
    { name: 'AES-GCM', length: KEY_LENGTH_BITS },
    true, // extractable: the raw key goes into the share-link fragment
    ['encrypt', 'decrypt'],
  );
  const raw = new Uint8Array(await getSubtle().exportKey('raw', key));
  return { key, raw };
}

/** Derive an AES-256-GCM key from a passphrase with PBKDF2-SHA-256. */
export async function deriveKeyFromPassphrase(passphrase, salt) {
  if (!passphrase) throw new Error('Passphrase must not be empty');
  const subtle = getSubtle();
  const baseKey = await subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: KEY_LENGTH_BITS },
    true, // extractable so tests can compare derived keys; the app never exports it
    ['encrypt', 'decrypt'],
  );
}

/** Import a raw 32-byte key (from a share-link fragment). */
export async function importKey(rawBytes) {
  if (rawBytes.length !== 32) throw new Error('Key must be 32 bytes (AES-256)');
  return getSubtle().importKey('raw', rawBytes, { name: 'AES-GCM', length: KEY_LENGTH_BITS }, false, ['encrypt', 'decrypt']);
}

export async function exportKeyRaw(key) {
  return new Uint8Array(await getSubtle().exportKey('raw', key));
}

/** AES-256-GCM encrypt. Returns ciphertext WITH the auth tag appended. */
export async function encryptBytes(plaintext, key, iv) {
  if (iv.length !== IV_LENGTH_BYTES) throw new Error('IV must be 12 bytes');
  const out = await getSubtle().encrypt(
    { name: 'AES-GCM', iv, tagLength: GCM_TAG_LENGTH_BITS },
    key,
    plaintext,
  );
  return new Uint8Array(out);
}

/**
 * AES-256-GCM decrypt. Throws (OperationError) if the ciphertext was
 * tampered with or the key/IV is wrong — GCM authentication failure.
 */
export async function decryptBytes(ciphertext, key, iv) {
  if (iv.length !== IV_LENGTH_BYTES) throw new Error('IV must be 12 bytes');
  const out = await getSubtle().decrypt(
    { name: 'AES-GCM', iv, tagLength: GCM_TAG_LENGTH_BITS },
    key,
    ciphertext,
  );
  return new Uint8Array(out);
}

/** Encrypt a filename with the file key and a dedicated IV. Returns base64url. */
export async function encryptFilename(filename, key, filenameIv) {
  const plain = new TextEncoder().encode(filename);
  const cipher = await encryptBytes(plain, key, filenameIv);
  return bytesToBase64url(cipher);
}

/** Decrypt a filename produced by encryptFilename. */
export async function decryptFilename(filenameEnc, key, filenameIv) {
  const cipher = base64urlToBytes(filenameEnc);
  const plain = await decryptBytes(cipher, key, filenameIv);
  return new TextDecoder().decode(plain);
}

/**
 * Encrypt a whole file for upload.
 *
 * @param {Uint8Array} data - plaintext file bytes
 * @param {string} filename - original filename (encrypted, never sent plain)
 * @param {{ passphrase?: string }} [opts]
 * @returns {{ ciphertext, iv, filenameIv, salt, sha256, filenameEnc, keyB64url }}
 *   iv / filenameIv / salt are base64url; sha256 is hex of the ciphertext;
 *   keyB64url is the raw key (base64url) ONLY when no passphrase was set —
 *   with a passphrase it is null and the recipient must enter the passphrase.
 */
export async function encryptFile(data, filename, opts = {}) {
  const { passphrase } = opts;
  let key;
  let salt = null;
  let keyB64url = null;
  if (passphrase) {
    salt = randomBytes(SALT_LENGTH_BYTES);
    key = await deriveKeyFromPassphrase(passphrase, salt);
  } else {
    const generated = await generateFileKey();
    key = generated.key;
    keyB64url = bytesToBase64url(generated.raw);
  }
  const iv = randomBytes(IV_LENGTH_BYTES);
  const filenameIv = randomBytes(IV_LENGTH_BYTES);
  const ciphertext = await encryptBytes(data, key, iv);
  const filenameEnc = await encryptFilename(filename, key, filenameIv);
  return {
    ciphertext,
    iv: bytesToBase64url(iv),
    filenameIv: bytesToBase64url(filenameIv),
    salt: salt ? bytesToBase64url(salt) : null,
    sha256: await sha256Hex(ciphertext),
    filenameEnc,
    keyB64url,
  };
}

/**
 * Decrypt a downloaded file. Verifies the SHA-256 integrity hash BEFORE
 * decrypting, then relies on the GCM auth tag as a second check.
 *
 * @param {Uint8Array} ciphertext
 * @param {{ iv, filenameIv, salt, sha256, filenameEnc }} meta - from the server
 * @param {{ keyB64url?: string, passphrase?: string }} opts - exactly one source
 * @returns {{ data: Uint8Array, filename: string }}
 */
export async function decryptFile(ciphertext, meta, opts = {}) {
  const { keyB64url, passphrase } = opts;
  const actualHash = await sha256Hex(ciphertext);
  if (actualHash !== meta.sha256.toLowerCase()) {
    throw new Error('Integrity check failed: downloaded data does not match its SHA-256 hash (corrupted or tampered).');
  }
  let key;
  if (passphrase) {
    if (!meta.salt) throw new Error('This file has no passphrase salt; use the key from the share link instead.');
    key = await deriveKeyFromPassphrase(passphrase, base64urlToBytes(meta.salt));
  } else if (keyB64url) {
    key = await importKey(base64urlToBytes(keyB64url));
  } else {
    throw new Error('No key or passphrase provided.');
  }
  const iv = base64urlToBytes(meta.iv);
  const filenameIv = base64urlToBytes(meta.filenameIv);
  let data;
  let filename;
  try {
    data = await decryptBytes(ciphertext, key, iv);
    filename = await decryptFilename(meta.filenameEnc, key, filenameIv);
  } catch {
    throw new Error('Decryption failed: wrong key or passphrase, or the file was tampered with.');
  }
  return { data, filename };
}

/**
 * Build a share link. The key (if any) goes in the URL FRAGMENT, which
 * browsers never send to the server. Passphrase-protected files get a
 * keyless link — the recipient must know the passphrase.
 */
export function buildShareLink(serverBase, id, keyB64url) {
  const base = serverBase.replace(/\/$/, '');
  return keyB64url ? `${base}/d/${id}#key=${keyB64url}` : `${base}/d/${id}`;
}

/**
 * Parse a share link (or a pasted app URL) into { id, keyB64url }.
 * Accepts /d/<id>#key=..., /?id=<id>#key=..., or a bare <id> / <id>#key=....
 */
export function parseShareLink(input) {
  const text = String(input || '').trim();
  if (!text) throw new Error('Empty link');
  let hash = '';
  let rest = text;
  const hashIdx = text.indexOf('#');
  if (hashIdx >= 0) {
    hash = text.slice(hashIdx + 1);
    rest = text.slice(0, hashIdx);
  }
  let keyB64url = null;
  if (hash) {
    const m = hash.match(/(?:^|&)key=([A-Za-z0-9_-]+)/);
    if (m) keyB64url = m[1];
  }
  let id = null;
  const dMatch = rest.match(/\/d\/([A-Za-z0-9-]{8,64})/);
  const qMatch = rest.match(/[?&]id=([A-Za-z0-9-]{8,64})/);
  const bareMatch = rest.match(/^([A-Za-z0-9-]{8,64})$/);
  if (dMatch) id = dMatch[1];
  else if (qMatch) id = qMatch[1];
  else if (bareMatch) id = bareMatch[1];
  if (!id) throw new Error('Could not find a file id in that link.');
  return { id, keyB64url };
}
