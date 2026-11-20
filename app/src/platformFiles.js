/**
 * Native (Android / iOS) file I/O for SecureShare.
 *
 * Uses the modern expo-file-system API (SDK 52+): `File` / `Paths`.
 * This file is ONLY bundled for native targets — Metro resolves
 * `platformFiles.web.js` instead on web, so no native module code
 * ships in the web bundle. See polyfill-note.js: native also needs a
 * WebCrypto shim before crypto.js can run there.
 */
import { File, Paths } from 'expo-file-system';
import * as Sharing from 'expo-sharing';

/** Strip any directory components — a filename must never escape the cache dir. */
function safeFilename(name) {
  const base = String(name || 'download').split(/[\\/]/).pop() || 'download';
  return base.slice(0, 200);
}

/** Read the bytes of a file picked with expo-document-picker. */
export async function readPickedFileBytes(asset) {
  const file = new File(asset.uri);
  return file.bytes();
}

/**
 * Save decrypted bytes and open the native share sheet so the user can
 * keep the file (Save to Files, send to another app, …).
 */
export async function saveDownloadedFile(filename, bytes) {
  const file = new File(Paths.cache, safeFilename(filename));
  if (file.exists) file.delete();
  file.create();
  await file.write(bytes);
  if (await Sharing.isAvailableAsync()) {
    await Sharing.shareAsync(file.uri, { dialogTitle: `Save ${safeFilename(filename)}` });
    return 'shared';
  }
  // No share sheet (e.g. some Android emulators): fall back to preview.
  if (await File.canPreview(file)) {
    await File.preview(file);
    return 'previewed';
  }
  return 'saved';
}
