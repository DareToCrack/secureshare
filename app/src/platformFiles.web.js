/**
 * Web file I/O for SecureShare (Metro resolves this file instead of
 * platformFiles.js when bundling for web).
 *
 * No native modules: picked files are read via the web File API /
 * fetch, and decrypted files are saved with a blob + anchor download.
 */

/** Strip any directory components — a filename must never contain a path. */
function safeFilename(name) {
  const base = String(name || 'download').split(/[\\/]/).pop() || 'download';
  return base.slice(0, 200);
}

/**
 * Read the bytes of a file picked with expo-document-picker.
 * On web the picker asset carries the DOM File object (`asset.file`) and
 * the result also exposes a FileList (`result.output`); fall back to
 * fetching the asset URI (blob: or data: URL).
 */
export async function readPickedFileBytes(asset) {
  if (asset.file && typeof asset.file.arrayBuffer === 'function') {
    return new Uint8Array(await asset.file.arrayBuffer());
  }
  const res = await fetch(asset.uri);
  if (!res.ok) throw new Error(`Could not read picked file (HTTP ${res.status})`);
  return new Uint8Array(await res.arrayBuffer());
}

/** Save decrypted bytes via a blob + anchor download in the browser. */
export async function saveDownloadedFile(filename, bytes) {
  const blob = new Blob([bytes], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement('a');
    a.href = url;
    a.download = safeFilename(filename);
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }
  return 'downloaded';
}
