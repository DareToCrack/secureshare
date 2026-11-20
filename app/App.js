/**
 * SecureShare — encrypted file sharing.
 *
 * Files are encrypted client-side with AES-256-GCM (WebCrypto) BEFORE
 * upload. The server only ever sees ciphertext + an encrypted filename.
 * The decryption key travels in the URL fragment (#key=...) of the share
 * link, which browsers never send to the server. With a passphrase, no
 * key is put in the link at all — the recipient must know the passphrase.
 *
 * Verified target: Expo web. On native, WebCrypto needs a shim — see
 * src/crypto/polyfill-note.js.
 */
import { useEffect, useState } from 'react';
import {
  ActivityIndicator,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Switch,
  Text,
  TextInput,
  View,
} from 'react-native';
import { StatusBar } from 'expo-status-bar';
import * as DocumentPicker from 'expo-document-picker';
import * as Clipboard from 'expo-clipboard';
import {
  encryptFile,
  decryptFile,
  buildShareLink,
  parseShareLink,
} from './src/crypto/crypto.js';
import { readPickedFileBytes, saveDownloadedFile } from './src/platformFiles';
import { API_BASE_URL, SERVER_BASE_URL, MAX_FILE_MB } from './src/config.js';

const EXPIRY_PRESETS = [
  { label: '1 hour', hours: 1 },
  { label: '24 hours', hours: 24 },
  { label: '7 days', hours: 168 },
];

function formatBytes(n) {
  if (n == null) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function formatExpiry(ts) {
  const d = new Date(ts);
  const mins = Math.max(0, Math.round((ts - Date.now()) / 60000));
  const when = mins < 60
    ? `in ${mins} min`
    : mins < 60 * 24
      ? `in ${Math.round(mins / 60)} h`
      : `in ${Math.round(mins / (60 * 24))} d`;
  return `${d.toLocaleString()} (${when})`;
}

export default function App() {
  const [screen, setScreen] = useState('upload');
  const [deepLink, setDeepLink] = useState(null);

  // If the app was opened via a share link (/?id=...#key=...), jump
  // straight to the Download screen with the link prefilled.
  useEffect(() => {
    if (Platform.OS !== 'web') return;
    try {
      const parsed = parseShareLink(window.location.href);
      if (parsed.id) {
        setDeepLink({ href: window.location.href, ...parsed });
        setScreen('download');
      }
    } catch {
      // Not a share link — stay on the Upload screen.
    }
  }, []);

  return (
    <View style={styles.root}>
      <StatusBar style="light" />
      <ScrollView contentContainerStyle={styles.scroll}>
        <View style={styles.container}>
          <Text style={styles.title}>🔒 SecureShare</Text>
          <Text style={styles.tagline}>Encrypted file sharing — auto-deleting links</Text>

          <View style={styles.notice}>
            <Text style={styles.noticeText}>
              Encrypted in your browser before upload — the server never sees your file, its
              name, or the key. Files auto-delete when they expire.
            </Text>
          </View>

          <View style={styles.tabs}>
            <Pressable
              style={[styles.tab, screen === 'upload' && styles.tabActive]}
              onPress={() => setScreen('upload')}
            >
              <Text style={[styles.tabText, screen === 'upload' && styles.tabTextActive]}>⬆ Upload</Text>
            </Pressable>
            <Pressable
              style={[styles.tab, screen === 'download' && styles.tabActive]}
              onPress={() => setScreen('download')}
            >
              <Text style={[styles.tabText, screen === 'download' && styles.tabTextActive]}>⬇ Download</Text>
            </Pressable>
          </View>

          {screen === 'upload'
            ? <UploadScreen />
            : <DownloadScreen deepLink={deepLink} />}
        </View>
      </ScrollView>
    </View>
  );
}

function UploadScreen() {
  const [picked, setPicked] = useState(null);
  const [passphrase, setPassphrase] = useState('');
  const [expiryHours, setExpiryHours] = useState(24);
  const [customHours, setCustomHours] = useState('');
  const [burn, setBurn] = useState(false);
  const [status, setStatus] = useState('idle'); // idle | encrypting | uploading | done | error
  const [error, setError] = useState('');
  const [shareLink, setShareLink] = useState('');
  const [shareIsPassphrase, setShareIsPassphrase] = useState(false);
  const [expiresAt, setExpiresAt] = useState(null);
  const [copied, setCopied] = useState(false);

  async function pickFile() {
    setError('');
    try {
      const result = await DocumentPicker.getDocumentAsync({
        type: '*/*',
        copyToCacheDirectory: true,
        multiple: false,
      });
      if (result.canceled || !result.assets?.length) return;
      const asset = result.assets[0];
      if (asset.size && asset.size > MAX_FILE_MB * 1024 * 1024) {
        setError(`File is too large — max ${MAX_FILE_MB} MB.`);
        return;
      }
      setPicked(asset);
      setShareLink('');
      setStatus('idle');
    } catch (e) {
      setError(`Could not pick a file: ${e.message}`);
    }
  }

  async function upload() {
    if (!picked) return;
    setError('');
    setStatus('encrypting');
    try {
      const bytes = await readPickedFileBytes(picked);
      const usePassphrase = passphrase.trim().length > 0;
      const result = await encryptFile(
        bytes,
        picked.name,
        usePassphrase ? { passphrase: passphrase.trim() } : {},
      );
      setStatus('uploading');
      const form = new FormData();
      form.append('file', new Blob([result.ciphertext], { type: 'application/octet-stream' }), 'blob.bin');
      form.append('meta', JSON.stringify({
        iv: result.iv,
        filenameIv: result.filenameIv,
        salt: result.salt,
        sha256: result.sha256,
        filenameEnc: result.filenameEnc,
        originalSize: bytes.length,
        expiresInHours: expiryHours,
        burnAfterReading: burn,
      }));
      const res = await fetch(`${API_BASE_URL}/api/upload`, { method: 'POST', body: form });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(body.error === 'file_too_large'
          ? `File too large — the server allows max ${body.maxMb} MB.`
          : `Upload failed (${res.status}): ${body.error || 'unknown error'}`);
      }
      setShareLink(buildShareLink(SERVER_BASE_URL, body.id, result.keyB64url));
      setShareIsPassphrase(usePassphrase);
      setExpiresAt(body.expiresAt);
      setStatus('done');
    } catch (e) {
      setError(e.message);
      setStatus('error');
    }
  }

  async function copyLink() {
    try {
      await Clipboard.setStringAsync(shareLink, { android: { isSensitive: true } });
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      try {
        await navigator.clipboard.writeText(shareLink);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } catch {
        setError('Copy failed — select the link manually.');
      }
    }
  }

  function reset() {
    setPicked(null);
    setPassphrase('');
    setBurn(false);
    setShareLink('');
    setExpiresAt(null);
    setStatus('idle');
    setError('');
  }

  const busy = status === 'encrypting' || status === 'uploading';

  return (
    <View style={styles.card}>
      <Text style={styles.sectionTitle}>Share a file securely</Text>

      <Pressable style={styles.pickButton} onPress={pickFile} disabled={busy}>
        <Text style={styles.pickButtonText}>{picked ? '📄 Change file' : '📁 Choose a file'}</Text>
      </Pressable>
      {picked && (
        <Text style={styles.fileInfo}>{picked.name} · {formatBytes(picked.size)}</Text>
      )}
      <Text style={styles.hint}>Max {MAX_FILE_MB} MB. Encrypted with AES-256-GCM on your device.</Text>

      <Text style={styles.label}>Passphrase (optional)</Text>
      <TextInput
        style={styles.input}
        placeholder="Leave empty for a key-in-link share"
        placeholderTextColor="#64748b"
        secureTextEntry
        value={passphrase}
        onChangeText={setPassphrase}
        editable={!busy}
      />
      <Text style={styles.hint}>
        With a passphrase, the link alone cannot decrypt the file — the recipient must know it.
      </Text>

      <Text style={styles.label}>Auto-delete after</Text>
      <View style={styles.presetRow}>
        {EXPIRY_PRESETS.map((p) => (
          <Pressable
            key={p.hours}
            style={[styles.preset, expiryHours === p.hours && styles.presetActive]}
            onPress={() => { setExpiryHours(p.hours); setCustomHours(''); }}
            disabled={busy}
          >
            <Text style={[styles.presetText, expiryHours === p.hours && styles.presetTextActive]}>{p.label}</Text>
          </Pressable>
        ))}
      </View>
      <TextInput
        style={styles.input}
        placeholder="Or custom hours (1–168)"
        placeholderTextColor="#64748b"
        keyboardType="numeric"
        value={customHours}
        editable={!busy}
        onChangeText={(t) => {
          setCustomHours(t.replace(/[^0-9]/g, ''));
          const n = parseInt(t, 10);
          if (Number.isFinite(n)) setExpiryHours(Math.min(168, Math.max(1, n)));
        }}
      />

      <View style={styles.switchRow}>
        <Text style={styles.switchLabel}>Delete after first download</Text>
        <Switch value={burn} onValueChange={setBurn} disabled={busy} trackColor={{ true: '#22c55e' }} />
      </View>

      <Pressable
        style={[styles.primaryButton, (!picked || busy) && styles.buttonDisabled]}
        onPress={upload}
        disabled={!picked || busy}
      >
        {busy
          ? <ActivityIndicator color="#fff" />
          : <Text style={styles.primaryButtonText}>🔐 Encrypt & Upload</Text>}
      </Pressable>
      {status === 'encrypting' && <Text style={styles.statusText}>Encrypting on your device…</Text>}
      {status === 'uploading' && <Text style={styles.statusText}>Uploading ciphertext…</Text>}
      {error !== '' && <Text style={styles.errorText}>{error}</Text>}

      {status === 'done' && shareLink !== '' && (
        <View style={styles.shareBox}>
          <Text style={styles.shareTitle}>✅ Your secure link</Text>
          <Text style={styles.shareLink} selectable>{shareLink}</Text>
          {shareIsPassphrase && (
            <Text style={styles.shareNote}>Passphrase-protected: share the passphrase separately — the link alone will not open this file.</Text>
          )}
          {!shareIsPassphrase && (
            <Text style={styles.shareNote}>Anyone with this link can decrypt the file — the key is in the link itself. Send it over a trusted channel.</Text>
          )}
          <Text style={styles.shareNote}>Expires {expiresAt ? formatExpiry(expiresAt) : ''} — then it is deleted from the server.</Text>
          <Pressable style={styles.copyButton} onPress={copyLink}>
            <Text style={styles.copyButtonText}>{copied ? '✓ Copied!' : '📋 Copy link'}</Text>
          </Pressable>
          <Pressable style={styles.secondaryButton} onPress={reset}>
            <Text style={styles.secondaryButtonText}>Share another file</Text>
          </Pressable>
        </View>
      )}
    </View>
  );
}

function DownloadScreen({ deepLink }) {
  const [link, setLink] = useState('');
  const [fileId, setFileId] = useState('');
  const [keyB64url, setKeyB64url] = useState(null);
  const [meta, setMeta] = useState(null);
  const [dlPassphrase, setDlPassphrase] = useState('');
  const [status, setStatus] = useState('idle'); // idle | loading | ready | decrypting | done | error
  const [error, setError] = useState('');
  const [savedName, setSavedName] = useState('');

  useEffect(() => {
    if (deepLink?.href) {
      setLink(deepLink.href);
      loadMeta(deepLink.href);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deepLink]);

  async function loadMeta(linkText) {
    setError('');
    setMeta(null);
    setSavedName('');
    setStatus('loading');
    try {
      const parsed = parseShareLink(linkText);
      setFileId(parsed.id);
      setKeyB64url(parsed.keyB64url);
      const res = await fetch(`${API_BASE_URL}/api/files/${parsed.id}/meta`);
      const body = await res.json().catch(() => ({}));
      if (res.status === 410) throw new Error('This file has expired and been deleted.');
      if (res.status === 404) throw new Error('File not found — the link may be wrong, or the file was deleted.');
      if (!res.ok) throw new Error(`Could not load file info (${res.status})`);
      setMeta(body);
      setStatus('ready');
    } catch (e) {
      setError(e.message);
      setStatus('error');
    }
  }

  async function downloadAndDecrypt() {
    if (!meta) return;
    setError('');
    setStatus('decrypting');
    try {
      if (meta.salt && !dlPassphrase) throw new Error('This file needs its passphrase.');
      const res = await fetch(`${API_BASE_URL}/api/files/${fileId}/download`);
      if (res.status === 410) throw new Error('This file has expired and been deleted.');
      if (!res.ok) throw new Error(`Download failed (${res.status})`);
      const ciphertext = new Uint8Array(await res.arrayBuffer());
      const opts = meta.salt
        ? { passphrase: dlPassphrase }
        : { keyB64url };
      const { data, filename } = await decryptFile(ciphertext, meta, opts);
      await saveDownloadedFile(filename, data);
      setSavedName(filename);
      setStatus('done');
    } catch (e) {
      setError(e.message);
      setStatus('error');
    }
  }

  const busy = status === 'loading' || status === 'decrypting';

  return (
    <View style={styles.card}>
      <Text style={styles.sectionTitle}>Open a shared file</Text>
      <Text style={styles.label}>Share link (or file id)</Text>
      <TextInput
        style={styles.input}
        placeholder="https://…/d/<id>#key=…"
        placeholderTextColor="#64748b"
        value={link}
        onChangeText={setLink}
        editable={!busy}
        autoCapitalize="none"
        autoCorrect={false}
      />
      <Pressable
        style={[styles.primaryButton, (!link.trim() || busy) && styles.buttonDisabled]}
        onPress={() => loadMeta(link)}
        disabled={!link.trim() || busy}
      >
        {status === 'loading'
          ? <ActivityIndicator color="#fff" />
          : <Text style={styles.primaryButtonText}>🔍 Load file info</Text>}
      </Pressable>
      {error !== '' && <Text style={styles.errorText}>{error}</Text>}

      {meta && (
        <View style={styles.metaBox}>
          <Text style={styles.metaRow}>Size: <Text style={styles.metaValue}>{formatBytes(meta.originalSize)}</Text></Text>
          <Text style={styles.metaRow}>Expires: <Text style={styles.metaValue}>{formatExpiry(meta.expiresAt)}</Text></Text>
          <Text style={styles.metaRow}>Protection: <Text style={styles.metaValue}>{meta.salt ? 'Passphrase required' : 'Key in link'}</Text></Text>
          {meta.burnAfterReading && (
            <Text style={styles.metaRow}>⚠️ <Text style={styles.metaValue}>Burns after first download — this link works once.</Text></Text>
          )}
          {meta.downloads > 0 && (
            <Text style={styles.metaRow}>Downloads so far: <Text style={styles.metaValue}>{meta.downloads}</Text></Text>
          )}

          {meta.salt && (
            <>
              <Text style={styles.label}>Passphrase</Text>
              <TextInput
                style={styles.input}
                placeholder="Enter the file passphrase"
                placeholderTextColor="#64748b"
                secureTextEntry
                value={dlPassphrase}
                onChangeText={setDlPassphrase}
                editable={!busy}
              />
            </>
          )}

          <Pressable
            style={[styles.primaryButton, busy && styles.buttonDisabled]}
            onPress={downloadAndDecrypt}
            disabled={busy}
          >
            {status === 'decrypting'
              ? <ActivityIndicator color="#fff" />
              : <Text style={styles.primaryButtonText}>🔓 Decrypt & Download</Text>}
          </Pressable>
          {status === 'decrypting' && <Text style={styles.statusText}>Verifying integrity & decrypting…</Text>}
          {status === 'done' && savedName !== '' && (
            <Text style={styles.successText}>✅ Saved “{savedName}” — decrypted on your device.</Text>
          )}
        </View>
      )}
      <Text style={styles.hint}>
        Decryption happens on your device. The key (from the link fragment) and any passphrase
        are never sent to the server.
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: '#0b1220' },
  scroll: { flexGrow: 1 },
  container: {
    flex: 1,
    padding: 20,
    maxWidth: 640,
    width: '100%',
    alignSelf: 'center',
  },
  title: { fontSize: 30, fontWeight: '800', color: '#f1f5f9', marginTop: 24, textAlign: 'center' },
  tagline: { fontSize: 14, color: '#94a3b8', textAlign: 'center', marginTop: 6, marginBottom: 16 },
  notice: {
    backgroundColor: '#12233d',
    borderColor: '#1e3a5f',
    borderWidth: 1,
    borderRadius: 10,
    padding: 12,
    marginBottom: 18,
  },
  noticeText: { color: '#bae6fd', fontSize: 13, lineHeight: 19, textAlign: 'center' },
  tabs: { flexDirection: 'row', backgroundColor: '#111c33', borderRadius: 10, padding: 4, marginBottom: 16 },
  tab: { flex: 1, paddingVertical: 10, borderRadius: 8, alignItems: 'center' },
  tabActive: { backgroundColor: '#22c55e' },
  tabText: { color: '#94a3b8', fontWeight: '700', fontSize: 15 },
  tabTextActive: { color: '#04120a' },
  card: {
    backgroundColor: '#111c33',
    borderRadius: 14,
    borderWidth: 1,
    borderColor: '#1e293b',
    padding: 18,
    marginBottom: 24,
  },
  sectionTitle: { fontSize: 19, fontWeight: '700', color: '#f1f5f9', marginBottom: 14 },
  label: { fontSize: 13, fontWeight: '700', color: '#cbd5e1', marginTop: 14, marginBottom: 6 },
  input: {
    backgroundColor: '#0b1220',
    borderWidth: 1,
    borderColor: '#334155',
    borderRadius: 9,
    color: '#f1f5f9',
    fontSize: 15,
    paddingHorizontal: 12,
    paddingVertical: 10,
  },
  hint: { fontSize: 12, color: '#64748b', marginTop: 6, lineHeight: 17 },
  pickButton: {
    backgroundColor: '#1e293b',
    borderWidth: 1,
    borderColor: '#38bdf8',
    borderRadius: 9,
    paddingVertical: 13,
    alignItems: 'center',
  },
  pickButtonText: { color: '#7dd3fc', fontWeight: '700', fontSize: 15 },
  fileInfo: { color: '#e2e8f0', fontSize: 14, marginTop: 10 },
  presetRow: { flexDirection: 'row', gap: 8 },
  preset: {
    flex: 1,
    borderWidth: 1,
    borderColor: '#334155',
    borderRadius: 9,
    paddingVertical: 9,
    alignItems: 'center',
  },
  presetActive: { backgroundColor: '#14532d', borderColor: '#22c55e' },
  presetText: { color: '#94a3b8', fontWeight: '700', fontSize: 13 },
  presetTextActive: { color: '#bbf7d0' },
  switchRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', marginTop: 16 },
  switchLabel: { color: '#cbd5e1', fontSize: 14, fontWeight: '600' },
  primaryButton: {
    backgroundColor: '#22c55e',
    borderRadius: 9,
    paddingVertical: 13,
    alignItems: 'center',
    marginTop: 18,
  },
  primaryButtonText: { color: '#04120a', fontWeight: '800', fontSize: 16 },
  buttonDisabled: { opacity: 0.45 },
  statusText: { color: '#94a3b8', fontSize: 13, marginTop: 10, textAlign: 'center' },
  errorText: { color: '#fca5a5', fontSize: 13, marginTop: 12, lineHeight: 18 },
  successText: { color: '#86efac', fontSize: 13, marginTop: 12, lineHeight: 18 },
  shareBox: {
    backgroundColor: '#0b1220',
    borderWidth: 1,
    borderColor: '#22c55e',
    borderRadius: 10,
    padding: 14,
    marginTop: 16,
  },
  shareTitle: { color: '#bbf7d0', fontWeight: '800', fontSize: 15, marginBottom: 8 },
  shareLink: { color: '#7dd3fc', fontSize: 13, lineHeight: 19, marginBottom: 10 },
  shareNote: { color: '#94a3b8', fontSize: 12, lineHeight: 17, marginBottom: 6 },
  copyButton: {
    backgroundColor: '#38bdf8',
    borderRadius: 9,
    paddingVertical: 11,
    alignItems: 'center',
    marginTop: 8,
  },
  copyButtonText: { color: '#082f49', fontWeight: '800', fontSize: 15 },
  secondaryButton: { paddingVertical: 10, alignItems: 'center', marginTop: 6 },
  secondaryButtonText: { color: '#94a3b8', fontWeight: '700', fontSize: 14 },
  metaBox: {
    backgroundColor: '#0b1220',
    borderWidth: 1,
    borderColor: '#334155',
    borderRadius: 10,
    padding: 14,
    marginTop: 16,
  },
  metaRow: { color: '#94a3b8', fontSize: 14, marginBottom: 6 },
  metaValue: { color: '#e2e8f0', fontWeight: '600' },
});
