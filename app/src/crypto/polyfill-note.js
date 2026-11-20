/**
 * WebCrypto on React Native — why this app targets Expo WEB.
 *
 * The crypto in crypto.js uses ONLY `globalThis.crypto.subtle` (WebCrypto).
 * That is available in:
 *   - all modern browsers (Expo web target) — the verified target of this app
 *   - Node 19+ (globalThis.crypto) — used by the test suite
 *
 * It is NOT available in raw React Native (Hermes / JavaScriptCore on
 * iOS and Android): those runtimes ship no WebCrypto implementation, and
 * `globalThis.crypto.subtle` is undefined there. `getSubtle()` in crypto.js
 * throws a clear error in that case instead of silently failing.
 *
 * To run this app's crypto on native, add ONE of these (not included, so
 * the verified web build stays dependency-light):
 *
 *   1. `react-native-get-random-values` + a WebCrypto shim
 *      (e.g. `react-native-webcrypto` or `@peculiar/webcrypto` with a
 *      subtle-crypto provider), then assign the shim to
 *      `globalThis.crypto` before importing crypto.js.
 *   2. `expo-crypto` — provides digest + random bytes only, NOT AES-GCM,
 *      so it cannot power this module on its own; it can supply the
 *      random IV/salt while a shim provides subtle crypto.
 *   3. A native module (e.g. `react-native-aes-crypto`) — fastest, but
 *      ties the crypto to native code and needs per-platform testing.
 *
 * Whichever route you take, keep the crypto module's contract intact:
 * AES-256-GCM, PBKDF2-SHA-256 (600k iterations), keys never logged and
 * never persisted, key material only ever in the share-link fragment.
 */

// This file is documentation only; it exports nothing.
export {};
