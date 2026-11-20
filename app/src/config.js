/**
 * App configuration.
 *
 * Override with environment variables at build/dev time:
 *   EXPO_PUBLIC_API_URL     base URL of the SecureShare API server
 *                           (default http://localhost:3001)
 *   EXPO_PUBLIC_SERVER_URL  base URL used in share links (defaults to the
 *                           API URL — the server serves /d/<id> links)
 */
export const API_BASE_URL = (process.env.EXPO_PUBLIC_API_URL || 'http://localhost:3001').replace(/\/$/, '');
export const SERVER_BASE_URL = (process.env.EXPO_PUBLIC_SERVER_URL || API_BASE_URL).replace(/\/$/, '');
export const MAX_FILE_MB = 25;
