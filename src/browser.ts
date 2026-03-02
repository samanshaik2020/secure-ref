// Browser-safe re-exports (no Node.js-only APIs like rateLimit, crypto-backed jwt)
export { sanitize, escapeHtml, nonce, browser } from './index.js';
export { REFERENCE } from './reference.js';
export type { SecureRefOptions, CookieOptions, JwtPayload } from './index.js';
