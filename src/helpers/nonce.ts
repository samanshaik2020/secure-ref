/**
 * secure-ref — CSP Nonce Generator
 * Generates cryptographically random nonces for Content-Security-Policy.
 *
 * Uses Node.js built-in `crypto.randomBytes` — no external dependencies.
 */

import { randomBytes } from 'node:crypto';

/**
 * Generates a cryptographically random CSP nonce (base64url encoded).
 *
 * Use with Content-Security-Policy `'nonce-{value}'` syntax.
 * A new nonce MUST be generated for every HTTP response.
 *
 * @param byteLength - Number of random bytes (default: 16 = 128-bit entropy)
 * @returns Base64url-encoded nonce string
 *
 * @example Express
 * ```ts
 * app.use((req, res, next) => {
 *   res.locals.nonce = secureRef.nonce();
 *   next();
 * });
 *
 * app.use(secureRef({
 *   csp: `script-src 'nonce-${res.locals.nonce}' 'strict-dynamic'`
 * }));
 * ```
 *
 * @example HTML template
 * ```html
 * <script nonce="<%= nonce %>">/* your inline script *\/</script>
 * ```
 */
export function nonce(byteLength = 16): string {
    return randomBytes(byteLength).toString('base64url');
}
