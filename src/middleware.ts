/**
 * secure-ref — Core Security Middleware
 */

import type {
    SecureRefOptions,
    SecureRefMiddleware,
    SecureRefRequest,
    SecureRefResponse,
    NextFunction,
} from './types';

/** Default header values per OWASP Secure Headers Project */
const DEFAULTS = {
    csp: "default-src 'self'",
    contentTypeOptions: 'nosniff',
    frameOptions: 'DENY',
    hsts: 'max-age=31536000; includeSubDomains',
    referrerPolicy: 'no-referrer',
    permissionsPolicy: 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
    xssProtection: '0',
    coop: 'same-origin',
    corp: 'same-origin',
    coep: 'require-corp',
    removeServer: true,
} as const;

export function createMiddleware(options: SecureRefOptions = {}): SecureRefMiddleware {
    const opts = { ...DEFAULTS, ...options };

    const headers: [string, string][] = [];

    if (opts.csp !== false) headers.push(['Content-Security-Policy', opts.csp as string]);
    if (opts.contentTypeOptions !== false) headers.push(['X-Content-Type-Options', opts.contentTypeOptions as string]);
    if (opts.frameOptions !== false) headers.push(['X-Frame-Options', opts.frameOptions as string]);
    if (opts.hsts !== false) headers.push(['Strict-Transport-Security', opts.hsts as string]);
    if (opts.referrerPolicy !== false) headers.push(['Referrer-Policy', opts.referrerPolicy as string]);
    if (opts.permissionsPolicy !== false) headers.push(['Permissions-Policy', opts.permissionsPolicy as string]);
    if (opts.xssProtection !== false) headers.push(['X-XSS-Protection', opts.xssProtection as string]);
    if (opts.coop !== false) headers.push(['Cross-Origin-Opener-Policy', opts.coop as string]);
    if (opts.corp !== false) headers.push(['Cross-Origin-Resource-Policy', opts.corp as string]);
    if (opts.coep !== false) headers.push(['Cross-Origin-Embedder-Policy', opts.coep as string]);

    return function secureRefMiddleware(
        _req: SecureRefRequest,
        res: SecureRefResponse,
        next: NextFunction
    ): void {
        for (const [name, value] of headers) {
            res.setHeader(name, value);
        }
        if (opts.removeServer !== false) {
            res.removeHeader('Server');
            res.removeHeader('X-Powered-By');
        }
        next();
    };
}
