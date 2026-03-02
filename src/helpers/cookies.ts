import type { CookieOptions, CookieResult } from '../types';

export function cookie(options: CookieOptions): CookieResult {
    const {
        name,
        value,
        maxAge = 3600,
        httpOnly = true,
        secure = true,
        sameSite = 'Strict',
        path = '/',
        domain,
        partitioned = false,
    } = options;

    const warnings: string[] = [];
    let securityScore = 100;

    const parts: string[] = [`${encodeURIComponent(name)}=${encodeURIComponent(value)}`];

    if (maxAge !== undefined) parts.push(`Max-Age=${maxAge}`);
    parts.push(`Path=${path}`);
    if (domain) parts.push(`Domain=${domain}`);

    if (httpOnly) {
        parts.push('HttpOnly');
    } else {
        warnings.push('⚠ HttpOnly not set — cookie is accessible via JavaScript (XSS risk)');
        securityScore -= 30;
    }

    if (secure) {
        parts.push('Secure');
    } else {
        warnings.push('⚠ Secure not set — cookie will be sent over HTTP connections');
        securityScore -= 30;
    }

    if (sameSite) {
        parts.push(`SameSite=${sameSite}`);
        if (sameSite === 'None' && !secure) {
            warnings.push('⚠ SameSite=None requires Secure flag — this configuration is invalid');
            securityScore -= 20;
        }
        if (sameSite === 'None') {
            warnings.push('ℹ SameSite=None allows cross-origin requests — ensure this is intentional');
            securityScore -= 10;
        }
    } else {
        warnings.push('⚠ SameSite not set — may be vulnerable to CSRF attacks');
        securityScore -= 20;
    }

    if (partitioned) parts.push('Partitioned');

    if (maxAge > 86400 * 30) {
        warnings.push('ℹ Long-lived cookie (>30 days) — consider shorter expiry for session cookies');
        securityScore -= 5;
    }

    return {
        header: parts.join('; '),
        securityScore: Math.max(0, securityScore),
        warnings,
    };
}
