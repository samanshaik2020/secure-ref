/**
 * tests/index.test.ts
 * Full test suite for secure-ref v1.1.0
 */

import { describe, it, expect, vi } from 'vitest';

// Import directly from source (Vitest resolves .js → .ts automatically)
import secureRef, {
    nonce, cookie, sanitize, escapeHtml, rateLimit, jwt, sri, log, configureLogger, version
} from '../src/index.js';
import { REFERENCE } from '../src/reference.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function mockRes() {
    const headers: Record<string, string> = {};
    const removed: string[] = [];
    return {
        setHeader: (k: string, v: string) => void (headers[k] = v),
        removeHeader: (k: string) => void (removed.push(k), delete headers[k]),
        _h: headers,
        _r: removed,
    };
}

const fakeReq = { headers: {}, socket: {} };

// ─── Middleware ───────────────────────────────────────────────────────────────

describe('secureRef() middleware', () => {
    it('sets all 10 OWASP headers in production mode', () => {
        const res = mockRes();
        secureRef({ mode: 'production' })(fakeReq as never, res, vi.fn());

        expect(res._h['Content-Security-Policy']).toBe("default-src 'self'; script-src 'self'");
        expect(res._h['X-Content-Type-Options']).toBe('nosniff');
        expect(res._h['X-Frame-Options']).toBe('DENY');
        expect(res._h['Strict-Transport-Security']).toBe('max-age=31536000; includeSubDomains');
        expect(res._h['Referrer-Policy']).toBe('no-referrer');
        expect(res._h['Permissions-Policy']).toBe('camera=(), microphone=(), geolocation=()');
        expect(res._h['X-XSS-Protection']).toBe('0');
        expect(res._h['Cross-Origin-Opener-Policy']).toBe('same-origin');
        expect(res._h['Cross-Origin-Resource-Policy']).toBe('same-origin');
        expect(res._h['Cross-Origin-Embedder-Policy']).toBe('require-corp');
    });

    it('removes Server and X-Powered-By in production mode', () => {
        const res = mockRes();
        secureRef({ mode: 'production' })(fakeReq as never, res, vi.fn());
        expect(res._r).toContain('Server');
        expect(res._r).toContain('X-Powered-By');
    });

    it('calls next() exactly once', () => {
        const next = vi.fn();
        secureRef()(fakeReq as never, mockRes(), next);
        expect(next).toHaveBeenCalledOnce();
    });

    it('overrides CSP when provided', () => {
        const res = mockRes();
        secureRef({ csp: "default-src 'none'" })(fakeReq as never, res, vi.fn());
        expect(res._h['Content-Security-Policy']).toBe("default-src 'none'");
    });

    it('disables a header when set to false', () => {
        const res = mockRes();
        secureRef({ frameOptions: false })(fakeReq as never, res, vi.fn());
        expect(res._h['X-Frame-Options']).toBeUndefined();
    });

    it('disables HSTS when hsts is false', () => {
        const res = mockRes();
        secureRef({ hsts: false })(fakeReq as never, res, vi.fn());
        expect(res._h['Strict-Transport-Security']).toBeUndefined();
    });
});

// ─── Smart Security Modes ──────────────────────────────────────────────────────────────

describe('Smart Security Modes', () => {
    it('dev mode — disables HSTS and COEP, keeps Server header', () => {
        const res = mockRes();
        secureRef({ mode: 'dev' })(fakeReq as never, res, vi.fn());
        expect(res._h['Strict-Transport-Security']).toBeUndefined();
        expect(res._h['Cross-Origin-Embedder-Policy']).toBeUndefined();
        // removeServer: false in dev mode
        expect(res._r).not.toContain('Server');
    });

    it('dev mode — allows unsafe-inline scripts (for hot reload)', () => {
        const res = mockRes();
        secureRef({ mode: 'dev' })(fakeReq as never, res, vi.fn());
        expect(res._h['Content-Security-Policy']).toContain("'unsafe-inline'");
    });

    it('production mode — enforces HSTS and strict CSP', () => {
        const res = mockRes();
        secureRef({ mode: 'production' })(fakeReq as never, res, vi.fn());
        expect(res._h['Strict-Transport-Security']).toContain('max-age=31536000');
        expect(res._h['X-Frame-Options']).toBe('DENY');
        expect(res._h['Content-Security-Policy']).toBe("default-src 'self'; script-src 'self'");
        // removeServer: true → Server is removed
        expect(res._r).toContain('Server');
    });

    it('strict mode — max-age 2 years HSTS with preload', () => {
        const res = mockRes();
        secureRef({ mode: 'strict' })(fakeReq as never, res, vi.fn());
        expect(res._h['Strict-Transport-Security']).toContain('preload');
        expect(res._h['Strict-Transport-Security']).toContain('63072000');
    });

    it('strict mode — CSP allows nothing by default (default-src none)', () => {
        const res = mockRes();
        secureRef({ mode: 'strict' })(fakeReq as never, res, vi.fn());
        expect(res._h['Content-Security-Policy']).toContain("default-src 'none'");
        expect(res._h['Content-Security-Policy']).toContain("frame-ancestors 'none'");
    });

    it('strict mode — Permissions-Policy blocks payment and usb', () => {
        const res = mockRes();
        secureRef({ mode: 'strict' })(fakeReq as never, res, vi.fn());
        expect(res._h['Permissions-Policy']).toContain('payment=()');
        expect(res._h['Permissions-Policy']).toContain('usb=()');
    });

    it('user options always override mode preset', () => {
        const res = mockRes();
        secureRef({ mode: 'strict', csp: "default-src 'self'" })(fakeReq as never, res, vi.fn());
        // User CSP overrides strict mode's CSP
        expect(res._h['Content-Security-Policy']).toBe("default-src 'self'");
        // But strict mode's HSTS still applies
        expect(res._h['Strict-Transport-Security']).toContain('preload');
    });

    it('resolveMode() returns dev by default when NODE_ENV is not production', () => {
        const original = process.env['NODE_ENV'];
        delete process.env['NODE_ENV'];
        expect(secureRef.resolveMode()).toBe('dev');
        process.env['NODE_ENV'] = original;
    });

    it('resolveMode() returns production when NODE_ENV=production', () => {
        const original = process.env['NODE_ENV'];
        process.env['NODE_ENV'] = 'production';
        expect(secureRef.resolveMode()).toBe('production');
        process.env['NODE_ENV'] = original;
    });

    it('resolveMode() respects explicit mode regardless of NODE_ENV', () => {
        process.env['NODE_ENV'] = 'production';
        expect(secureRef.resolveMode({ mode: 'strict' })).toBe('strict');
        expect(secureRef.resolveMode({ mode: 'dev' })).toBe('dev');
        delete process.env['NODE_ENV'];
    });

    it('secureRef.modes exposes all 3 mode configs', () => {
        expect(secureRef.modes).toHaveProperty('dev');
        expect(secureRef.modes).toHaveProperty('production');
        expect(secureRef.modes).toHaveProperty('strict');
    });
});

// ─── Reference ────────────────────────────────────────────────────────────────

describe('secureRef.reference() / REFERENCE', () => {
    it('returns the OWASP reference object', () => {
        const ref = secureRef.reference();
        expect(ref).toBeDefined();
        expect(ref).toBe(REFERENCE);
    });

    it('has all 11 header entries', () => {
        const ref = secureRef.reference();
        const expectedHeaders = [
            'Content-Security-Policy', 'X-Content-Type-Options', 'X-Frame-Options',
            'Strict-Transport-Security', 'Referrer-Policy', 'Permissions-Policy',
            'X-XSS-Protection', 'Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy',
            'Cross-Origin-Embedder-Policy', 'Server',
        ];
        for (const h of expectedHeaders) {
            expect(ref.headers[h as keyof typeof ref.headers], `Missing: ${h}`).toBeDefined();
        }
    });

    it('has all 10 OWASP Top 10:2025 entries', () => {
        const ref = secureRef.reference();
        for (let i = 1; i <= 10; i++) {
            const key = `A${String(i).padStart(2, '0')}:2025` as keyof typeof ref.owaspTop10;
            expect(ref.owaspTop10[key], `Missing OWASP entry: ${key}`).toBeDefined();
        }
    });

    it('has best practices and links', () => {
        const ref = secureRef.reference();
        expect(ref.bestPractices.length).toBeGreaterThan(0);
        expect(ref.links.owasp).toMatch(/^https?:\/\//);
    });
});

// ─── Nonce ────────────────────────────────────────────────────────────────────

describe('nonce()', () => {
    it('returns a non-empty base64url string', () => {
        expect(nonce()).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('generates unique values on each call', () => {
        expect(nonce()).not.toBe(nonce());
    });

    it('respects custom byte length', () => {
        expect(nonce(32).length).toBeGreaterThanOrEqual(40);
    });
});

// ─── Cookie ───────────────────────────────────────────────────────────────────

describe('cookie()', () => {
    it('produces a secure cookie header with defaults (score 100)', () => {
        const { header, securityScore, warnings } = cookie({ name: 'sid', value: 'abc123' });
        expect(header).toContain('HttpOnly');
        expect(header).toContain('Secure');
        expect(header).toContain('SameSite=Strict');
        expect(header).toContain('Max-Age=3600');
        expect(securityScore).toBe(100);
        expect(warnings).toHaveLength(0);
    });

    it('warns and lowers score when HttpOnly is disabled', () => {
        const { warnings, securityScore } = cookie({ name: 'x', value: 'y', httpOnly: false });
        expect(warnings.some(w => w.includes('HttpOnly'))).toBe(true);
        expect(securityScore).toBeLessThan(100);
    });

    it('warns and lowers score when Secure is disabled', () => {
        const { warnings, securityScore } = cookie({ name: 'x', value: 'y', secure: false });
        expect(warnings.some(w => w.includes('Secure'))).toBe(true);
        expect(securityScore).toBeLessThan(100);
    });

    it('URL-encodes name and value', () => {
        const { header } = cookie({ name: 'my cookie', value: 'val=ue' });
        expect(header).toContain('my%20cookie');
        expect(header).toContain('val%3Due');
    });
});

// ─── Sanitize ─────────────────────────────────────────────────────────────────

describe('sanitize()', () => {
    it('removes <script> tags', () => {
        expect(sanitize('<script>alert(1)</script>Hello')).not.toContain('<script>');
        expect(sanitize('<script>alert(1)</script>Hello')).toContain('Hello');
    });

    it('removes javascript: protocol', () => {
        expect(sanitize('<a href="javascript:void(0)">x</a>')).not.toContain('javascript:');
    });

    it('removes inline event handlers', () => {
        expect(sanitize('<img onerror="alert(1)" src="x">')).not.toContain('onerror');
    });

    it('removes iframe tags', () => {
        expect(sanitize('<iframe src="evil.com"></iframe>')).not.toContain('iframe');
    });

    it('preserves safe HTML like <p> and <strong>', () => {
        const result = sanitize('<p>Hello <strong>world</strong></p>');
        expect(result).toContain('<p>');
        expect(result).toContain('<strong>');
    });

    it('handles non-string input gracefully', () => {
        // @ts-expect-error testing runtime behaviour
        expect(sanitize(42)).toBe('42');
    });
});

describe('escapeHtml()', () => {
    it('escapes < > & " \'', () => {
        const result = escapeHtml('<script>alert("xss")</script>');
        expect(result).toContain('&lt;');
        expect(result).toContain('&gt;');
        expect(result).not.toContain('<script>');
    });
});

// ─── JWT ──────────────────────────────────────────────────────────────────────

describe('jwt', () => {
    const SECRET = 'super-secret-at-least-32-chars!!!';

    it('sign() produces a 3-part token', () => {
        expect(jwt.sign({ userId: '1' }, SECRET).split('.')).toHaveLength(3);
    });

    it('verify() returns valid=true for a fresh token', () => {
        const token = jwt.sign({ userId: '1' }, SECRET);
        const { valid, payload } = jwt.verify(token, SECRET);
        expect(valid).toBe(true);
        expect(payload?.userId).toBe('1');
    });

    it('verify() returns valid=false for tampered token', () => {
        const token = jwt.sign({ userId: '1' }, SECRET);
        const { valid } = jwt.verify(token.slice(0, -4) + 'XXXX', SECRET);
        expect(valid).toBe(false);
    });

    it('verify() returns valid=false for expired token', () => {
        const token = jwt.sign({ u: 1 }, SECRET, { expiresIn: -1 });
        const { valid, error } = jwt.verify(token, SECRET);
        expect(valid).toBe(false);
        expect(error).toMatch(/expired/i);
    });

    it('verify() rejects wrong secret', () => {
        const token = jwt.sign({ u: 1 }, SECRET);
        expect(jwt.verify(token, 'a-different-secret-of-32-chars!!').valid).toBe(false);
    });

    it('sign() throws for short secret', () => {
        expect(() => jwt.sign({ u: 1 }, 'short')).toThrow();
    });

    it('decode() returns payload without verifying', () => {
        const token = jwt.sign({ userId: 'abc' }, SECRET);
        expect(jwt.decode(token)?.userId).toBe('abc');
    });

    it('decode() returns null for malformed token', () => {
        expect(jwt.decode('not.a.token')).toBeNull();
    });
});

// ─── SRI ──────────────────────────────────────────────────────────────────────

describe('sri()', () => {
    const content = Buffer.from('console.log("hello")');

    it('defaults to sha384', () => {
        expect(sri(content).algorithm).toBe('sha384');
        expect(sri(content).integrityAttribute).toMatch(/^sha384-/);
    });

    it('supports sha256 and sha512', () => {
        expect(sri(content, 'sha256').integrityAttribute).toMatch(/^sha256-/);
        expect(sri(content, 'sha512').integrityAttribute).toMatch(/^sha512-/);
    });

    it('produces consistent hashes', () => {
        expect(sri(content).integrityAttribute).toBe(sri(content).integrityAttribute);
    });

    it('includes URL in htmlTag when provided', () => {
        const tag = sri(content, 'sha384', 'https://cdn.example.com/app.js').htmlTag;
        expect(tag).toContain('src="https://cdn.example.com/app.js"');
        expect(tag).toContain('crossorigin="anonymous"');
    });
});

// ─── Logger ───────────────────────────────────────────────────────────────────

describe('log() + configureLogger()', () => {
    it('log() returns a structured event object', () => {
        const entry = log('auth_failure', { username: 'test' });
        expect(entry.event).toBe('auth_failure');
        expect(entry.severity).toBe('high');
        expect(entry.timestamp).toBeTruthy();
    });

    it('configureLogger() replaces transports', () => {
        const received: unknown[] = [];
        configureLogger([{ log: (e) => received.push(e) }]);
        log('custom_event', { foo: 'bar' });
        expect(received.length).toBe(1);
        // Restore console transport
        configureLogger([{ log: (e) => console.log('[secure-ref]', e.event) }]);
    });
});

// ─── Version ─────────────────────────────────────────────────────────────────

describe('version', () => {
    it('exports a semver version string', () => {
        expect(version).toMatch(/^\d+\.\d+\.\d+$/);
    });

    it('is v1.1.0', () => {
        expect(version).toBe('1.1.0');
    });
});
