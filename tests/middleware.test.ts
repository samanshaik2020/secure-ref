/**
 * Tests: Core middleware
 */

import { describe, it, expect, vi } from 'vitest';
import { createMiddleware } from '../src/middleware';

function mockRes() {
    const headers: Record<string, string> = {};
    const removed: string[] = [];
    return {
        setHeader(name: string, value: string) {
            headers[name] = value;
        },
        removeHeader(name: string) {
            removed.push(name);
            delete headers[name];
        },
        _headers: headers,
        _removed: removed,
    };
}

function mockReq() {
    return { headers: {} as Record<string, string> };
}

describe('createMiddleware()', () => {
    it('sets all 10 default security headers', () => {
        const middleware = createMiddleware();
        const res = mockRes();
        const next = vi.fn();

        middleware(mockReq(), res, next);

        expect(res._headers['Content-Security-Policy']).toBe("default-src 'self'");
        expect(res._headers['X-Content-Type-Options']).toBe('nosniff');
        expect(res._headers['X-Frame-Options']).toBe('DENY');
        expect(res._headers['Strict-Transport-Security']).toBe('max-age=31536000; includeSubDomains');
        expect(res._headers['Referrer-Policy']).toBe('no-referrer');
        expect(res._headers['X-XSS-Protection']).toBe('0');
        expect(res._headers['Cross-Origin-Opener-Policy']).toBe('same-origin');
        expect(res._headers['Cross-Origin-Resource-Policy']).toBe('same-origin');
        expect(res._headers['Cross-Origin-Embedder-Policy']).toBe('require-corp');
        expect(next).toHaveBeenCalledOnce();
    });

    it('removes Server and X-Powered-By headers by default', () => {
        const middleware = createMiddleware();
        const res = mockRes();
        middleware(mockReq(), res, vi.fn());

        expect(res._removed).toContain('Server');
        expect(res._removed).toContain('X-Powered-By');
    });

    it('allows overriding the CSP header', () => {
        const middleware = createMiddleware({ csp: "default-src 'none'" });
        const res = mockRes();
        middleware(mockReq(), res, vi.fn());

        expect(res._headers['Content-Security-Policy']).toBe("default-src 'none'");
    });

    it('disables a header when set to false', () => {
        const middleware = createMiddleware({ frameOptions: false });
        const res = mockRes();
        middleware(mockReq(), res, vi.fn());

        expect(res._headers['X-Frame-Options']).toBeUndefined();
    });

    it('calls next() exactly once', () => {
        const middleware = createMiddleware();
        const next = vi.fn();
        middleware(mockReq(), mockRes(), next);
        expect(next).toHaveBeenCalledTimes(1);
    });

    it('does not remove Server header when removeServer is false', () => {
        const middleware = createMiddleware({ removeServer: false });
        const res = mockRes();
        middleware(mockReq(), res, vi.fn());
        expect(res._removed).not.toContain('Server');
    });
});
