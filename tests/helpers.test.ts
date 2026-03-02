/**
 * Tests: Helper functions (cookie, nonce, sanitize, jwt, sri)
 */

import { describe, it, expect } from 'vitest';
import { cookie } from '../src/helpers/cookies';
import { nonce } from '../src/helpers/nonce';
import { sanitize, escapeHtml } from '../src/helpers/sanitize';
import { sign, verify, decode } from '../src/helpers/jwt';
import { sri } from '../src/helpers/sri';

// ─── Cookie ───────────────────────────────────────────────────────────────────

describe('cookie()', () => {
    it('produces a secure cookie header with defaults', () => {
        const { header, securityScore, warnings } = cookie({ name: 'session', value: 'tok123' });
        expect(header).toContain('HttpOnly');
        expect(header).toContain('Secure');
        expect(header).toContain('SameSite=Strict');
        expect(header).toContain('Max-Age=3600');
        expect(securityScore).toBe(100);
        expect(warnings).toHaveLength(0);
    });

    it('warns when HttpOnly is disabled', () => {
        const { warnings, securityScore } = cookie({ name: 'x', value: 'y', httpOnly: false });
        expect(warnings.some((w) => w.includes('HttpOnly'))).toBe(true);
        expect(securityScore).toBeLessThan(100);
    });

    it('warns when Secure is disabled', () => {
        const { warnings, securityScore } = cookie({ name: 'x', value: 'y', secure: false });
        expect(warnings.some((w) => w.includes('Secure'))).toBe(true);
        expect(securityScore).toBeLessThan(100);
    });

    it('URL-encodes the cookie name and value', () => {
        const { header } = cookie({ name: 'my cookie', value: 'val=ue' });
        expect(header).toContain('my%20cookie');
        expect(header).toContain('val%3Due');
    });
});

// ─── Nonce ────────────────────────────────────────────────────────────────────

describe('nonce()', () => {
    it('returns a non-empty string', () => {
        const n = nonce();
        expect(typeof n).toBe('string');
        expect(n.length).toBeGreaterThan(0);
    });

    it('returns different values on each call', () => {
        const n1 = nonce();
        const n2 = nonce();
        expect(n1).not.toBe(n2);
    });

    it('returns a base64url-safe string (no +, /, =)', () => {
        const n = nonce();
        expect(n).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('respects custom byte length', () => {
        const n32 = nonce(32);
        expect(n32.length).toBeGreaterThanOrEqual(40);
    });
});

// ─── Sanitize ─────────────────────────────────────────────────────────────────

describe('sanitize()', () => {
    it('removes script tags', () => {
        const result = sanitize('<script>alert("xss")</script>Hello');
        expect(result).not.toContain('<script>');
        expect(result).toContain('Hello');
    });

    it('removes javascript: protocol', () => {
        const result = sanitize('<a href="javascript:alert(1)">click</a>');
        expect(result).not.toContain('javascript:');
    });

    it('removes event handlers', () => {
        const result = sanitize('<img src="x" onerror="alert(1)">');
        expect(result).not.toContain('onerror');
    });

    it('removes iframe tags', () => {
        const result = sanitize('<iframe src="evil.com"></iframe>');
        expect(result).not.toContain('iframe');
    });

    it('preserves safe HTML', () => {
        const safe = '<p>Hello <strong>world</strong></p>';
        const result = sanitize(safe);
        expect(result).toContain('<p>');
        expect(result).toContain('<strong>');
    });

    it('handles non-string input gracefully', () => {
        // @ts-expect-error testing JS runtime behaviour
        const result = sanitize(42);
        expect(result).toBe('42');
    });
});

describe('escapeHtml()', () => {
    it('escapes all HTML special characters', () => {
        const result = escapeHtml('<script>alert("xss")</script>');
        expect(result).not.toContain('<');
        expect(result).not.toContain('>');
        expect(result).toContain('&lt;');
        expect(result).toContain('&gt;');
    });

    it('escapes double quotes', () => {
        expect(escapeHtml('"hello"')).toContain('&quot;');
    });
});

// ─── JWT ──────────────────────────────────────────────────────────────────────

describe('jwt.sign() + jwt.verify()', () => {
    const SECRET = 'super-secret-key-min-32-chars!!!';

    it('produces a 3-part JWT', () => {
        const token = sign({ userId: '123' }, SECRET);
        expect(token.split('.')).toHaveLength(3);
    });

    it('verifies a valid token', () => {
        const token = sign({ userId: '123' }, SECRET);
        const result = verify(token, SECRET);
        expect(result.valid).toBe(true);
        expect(result.payload?.userId).toBe('123');
    });

    it('rejects a tampered token', () => {
        const token = sign({ userId: '123' }, SECRET);
        const tampered = token.slice(0, -4) + 'XXXX';
        const result = verify(tampered, SECRET);
        expect(result.valid).toBe(false);
    });

    it('rejects an expired token', () => {
        const token = sign({ userId: '123' }, SECRET, { expiresIn: -1 });
        const result = verify(token, SECRET);
        expect(result.valid).toBe(false);
        expect(result.error).toContain('expired');
    });

    it('rejects wrong secret', () => {
        const token = sign({ userId: '123' }, SECRET);
        const result = verify(token, 'wrong-secret-key-min-32-chars!!!!');
        expect(result.valid).toBe(false);
    });

    it('includes iat and exp in payload', () => {
        const token = sign({ u: 1 }, SECRET);
        const payload = decode(token);
        expect(payload?.iat).toBeTypeOf('number');
        expect(payload?.exp).toBeTypeOf('number');
    });

    it('throws when secret is too short', () => {
        expect(() => sign({ u: 1 }, 'short')).toThrow();
    });

    it('decode() returns payload without verification', () => {
        const token = sign({ userId: 'abc' }, SECRET);
        const payload = decode(token);
        expect(payload?.userId).toBe('abc');
    });

    it('decode() returns null for malformed token', () => {
        expect(decode('not.valid')).toBeNull();
    });
});

// ─── SRI ──────────────────────────────────────────────────────────────────────

describe('sri()', () => {
    const content = Buffer.from('console.log("hello")');

    it('generates a sha384 hash by default', () => {
        const result = sri(content);
        expect(result.algorithm).toBe('sha384');
        expect(result.integrityAttribute).toMatch(/^sha384-/);
    });

    it('supports sha256 and sha512', () => {
        expect(sri(content, 'sha256').integrityAttribute).toMatch(/^sha256-/);
        expect(sri(content, 'sha512').integrityAttribute).toMatch(/^sha512-/);
    });

    it('produces consistent hashes for same content', () => {
        const r1 = sri(content);
        const r2 = sri(content);
        expect(r1.integrityAttribute).toBe(r2.integrityAttribute);
    });

    it('produces different hashes for different content', () => {
        const r1 = sri(content);
        const r2 = sri(Buffer.from('different content'));
        expect(r1.integrityAttribute).not.toBe(r2.integrityAttribute);
    });

    it('includes url in htmlTag when provided', () => {
        const result = sri(content, 'sha384', 'https://cdn.example.com/app.js');
        expect(result.htmlTag).toContain('src="https://cdn.example.com/app.js"');
        expect(result.htmlTag).toContain('crossorigin="anonymous"');
    });
});
