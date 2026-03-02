/**
 * Tests: Reference module
 * src/reference.ts exports REFERENCE as a const (not a function).
 */

import { describe, it, expect } from 'vitest';
import { REFERENCE } from '../src/reference.js';

describe('reference()', () => {
    it('returns a non-null object', () => {
        expect(REFERENCE).toBeDefined();
        expect(typeof REFERENCE).toBe('object');
    });

    it('contains all 11 OWASP security headers', () => {
        const expectedHeaders = [
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Strict-Transport-Security',
            'Referrer-Policy',
            'Permissions-Policy',
            'X-XSS-Protection',
            'Cross-Origin-Opener-Policy',
            'Cross-Origin-Resource-Policy',
            'Cross-Origin-Embedder-Policy',
            'Server',
        ];
        for (const header of expectedHeaders) {
            expect(
                REFERENCE.headers[header as keyof typeof REFERENCE.headers],
                `Missing header entry: ${header}`
            ).toBeDefined();
        }
    });

    it('each header entry has required fields', () => {
        for (const [name, entry] of Object.entries(REFERENCE.headers)) {
            expect(entry.explanation, `${name}: missing explanation`).toBeTruthy();
            expect(entry.defaultValue, `${name}: missing defaultValue`).toBeTruthy();
            expect(entry.owaspLink, `${name}: missing owaspLink`).toBeTruthy();
            expect(entry.attackPrevented, `${name}: missing attackPrevented`).toBeTruthy();
            expect(entry.riskLevel, `${name}: missing riskLevel`).toBeTruthy();
        }
    });

    it('contains all 10 OWASP Top 10:2025 entries (A01–A10)', () => {
        for (let i = 1; i <= 10; i++) {
            const key = `A${String(i).padStart(2, '0')}:2025` as keyof typeof REFERENCE.owaspTop10;
            expect(REFERENCE.owaspTop10[key], `Missing OWASP entry: ${key}`).toBeDefined();
        }
    });

    it('each OWASP entry has required fields', () => {
        for (const [key, entry] of Object.entries(REFERENCE.owaspTop10)) {
            expect(entry.name, `${key}: missing name`).toBeTruthy();
            expect(entry.description, `${key}: missing description`).toBeTruthy();
            expect(entry.mitigation, `${key}: missing mitigation`).toBeTruthy();
            expect(entry.owaspLink, `${key}: missing owaspLink`).toBeTruthy();
            expect(Array.isArray(entry.cweIds), `${key}: cweIds must be array`).toBe(true);
        }
    });

    it('contains best practices with categorised items', () => {
        expect(Array.isArray(REFERENCE.bestPractices)).toBe(true);
        expect(REFERENCE.bestPractices.length).toBeGreaterThan(0);
        for (const practice of REFERENCE.bestPractices) {
            expect(practice.category).toBeTruthy();
            expect(Array.isArray(practice.items)).toBe(true);
            expect(practice.items.length).toBeGreaterThan(0);
        }
    });

    it('contains reference links', () => {
        expect(REFERENCE.links.owasp).toMatch(/^https?:\/\//);
        expect(REFERENCE.links.secureHeaders).toMatch(/^https?:\/\//);
        expect(REFERENCE.links.nodeSecurity).toMatch(/^https?:\/\//);
    });

    it('is cached — same object reference every time', () => {
        // REFERENCE is a module-level const, always the same reference
        const r1 = REFERENCE;
        const r2 = REFERENCE;
        expect(r1).toBe(r2);
    });
});
