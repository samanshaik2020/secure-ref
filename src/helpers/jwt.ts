import { createHmac, timingSafeEqual } from 'node:crypto';
import type { JwtPayload, JwtSignOptions, JwtVerifyResult } from '../types';

export function sign(payload: JwtPayload, secret: string, options: JwtSignOptions = {}): string {
    if (!secret || secret.length < 16) {
        throw new Error('[secure-ref] JWT secret must be at least 16 characters long');
    }
    const { expiresIn = 3600, issuer, audience, subject } = options;
    const now = Math.floor(Date.now() / 1000);
    const claims: JwtPayload = {
        ...payload,
        iat: now,
        exp: now + expiresIn,
        ...(issuer !== undefined && { iss: issuer }),
        ...(audience !== undefined && { aud: audience }),
        ...(subject !== undefined && { sub: subject }),
    };
    const header = b64encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const body = b64encode(JSON.stringify(claims));
    const data = `${header}.${body}`;
    return `${data}.${hmac256(data, secret)}`;
}

export function verify(token: string, secret: string): JwtVerifyResult {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return { valid: false, error: 'Malformed JWT: expected 3 parts' };
        const [header, body, sig] = parts as [string, string, string];

        const headerParsed = JSON.parse(b64decode(header)) as { alg?: string };
        if (headerParsed.alg !== 'HS256') {
            return { valid: false, error: `Unsupported algorithm: ${headerParsed.alg ?? 'none'}` };
        }

        const expected = hmac256(`${header}.${body}`, secret);
        try {
            const a = Buffer.from(sig);
            const b = Buffer.from(expected);
            if (a.length !== b.length || !timingSafeEqual(a, b)) {
                return { valid: false, error: 'Invalid signature' };
            }
        } catch {
            return { valid: false, error: 'Invalid signature' };
        }

        const payload = JSON.parse(b64decode(body)) as JwtPayload;
        const now = Math.floor(Date.now() / 1000);
        if (typeof payload.exp === 'number' && now > payload.exp) {
            return { valid: false, error: `Token expired ${now - payload.exp}s ago` };
        }
        if (typeof payload.nbf === 'number' && now < payload.nbf) {
            return { valid: false, error: 'Token not yet valid (nbf claim)' };
        }
        return { valid: true, payload };
    } catch (err) {
        return { valid: false, error: `JWT verification failed: ${(err as Error).message}` };
    }
}

export function decode(token: string): JwtPayload | null {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        return JSON.parse(b64decode(parts[1]!)) as JwtPayload;
    } catch {
        return null;
    }
}

function hmac256(data: string, secret: string): string {
    return createHmac('sha256', secret).update(data).digest('base64url');
}
function b64encode(str: string): string {
    return Buffer.from(str, 'utf8').toString('base64url');
}
function b64decode(str: string): string {
    return Buffer.from(str, 'base64url').toString('utf8');
}
