import { randomBytes, createHmac, timingSafeEqual, createHash } from 'node:crypto';
import { REFERENCE } from './reference.js';

// ─── Types ────────────────────────────────────────────────────────────────────

export type SecureRefOptions = {
    csp?: string | false;
    frameOptions?: string | false;
    hsts?: string | false;
    contentTypeOptions?: string | false;
    referrerPolicy?: string | false;
    permissionsPolicy?: string | false;
    xssProtection?: string | false;
    coop?: string | false;
    corp?: string | false;
    coep?: string | false;
    removeServer?: boolean;
    [key: string]: unknown;
};

export type CookieOptions = {
    name: string;
    value: string;
    maxAge?: number;
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: 'Strict' | 'Lax' | 'None';
    path?: string;
    domain?: string;
};

export type RateLimitConfig = {
    windowMs?: number;
    max?: number;
    message?: string;
};

export type JwtPayload = Record<string, unknown> & {
    iat?: number;
    exp?: number;
    iss?: string;
    sub?: string;
    aud?: string | string[];
};

export type JwtSignOptions = {
    expiresIn?: number;
    issuer?: string;
    subject?: string;
    audience?: string | string[];
};

// ─── Modes ───────────────────────────────────────────────────────────────────

/**
 * Security mode presets.
 *
 * - `dev`        — relaxed for local development (no HSTS, allows unsafe-inline scripts)
 * - `production` — strong OWASP defaults (auto-selected when NODE_ENV=production)
 * - `strict`     — maximum security for high-value targets (banking, finance, healthcare)
 *
 * User-supplied options always override the mode preset.
 */
export type Mode = 'dev' | 'production' | 'strict';

const MODE_CONFIGS: Record<Mode, Partial<SecureRefOptions>> = {
    dev: {
        hsts: false,
        coep: false,
        csp: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
        removeServer: false,
    },
    production: {
        hsts: 'max-age=31536000; includeSubDomains',
        frameOptions: 'DENY',
        csp: "default-src 'self'; script-src 'self'",
        removeServer: true,
    },
    strict: {
        hsts: 'max-age=63072000; includeSubDomains; preload',
        frameOptions: 'DENY',
        csp: "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'",
        permissionsPolicy: 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
        removeServer: true,
    },
};

// ─── Default Headers ─────────────────────────────────────────────────────────

const DEFAULT_HEADERS: Record<string, string> = {
    'Content-Security-Policy': "default-src 'self'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'X-XSS-Protection': '0',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Cross-Origin-Embedder-Policy': 'require-corp',
};

// ─── Main Middleware ──────────────────────────────────────────────────────────

/**
 * Creates security middleware that sets OWASP-recommended HTTP security headers.
 *
 * Pass `mode` to select a preset, then override individual headers as needed.
 * Auto-detects NODE_ENV when no mode is specified.
 *
 * @example Auto mode (recommended)
 * ```ts
 * app.use(secureRef()); // 'dev' locally, 'production' when NODE_ENV=production
 * ```
 * @example Explicit modes
 * ```ts
 * app.use(secureRef({ mode: 'strict' }));                    // banking/finance
 * app.use(secureRef({ mode: 'production', csp: 'custom' })); // override one header
 * ```
 */
export default function secureRef(options: SecureRefOptions & { mode?: Mode } = {}) {
    // 1. Resolve mode: explicit > NODE_ENV > 'dev'
    const mode: Mode = options.mode ??
        (process.env['NODE_ENV'] === 'production' ? 'production' : 'dev');

    // 2. Merge: defaults ← mode preset ← user options (user always wins)
    const { mode: _mode, ...userOpts } = options;
    const resolved: SecureRefOptions = { ...MODE_CONFIGS[mode], ...userOpts };

    // 3. Build the headers map from resolved options
    const headers = { ...DEFAULT_HEADERS };

    function applyOpt(opt: string | false | undefined, headerName: string) {
        if (opt === undefined) return;
        if (opt === false) delete headers[headerName];
        else headers[headerName] = opt;
    }

    applyOpt(resolved.csp, 'Content-Security-Policy');
    applyOpt(resolved.frameOptions, 'X-Frame-Options');
    applyOpt(resolved.hsts, 'Strict-Transport-Security');
    applyOpt(resolved.contentTypeOptions, 'X-Content-Type-Options');
    applyOpt(resolved.referrerPolicy, 'Referrer-Policy');
    applyOpt(resolved.permissionsPolicy, 'Permissions-Policy');
    applyOpt(resolved.xssProtection, 'X-XSS-Protection');
    applyOpt(resolved.coop, 'Cross-Origin-Opener-Policy');
    applyOpt(resolved.corp, 'Cross-Origin-Resource-Policy');
    applyOpt(resolved.coep, 'Cross-Origin-Embedder-Policy');

    // Pre-compute entries once at factory time — zero overhead per request
    const entries = Object.entries(headers) as [string, string][];
    const shouldRemoveServer = resolved.removeServer !== false;

    return (req: unknown, res: { setHeader: (k: string, v: string) => void; removeHeader: (k: string) => void }, next: () => void) => {
        for (const [k, v] of entries) res.setHeader(k, v);
        if (shouldRemoveServer) {
            res.removeHeader('Server');
            res.removeHeader('X-Powered-By');
        }
        next();
    };
}

/** Returns the active mode that would be selected for a given options object */
secureRef.resolveMode = (options: { mode?: Mode } = {}): Mode =>
    options.mode ?? (process.env['NODE_ENV'] === 'production' ? 'production' : 'dev');

/** The full mode configuration map (useful for introspection/tooling) */
secureRef.modes = MODE_CONFIGS;

// Attach static helpers to the default export
secureRef.reference = (): typeof REFERENCE => REFERENCE;

// ─── Nonce ────────────────────────────────────────────────────────────────────

/**
 * Generates a cryptographically random CSP nonce (base64url).
 * Generate a new nonce for EVERY response — never reuse.
 */
export function nonce(byteLength = 16): string {
    return randomBytes(byteLength).toString('base64url');
}
secureRef.nonce = nonce;

// ─── Cookie ───────────────────────────────────────────────────────────────────

/**
 * Generates an OWASP-compliant Set-Cookie header value with security scoring.
 */
export function cookie(opts: CookieOptions): { header: string; securityScore: number; warnings: string[] } {
    const {
        name, value,
        maxAge = 3600,
        httpOnly = true,
        secure = true,
        sameSite = 'Strict',
        path = '/',
        domain,
    } = opts;

    const warnings: string[] = [];
    let score = 0;

    const parts = [`${encodeURIComponent(name)}=${encodeURIComponent(value)}`, `Max-Age=${maxAge}`, `Path=${path}`];
    if (domain) parts.push(`Domain=${domain}`);

    if (httpOnly) { parts.push('HttpOnly'); score += 30; }
    else { warnings.push('⚠ HttpOnly missing — XSS can read this cookie'); }

    if (secure) { parts.push('Secure'); score += 30; }
    else { warnings.push('⚠ Secure missing — cookie sent over HTTP'); }

    if (sameSite) {
        parts.push(`SameSite=${sameSite}`);
        if (sameSite === 'Strict') score += 40;
        else if (sameSite === 'Lax') score += 25;
        else { score += 5; warnings.push('⚠ SameSite=None is risky — requires Secure + explicit need'); }
    } else {
        warnings.push('⚠ SameSite missing — CSRF risk');
    }

    return { header: parts.join('; '), securityScore: Math.min(100, score), warnings };
}
secureRef.cookie = cookie;

// ─── Sanitize ─────────────────────────────────────────────────────────────────

/**
 * Strips common XSS attack vectors from a string (regex-based defence-in-depth).
 * NOT a replacement for proper output encoding — use escapeHtml() for HTML contexts.
 */
export function sanitize(input: string): string {
    if (typeof input !== 'string') return String(input);
    return input
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/<\/?(iframe|object|embed|form|base|applet)[^>]*>/gi, '')
        .replace(/\b(javascript|vbscript|data):/gi, '#')
        .replace(/\s+on\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]*)/gi, '')
        .replace(/expression\s*\([^)]*\)/gi, '')
        .replace(/<!--[\s\S]*?-->/g, '');
}
secureRef.sanitize = sanitize;

/**
 * HTML-encodes special characters. Use when inserting user content into HTML.
 */
export function escapeHtml(unsafe: string): string {
    return String(unsafe)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
}
secureRef.escapeHtml = escapeHtml;

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

const _rateStore = new Map<string, { count: number; resetTime: number }>();

/**
 * In-memory sliding window rate limiter middleware.
 * For multi-process deployments, use a Redis adapter (v1.1 roadmap).
 */
export function rateLimit(config: RateLimitConfig = {}) {
    const { windowMs = 60_000, max = 100, message = 'Too many requests — please try again later.' } = config;

    const interval = setInterval(() => {
        const now = Date.now();
        for (const [k, v] of _rateStore) if (now > v.resetTime) _rateStore.delete(k);
    }, windowMs * 2);
    if ((interval as NodeJS.Timeout).unref) (interval as NodeJS.Timeout).unref();

    return (req: { ip?: string; socket?: { remoteAddress?: string }; headers?: Record<string, string | string[] | undefined> }, res: { setHeader: (k: string, v: string) => void; status?: (c: number) => { json: (b: unknown) => void }; writeHead?: (c: number) => void; end?: (b: string) => void }, next: () => void) => {
        const xff = req.headers?.['x-forwarded-for'];
        const ip = (Array.isArray(xff) ? xff[0] : xff?.split(',')[0]?.trim()) ?? req.ip ?? req.socket?.remoteAddress ?? 'unknown';
        const now = Date.now();

        let record = _rateStore.get(ip);
        if (!record || now > record.resetTime) {
            record = { count: 0, resetTime: now + windowMs };
            _rateStore.set(ip, record);
        }
        record.count++;

        res.setHeader('RateLimit-Limit', String(max));
        res.setHeader('RateLimit-Remaining', String(Math.max(0, max - record.count)));
        res.setHeader('RateLimit-Reset', String(Math.ceil(record.resetTime / 1000)));

        if (record.count > max) {
            res.setHeader('Retry-After', String(Math.ceil((record.resetTime - now) / 1000)));
            if (res.status) return res.status(429).json({ error: message });
            if (res.writeHead && res.end) { res.writeHead(429); res.end(message); return; }
            return;
        }
        next();
    };
}
secureRef.rateLimit = rateLimit;

// ─── JWT ──────────────────────────────────────────────────────────────────────

export const jwt = {
    /**
     * Signs a JWT using HS256. Enforces exp (OWASP requirement).
     * Secret must be ≥16 chars.
     */
    sign(payload: JwtPayload, secret: string, options: JwtSignOptions = {}): string {
        if (!secret || secret.length < 16) throw new Error('[secure-ref] JWT secret must be ≥16 characters');
        const now = Math.floor(Date.now() / 1000);
        const claims = {
            iat: now,
            exp: now + (options.expiresIn ?? 3600),
            ...(options.issuer && { iss: options.issuer }),
            ...(options.subject && { sub: options.subject }),
            ...(options.audience && { aud: options.audience }),
            ...payload,
        };
        const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
        const p = Buffer.from(JSON.stringify(claims)).toString('base64url');
        const s = createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url');
        return `${h}.${p}.${s}`;
    },

    /**
     * Verifies a JWT using timing-safe comparison (prevents timing attacks).
     * Returns { valid, payload } or { valid: false, error }.
     */
    verify(token: string, secret: string): { valid: boolean; payload?: JwtPayload; error?: string } {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) return { valid: false, error: 'Malformed token' };
            const [h, p, sig] = parts as [string, string, string];

            const hParsed = JSON.parse(Buffer.from(h, 'base64url').toString()) as { alg?: string };
            if (hParsed.alg !== 'HS256') return { valid: false, error: `Unsupported algorithm: ${hParsed.alg ?? 'none'}` };

            const expected = createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url');
            const a = Buffer.from(sig), b = Buffer.from(expected);
            if (a.length !== b.length || !timingSafeEqual(a, b)) return { valid: false, error: 'Invalid signature' };

            const payload = JSON.parse(Buffer.from(p, 'base64url').toString()) as JwtPayload;
            const now = Math.floor(Date.now() / 1000);
            if (typeof payload.exp === 'number' && now > payload.exp) return { valid: false, error: `Token expired ${now - payload.exp}s ago` };

            return { valid: true, payload };
        } catch (e) {
            return { valid: false, error: `JWT error: ${(e as Error).message}` };
        }
    },

    /** Decodes a JWT without verifying signature. NEVER use for authorization. */
    decode(token: string): JwtPayload | null {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) return null;
            return JSON.parse(Buffer.from(parts[1]!, 'base64url').toString()) as JwtPayload;
        } catch { return null; }
    }
};
secureRef.jwt = jwt;

// ─── SRI ──────────────────────────────────────────────────────────────────────

/**
 * Generates a Subresource Integrity hash for a CDN resource.
 */
export function sri(content: string | Buffer, algorithm: 'sha256' | 'sha384' | 'sha512' = 'sha384', url = '') {
    const hash = createHash(algorithm).update(content).digest('base64');
    const integrityAttribute = `${algorithm}-${hash}`;
    return {
        integrityAttribute,
        algorithm,
        url,
        htmlTag: url
            ? `<script src="${url}" integrity="${integrityAttribute}" crossorigin="anonymous"></script>`
            : `integrity="${integrityAttribute}" crossorigin="anonymous"`,
    };
}
secureRef.sri = sri;

// ─── Logger ───────────────────────────────────────────────────────────────────

type LogTransport = { log: (e: LogEntry) => void };
type LogEntry = { timestamp: string; event: string; severity: string; ip?: string; userAgent?: string;[key: string]: unknown };

let _logTransports: LogTransport[] = [
    { log: (e) => console.log(`[secure-ref] ${e.event}`, e) }
];

export function log(event: string, data: Record<string, unknown> = {}, req?: { ip?: string; socket?: { remoteAddress?: string }; headers?: { 'user-agent'?: string } }): LogEntry {
    const entry: LogEntry = {
        timestamp: new Date().toISOString(),
        event,
        severity: /fail|block|inject|violation|csrf|xss/i.test(event) ? 'high' : 'medium',
        ...(req?.ip || req?.socket?.remoteAddress ? { ip: req.ip ?? req.socket?.remoteAddress } : {}),
        ...(req?.headers?.['user-agent'] ? { userAgent: req.headers['user-agent'] } : {}),
        ...data,
    };
    for (const t of _logTransports) { try { t.log(entry); } catch { /* never bubble */ } }
    return entry;
}
secureRef.log = log;

export function configureLogger(transports: LogTransport[]): void { _logTransports = transports; }
secureRef.configureLogger = configureLogger;

// ─── Browser subset ───────────────────────────────────────────────────────────

export const browser = { reference: secureRef.reference, sanitize, escapeHtml, nonce };

// ─── Version ─────────────────────────────────────────────────────────────────

export const version = '1.1.0';
secureRef.version = version;
