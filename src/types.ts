/**
 * secure-ref — TypeScript types
 * Zero-dependency, ultra-lightweight security middleware + OWASP reference
 */

// ─── Middleware ────────────────────────────────────────────────────────────────

export interface SecureRefOptions {
    /** Override Content-Security-Policy. Set false to disable. */
    csp?: string | false;
    /** Override X-Content-Type-Options. Set false to disable. */
    contentTypeOptions?: string | false;
    /** Override X-Frame-Options. Set false to disable. */
    frameOptions?: string | false;
    /** Override Strict-Transport-Security. Set false to disable. */
    hsts?: string | false;
    /** Override Referrer-Policy. Set false to disable. */
    referrerPolicy?: string | false;
    /** Override Permissions-Policy. Set false to disable. */
    permissionsPolicy?: string | false;
    /** Override X-XSS-Protection. Set false to disable. */
    xssProtection?: string | false;
    /** Override Cross-Origin-Opener-Policy. Set false to disable. */
    coop?: string | false;
    /** Override Cross-Origin-Resource-Policy. Set false to disable. */
    corp?: string | false;
    /** Override Cross-Origin-Embedder-Policy. Set false to disable. */
    coep?: string | false;
    /** Remove the Server header. Default: true */
    removeServer?: boolean;
}

/** Generic Node.js-compatible IncomingMessage subset */
export interface SecureRefRequest {
    method?: string;
    url?: string;
    headers: Record<string, string | string[] | undefined>;
}

/** Generic Node.js-compatible ServerResponse subset */
export interface SecureRefResponse {
    setHeader(name: string, value: string): void;
    removeHeader(name: string): void;
    getHeader?(name: string): string | number | string[] | undefined;
}

/** Framework-agnostic next() callback */
export type NextFunction = (err?: unknown) => void;

/** The middleware function returned by secureRef() */
export type SecureRefMiddleware = (
    req: SecureRefRequest,
    res: SecureRefResponse,
    next: NextFunction
) => void;

// ─── Reference ────────────────────────────────────────────────────────────────

export interface HeaderReference {
    explanation: string;
    defaultValue: string;
    owaspLink: string;
    mdnLink?: string;
    attackPrevented: string;
    example: string;
    riskLevel: 'critical' | 'high' | 'medium' | 'low';
}

export interface OwaspEntry {
    name: string;
    description: string;
    mitigation: string;
    owaspLink: string;
    cweIds: string[];
    prevalence: string;
}

export interface BestPractice {
    category: string;
    items: string[];
}

export interface SecurityReference {
    headers: Record<string, HeaderReference>;
    owaspTop10: Record<string, OwaspEntry>;
    bestPractices: BestPractice[];
    links: {
        owasp: string;
        secureHeaders: string;
        nodeSecurity: string;
        nvd: string;
        mdn: string;
    };
    version: string;
    lastUpdated: string;
}

// ─── Cookie Helper ────────────────────────────────────────────────────────────

export interface CookieOptions {
    /** The cookie name */
    name: string;
    /** The cookie value */
    value: string;
    /** Max age in seconds. Default: 3600 */
    maxAge?: number;
    /** Restrict to HTTP only. Default: true */
    httpOnly?: boolean;
    /** HTTPS only. Default: true */
    secure?: boolean;
    /** SameSite policy. Default: 'Strict' */
    sameSite?: 'Strict' | 'Lax' | 'None';
    /** Cookie path. Default: '/' */
    path?: string;
    /** Cookie domain */
    domain?: string;
    /** Partition key isolation (CHIPS) */
    partitioned?: boolean;
}

export interface CookieResult {
    /** The formatted Set-Cookie header value */
    header: string;
    /** Security score 0-100 */
    securityScore: number;
    /** Any warnings about cookie configuration */
    warnings: string[];
}

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

export interface RateLimitConfig {
    /** Time window in milliseconds. Default: 60000 (1 min) */
    windowMs?: number;
    /** Max requests per window. Default: 100 */
    max?: number;
    /** Message when limit exceeded */
    message?: string;
    /** HTTP status code. Default: 429 */
    statusCode?: number;
    /** Key generator function */
    keyGenerator?: (req: SecureRefRequest) => string;
}

export interface RateLimitStore {
    count: number;
    resetTime: number;
}

// ─── JWT Helpers ──────────────────────────────────────────────────────────────

export interface JwtPayload {
    [key: string]: unknown;
    iat?: number;
    exp?: number;
    nbf?: number;
    iss?: string;
    aud?: string | string[];
    sub?: string;
    jti?: string;
}

export interface JwtSignOptions {
    /** Expiry in seconds. Default: 3600 */
    expiresIn?: number;
    /** Issuer claim */
    issuer?: string;
    /** Audience claim */
    audience?: string | string[];
    /** Subject claim */
    subject?: string;
}

export interface JwtVerifyResult {
    valid: boolean;
    payload?: JwtPayload;
    error?: string;
}

// ─── Security Logger ──────────────────────────────────────────────────────────

export type LogEventType =
    | 'auth_failure'
    | 'rate_limit_exceeded'
    | 'csrf_violation'
    | 'xss_attempt'
    | 'sql_injection_attempt'
    | 'suspicious_request'
    | 'header_violation'
    | 'jwt_invalid'
    | 'custom';

export interface LogEvent {
    event: LogEventType;
    timestamp: string;
    ip?: string;
    userAgent?: string;
    url?: string;
    data?: Record<string, unknown>;
    severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface LogTransport {
    log(event: LogEvent): void | Promise<void>;
}

// ─── SRI ──────────────────────────────────────────────────────────────────────

export interface SriResult {
    url: string;
    hash: string;
    algorithm: 'sha256' | 'sha384' | 'sha512';
    integrityAttribute: string;
    htmlTag: string;
}

// ─── Main Export ─────────────────────────────────────────────────────────────

export interface SecureRefStatic extends SecureRefMiddlewareFn {
    /** Returns the full OWASP + headers reference JSON */
    reference(): SecurityReference;
    /** Generate a secure cookie Set-Cookie header */
    cookie(options: CookieOptions): CookieResult;
    /** Generate a crypto-random CSP nonce */
    nonce(): string;
    /** In-memory rate limiter middleware factory */
    rateLimit(config?: RateLimitConfig): SecureRefMiddleware;
    /** Sanitize a string against basic XSS (regex-based) */
    sanitize(input: string): string;
    /** JWT utilities */
    jwt: {
        sign(payload: JwtPayload, secret: string, options?: JwtSignOptions): string;
        verify(token: string, secret: string): JwtVerifyResult;
        decode(token: string): JwtPayload | null;
    };
    /** Security event logger */
    log(event: LogEventType, data?: Record<string, unknown>, req?: SecureRefRequest): LogEvent;
    /** Configure log transports */
    configureLogger(transports: LogTransport[]): void;
    /** Generate SRI hash string for a given content buffer */
    sri(content: Buffer, algorithm?: 'sha256' | 'sha384' | 'sha512'): SriResult;
    /** Package version */
    version: string;
}

export interface SecureRefMiddlewareFn {
    (options?: SecureRefOptions): SecureRefMiddleware;
}
