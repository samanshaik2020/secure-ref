import type {
    RateLimitConfig,
    RateLimitStore,
    SecureRefMiddleware,
    SecureRefRequest,
    SecureRefResponse,
    NextFunction,
} from '../types';

export function rateLimit(config: RateLimitConfig = {}): SecureRefMiddleware {
    const {
        windowMs = 60_000,
        max = 100,
        message = 'Too Many Requests — please try again later.',
        statusCode = 429,
        keyGenerator = defaultKeyGenerator,
    } = config;

    const store = new Map<string, RateLimitStore>();

    const cleanupInterval = setInterval(() => {
        const now = Date.now();
        for (const [key, entry] of store) {
            if (now > entry.resetTime) store.delete(key);
        }
    }, windowMs * 2);

    if (cleanupInterval.unref) cleanupInterval.unref();

    return function rateLimitMiddleware(
        req: SecureRefRequest,
        res: SecureRefResponse,
        next: NextFunction
    ): void {
        const key = keyGenerator(req);
        const now = Date.now();

        let entry = store.get(key);
        if (!entry || now > entry.resetTime) {
            entry = { count: 1, resetTime: now + windowMs };
            store.set(key, entry);
        } else {
            entry.count++;
        }

        const remaining = Math.max(0, max - entry.count);
        const retryAfter = Math.ceil((entry.resetTime - now) / 1000);

        res.setHeader('RateLimit-Limit', String(max));
        res.setHeader('RateLimit-Remaining', String(remaining));
        res.setHeader('RateLimit-Reset', String(Math.ceil(entry.resetTime / 1000)));

        if (entry.count > max) {
            res.setHeader('Retry-After', String(retryAfter));
            const rawRes = res as unknown as {
                status?: (code: number) => { send: (msg: string) => void };
                statusCode?: number;
                end?: (msg: string) => void;
                writeHead?: (code: number, headers: Record<string, string>) => void;
            };
            if (typeof rawRes.status === 'function') {
                rawRes.status(statusCode).send(message);
            } else if (rawRes.writeHead && rawRes.end) {
                rawRes.writeHead(statusCode, { 'Content-Type': 'text/plain' });
                rawRes.end(message);
            } else {
                next(Object.assign(new Error(message), { statusCode }));
            }
            return;
        }
        next();
    };
}

function defaultKeyGenerator(req: SecureRefRequest): string {
    const xff = req.headers['x-forwarded-for'];
    if (xff) {
        const ip = Array.isArray(xff) ? xff[0] : xff.split(',')[0];
        return ip.trim();
    }
    return req.headers['x-real-ip']?.toString() ?? '::1';
}
