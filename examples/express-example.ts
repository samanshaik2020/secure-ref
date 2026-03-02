/**
 * secure-ref — Express Example
 *
 * Run: node --loader ts-node/esm examples/express-example.ts
 * (or compile first: npm run build && node dist/esm/examples/express-example.js)
 */

// @ts-ignore — express is a dev-only peer dep for this example
import express from 'express';
import secureRef, { cookie, rateLimit, sanitize } from '../src/index.js';

const app = express();
app.use(express.json());

// ─── 1. Apply all OWASP headers in one line ───────────────────────────────────
app.use(secureRef({
    // Custom CSP to allow inline scripts via nonce (generate per request — see /api/nonce)
    csp: "default-src 'self'; script-src 'self'",
    // Allow embedding in same origin only
    frameOptions: 'SAMEORIGIN',
}));

// ─── 2. Rate limiting on auth endpoints ──────────────────────────────────────
app.use('/api/auth', rateLimit({ windowMs: 60_000, max: 5, message: 'Too many login attempts' }));

// ─── 3. Global rate limit ─────────────────────────────────────────────────────
app.use(rateLimit({ windowMs: 60_000, max: 100 }));

// ─── Routes ──────────────────────────────────────────────────────────────────

app.get('/', (_req: any, res: any) => {
    res.json({
        message: 'Hello! secure-ref is protecting this endpoint.',
        headers: 'Check response headers — all 10 OWASP headers are set.',
    });
});

app.get('/api/reference', (_req: any, res: any) => {
    // Serve the OWASP reference directly from the package
    res.json(secureRef.reference());
});

app.get('/api/nonce', (_req: any, res: any) => {
    // Generate a fresh CSP nonce for each page load
    const n = secureRef.nonce();
    res.json({ nonce: n, usage: `script-src 'nonce-${n}'` });
});

app.post('/api/auth/login', (req: any, res: any) => {
    const username = sanitize(req.body?.username ?? '');

    // Secure session cookie
    const { header } = cookie({
        name: 'session',
        value: 'session-token-here',
        maxAge: 3600,
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
    });

    res.setHeader('Set-Cookie', header);

    secureRef.log('auth_failure', { username }, req);

    res.json({ message: `Processing login for: ${username}` });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`\n🔒 secure-ref Express demo running at http://localhost:${PORT}\n`);
    console.log('  GET  /                → Hello + header check');
    console.log('  GET  /api/reference   → Full OWASP reference JSON');
    console.log('  GET  /api/nonce       → Fresh CSP nonce');
    console.log('  POST /api/auth/login  → Secure login stub\n');
});
