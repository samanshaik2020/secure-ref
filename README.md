# secure-ref

[![npm version](https://badge.fury.io/js/secure-ref.svg)](https://badge.fury.io/js/secure-ref)
[![npm downloads](https://img.shields.io/npm/dw/secure-ref)](https://www.npmjs.com/package/secure-ref)
[![bundle size](https://img.shields.io/bundlephobia/minzip/secure-ref)](https://bundlephobia.com/package/secure-ref)
[![license](https://img.shields.io/npm/l/secure-ref)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)](https://www.typescriptlang.org/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](package.json)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%3A2025-red)](https://owasp.org/Top10/2025/)

**Helmet + OWASP docs in one zero-dependency import.**

`secure-ref` is an ultra-lightweight (<5KB gzipped) Node.js security package that combines:

- 🛡️ **Active Security** — Framework-agnostic middleware applying 11 OWASP Secure Headers
- 📖 **OWASP Reference** — Built-in OWASP Top 10:2025 + header explanations, instantly accessible
- 🍪 **Secure Cookies** — OWASP-compliant cookie helper with security scoring
- 🔑 **JWT Helpers** — Sign/verify with OWASP best practices enforced
- ⏱️ **Rate Limiter** — In-memory token bucket middleware
- 🧹 **Sanitizer** — XSS input stripping + HTML encoding
- 🔒 **CSP Nonce** — Crypto-random nonce generator
- 🔐 **SRI** — Subresource Integrity hash generator
- 📊 **Security Logger** — Structured security event logging

**Why it exists**: Helmet is great for headers, but nothing teaches *why* you're setting them. `secure-ref` is security middleware meets OWASP education — perfect for solo devs, startups, and teams who want security **without** the learning curve or bloat.

---

## CLI Foundation

Get started instantly with a pre-configured security file:

```bash
npx secure-ref init
```

This creates a `security.config.ts` path with **Smart Modes** pre-configured for your environment.

---

## Installation

```bash
npm install secure-ref
# or
pnpm add secure-ref
# or
yarn add secure-ref
```

**Requirements**: Node.js ≥ 18.0.0 | Zero runtime dependencies

---

## Quick Start

### Express (1 line)

```ts
import express from 'express';
import secureRef from 'secure-ref';

const app = express();

// Apply all 11 OWASP headers in one line
app.use(secureRef());

app.get('/', (req, res) => res.json({ ok: true }));
app.listen(3000);
```

### Smart Modes (v1.1.0+)

`secure-ref` now supports three security "personalities" to balance protection and developer experience:

- 🛠️ **`dev`** — Permissive headers (allows `unsafe-inline` for HMR, local HSTS disabled).
- 🚀 **`production`** — OWASP-recommended defaults (Strict HSTS, Secure CSP).
- 🛡️ **`strict`** — Maximum security (No frames, no external scripts, zero-tolerance).

```ts
app.use(secureRef({ mode: 'production' }));
```

---

**Headers set automatically (Production mode):**

| Header | Default |
|--------|---------|
| `Content-Security-Policy` | `default-src 'self'` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `Referrer-Policy` | `no-referrer` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` |
| `X-XSS-Protection` | `0` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Cross-Origin-Embedder-Policy` | `require-corp` |
| `Server` | *(removed)* |

---

## API Reference

### `secureRef(options?)` — Security Middleware

```ts
import secureRef from 'secure-ref';

// Default: all 11 headers at OWASP-recommended values
app.use(secureRef());

// Custom options
app.use(secureRef({
  csp: "default-src 'self'; script-src 'self' 'nonce-abc123'",
  frameOptions: 'SAMEORIGIN',   // or false to disable
  hsts: false,                   // disable during local development
  removeServer: true,            // removes Server + X-Powered-By
}));
```

**All options are optional.** Set any header to `false` to skip it entirely.

---

### `secureRef.reference()` — OWASP Reference

Returns the full OWASP security reference database as a plain object.

```ts
const ref = secureRef.reference();

// Header explanations
console.log(ref.headers['X-Frame-Options']);
// {
//   explanation: "Controls whether a browser should be allowed to render a page in a <frame>...",
//   defaultValue: "DENY",
//   owaspLink: "https://owasp.org/www-project-secure-headers/...",
//   attackPrevented: "Clickjacking, UI redressing attacks",
//   riskLevel: "high"
// }

// OWASP Top 10:2025
console.log(ref.owaspTop10['A03:2025']);
// {
//   name: "Software Supply Chain Failures",
//   description: "...",
//   mitigation: "Use zero-dependency packages...",
//   owaspLink: "...",
//   cweIds: ["CWE-1104", "CWE-506"]
// }

// Security checklists
for (const practice of ref.bestPractices) {
  console.log(practice.category, practice.items);
}
```

Great for embedding in developer docs, CLI tools, or admin dashboards.

---

### `secureRef.cookie(options)` — Secure Cookies

```ts
const { header, securityScore, warnings } = secureRef.cookie({
  name: 'session',
  value: sessionToken,
  maxAge: 3600,       // 1 hour
  httpOnly: true,     // default: true  (XSS protection)
  secure: true,       // default: true  (HTTPS only)
  sameSite: 'Strict', // default: Strict (CSRF protection)
  path: '/',
});

res.setHeader('Set-Cookie', header);
console.log(`Cookie security score: ${securityScore}/100`);
// warnings: ['⚠ HttpOnly not set'] if misconfigured
```

---

### `secureRef.nonce()` — CSP Nonce

```ts
// Generate a fresh nonce for EVERY request (never reuse!)
app.use((req, res, next) => {
  res.locals.nonce = secureRef.nonce();
  next();
});

app.use((req, res, next) => {
  secureRef({ csp: `script-src 'nonce-${res.locals.nonce}' 'strict-dynamic'` })(req, res, next);
});

// In your HTML template:
// <script nonce="<%= nonce %>">/* safe inline script */</script>
```

---

### `secureRef.rateLimit(config?)` — Rate Limiter

```ts
import { rateLimit } from 'secure-ref';

// Global: 100 req/min
app.use(rateLimit());

// Auth endpoint: 5 req/min (stricter)
app.use('/api/auth', rateLimit({
  windowMs: 60_000,  // 1 minute
  max: 5,
  message: 'Too many login attempts — please try again in 1 minute.',
}));
```

Sets `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, and `Retry-After` headers automatically (RFC 6585).

---

### `secureRef.jwt` — JWT Helpers

```ts
const token = secureRef.jwt.sign(
  { userId: '123', role: 'admin' },
  process.env.JWT_SECRET!,
  { expiresIn: 3600, issuer: 'my-app' }
);

const { valid, payload, error } = secureRef.jwt.verify(token, process.env.JWT_SECRET!);
if (!valid) return res.status(401).json({ error });

// OWASP enforcements built-in:
// ✓ Algorithm hardcoded to HS256 (no "alg: none" bypass)
// ✓ exp always set (default: 1 hour)
// ✓ iat always set
// ✓ Timing-safe signature comparison (prevents timing attacks)
```

---

### `secureRef.sanitize(input)` — XSS Sanitizer

```ts
const clean = secureRef.sanitize(req.body.comment);
// Removes: <script>, javascript:, event handlers, iframes, etc.

// For HTML contexts, use escapeHtml:
import { escapeHtml } from 'secure-ref';
const safe = escapeHtml(userInput); // Encodes < > " ' / ` =
```

---

### `secureRef.sri(content, algorithm?, url?)` — SRI Hashes

```ts
import { readFileSync } from 'fs';
import { sri } from 'secure-ref';

const content = readFileSync('./public/app.js');
const { integrityAttribute, htmlTag } = sri(content, 'sha384', '/app.js');

// htmlTag: <script src="/app.js" integrity="sha384-..." crossorigin="anonymous"></script>
```

---

### `secureRef.log(event, data?, req?)` — Security Logger

```ts
secureRef.log('auth_failure', { username }, req);
secureRef.log('rate_limit_exceeded', { endpoint: '/api/login' }, req);
// Auto-captures: timestamp, IP, userAgent, URL, severity

// Custom transport (Sentry, Datadog, etc.)
secureRef.configureLogger([{
  log(event) {
    Sentry.captureEvent({ message: event.event, level: event.severity });
  }
}]);
```

---

## Framework Examples

### Fastify

```ts
import Fastify from 'fastify';
import secureRef from 'secure-ref';

const fastify = Fastify();

fastify.addHook('onRequest', (req, reply, done) => {
  secureRef()(req.raw, reply.raw, done);
});
```

### Next.js (App Router — middleware.ts)

```ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { reference } from 'secure-ref/browser'; // browser-safe import

const HEADERS: Record<string, string> = {
  'Content-Security-Policy': "default-src 'self'",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=()',
};

export function middleware(request: NextRequest) {
  const response = NextResponse.next();
  for (const [key, value] of Object.entries(HEADERS)) {
    response.headers.set(key, value);
  }
  return response;
}
```

### Hono

```ts
import { Hono } from 'hono';
import secureRef from 'secure-ref';

const app = new Hono();

app.use('*', (c, next) => {
  return new Promise((resolve) => {
    secureRef()(c.req.raw as any, c.res as any, () => resolve(next()));
  });
});
```

---

## Browser Usage

```ts
// Safe to import in browsers, Deno, Bun, Cloudflare Workers
import { reference, sanitize } from 'secure-ref/browser';

const ref = reference();
const clean = sanitize(userInput);
```

---

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

This package:
- ✅ Zero runtime dependencies
- ✅ npm provenance enabled
- ✅ 2FA on npm account
- ✅ Signed commits
- ✅ `npm audit clean` — 0 high/critical advisories
- ✅ OWASP Top 10:2025 aligned (A02, A03, A07, A08)

---

## Migration from Helmet

```ts
// Before (Helmet):
import helmet from 'helmet';
app.use(helmet());

// After (secure-ref) — drop-in replacement + OWASP reference:
import secureRef from 'secure-ref';
app.use(secureRef());

// Bonus: Ask why any header exists
console.log(secureRef.reference().headers['X-Frame-Options'].explanation);
```

**Differences:**
- `secure-ref` removes `Server` and `X-Powered-By` headers by default
- `secure-ref` sets `X-XSS-Protection: 0` (OWASP recommended for modern browsers)
- `secure-ref` includes OWASP reference, JWT, rate limiter, cookies, SRI — Helmet does not

---

## Roadmap

| Version | Target | Features |
|---------|--------|----------|
| v0.1.0 | ✅ Today | Core headers + reference + all helpers |
| v1.0.0 | +2 days | Full test coverage + npm publish |
| v1.1.x | ✅ Done | CLI: `npx secure-ref init` + Smart Modes |
| v2.0.0 | Q2 2026 | Browser bundle + Vercel docs site + Redis adapter |

---

## License

MIT © secure-ref contributors
