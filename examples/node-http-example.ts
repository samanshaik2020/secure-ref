/**
 * secure-ref — Node.js (plain http) Example
 *
 * Works with raw http.createServer — no framework required.
 * Run: npx ts-node examples/node-http-example.ts
 */

import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import secureRef from '../src/index.js';

// Create middleware with custom options
const secureHeaders = secureRef({
    hsts: 'max-age=63072000; includeSubDomains; preload',
    csp: "default-src 'self'; upgrade-insecure-requests",
});

const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    // Apply secure headers
    secureHeaders(
        req as any,
        res as any,
        () => {
            // Route handling
            if (req.url === '/reference' && req.method === 'GET') {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(secureRef.reference(), null, 2));
            } else {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'secure-ref protecting plain Node.js http!' }));
            }
        }
    );
});

server.listen(3001, () => {
    console.log('🔒 Plain HTTP server with secure-ref → http://localhost:3001');
    console.log('   GET /reference — OWASP reference JSON');
});
