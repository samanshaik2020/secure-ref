/**
 * secure-ref — Basic Input Sanitizer
 * Regex-based XSS stripping for quick defence-in-depth sanitization.
 *
 * ⚠ This is NOT a replacement for proper output encoding.
 * For full HTML sanitization, use a dedicated library like DOMPurify.
 * This helper covers the most common attack vectors and is <1KB.
 *
 * Zero dependencies. Works in Node.js and browsers.
 */

/**
 * Strips common XSS attack vectors from an input string.
 *
 * Removes/neutralises:
 * - `<script>` tags and content
 * - `javascript:` protocol handlers
 * - HTML event handlers (`onclick`, `onerror`, etc.)
 * - `<iframe>`, `<object>`, `<embed>`, `<form>` tags
 * - `data:` URIs
 * - CSS `expression()` and `@import`
 * - HTML comment injection
 *
 * @param input - Raw user input string
 * @returns Sanitized string with XSS vectors removed
 *
 * @example
 * ```ts
 * const clean = secureRef.sanitize('<script>alert("xss")</script>Hello, world!');
 * // Returns: 'Hello, world!'
 * ```
 *
 * @example
 * ```ts
 * const clean = secureRef.sanitize('Click <a href="javascript:alert(1)">here</a>');
 * // Returns: 'Click <a href="#">here</a>'
 * ```
 */
export function sanitize(input: string): string {
    if (typeof input !== 'string') {
        return String(input);
    }

    let result = input;

    // 1. Remove <script> blocks and their content
    result = result.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');

    // 2. Remove dangerous tags
    result = result.replace(
        /<\/?(iframe|object|embed|form|base|applet|link|meta|xml|xss)[^>]*>/gi,
        ''
    );

    // 3. Remove javascript: / vbscript: / data: protocol handlers
    result = result.replace(/\b(javascript|vbscript|data):/gi, '#');

    // 4. Remove HTML event handlers (on*)
    result = result.replace(/\s+on\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]*)/gi, '');

    // 5. Remove CSS expressions
    result = result.replace(/expression\s*\([^)]*\)/gi, '');
    result = result.replace(/@import\b[^;]*/gi, '');

    // 6. Remove HTML comments (can hide payloads)
    result = result.replace(/<!--[\s\S]*?-->/g, '');

    // 7. Neutralise document/window references in attributes
    result = result.replace(/\b(document|window|localStorage|sessionStorage)\s*\./gi, '[blocked].');

    return result;
}

/**
 * HTML-encodes special characters to prevent XSS in HTML contexts.
 * Use when inserting user content into HTML attribute values or text nodes.
 *
 * @param input - Raw string to encode
 * @returns HTML-encoded string safe for embedding in HTML
 *
 * @example
 * ```ts
 * const safe = secureRef.escapeHtml('<img src="x" onerror="alert(1)">');
 * // Returns: '&lt;img src=&quot;x&quot; onerror=&quot;alert(1)&quot;&gt;'
 * ```
 */
export function escapeHtml(input: string): string {
    const charMap: Record<string, string> = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;',
        '`': '&#x60;',
        '=': '&#x3D;',
    };
    return String(input).replace(/[&<>"'`=/]/g, (char) => charMap[char] ?? char);
}
