/** Complete OWASP security reference data — embedded as a constant, zero I/O. */
export const REFERENCE = {
    version: "2026.03",
    headers: {
        "Content-Security-Policy": {
            explanation: "Restricts sources the browser may load content from. The primary defence against XSS by preventing execution of injected scripts and loading of unauthorized resources.",
            defaultValue: "default-src 'self'",
            owaspLink: "https://owasp.org/www-project-secure-headers/#content-security-policy",
            mdnLink: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            attackPrevented: "XSS, Data Injection, Clickjacking via frames",
            riskLevel: "critical"
        },
        "X-Content-Type-Options": {
            explanation: "Prevents browsers from MIME-sniffing a response away from the declared content-type. Without this, a browser may execute a .jpg file as JavaScript if it contains script-like content.",
            defaultValue: "nosniff",
            owaspLink: "https://owasp.org/www-project-secure-headers/#x-content-type-options",
            mdnLink: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
            attackPrevented: "MIME sniffing, Drive-by downloads, Content injection",
            riskLevel: "high"
        },
        "X-Frame-Options": {
            explanation: "Controls whether the browser can render a page in a frame, iframe, embed or object. Prevents attackers from embedding your site in their own to perform clickjacking.",
            defaultValue: "DENY",
            owaspLink: "https://owasp.org/www-project-secure-headers/#x-frame-options",
            mdnLink: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            attackPrevented: "Clickjacking, UI redressing attacks",
            riskLevel: "high"
        },
        "Strict-Transport-Security": {
            explanation: "Forces browsers to use HTTPS for all future requests to the origin. Once set, browsers refuse HTTP and auto-upgrade even if the user types http://.",
            defaultValue: "max-age=31536000; includeSubDomains",
            owaspLink: "https://owasp.org/www-project-secure-headers/#http-strict-transport-security",
            mdnLink: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            attackPrevented: "SSL stripping, Protocol downgrade attacks, MITM attacks",
            riskLevel: "critical"
        },
        "Referrer-Policy": {
            explanation: "Controls how much referrer information is sent with requests. Prevents leaking sensitive URL parameters or internal paths to third-party services.",
            defaultValue: "no-referrer",
            owaspLink: "https://owasp.org/www-project-secure-headers/#referrer-policy",
            mdnLink: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
            attackPrevented: "Information disclosure, Session token leakage via Referer header",
            riskLevel: "medium"
        },
        "Permissions-Policy": {
            explanation: "Allows or denies browser APIs and features (camera, microphone, geolocation, etc.) for the origin. Limits attack surface by disabling capabilities not required by the app.",
            defaultValue: "camera=(), microphone=(), geolocation=()",
            owaspLink: "https://owasp.org/www-project-secure-headers/#permissions-policy",
            mdnLink: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
            attackPrevented: "Unauthorized hardware access, Fingerprinting, Feature abuse",
            riskLevel: "medium"
        },
        "X-XSS-Protection": {
            explanation: "A legacy header for older browser XSS filters. OWASP recommends setting to '0' to DISABLE the filter, which itself introduced vulnerabilities in some browsers. Rely on CSP instead.",
            defaultValue: "0",
            owaspLink: "https://owasp.org/www-project-secure-headers/#x-xss-protection",
            mdnLink: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
            attackPrevented: "Disabling '0' prevents the filter from introducing its own vulnerabilities",
            riskLevel: "low"
        },
        "Cross-Origin-Opener-Policy": {
            explanation: "Isolates the browsing context from cross-origin windows. Prevents a malicious site opened in a new tab from accessing your global object. Required for SharedArrayBuffer.",
            defaultValue: "same-origin",
            owaspLink: "https://owasp.org/www-project-secure-headers/#cross-origin-opener-policy",
            mdnLink: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
            attackPrevented: "Cross-origin window access, Spectre side-channel attacks",
            riskLevel: "high"
        },
        "Cross-Origin-Resource-Policy": {
            explanation: "Prevents other origins from loading your resources via no-cors requests. Defends against cross-site leaks and Spectre-based side-channel attacks on your assets.",
            defaultValue: "same-origin",
            owaspLink: "https://owasp.org/www-project-secure-headers/#cross-origin-resource-policy",
            mdnLink: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
            attackPrevented: "Spectre attacks, Cross-origin data leakage",
            riskLevel: "high"
        },
        "Cross-Origin-Embedder-Policy": {
            explanation: "Requires all cross-origin resources to explicitly grant permission via CORS or CORP. Required alongside COOP to enable cross-origin isolation.",
            defaultValue: "require-corp",
            owaspLink: "https://owasp.org/www-project-secure-headers/#cross-origin-embedder-policy",
            mdnLink: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy",
            attackPrevented: "Cross-origin data leaks, Spectre mitigations bypass",
            riskLevel: "high"
        },
        "Server": {
            explanation: "Removing the Server header prevents attackers from learning which web server software and version you are running, reducing targeted attack surface.",
            defaultValue: "(removed)",
            owaspLink: "https://owasp.org/www-project-secure-headers/#server",
            attackPrevented: "Fingerprinting, Targeted attacks on specific server software versions",
            riskLevel: "medium"
        }
    },
    owaspTop10: {
        "A01:2025": {
            name: "Broken Access Control",
            description: "Access control enforces policy so users cannot act outside their intended permissions. Failures lead to unauthorized information disclosure, modification, or destruction of all data.",
            mitigation: "Deny access by default. Implement RBAC/ABAC. Use secure-ref headers to reduce attack surface. Log and alert on access control failures. Rate-limit all API endpoints.",
            owaspLink: "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/",
            cweIds: ["CWE-284", "CWE-285", "CWE-352"]
        },
        "A02:2025": {
            name: "Security Misconfiguration",
            description: "Applications are frequently misconfigured: missing security headers, default accounts, unnecessary features enabled, verbose error messages revealing stack traces.",
            mitigation: "Use secure-ref() for automatic OWASP headers. Disable unused features. Implement minimal base images. Validate all configuration at startup. Automate security checks in CI/CD.",
            owaspLink: "https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/",
            cweIds: ["CWE-16", "CWE-611"]
        },
        "A03:2025": {
            name: "Software Supply Chain Failures",
            description: "Compromised dependencies, insecure CI/CD pipelines, or dependency confusion attacks. Examples: event-stream (2018), ua-parser-js (2021), node-ipc (2022), chalk/debug (2022).",
            mitigation: "Prefer zero-dependency packages like secure-ref. Run npm audit in CI. Enable npm provenance. Pin all dep versions in lockfiles. Use Dependabot/Renovate for automated updates.",
            owaspLink: "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/",
            cweIds: ["CWE-1104", "CWE-829"]
        },
        "A04:2025": {
            name: "Cryptographic Failures",
            description: "Failures related to cryptography (or lack thereof) often lead to sensitive data exposure. Includes use of weak algorithms, hard-coded secrets, improper key management.",
            mitigation: "Use HTTPS (HSTS via secure-ref). Never hard-code secrets. Use AES-256/RSA-4096/ECDSA for crypto. Store passwords with Argon2id or bcrypt. Use secure-ref.jwt for OWASP-compliant tokens.",
            owaspLink: "https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/",
            cweIds: ["CWE-259", "CWE-327", "CWE-331"]
        },
        "A05:2025": {
            name: "Injection",
            description: "SQL, NoSQL, OS, LDAP, and other injection attacks occur when untrusted data is sent to an interpreter as part of a command or query. Attacker can read/modify/delete data or execute OS commands.",
            mitigation: "Use parameterised queries. Validate and sanitize all inputs (use secure-ref.sanitize()). Apply allowlist input validation. Use ORMs. Apply principle of least privilege on DB accounts.",
            owaspLink: "https://owasp.org/Top10/2025/A05_2025-Injection/",
            cweIds: ["CWE-89", "CWE-77", "CWE-79"]
        },
        "A06:2025": {
            name: "Insecure Design",
            description: "Missing or ineffective security control design — threat modelling failures, insecure architecture decisions, or missing compensating controls built at design time.",
            mitigation: "Integrate threat modelling into design. Use secure design patterns. Define security user stories. Apply defence-in-depth. Use reference architectures with security built in.",
            owaspLink: "https://owasp.org/Top10/2025/A06_2025-Insecure_Design/",
            cweIds: ["CWE-73", "CWE-183", "CWE-209"]
        },
        "A07:2025": {
            name: "Identification and Authentication Failures",
            description: "Weaknesses in authentication: exposed credentials, weak passwords, missing MFA, insecure session management, JWT algorithm confusion, credential stuffing.",
            mitigation: "Enable MFA. Use secure-ref.jwt for OWASP-compliant tokens. Rate-limit with secure-ref.rateLimit(). Use secure-ref.cookie() for session cookies. Validate all JWTs server-side on every request.",
            owaspLink: "https://owasp.org/Top10/2025/A07_2025-Identification_and_Authentication_Failures/",
            cweIds: ["CWE-297", "CWE-287", "CWE-384"]
        },
        "A08:2025": {
            name: "Software and Data Integrity Failures",
            description: "Code and infrastructure that does not protect against integrity violations: insecure deserialization, insecure CI/CD pipelines, auto-update without signature verification.",
            mitigation: "Use SRI (secure-ref.sri()) for CDN resources. Verify digital signatures on packages. Secure CI/CD pipeline. Use trusted package repositories with npm provenance. Avoid unsafe deserialization.",
            owaspLink: "https://owasp.org/Top10/2025/A08_2025-Software_and_Data_Integrity_Failures/",
            cweIds: ["CWE-829", "CWE-494", "CWE-502"]
        },
        "A09:2025": {
            name: "Security Logging and Alerting Failures",
            description: "Insufficient logging, detection, monitoring, and active response. Average breach dwell time is 200+ days because of poor detection. You can't defend what you can't see.",
            mitigation: "Use secure-ref.log() for security events. Log all auth failures, rate-limit triggers, and suspicious requests. Centralise logs in a SIEM. Set up real-time alerting for critical events.",
            owaspLink: "https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/",
            cweIds: ["CWE-778", "CWE-117"]
        },
        "A10:2025": {
            name: "Mishandling of Exceptional Conditions",
            description: "Improper error handling that leaks sensitive information via stack traces, database errors, or overly verbose error messages exposed to end users or in logs.",
            mitigation: "Never expose stack traces in production. Return generic error messages to users. Log detailed errors internally only. Set appropriate error codes (never 200 for errors). Test all error paths.",
            owaspLink: "https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/",
            cweIds: ["CWE-209", "CWE-390"]
        }
    },
    bestPractices: [
        {
            category: "Headers",
            items: [
                "Always set all 11 OWASP-recommended headers via secure-ref()",
                "Never trust client-side security alone — enforce on the server",
                "Customise CSP per-page if different pages load different assets",
                "Use HSTS preloading for production domains (add 'preload' directive)"
            ]
        },
        {
            category: "Authentication",
            items: [
                "Use secure-ref.cookie() for all session cookies",
                "Rate-limit auth endpoints with secure-ref.rateLimit({ max: 5 })",
                "Validate JWTs on every request with secure-ref.jwt.verify()",
                "Rotate session IDs after privilege escalation"
            ]
        },
        {
            category: "Input Handling",
            items: [
                "Validate ALL inputs on the server — client-side validation is UX, not security",
                "Use secure-ref.sanitize() on all user-generated HTML content",
                "Use parameterised queries for all database operations",
                "Use secure-ref.escapeHtml() when rendering user content in HTML"
            ]
        },
        {
            category: "Supply Chain",
            items: [
                "Prefer zero-dependency packages like secure-ref to reduce attack surface",
                "Enable npm provenance to verify package authenticity",
                "Run npm audit in every CI/CD pipeline build",
                "Lock all versions in package-lock.json — never use wildcard ranges in production"
            ]
        }
    ],
    links: {
        owasp: "https://owasp.org/",
        secureHeaders: "https://owasp.org/www-project-secure-headers/",
        nodeSecurity: "https://nodejs.org/en/learn/getting-started/security-best-practices",
        nvd: "https://nvd.nist.gov/",
        mdn: "https://developer.mozilla.org/en-US/docs/Web/Security"
    }
} as const;
