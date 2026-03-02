# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x.x   | ✅ Current |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

To report a security vulnerability:

1. **Email**: security@secure-ref.dev *(or create a private GitHub advisory)*
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (optional)

**Response SLA**:
- Acknowledgement: within 24 hours
- Fix timeline: within 72 hours for critical, 7 days for high

## Security Best Practices for Users

- Keep `secure-ref` updated to the latest version
- Run `npm audit` regularly in your project
- Enable `npm provenance` verification
- Never disable security headers without understanding the risk (see `secureRef.reference()`)

## Our Security Commitments

- ✅ Zero runtime dependencies (eliminates supply chain risk)
- ✅ `npm audit` clean on every release
- ✅ 2FA enabled on npm publish account
- ✅ Signed commits (GPG)
- ✅ npm provenance attestation
- ✅ OWASP Top 10:2025 aligned

## Disclosure Policy

We follow [responsible disclosure](https://owasp.org/www-community/Vulnerability_Disclosure_Cheat_Sheet).
Fixes will be released within the stated SLA, followed by a public advisory post-fix.
