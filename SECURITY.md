# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
| < 1.0   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in Chalk, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email security@chalk.dev with:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix or mitigation**: Within 30 days for critical issues

## Scope

The following are in scope:
- Authentication bypass
- Authorization flaws
- SQL injection
- Cross-site scripting (XSS)
- Cross-site request forgery (CSRF)
- Sensitive data exposure
- Encryption weaknesses
- Remote code execution

## Security Measures

Chalk implements:
- Argon2 password hashing
- AES-256-GCM encryption at rest
- CSRF token validation
- Security headers (X-Frame-Options, X-Content-Type-Options)
- Session-based authentication
- Admin audit logging

See [docs/security.md](docs/security.md) for details.
