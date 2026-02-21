# Security

Chalk implements multiple layers of security to protect student data and administrative access.

## Admin Console Authentication

The admin console requires authentication for all pages except the health check endpoint.

- **Password**: Set during `chalk init`, hashed with Argon2
- **Sessions**: Random token stored in a secure cookie
- **Timeout**: Sessions expire after a configurable period

### Public Paths (no auth required)

- `/health` — Health check endpoint
- `/login` — Login page
- `/api/*` — API endpoints (separate token auth planned)

## CSRF Protection

All POST requests to the console require a valid CSRF token.

- Tokens are generated per-session and stored in a cookie
- HTMX requests include the token via the `X-CSRF-Token` header
- Requests without a valid token receive a 403 Forbidden response

## Security Headers

The console server sets the following security headers on all responses:

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME type sniffing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Control referrer information |

## Encryption at Rest

Sensitive data (SIS credentials, API tokens) is encrypted at rest using AES-256-GCM.

- **Master key**: Generated during `chalk init`, stored at `{data_dir}/chalk.key`
- **Algorithm**: AES-256-GCM with random 12-byte nonce
- **Format**: `nonce (12 bytes) || ciphertext`

Protect the master key file:
```bash
chmod 600 /var/lib/chalk/chalk.key
```

## Admin Audit Logging

All administrative actions are logged to an audit trail:

- Login attempts (success and failure)
- Sync triggers
- Configuration changes
- Data exports

View the audit log in the console at **Settings** > **Audit Log**.

## Best Practices

1. **Restrict network access**: Run the console on a private network or behind a reverse proxy
2. **Use HTTPS**: Place Chalk behind a TLS-terminating proxy (nginx, Caddy)
3. **Rotate credentials**: Periodically update SIS API credentials
4. **Monitor audit logs**: Review the audit log regularly for unexpected activity
5. **Backup data**: Regularly back up the SQLite database and master key
6. **Principle of least privilege**: Only grant SIS API access that Chalk needs

## Vulnerability Reporting

See [SECURITY.md](../SECURITY.md) for our vulnerability disclosure policy.
