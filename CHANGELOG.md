# Changelog

All notable changes to Chalk will be documented in this file.

## [1.0.0] - 2026-02-20

### Added
- OneRoster 1.1 data models (users, orgs, courses, classes, enrollments, academic sessions, demographics)
- PowerSchool SIS connector with OAuth 2.0
- Infinite Campus SIS connector
- Skyward SIS connector
- Sync engine with dependency-ordered persistence
- SQLite database with migration support
- HTMX-powered admin console with dashboard, user directory, and settings
- SAML 2.0 identity provider with QR badge and picture password authentication
- Google Workspace sync (user provisioning, OU management)
- OneRoster CSV import/export
- OneRoster 1.1 REST API (`/api/oneroster/v1p1/`)
- Clever migration support
- ClassLink migration support
- Console authentication with Argon2 password hashing
- CSRF protection for all POST requests
- Security headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- AES-256-GCM encryption for sensitive data at rest
- Admin audit logging
- Anonymous telemetry (disabled by default)
- CLI commands: init, sync, serve, status, update, import, export, migrate, google-sync
- AI diagnostic agent
- Comprehensive test suite (550+ tests)
