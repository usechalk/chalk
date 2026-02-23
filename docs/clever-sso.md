# Clever-Compatible SSO

## Overview

Chalk exposes Clever's exact OAuth 2.0 and OIDC endpoints so that vendors already integrated with Clever SSO can switch to Chalk without any code changes. Chalk maps its roster data to Clever's response shapes, providing a drop-in replacement.

The student portal auto-redirects for Clever-compatible partners -- no consent page is shown. Students click an app tile and are instantly signed in.

## Prerequisites

1. Chalk initialized and users synced from your SIS (`chalk init` and `chalk sync`)
2. The vendor's Clever OAuth client ID and secret
3. The vendor's OAuth callback URL

## Configuration

Add a `[[sso_partners]]` entry to your `chalk.toml` with `protocol = "clever-compatible"`:

```toml
[[sso_partners]]
name = "Reading App"
protocol = "clever-compatible"
enabled = true
oidc_client_id = "your-clever-app-client-id"
oidc_client_secret = "your-clever-app-secret"
oidc_redirect_uris = ["https://readingapp.example.com/oauth/callback"]
roles = ["student", "teacher"]
```

| Key | Description |
|-----|-------------|
| `name` | Display name shown on the student/teacher portal |
| `protocol` | Must be `"clever-compatible"` |
| `enabled` | Enable or disable this partner |
| `oidc_client_id` | The vendor's Clever OAuth client ID |
| `oidc_client_secret` | The vendor's Clever OAuth client secret |
| `oidc_redirect_uris` | List of allowed redirect URIs for the OAuth flow |
| `roles` | Which roles can see and use this app (`"student"`, `"teacher"`, `"staff"`) |

## Available Endpoints

Chalk serves the following Clever-compatible endpoints:

| Endpoint | Description |
|----------|-------------|
| `/oauth/authorize` | OAuth 2.0 authorization endpoint |
| `/oauth/tokens` | Token exchange endpoint |
| `/v3.0/me` | Current user info (v3.0) |
| `/v3.1/me` | Current user info (v3.1) |
| `/v3.0/users/{id}` | User details by ID |
| `/v3.0/users/{id}/sections` | Sections (classes) for a user |
| `/v3.0/users/{id}/schools` | Schools for a user |
| `/v3.0/users/{id}/myteachers` | Teachers for a student |
| `/v3.0/users/{id}/mystudents` | Students for a teacher |
| `/v3.0/districts/{id}` | District information |
| `/userinfo` | OIDC UserInfo endpoint |
| `/.well-known/openid-configuration` | OIDC discovery document |

All responses match Clever's JSON response shapes, so existing vendor integrations work without modification.

## How It Works

1. The vendor redirects the user to Chalk's `/oauth/authorize` endpoint with the same parameters they would send to Clever.
2. Chalk authenticates the user via the student/teacher portal session and auto-redirects back to the vendor's callback URL with an authorization code.
3. The vendor exchanges the code at `/oauth/tokens` for an access token.
4. The vendor calls `/v3.0/me` or other endpoints using the access token. Chalk returns roster data in Clever's response format.

## External ID Mapping

Chalk stores a Clever-compatible external ID for each user. Vendors that reference Clever user IDs will find the same IDs in Chalk's responses, ensuring continuity during migration.

## Troubleshooting

| Issue | Cause | Solution |
|---|---|---|
| "invalid_client" error on token exchange | Wrong client ID or secret | Verify `oidc_client_id` and `oidc_client_secret` match the vendor's credentials |
| Redirect URI mismatch | Callback URL not in allowed list | Add the vendor's callback URL to `oidc_redirect_uris` |
| User not found in `/v3.0/me` | User not synced from SIS | Run `chalk sync` to populate roster data |
| App not visible on portal | Wrong role configuration | Check that `roles` includes the user's role |
