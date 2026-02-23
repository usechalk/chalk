# ClassLink-Compatible SSO

## Overview

Chalk exposes ClassLink's exact OAuth 2.0 endpoints so that vendors already integrated with ClassLink SSO can switch to Chalk without any code changes. Chalk maps its roster data to ClassLink's response shapes, providing a drop-in replacement.

The student portal auto-redirects for ClassLink-compatible partners -- no consent page is shown. Students click an app tile and are instantly signed in.

## Prerequisites

1. Chalk initialized and users synced from your SIS (`chalk init` and `chalk sync`)
2. The vendor's ClassLink OAuth client ID and secret
3. The vendor's OAuth callback URL

## Configuration

Add a `[[sso_partners]]` entry to your `chalk.toml` with `protocol = "classlink_compat"`:

```toml
[[sso_partners]]
name = "Math App"
protocol = "classlink_compat"
enabled = true
oidc_client_id = "your-classlink-app-client-id"
oidc_client_secret = "your-classlink-app-secret"
oidc_redirect_uris = ["https://mathapp.example.com/oauth/callback"]
roles = ["student"]
```

| Key | Description |
|-----|-------------|
| `name` | Display name shown on the student/teacher portal |
| `protocol` | Must be `"classlink_compat"` |
| `enabled` | Enable or disable this partner |
| `oidc_client_id` | The vendor's ClassLink OAuth client ID |
| `oidc_client_secret` | The vendor's ClassLink OAuth client secret |
| `oidc_redirect_uris` | List of allowed redirect URIs for the OAuth flow |
| `roles` | Which roles can see and use this app (`"student"`, `"teacher"`, `"staff"`) |

## Available Endpoints

Chalk serves the following ClassLink-compatible endpoints:

| Endpoint | Description |
|----------|-------------|
| `/oauth2/v2/auth` | OAuth 2.0 authorization endpoint |
| `/oauth2/v2/token` | Token exchange endpoint |
| `/v2/my/info` | Current user info |

## User Info Response

The `/v2/my/info` endpoint returns the full set of ClassLink fields:

| Field | Description |
|-------|-------------|
| `UserId` | Unique user identifier |
| `LoginId` | User's login name |
| `TenantId` | District/tenant identifier |
| `FirstName` | User's first name |
| `LastName` | User's last name |
| `Email` | User's email address |
| `Role` | User's role (student, teacher, staff) |
| `SourcedId` | OneRoster sourced ID |
| `OrgSourcedId` | Organization sourced ID |
| `OrgName` | Organization name |

Chalk maps its roster data to these fields so existing vendor integrations work without modification.

## How It Works

1. The vendor redirects the user to Chalk's `/oauth2/v2/auth` endpoint with the same parameters they would send to ClassLink.
2. Chalk authenticates the user via the student/teacher portal session and auto-redirects back to the vendor's callback URL with an authorization code.
3. The vendor exchanges the code at `/oauth2/v2/token` for an access token.
4. The vendor calls `/v2/my/info` using the access token. Chalk returns roster data in ClassLink's response format.

## External ID Mapping

Chalk stores a ClassLink-compatible external ID for each user. Vendors that reference ClassLink user IDs will find the same IDs in Chalk's responses, ensuring continuity during migration.

## Troubleshooting

| Issue | Cause | Solution |
|---|---|---|
| "invalid_client" error on token exchange | Wrong client ID or secret | Verify `oidc_client_id` and `oidc_client_secret` match the vendor's credentials |
| Redirect URI mismatch | Callback URL not in allowed list | Add the vendor's callback URL to `oidc_redirect_uris` |
| User not found in `/v2/my/info` | User not synced from SIS | Run `chalk sync` to populate roster data |
| App not visible on portal | Wrong role configuration | Check that `roles` includes the user's role |
