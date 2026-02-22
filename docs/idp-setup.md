# Identity Provider Setup

## Overview

Chalk includes a built-in Identity Provider (IDP) that lets K-12 schools authenticate students and staff without relying on external services. It supports three authentication methods:

- **Password login** — Traditional username and password
- **QR badge scan** — Tap or scan a printed badge
- **Picture passwords** — Select images in a memorized sequence

The IDP can also act as a **SAML Identity Provider** for Google Workspace, enabling single sign-on (SSO) so users log in once through Chalk and gain access to Google apps.

## Prerequisites

Before setting up the IDP, ensure:

1. Chalk is initialized (`chalk init`)
2. Users are synced from your SIS or imported via CSV (`chalk sync` or `chalk import`)
3. Chalk server is running (`chalk serve`)

## Enable the IDP

Add or update the `[idp]` section in your `chalk.toml`:

```toml
[idp]
enabled = true
saml_cert_path = "/var/lib/chalk/saml.crt"
saml_key_path = "/var/lib/chalk/saml.key"
```

You must also set `chalk.public_url` so the IDP can generate correct SAML metadata and login URLs:

```toml
[chalk]
public_url = "https://chalk.springfield.k12.us"
```

Restart Chalk after making configuration changes.

## Set Up User Passwords

### Password Pattern

Chalk can auto-generate passwords for users based on a configurable pattern. Add these settings to your `[idp]` section:

```toml
[idp]
default_password_pattern = "{lastName}{birthYear}"
default_password_roles = ["student", "teacher"]
```

- `default_password_pattern` defines the template used to generate passwords.
- `default_password_roles` controls which user roles receive auto-generated passwords.

### Available Placeholders

| Placeholder | Source | Example |
|---|---|---|
| `{firstName}` | User's given name | `Alice` |
| `{lastName}` | User's family name | `Smith` |
| `{username}` | User's username | `asmith` |
| `{identifier}` | Student/staff ID | `S001` |
| `{email}` | User's email | `asmith@springfield.edu` |
| `{sourcedId}` | Internal record ID | `user-002` |
| `{birthYear}` | Birth year from demographics | `2009` |
| `{birthDate}` | Birth MMDD from demographics | `0315` |
| `{grade}` | User's grade level | `09` |

### Common Patterns

- `{lastName}{birthYear}` produces `Smith2009`
- `{firstName}.{identifier}` produces `Alice.S001`
- `{username}{birthDate}` produces `asmith0315`

### When Passwords Are Generated

Passwords are automatically generated during sync for new users that match the configured roles and do not already have a password set. Existing passwords are never overwritten during sync.

### CLI Commands

You can also manage passwords manually with the CLI:

```bash
# Generate passwords for all matching users who don't have one
chalk passwords generate

# Generate a password for a specific user
chalk passwords generate --user user-001

# Regenerate passwords even if one already exists
chalk passwords generate --force
```

The `--force` flag is useful when you change the password pattern and want all users to receive a new password based on the updated template.

## Test Standalone Login

Once passwords are generated, verify that login works:

1. Open `{public_url}/idp/login` in your browser (e.g., `https://chalk.springfield.k12.us/idp/login`)
2. Enter a user's username and their generated password
3. On success, you should see the user's authenticated session

## Connect to Google Workspace

### Chalk Configuration

Add the Google SAML settings to your `chalk.toml`:

```toml
[idp.google]
workspace_domain = "springfield.k12.us"
google_acs_url = "https://accounts.google.com/samlrp/acs"
google_entity_id = "google.com"
```

### Google Admin Console Setup

1. Sign in to the [Google Admin Console](https://admin.google.com)
2. Go to **Security > Authentication > SSO with third party IdP**
3. Click **Add SAML profile**
4. Set **IDP entity ID** to `{public_url}/idp/saml/metadata` (e.g., `https://chalk.springfield.k12.us/idp/saml/metadata`)
5. Set **SSO URL** to `{public_url}/idp/saml/sso` (e.g., `https://chalk.springfield.k12.us/idp/saml/sso`)
6. Upload the SAML certificate from the path configured in `saml_cert_path`
7. Save the profile and assign it to the appropriate organizational units

## Test SSO

1. Open a browser and navigate to Google login for your Workspace domain
2. You should be redirected to the Chalk IDP login page
3. Enter the user's credentials
4. On successful authentication, you should be redirected back to Google and signed in

If the redirect does not happen, verify that the SAML profile is assigned to the correct organizational units in Google Admin Console.

## QR Badge Login

QR badge login allows users (especially younger students) to authenticate by scanning a printed badge.

### Enable

```toml
[idp]
qr_badge_login = true
```

### Badge Generation

Badges are generated per-user and contain an encrypted token tied to their account. Generate badges through the admin console or CLI. Print and distribute them to users.

### User Flow

1. User visits the login page and selects **Scan Badge**
2. User holds their printed badge up to the camera, or scans it with a connected scanner
3. Chalk verifies the badge token and logs the user in

Badges can be revoked and regenerated if lost or compromised.

## Picture Password Login

Picture passwords let users authenticate by selecting a sequence of images rather than typing a password. This is useful for younger students who may struggle with traditional passwords.

### Enable

```toml
[idp]
picture_passwords = true
```

### Setting a Picture Password

Administrators or teachers can set picture password sequences for users through the admin console. Each sequence consists of a series of images the user must select in order.

### User Flow

1. User visits the login page and selects **Picture Password**
2. User enters their username
3. A grid of images is displayed
4. User selects the images in their memorized sequence
5. On correct sequence, the user is logged in

## Troubleshooting

| Issue | Cause | Solution |
|---|---|---|
| "No password set for user" | Password not generated | Run `chalk passwords generate` |
| SAML assertion invalid | Clock skew between Chalk and Google | Sync server time with NTP |
| Google SSO loop | Wrong ACS URL in config | Verify `google_acs_url` matches the value in Google Admin Console |
| QR badge not working | Badge has been revoked | Generate a new badge for the user |
| Password incorrect | Pattern changed after password was generated | Run `chalk passwords generate --force` to regenerate |
| Login page not loading | IDP not enabled | Set `enabled = true` in `[idp]` and restart Chalk |
| SAML metadata 404 | Missing `public_url` | Set `chalk.public_url` in your configuration |
