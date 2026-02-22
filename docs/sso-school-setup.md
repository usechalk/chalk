# SSO School Setup Guide

## Prerequisites

Before configuring SSO partners, ensure the following are in place:

1. **Chalk IDP is enabled** — Set `idp.enabled = true` in your `chalk.toml`
2. **SAML keypair exists** — Created automatically during `chalk init`, stored at the paths specified by `saml_cert_path` and `saml_key_path`
3. **Public URL is configured** — Set `chalk.public_url` to your Chalk server's externally-accessible URL (e.g., `https://chalk.springfield.k12.us`)
4. **Users are synced** — Run `chalk sync` or `chalk import` to populate the user directory

Your `chalk.toml` should include at minimum:

```toml
[chalk]
instance_name = "Springfield USD"
public_url = "https://chalk.springfield.k12.us"
data_dir = "/var/lib/chalk"

[idp]
enabled = true
saml_cert_path = "/var/lib/chalk/saml.crt"
saml_key_path = "/var/lib/chalk/saml.key"
```

---

## Adding SSO Partners via TOML

You can add SSO partner applications directly in your `chalk.toml` configuration file. Each partner is defined as a `[[sso_partners]]` entry.

### SAML Partner Example (Canvas LMS)

```toml
[[sso_partners]]
name = "Canvas LMS"
protocol = "saml"
saml_entity_id = "https://canvas.springfield.k12.us"
saml_acs_url = "https://canvas.springfield.k12.us/saml/consume"
roles = ["student", "teacher"]
logo_url = "https://canvas.springfield.k12.us/logo.png"
enabled = true
```

| Field | Required | Description |
|---|---|---|
| `name` | Yes | Display name shown to users in the portal |
| `protocol` | Yes | Must be `"saml"` |
| `saml_entity_id` | Yes | The SP Entity ID provided by the partner app |
| `saml_acs_url` | Yes | The ACS URL where Chalk sends SAML assertions |
| `roles` | No | Which user roles can access this app (empty = everyone) |
| `logo_url` | No | URL to a logo image displayed in the portal |
| `enabled` | No | Defaults to `true`; set to `false` to temporarily disable |

### OIDC Partner Example (Reading App)

```toml
[[sso_partners]]
name = "ReadingBuddy"
protocol = "oidc"
oidc_client_id = "chalk-readingbuddy"
oidc_client_secret = "a-secure-shared-secret"
oidc_redirect_uris = ["https://readingbuddy.com/auth/callback"]
roles = ["student"]
logo_url = "https://readingbuddy.com/assets/logo.png"
enabled = true
```

| Field | Required | Description |
|---|---|---|
| `name` | Yes | Display name shown to users in the portal |
| `protocol` | Yes | Must be `"oidc"` |
| `oidc_client_id` | Yes | Client ID provided by the partner app |
| `oidc_client_secret` | Yes | Client secret provided by the partner app |
| `oidc_redirect_uris` | Yes | List of allowed callback URLs |
| `roles` | No | Which user roles can access this app (empty = everyone) |
| `logo_url` | No | URL to a logo image displayed in the portal |
| `enabled` | No | Defaults to `true`; set to `false` to temporarily disable |

### Multiple Partners

You can add as many partners as needed. Each one gets its own `[[sso_partners]]` block:

```toml
[[sso_partners]]
name = "Canvas LMS"
protocol = "saml"
saml_entity_id = "https://canvas.springfield.k12.us"
saml_acs_url = "https://canvas.springfield.k12.us/saml/consume"
roles = ["student", "teacher"]

[[sso_partners]]
name = "ReadingBuddy"
protocol = "oidc"
oidc_client_id = "chalk-readingbuddy"
oidc_client_secret = "a-secure-shared-secret"
oidc_redirect_uris = ["https://readingbuddy.com/auth/callback"]
roles = ["student"]

[[sso_partners]]
name = "Schoology"
protocol = "saml"
saml_entity_id = "https://schoology.com"
saml_acs_url = "https://springfield.schoology.com/saml/consume"
roles = ["student", "teacher"]

[[sso_partners]]
name = "MathLab Pro"
protocol = "oidc"
oidc_client_id = "chalk-mathlab"
oidc_client_secret = "mathlab-secret-key"
oidc_redirect_uris = ["https://mathlab.pro/oauth/callback"]
roles = ["student"]
```

After editing `chalk.toml`, restart Chalk for changes to take effect.

---

## Adding SSO Partners via Admin Console

You can also manage SSO partners through the Chalk admin console web interface.

### Steps

1. Open the Chalk admin console in your browser (typically `{chalk_url}/admin`)
2. Log in with your administrator credentials
3. Click **SSO Partners** in the sidebar navigation
4. Click the **Add Partner** button
5. Fill in the partner details:
   - **Name** — A friendly display name (e.g., "Canvas LMS")
   - **Protocol** — Select either SAML or OIDC
6. For **SAML** partners, provide:
   - **SP Entity ID** — The partner's entity identifier
   - **ACS URL** — The partner's Assertion Consumer Service URL
7. For **OIDC** partners, provide:
   - **Client ID** — The partner's client identifier
   - **Client Secret** — The partner's client secret
   - **Redirect URIs** — One or more callback URLs (one per line)
8. Optionally configure:
   - **Roles** — Select which roles can access this app
   - **Logo URL** — A link to the app's logo
   - **Enabled** — Toggle to enable or disable
9. Click **Save**

Partners added through the admin console are stored in the database and do not require a restart.

---

## Popular App Setup Examples

### Canvas LMS (SAML)

Canvas uses SAML for SSO. In Canvas:
1. Go to your Canvas admin settings
2. Navigate to **Authentication** and add a SAML configuration
3. Set the **IDP Metadata URL** to `{chalk_url}/idp/saml/metadata`
4. Note the **SP Entity ID** and **ACS URL** that Canvas provides

In Chalk:
```toml
[[sso_partners]]
name = "Canvas LMS"
protocol = "saml"
saml_entity_id = "https://canvas.springfield.k12.us"
saml_acs_url = "https://canvas.springfield.k12.us/saml/consume"
roles = ["student", "teacher"]
```

### Schoology (SAML)

In Schoology:
1. Go to **System Settings > Integration > SAML**
2. Set the **IDP Metadata URL** to `{chalk_url}/idp/saml/metadata`
3. Note the **Entity ID** and **ACS URL** from Schoology

In Chalk:
```toml
[[sso_partners]]
name = "Schoology"
protocol = "saml"
saml_entity_id = "https://schoology.com"
saml_acs_url = "https://springfield.schoology.com/saml/consume"
roles = ["student", "teacher"]
```

### Google Workspace

Google Workspace SSO has dedicated support in Chalk via the `[idp.google]` configuration block. If you already have Google configured this way, it continues to work. See [Migrating from idp.google to sso_partners](#migrating-from-idpgoogle-to-sso_partners) if you want to move it to the new format.

Existing configuration:
```toml
[idp.google]
workspace_domain = "springfield.k12.us"
google_acs_url = "https://accounts.google.com/samlrp/acs"
google_entity_id = "google.com"
```

### Generic OIDC App

For any application that supports OpenID Connect:

1. Ask the app vendor for their **Client ID**, **Client Secret**, and **Redirect URI**
2. Provide the vendor with Chalk's OIDC discovery URL: `{chalk_url}/idp/oidc/.well-known/openid-configuration`

In Chalk:
```toml
[[sso_partners]]
name = "My OIDC App"
protocol = "oidc"
oidc_client_id = "client-id-from-vendor"
oidc_client_secret = "client-secret-from-vendor"
oidc_redirect_uris = ["https://app.vendor.com/auth/callback"]
```

---

## Configuring Role-Based Access

Each SSO partner can be restricted to specific user roles. This controls which apps appear in a user's launch portal.

### How It Works

- The `roles` field accepts a list of OneRoster role names (e.g., `student`, `teacher`, `administrator`, `aide`)
- If the `roles` list is **empty** (or omitted), **all users** can see and access the app
- If the `roles` list contains values, only users with a matching role will see the app
- Role matching is case-insensitive (`Student` matches `student`)

### Examples

**Student-only reading app:**
```toml
[[sso_partners]]
name = "ReadingBuddy"
protocol = "oidc"
oidc_client_id = "chalk-readingbuddy"
oidc_client_secret = "secret"
oidc_redirect_uris = ["https://readingbuddy.com/callback"]
roles = ["student"]
```

**App for both students and teachers (like an LMS):**
```toml
[[sso_partners]]
name = "Canvas LMS"
protocol = "saml"
saml_entity_id = "https://canvas.example.com"
saml_acs_url = "https://canvas.example.com/saml/consume"
roles = ["student", "teacher"]
```

**App available to everyone (leave roles empty):**
```toml
[[sso_partners]]
name = "School Portal"
protocol = "oidc"
oidc_client_id = "chalk-portal"
oidc_client_secret = "secret"
oidc_redirect_uris = ["https://portal.example.com/callback"]
roles = []
```

---

## Student Launch Portal

### What Is the Portal?

The Chalk launch portal is a web page where students and staff can see all the apps available to them and launch any of them with a single click. No additional login is needed after the first authentication.

The portal is located at:

```
{chalk_url}/portal
```

### How Auto-Login Works

1. The user navigates to the portal URL and logs in with their Chalk credentials (password, QR badge, or picture password)
2. Chalk creates a portal session that persists for the configured session duration (default: 8 hours)
3. The user sees a grid of app tiles based on their role
4. Clicking a tile triggers SSO to that partner app automatically (no re-authentication needed)
5. The session persists across page refreshes and browser restarts within the timeout window

### Distributing the Portal URL

To make the portal easy to access:

- Set it as the **browser homepage** on school devices
- Create a **bookmark** or desktop shortcut
- Add it to your school's **internal links page** or intranet
- For Chromebooks managed via Google Admin, push it as a pinned tab or app

### Device-Friendly Design

The portal is designed for:

- **Chromebooks and laptops** — Full-width tile layout
- **Tablets (iPads)** — Touch-friendly large tiles
- **Shared classroom devices** — Quick logout and re-login between students

---

## Migrating from [idp.google] to [[sso_partners]]

If you currently use the `[idp.google]` configuration block for Google Workspace SSO, your existing setup continues to work with no changes required. Chalk maintains full backward compatibility.

However, if you want to manage Google alongside other SSO partners in a unified way, you can migrate to the `[[sso_partners]]` format.

### Before (existing format)

```toml
[idp.google]
workspace_domain = "springfield.k12.us"
google_acs_url = "https://accounts.google.com/samlrp/acs"
google_entity_id = "google.com"
```

### After (new format)

```toml
[[sso_partners]]
name = "Google Workspace"
protocol = "saml"
saml_entity_id = "google.com"
saml_acs_url = "https://accounts.google.com/samlrp/acs"
logo_url = "https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_92x30dp.png"
roles = []
```

### Migration Steps

1. Add the `[[sso_partners]]` entry as shown above
2. Remove the `[idp.google]` section from your `chalk.toml`
3. Restart Chalk
4. Test that Google SSO still works by logging in through Chalk

> **Note:** You can keep both `[idp.google]` and a Google entry in `[[sso_partners]]` during testing. Remove `[idp.google]` once you have confirmed the new configuration works.

---

## Troubleshooting

### SSO Partner Not Appearing in Portal

- Verify the partner has `enabled = true` (this is the default)
- Check that the user's role matches the partner's `roles` list
- If the partner was added via TOML, make sure Chalk was restarted
- If the partner was added via the admin console, try refreshing the portal page

### SAML Assertion Errors

| Error | Likely Cause | Fix |
|---|---|---|
| "Invalid audience" | Entity ID mismatch | Make sure `saml_entity_id` in Chalk matches the Entity ID your app expects |
| "Assertion expired" | Clock skew | Sync your server's clock using NTP; assertions expire after 5 minutes |
| "Signature verification failed" | Wrong certificate | Re-download the certificate from `{chalk_url}/idp/saml/metadata` and update your app |
| "NameID not found" | User has no email address | Ensure all users have an email address set in Chalk (check your SIS sync) |

### OIDC Token Issues

| Error | Likely Cause | Fix |
|---|---|---|
| "Invalid client_id" | Mismatched client ID | Verify `oidc_client_id` matches exactly in both Chalk and the partner app |
| "Invalid client_secret" | Wrong secret | Re-check the client secret in your Chalk configuration |
| "Invalid redirect_uri" | URI not registered | Add the exact redirect URI (including trailing slashes) to `oidc_redirect_uris` |
| "Authorization code expired" | Code not exchanged in time | Authorization codes expire after 10 minutes; the app should exchange immediately |
| "Invalid grant" | Code already used | Authorization codes are single-use; request a new authorization |

### General Issues

| Issue | Fix |
|---|---|
| IDP login page not loading | Verify `idp.enabled = true` and Chalk is running (`chalk serve`) |
| SAML metadata returns 404 | Ensure `chalk.public_url` is set in your configuration |
| Partner works for teachers but not students | Check the `roles` configuration on the partner; add `"student"` if needed |
| Changes to TOML not taking effect | Restart Chalk after editing `chalk.toml` |
