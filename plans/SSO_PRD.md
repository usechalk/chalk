# Chalk Compatibility & Identity Spec

**Version:** 0.1 — Draft
**Date:** February 2026
**Status:** Pre-implementation — Defines the three features required for Chalk to be a drop-in replacement for Clever and ClassLink.

---

## Overview

Chalk needs three capabilities to eliminate switching cost barriers for districts migrating from Clever or ClassLink:

1. **Clever-Compatible SSO Mode** — Chalk exposes Clever's exact OAuth 2.0 / OIDC endpoints and data shapes so vendors with existing Clever integrations work with zero code changes.
2. **ClassLink-Compatible SSO Mode** — Same approach for ClassLink's OAuth 2.0 endpoints and user info API.
3. **Active Directory Sync** — Automated provisioning and management of on-prem AD accounts from SIS data, matching what Clever IDM and ClassLink OneSync offer.

Together, these make Chalk a genuine drop-in replacement. The district changes a hostname. The vendor changes nothing (or changes one environment variable). Teachers and students see no difference.

---

## 1. Clever-Compatible SSO Mode

### 1.1 What Clever Exposes to Vendors

Clever acts as an OAuth 2.0 / OIDC Authorization Server. A vendor integrated with Clever has:

- A `client_id` and `client_secret` registered with Clever
- Redirect URIs configured in Clever's app dashboard
- Code that calls these endpoints:

| Purpose | Clever Endpoint |
|---------|----------------|
| Authorization | `https://clever.com/oauth/authorize` |
| Token Exchange | `https://clever.com/oauth/tokens` |
| OIDC Discovery | `https://clever.com/.well-known/openid-configuration` |
| User Identity | `https://api.clever.com/v3.0/me` |
| User Details | `https://api.clever.com/v3.0/users/{id}` |
| District Info | `https://api.clever.com/v3.0/districts/{id}` |
| UserInfo (OIDC) | `https://api.clever.com/userinfo` |

### 1.2 What Chalk Implements

When a partner is configured with `mode = "clever-compatible"`, Chalk exposes the following endpoints on the Chalk instance (e.g., `chalk.springfield.k12.us`):

| Chalk Endpoint | Mirrors |
|----------------|---------|
| `/oauth/authorize` | Clever's authorize endpoint |
| `/oauth/tokens` | Clever's token endpoint |
| `/.well-known/openid-configuration` | Clever's OIDC discovery |
| `/v3.0/me` | Clever's /me endpoint |
| `/v3.0/users/{id}` | Clever's user detail endpoint |
| `/v3.0/districts/{id}` | Clever's district endpoint |
| `/userinfo` | Clever's OIDC userinfo endpoint |

### 1.3 OAuth Flow (Clever-Compatible)

The flow is identical to Clever's Authorization Code Grant:

```
1. User clicks app icon on Chalk portal (or vendor redirects user to):
   https://chalk.district.k12.us/oauth/authorize?
     response_type=code&
     client_id={vendor_client_id}&
     redirect_uri={vendor_callback}&
     state={csrf_token}

2. Chalk checks for an existing authenticated session.
   - IF SESSION EXISTS (typical path — user already logged into Chromebook/portal):
     Skip authentication entirely. Proceed immediately to step 3.
     This is the critical "click and you're in" experience.
   - IF NO SESSION (first login of the day, or direct vendor link):
     Chalk prompts for authentication (badge, password, Google, etc.)

3. Chalk redirects to vendor callback with auth code:
   https://vendor.com/callback?code={auth_code}&state={csrf_token}

4. Vendor exchanges code for token:
   POST https://chalk.district.k12.us/oauth/tokens
   Authorization: Basic base64(client_id:client_secret)
   Body: { "code": "...", "grant_type": "authorization_code", "redirect_uri": "..." }

5. Chalk returns:
   { "access_token": "...", "token_type": "Bearer" }
   (+ "id_token" JWT if OIDC-enabled)

6. Vendor calls /v3.0/me with bearer token:
   GET https://chalk.district.k12.us/v3.0/me
   Authorization: Bearer {access_token}

   Response: { "type": "user", "data": { "id": "{chalk_user_id}", "district": "{district_id}" } }

7. Vendor calls /v3.0/users/{id} for full profile:
   Response matches Clever's exact JSON schema (see 1.4)
```

### 1.4 Data Shapes (Clever-Compatible)

#### `/v3.0/me` Response
```json
{
  "type": "user",
  "data": {
    "id": "5f1a2b3c4d5e6f7a8b9c0d1e",
    "district": "4e1d2c3b4a5f6e7d8c9b0a1f",
    "type": "student"
  }
}
```

#### `/v3.0/users/{id}` Response (Student)
```json
{
  "data": {
    "id": "5f1a2b3c4d5e6f7a8b9c0d1e",
    "district": "4e1d2c3b4a5f6e7d8c9b0a1f",
    "type": "student",
    "name": {
      "first": "Jane",
      "middle": "M",
      "last": "Doe"
    },
    "email": "jane.doe@springfield.k12.us",
    "roles": {
      "student": {
        "school": "6a7b8c9d0e1f2a3b4c5d6e7f",
        "sis_id": "STU-12345",
        "state_id": "1234567890",
        "grade": "09",
        "enrollments": [
          {
            "id": "7b8c9d0e1f2a3b4c5d6e7f8a",
            "name": "Algebra I - Period 3",
            "subject": "math",
            "primary_teacher": {
              "id": "8c9d0e1f2a3b4c5d6e7f8a9b",
              "name": "Mr. Smith"
            }
          }
        ]
      }
    },
    "created": "2025-08-01T00:00:00.000Z",
    "last_modified": "2026-01-15T00:00:00.000Z"
  },
  "links": [
    { "rel": "self", "uri": "/v3.0/users/5f1a2b3c4d5e6f7a8b9c0d1e" }
  ]
}
```

#### `/v3.0/users/{id}` Response (Teacher)
```json
{
  "data": {
    "id": "8c9d0e1f2a3b4c5d6e7f8a9b",
    "district": "4e1d2c3b4a5f6e7d8c9b0a1f",
    "type": "teacher",
    "name": {
      "first": "John",
      "last": "Smith"
    },
    "email": "john.smith@springfield.k12.us",
    "roles": {
      "teacher": {
        "school": "6a7b8c9d0e1f2a3b4c5d6e7f",
        "sis_id": "TCH-98765",
        "title": "Mathematics Teacher",
        "sections": [
          {
            "id": "7b8c9d0e1f2a3b4c5d6e7f8a",
            "name": "Algebra I - Period 3",
            "subject": "math",
            "course": "ALG1",
            "students": ["5f1a2b3c4d5e6f7a8b9c0d1e"]
          }
        ]
      }
    },
    "created": "2024-07-01T00:00:00.000Z",
    "last_modified": "2026-01-15T00:00:00.000Z"
  }
}
```

#### OIDC Identity Token Claims
```json
{
  "iss": "https://chalk.springfield.k12.us",
  "sub": "5f1a2b3c4d5e6f7a8b9c0d1e",
  "aud": "{vendor_client_id}",
  "iat": 1708646400,
  "exp": 1708650000,
  "user_id": "5f1a2b3c4d5e6f7a8b9c0d1e",
  "user_type": "student",
  "district": "4e1d2c3b4a5f6e7d8c9b0a1f",
  "multi_role_user_id": "5f1a2b3c4d5e6f7a8b9c0d1e",
  "email": "jane.doe@springfield.k12.us",
  "email_verified": false,
  "given_name": "Jane",
  "family_name": "Doe",
  "nonce": "{if_provided}"
}
```

### 1.5 ID Mapping Strategy

Clever uses 24-character hex string IDs (MongoDB ObjectIds). Chalk must:

- **Generate IDs in the same format** — 24-char lowercase hex strings for all user, district, school, section, and course objects. This ensures vendor-side code that validates or stores Clever IDs doesn't break.
- **Maintain a stable ID mapping table** — `chalk_id → clever_compat_id`. Once generated, an ID never changes.
- **Import Clever IDs on migration** — When a district runs `chalk migrate --from clever`, Chalk imports the existing Clever ID for every user. The vendor's stored user records continue to match.
- **Support `sis_id` matching** — Vendors that match on SIS ID rather than Clever ID will work natively since Chalk has the same SIS data.

### 1.6 TOML Configuration

```toml
[[sso.partners]]
name = "Khan Academy"
mode = "clever-compatible"
client_id = "abc123def456"
client_secret = "encrypted:AES256:..."
redirect_uris = [
  "https://www.khanacademy.org/auth/clever/callback",
  "https://staging.khanacademy.org/auth/clever/callback"
]
user_types = ["student", "teacher"]
icon = "khan-academy.png"
visible_to = ["student", "teacher"]    # Portal visibility
data_access = "district_sso"           # "district_sso" or "library"
```

### 1.7 Vendor Experience

For a vendor already integrated with Clever:

1. Register with Chalk marketplace (or district provides credentials during paid setup)
2. Change 1-3 environment variables:
   - `CLEVER_BASE_URL` → `https://chalk.district.k12.us`
   - `CLEVER_CLIENT_ID` → new client_id from Chalk
   - `CLEVER_CLIENT_SECRET` → new secret from Chalk
3. Done. All existing OAuth code, token parsing, user matching, and API calls work unchanged.

For vendors with hardcoded `clever.com` URLs: a one-time PR to make the base URL configurable (environment variable or admin setting). This is a 10-minute code change.

---

## 2. ClassLink-Compatible SSO Mode

### 2.1 What ClassLink Exposes to Vendors

ClassLink uses OAuth 2.0 with these endpoints:

| Purpose | ClassLink Endpoint |
|---------|-------------------|
| Authorization | `https://launchpad.classlink.com/oauth2/v2/auth` |
| Token Exchange | `https://launchpad.classlink.com/oauth2/v2/token` |
| User Info | `https://nodeapi.classlink.com/v2/my/info` |
| Rostering (OneRoster) | `https://nodeapi.classlink.com/oneroster/v1p1/...` |

ClassLink also supports SAML for some integrations, and LTI 1.3 for LMS connections.

### 2.2 What Chalk Implements

When a partner is configured with `mode = "classlink-compatible"`, Chalk exposes:

| Chalk Endpoint | Mirrors |
|----------------|---------|
| `/oauth2/v2/auth` | ClassLink's authorize endpoint |
| `/oauth2/v2/token` | ClassLink's token endpoint |
| `/v2/my/info` | ClassLink's user info endpoint |
| `/oneroster/v1p1/*` | ClassLink's OneRoster API (Chalk already has OneRoster) |

### 2.3 OAuth Flow (ClassLink-Compatible)

```
1. User clicks app icon on Chalk portal (or vendor redirects user to):
   https://chalk.district.k12.us/oauth2/v2/auth?
     response_type=code&
     client_id={vendor_client_id}&
     redirect_uri={vendor_callback}&
     scope=full

2. Chalk checks for existing session.
   - IF SESSION EXISTS: Skip auth, proceed to step 3 (instant).
   - IF NO SESSION: Prompt for authentication.

3. Chalk redirects to vendor callback with auth code:
   https://vendor.com/callback?code={auth_code}

4. Vendor exchanges code for token:
   POST https://chalk.district.k12.us/oauth2/v2/token
   Body (form-encoded):
     grant_type=authorization_code&
     client_id={id}&
     client_secret={secret}&
     code={auth_code}&
     redirect_uri={vendor_callback}

5. Chalk returns:
   {
     "access_token": "eyJ...",
     "token_type": "Bearer",
     "expires_in": 3600,
     "refresh_token": "def502..."
   }

6. Vendor calls /v2/my/info with bearer token:
   GET https://chalk.district.k12.us/v2/my/info
   Authorization: Bearer {access_token}
```

### 2.4 Data Shapes (ClassLink-Compatible)

#### `/v2/my/info` Response
```json
{
  "UserId": 12345,
  "LoginId": "jane.doe",
  "TenantId": 67890,
  "FirstName": "Jane",
  "LastName": "Doe",
  "Email": "jane.doe@springfield.k12.us",
  "Role": "Student",
  "DisplayName": "Jane Doe",
  "Building": "Springfield High School",
  "BuildingId": 1001,
  "District": "Springfield USD",
  "DistrictId": 67890,
  "Grade": "09",
  "Tenant": "Springfield USD",
  "ImagePath": null,
  "WindowsId": null,
  "SourcedId": "STU-12345"
}
```

### 2.5 ClassLink Scopes

ClassLink uses `scope` parameter in auth requests. Common scopes:

| Scope | Meaning |
|-------|---------|
| `full` | Full user profile access |
| `profile` | Basic profile only |
| `oneroster` | OneRoster API access |
| `openid` | OIDC identity token |

Chalk maps these to appropriate data access levels internally.

### 2.6 TOML Configuration

```toml
[[sso.partners]]
name = "McGraw Hill"
mode = "classlink-compatible"
client_id = "def456ghi789"
client_secret = "encrypted:AES256:..."
redirect_uris = ["https://connect.mheducation.com/sso/callback"]
scopes = ["full", "oneroster"]
icon = "mcgraw-hill.png"
visible_to = ["student", "teacher"]
```

### 2.7 Vendor Experience

For a vendor already integrated with ClassLink:

1. Change base URL from `launchpad.classlink.com` → `chalk.district.k12.us`
2. Change user info URL from `nodeapi.classlink.com` → `chalk.district.k12.us`
3. Update client credentials
4. Done. OAuth flow, token handling, and user info parsing work unchanged.

---

## 3. Active Directory Sync

### 3.1 What Clever IDM and ClassLink OneSync Offer

Both products automate:

- **User provisioning** — Create AD accounts when users appear in SIS
- **User deprovisioning** — Disable/delete AD accounts when users leave SIS
- **Attribute sync** — Keep display name, email, department, title in sync with SIS
- **OU management** — Place users in correct OUs based on school/grade/role
- **Group membership** — Add users to security groups based on role/school/grade
- **Password management** — Generate initial passwords, support resets

Clever IDM charges $1/user/year for this. ClassLink OneSync pricing is opaque but similar.

### 3.2 Architecture

AD sync has a fundamental architectural constraint: Active Directory is on-premises. The Chalk binary must be able to talk to the district's AD domain controller via LDAP/LDAPS.

**Self-hosted Chalk (primary target):** No problem. The Chalk binary runs on the district's network and can reach the DC directly. LDAP operations are just another sync destination alongside Google Workspace.

**Future hosted tier:** Would require a lightweight on-prem agent that proxies LDAP operations from the Chalk cloud instance to the local DC. This is how Clever IDM works for their hosted service. Defer this until hosted tier is built.

### 3.3 Sync Operations

#### User Lifecycle

| SIS Event | AD Action |
|-----------|-----------|
| New student/teacher in SIS | Create AD account in correct OU |
| User changes school | Move to new OU |
| User changes grade | Move to new OU (if OU template uses grade) |
| User changes role | Update group memberships, possibly move OU |
| User leaves district | Disable account (configurable: disable vs. delete) |
| User returns to district | Re-enable account |

#### Username Generation

Same engine as Google Workspace sync, extended for AD:

```
Template: {first}.{last}
Collision: {first}.{last}{n}  → jane.doe, jane.doe2, jane.doe3

Supports:
  {first}           — full first name
  {first:1}         — first initial
  {last}            — full last name
  {last:5}          — first 5 chars of last name
  {sis_id}          — SIS student/staff ID
  {grad_year}       — graduation year (students)
```

#### OU Mapping

Same template system as Google Workspace sync:

```toml
[ad_sync.ou_mapping]
students = "OU=Students,OU={school},OU=Schools,DC=springfield,DC=k12,DC=us"
teachers = "OU=Teachers,OU={school},OU=Staff,DC=springfield,DC=k12,DC=us"
staff = "OU=Staff,OU={school},OU=Staff,DC=springfield,DC=k12,DC=us"
```

Template variables: `{school}`, `{grade}`, `{department}`, `{building_code}`

#### Group Management

```toml
[ad_sync.groups]
# Auto-create and manage group membership
by_school = true        # "Springfield-HS-Students", "Springfield-HS-Teachers"
by_grade = true         # "Grade-09", "Grade-10"
by_section = false      # Per-class groups (optional, can be noisy)
prefix = "Chalk-"       # "Chalk-Springfield-HS-Students" (namespacing)
```

#### Password Policy

```toml
[ad_sync.passwords]
# Initial password generation for new accounts
strategy = "generated"   # "generated" | "sis_id" | "template"
min_length = 12
require_uppercase = true
require_number = true
require_special = false
# Template example: {first:1}{Last:1}{sis_id}! → jD12345!
template = "{first:1}{Last:1}{sis_id}!"
# How to deliver initial passwords
delivery = "csv_export"  # "csv_export" | "email_admin" | "print_cards"
```

### 3.4 LDAP Connection Configuration

```toml
[ad_sync]
enabled = true
sync_schedule = "0 2 * * *"    # Daily at 2 AM (after SIS sync)

[ad_sync.connection]
server = "ldaps://dc01.springfield.k12.us:636"
bind_dn = "CN=Chalk Service,OU=Service Accounts,DC=springfield,DC=k12,DC=us"
bind_password = "encrypted:AES256:..."
base_dn = "DC=springfield,DC=k12,DC=us"
tls_verify = true
tls_ca_cert = "/var/lib/chalk/ad-ca.crt"   # Optional: custom CA for internal PKI

[ad_sync.options]
provision_users = true
deprovision_action = "disable"   # "disable" | "move_to_ou" | "delete"
deprovision_ou = "OU=Disabled,DC=springfield,DC=k12,DC=us"  # If move_to_ou
manage_ous = true                # Auto-create OUs from templates
manage_groups = true
sync_passwords = false           # Only set on initial creation, not ongoing
dry_run = false                  # Preview changes without applying
```

### 3.5 Sync Flow

```
SIS Data (already in Chalk DB via SIS connector)
  ↓
Chalk AD Sync Engine (runs on schedule or CLI: `chalk ad-sync`)
  ↓
1. Read current AD state via LDAP search
2. Diff against SIS-sourced user records
3. Generate change set:
   - Creates (new users in SIS not in AD)
   - Updates (attribute changes: name, email, OU, groups)
   - Disables (users removed from SIS)
4. Apply changes via LDAP modify/add/delete operations
5. Log all operations to audit table
6. Export initial passwords for new accounts (if configured)
  ↓
Audit Log (console + database)
```

### 3.6 Delta Sync

Like Google Workspace sync, AD sync is delta-only:

- Chalk stores a hash of each user's AD-relevant attributes
- On each sync, only users whose attributes changed since last sync are processed
- Typical daily sync for a 5,000 user district: 10-50 LDAP operations
- Full resync available via `chalk ad-sync --full`

### 3.7 Entra ID (Azure AD) Support

Many districts are hybrid or cloud-only with Microsoft Entra ID (formerly Azure AD). Chalk should support both:

- **On-prem AD:** Direct LDAP as described above
- **Entra ID:** Microsoft Graph API for user provisioning

```toml
[ad_sync.connection]
# For Entra ID instead of on-prem
provider = "entra"   # "ldap" (default) | "entra"
tenant_id = "..."
client_id = "..."
client_secret = "encrypted:AES256:..."
```

Entra ID sync uses Microsoft Graph API (`/users`, `/groups`) instead of LDAP. Same sync logic, different transport. Implementation priority: LDAP first (most districts still have on-prem AD), Entra ID second.

### 3.8 CLI Commands

```bash
chalk ad-sync                    # Run delta sync
chalk ad-sync --full             # Full resync
chalk ad-sync --dry-run          # Preview changes without applying
chalk ad-sync --export-passwords # Export initial passwords for new accounts
chalk ad-sync --status           # Show last sync results
chalk ad-sync --test-connection  # Verify LDAP connectivity and bind
```

---

## 4. Migration Tooling

### 4.1 Clever Migration

```bash
chalk migrate --from clever --clever-token {district_api_token}
```

This command:

1. Pulls all district data via Clever's Data API (users, schools, sections, enrollments)
2. Maps each Clever ID to a Chalk internal record, preserving the Clever ID as `clever_compat_id`
3. Imports SSO partner configurations (which apps the district has connected via Clever)
4. Generates TOML partner entries with `mode = "clever-compatible"` for each app
5. Outputs a migration report showing:
   - Users imported (students, teachers, staff)
   - Apps migrated (with compatibility status)
   - Apps requiring vendor-side URL change
   - Recommended next steps

### 4.2 ClassLink Migration

```bash
chalk migrate --from classlink --classlink-token {api_token}
```

Same approach: pull data, map IDs, generate TOML entries with `mode = "classlink-compatible"`.

### 4.3 Post-Migration Checklist

Generated automatically by the migration tool:

```
✅ SIS connection configured and syncing
✅ 2,847 students imported with Clever IDs preserved
✅ 312 teachers imported with Clever IDs preserved
✅ Google Workspace sync configured
✅ 14 SSO partners migrated:
   ✅ Khan Academy (clever-compatible) — ready
   ✅ Kahoot (clever-compatible) — ready
   ✅ IXL (clever-compatible) — ready
   ⚠️  Zoom (SAML) — district needs to update IDP metadata in Zoom admin
   ⚠️  McGraw Hill (classlink-compatible) — vendor needs URL update
   ❌ Custom App X — proprietary integration, needs manual setup

Next steps:
1. Update DNS: chalk.springfield.k12.us → this server
2. For ⚠️ apps: update IDP URL in vendor admin panels
3. Test SSO for each app with a pilot user
4. Run both Chalk and Clever in parallel for 2 weeks
5. When ready: disable Clever portal, make Chalk portal the default
```

---

## 5. TOML Configuration — Complete Example

```toml
[chalk]
instance_name = "Springfield USD"
data_dir = "/var/lib/chalk"
public_url = "https://chalk.springfield.k12.us"

[chalk.database]
driver = "sqlite"
path = "/var/lib/chalk/chalk.db"

# --- SIS ---
[sis]
enabled = true
provider = "PowerSchool"
base_url = "https://sis.springfield.k12.us"
client_id = "..."
client_secret = "encrypted:AES256:..."
sync_schedule = "0 1 * * *"

# --- Identity Provider ---
[idp]
enabled = true
qr_badge_login = true
picture_passwords = true

# --- Google Workspace Sync ---
[google_sync]
enabled = true
provision_users = true
manage_ous = true
suspend_inactive = true
sync_schedule = "0 3 * * *"
service_account_key_path = "/var/lib/chalk/google-sa.json"
admin_email = "admin@springfield.k12.us"
workspace_domain = "springfield.k12.us"

[google_sync.ou_mapping]
students = "/Students/{school}/{grade}"
teachers = "/Staff/{school}/Teachers"

# --- Active Directory Sync ---
[ad_sync]
enabled = true
sync_schedule = "0 2 * * *"

[ad_sync.connection]
server = "ldaps://dc01.springfield.k12.us:636"
bind_dn = "CN=Chalk Service,OU=Service Accounts,DC=springfield,DC=k12,DC=us"
bind_password = "encrypted:AES256:..."
base_dn = "DC=springfield,DC=k12,DC=us"
tls_verify = true

[ad_sync.ou_mapping]
students = "OU=Students,OU={school},OU=Schools,DC=springfield,DC=k12,DC=us"
teachers = "OU=Teachers,OU={school},OU=Staff,DC=springfield,DC=k12,DC=us"

[ad_sync.groups]
by_school = true
by_grade = true
prefix = "Chalk-"

[ad_sync.passwords]
strategy = "template"
template = "{first:1}{Last:1}{sis_id}!"
delivery = "csv_export"

[ad_sync.options]
provision_users = true
deprovision_action = "disable"
manage_ous = true
manage_groups = true

# --- SSO Partners ---

# Clever-compatible vendors (vendor changes nothing)
[[sso.partners]]
name = "Khan Academy"
mode = "clever-compatible"
client_id = "abc123"
client_secret = "encrypted:AES256:..."
redirect_uris = ["https://www.khanacademy.org/auth/clever/callback"]
user_types = ["student", "teacher"]
data_access = "district_sso"
icon = "khan-academy.png"
visible_to = ["student", "teacher"]

[[sso.partners]]
name = "IXL"
mode = "clever-compatible"
client_id = "def456"
client_secret = "encrypted:AES256:..."
redirect_uris = ["https://www.ixl.com/signin/clever"]
user_types = ["student", "teacher"]
data_access = "district_sso"
icon = "ixl.png"
visible_to = ["student", "teacher"]

# ClassLink-compatible vendors (vendor changes nothing)
[[sso.partners]]
name = "McGraw Hill"
mode = "classlink-compatible"
client_id = "ghi789"
client_secret = "encrypted:AES256:..."
redirect_uris = ["https://connect.mheducation.com/sso/callback"]
scopes = ["full", "oneroster"]
icon = "mcgraw-hill.png"
visible_to = ["student", "teacher"]

# Standard SAML (district configures, vendor supports any IDP)
[[sso.partners]]
name = "Zoom"
mode = "saml"
entity_id = "https://zoom.us/saml/metadata"
acs_url = "https://springfield.zoom.us/saml/SSO"
name_id_format = "email"
icon = "zoom.png"
visible_to = ["teacher", "staff"]

# Standard OIDC
[[sso.partners]]
name = "Custom Assessment Tool"
mode = "oidc"
client_id = "jkl012"
client_secret = "encrypted:AES256:..."
redirect_uris = ["https://assess.example.com/auth/callback"]
icon = "custom-assess.png"
visible_to = ["student", "teacher"]

# --- Marketplace ---
[marketplace]
enabled = false    # Pre-registration only for now
```

---

## 6. Session Management & Instant Login

This is the most important UX detail in the entire system. **A student who is logged into their Chromebook should never see a login prompt when clicking an app in the Chalk portal.** This is how Clever works today, and anything less is a regression that teachers will immediately notice and reject.

### 6.1 Session Establishment

A Chalk session is established when a user authenticates through any supported method:

| Auth Method | When It Happens | Session Created |
|-------------|----------------|-----------------|
| Google IDP federation | Student logs into Chromebook | Yes — Chalk session cookie set via IDP redirect |
| Chalk IDP (password) | Student types password on Chalk login page | Yes |
| QR badge scan | Student scans badge at shared device | Yes |
| Picture password | Young student selects images | Yes |
| Active Directory / Entra ID | Staff logs in via AD federation | Yes |

### 6.2 Session Cookie

Chalk sets an HTTP-only, Secure, SameSite=Lax session cookie on the Chalk domain (e.g., `chalk.springfield.k12.us`). This cookie persists for the duration configured by the district (default: school day, 8 hours).

```toml
[idp.session]
duration = "8h"              # Session lifetime
extend_on_activity = true    # Reset timer on each portal/SSO interaction
cookie_name = "chalk_session"
secure = true                # HTTPS only
same_site = "Lax"            # Required for OAuth redirects to work
```

### 6.3 The "Click and You're In" Flow

The typical Chromebook student experience:

```
Morning:
  1. Student opens Chromebook lid
  2. Logs into ChromeOS with Google account (jane.doe@springfield.k12.us)
  3. Google auth federates through Chalk IDP → Chalk session cookie set
  4. Browser opens to Chalk portal (bookmarked or set as homepage)
  5. Student sees their app icons — already authenticated, no login prompt

Throughout the day:
  6. Student clicks "Khan Academy" icon
  7. Chalk portal sends OAuth authorize request
  8. Chalk sees valid session → IMMEDIATELY generates auth code (no prompt)
  9. Redirects to Khan Academy callback with auth code
  10. Khan Academy exchanges code for token, gets user identity
  11. Student lands in Khan Academy, logged in
  12. Total time from click to app: <1 second (network round-trips only)

  13. Student clicks "IXL" icon → same instant flow
  14. Student clicks "McGraw Hill" icon → same instant flow
```

**There is no authentication step between steps 7 and 9.** The session is the authentication. This is the whole point.

### 6.4 Chromebook-Specific Integration

For districts using Chromebooks (the vast majority of K-12), the ideal flow is:

1. District configures Chalk as a SAML IDP for Google Workspace
2. Student logs into Chromebook → ChromeOS authenticates via Google → Google authenticates via Chalk SAML IDP
3. This SAML exchange establishes the Chalk session simultaneously
4. When the student opens the Chalk portal in Chrome, the session cookie is already present
5. Every app click is instant from that point forward

Alternatively, if the district uses Google as the primary IDP (not Chalk):

1. Student logs into Chromebook with Google credentials directly
2. Student navigates to Chalk portal
3. Portal detects no Chalk session → redirects to Google for authentication
4. Google recognizes the existing ChromeOS session → immediately redirects back (no prompt)
5. Chalk establishes session from Google OAuth token
6. All subsequent app clicks are instant

Either path results in the same UX: **log in once at the Chromebook, everything else is instant.**

### 6.5 Shared Device / Lab Scenario

On shared Chromebooks (computer labs, library), the flow differs:

1. Student approaches shared Chromebook (logged into a generic lab account, or ChromeOS guest)
2. Student opens Chalk portal → no session exists
3. Chalk shows login options: QR badge scan, picture password, or typed credentials
4. Student scans their badge → Chalk session established
5. All app clicks are instant for the rest of the session
6. Student clicks "Log Out" or session times out → next student repeats from step 2

```toml
[idp.session]
# Shorter sessions for shared devices (configurable per-device or per-network)
shared_device_duration = "45m"   # Class period length
```

---

## 7. Portal Behavior

The SSO portal at `/portal` renders the same regardless of partner mode. Students and teachers see their app icons. Clicking an icon initiates the appropriate flow based on the partner's `mode`:

- `clever-compatible` → OAuth 2.0 Authorization Code flow with Clever-format endpoints
- `classlink-compatible` → OAuth 2.0 Authorization Code flow with ClassLink-format endpoints
- `saml` → SAML 2.0 IDP-initiated flow
- `oidc` → OIDC Authorization Code flow

The user sees no difference between modes. They click an icon and land in their app, authenticated.

---

## 8. Marketplace Implications

The compatibility layers make the marketplace dramatically easier to build:

**Vendor onboarding becomes a form:**

1. "How are you currently integrated?" → Clever / ClassLink / SAML / OIDC / Other
2. If Clever: "What's your Clever app client_id?" → Auto-generate Chalk-compatible config
3. If ClassLink: "What's your ClassLink client_id?" → Auto-generate Chalk-compatible config
4. If SAML/OIDC: Standard metadata exchange
5. Test connection with sandbox district
6. Live

**The vendor pitch becomes:**

> "You already built for Clever or ClassLink. You're already integrated with Chalk. Register on our marketplace to reach schools that want open-source infrastructure. Same API, same data, same flow — just a different (and cheaper) address."

This is why the compatibility layer isn't just a migration tool — it's the marketplace's distribution advantage. Every vendor already integrated with Clever or ClassLink is a potential Chalk marketplace vendor with near-zero onboarding friction.

---

## 9. Implementation Priority

| Feature | Priority | Effort Estimate | Rationale |
|---------|----------|-----------------|-----------|
| Clever-Compatible SSO | P0 | 2-3 weeks | 65% of US K-12 is on Clever. This unlocks the majority of vendor connections. |
| Active Directory Sync (LDAP) | P0 | 2-3 weeks | Mid-to-large districts require this. Blocks enterprise adoption. |
| ClassLink-Compatible SSO | P1 | 1-2 weeks | Largely reuses Clever-compat architecture. Smaller but growing market share. |
| Entra ID Sync | P1 | 1-2 weeks | Graph API based. Growing number of cloud-only districts. |
| Migration CLI (Clever) | P1 | 1 week | Critical for paid setup service. Must work before first pilot district. |
| Migration CLI (ClassLink) | P2 | 1 week | After ClassLink-compat SSO is built. |

**Total estimated effort: 8-12 weeks for one developer.**

This puts all three features in place before pilot district recruitment, making the paid setup service pitch fully credible: "We'll migrate you from Clever in an afternoon. Your vendors won't know the difference."